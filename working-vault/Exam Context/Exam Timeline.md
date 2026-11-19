---
type: exam-timeline
project: OSCP-Exam-PoC
status: reconstructed
updated: "2026-11-07"
exam: IT GATE Academy OSCP-Style Examination
machine_count: 5
machine_sequence:
  - VE-01
  - EA-01
  - ME-01
  - HA-01
  - IN-01
tags:
  - exam
  - timeline
  - penetration-testing
  - oscp
  - exploitation
  - troubleshooting
---
# Exam Timeline

## 1. Purpose and Evidence Basis

This document reconstructs the examination's progression across all five machines.

It records the actual order of work, significant technical discoveries, successful attack paths, abandoned approaches, and incidents that affected the investigation.

The primary source is the preserved examination record.

### Timestamp conventions

The examination record does not preserve an individual timestamp for every step. The following distinctions therefore apply:

- **Kali timestamps:** Timestamps appearing in terminal prompts. These are preserved as recorded, using the local `+0200` offset where shown.
    
- **Target timestamps:** File modification times and service timestamps from the remote machines. These are not treated as examination event timestamps.
    
- **Reconstructed sequence:** Events whose order is established by the examination record but for which an exact time is unavailable.
    

The machine sequence is confirmed:

**VE-01 → EA-01 → ME-01 → HA-01 → IN-01**

The timeline does not manufacture timestamps to fill gaps.

---

## 2. Examination Progression

|Sequence|Difficulty|Machine|Initial Access|Privilege Escalation|
|---|---|---|---|---|
|01|Very Easy|VE-01|PHP file upload → command execution|Sudo `find`|
|02|Easy|EA-01|SQLite SQL injection → SSH as `robert`|SUID `find`|
|03|Medium|ME-01|Directory traversal → API key → command injection|`CAP_SETUID` on `pyadmin`|
|04|Hard|HA-01|Redis persistence → SSH as `devops`|Root cron → tar wildcard injection|
|05|Insane|IN-01|SSRF filter bypass → Python Pickle RCE|Sudo `LD_PRELOAD` injection|

All five machines were investigated sequentially, not as independent exercises.

---

## 3. VE-01 — Very Easy

**Position:** First machine in the examination.

**Attack chain:**

```
Public Web Application
        |
        v
PHP File Upload
        |
        v
PHP Command Execution
        |
        v
www-data
        |
        v
User Flag
        |
        v
Sudo Misconfiguration
        |
        v
find -exec
        |
        v
Root
```

### 3.1 Initial Access

The assigned target was:

```
http://x.x.x.x:PORT_L/
```

The application accepted a PHP file upload that was subsequently accessible through:

```
/uploads/file.php
```

The uploaded PHP script accepted a `cmd` parameter and executed operating-system commands.

A working-directory check returned:

```
/var/www/html/uploads
```

The execution context was the web-server account, `www-data`.

The user account was identified through:

```
/home/user
```

The user flag was retrieved from:

```
/home/user/user.txt
```

**Result:** User-level objective completed.

### 3.2 Privilege Escalation

The `sudo -l` output revealed:

```
User www-data may run the following commands:

(ALL) NOPASSWD: /usr/bin/find
```

GNU `find` was abused through its `-exec` functionality to execute a privileged shell.

The root objective was completed using the resulting elevated execution context.

**Result:** Root objective completed.

### 3.3 Examination Notes

The machine established the first successful exploitation pattern:

- Identify the application's upload mechanism.
    
- Confirm that the uploaded file is executed by the server.
    
- Establish command execution.
    
- Enumerate the execution identity.
    
- Inspect sudo permissions.
    
- Exploit the specific permitted binary.
    

The important distinction is that the initial access and privilege-escalation vectors were separate vulnerabilities.

**Detailed records:**

- [[VE-01 Overview]]
    
- [[Difficulty Levels/Very Easy/VE-01/user]]
    
- [[Difficulty Levels/Very Easy/VE-01/root]]
    

---

## 4. EA-01 — Easy

**Position:** Second machine in the examination.

**Attack chain:**

```
Public Web Application
        |
        v
SQL Injection
        |
        v
SQLite Enumeration
        |
        v
Credential Discovery
        |
        v
SSH as robert
        |
        v
User Flag
        |
        v
SUID find
        |
        v
Root
```

### 4.1 Initial Access

The machine exposed:

|Service|Endpoint|
|---|---|
|HTTP|`x.x.x.x:PORT_N`|
|SSH|`x.x.x.x:PORT_H`|

The web application accepted a search parameter:

```
?q=
```

Testing identified an SQL injection vulnerability.

The application returned two columns, allowing two-column `UNION SELECT` enumeration.

MySQL-specific enumeration failed. The following SQLite metadata query revealed the database structure:

```
' UNION SELECT name, sql FROM sqlite_master WHERE type='table'-- -
```

The relevant table was:

```
users
```

Its columns included:

```
id
username
password
```

Credential extraction identified `robert` as a candidate SSH account.

SSH access was established using the discovered credential.

The user flag was retrieved from:

```
/home/robert/user.txt
```

**Result:** User-level objective completed and submitted.

### 4.2 Privilege Escalation

The target did not have `sudo` installed.

SUID enumeration identified:

```
-rwsr-xr-x 1 root root ... /usr/bin/find
```

The SUID permission allowed the binary to execute with root effective privileges.

GNU `find` was used to invoke a privileged shell.

The resulting identity included:

```
uid=1000(robert) gid=1000(robert) euid=0(root)
```

The root flag was retrieved and the root objective was completed.

**Result:** Root objective completed.

### 4.3 Examination Notes

EA-01 introduced two distinctions:

1. Database credentials are not automatically Linux credentials. Their relationship must be tested.
    
2. The absence of `sudo` does not eliminate privilege-escalation opportunities.
    

The escalation mechanism resembled VE-01 at the binary level, but the vulnerable configuration was different:

|Machine|`find` configuration|
|---|---|
|VE-01|Sudo permission|
|EA-01|SUID permission|

**Detailed records:**

- [[Difficulty Levels/Easy/EA-01/EA-01 Overview]]
    
- [[Difficulty Levels/Easy/EA-01/user]]
    
- [[Difficulty Levels/Easy/EA-01/root]]
    

---

## 5. ME-01 — Medium

**Position:** Third machine in the examination.

**Investigation date:** November 4, 2026.

**Attack chain:**

```
Public API
    |
    v
Directory Traversal
    |
    v
Application File Read
    |
    +-------> user.txt
    |
    v
Application Source / Configuration Discovery
    |
    v
API Key Recovery
    |
    v
Command Injection
    |
    v
svc
    |
    v
CAP_SETUID on pyadmin
    |
    v
Root
```

### 5.1 Initial Reconnaissance

The machine exposed an HTTP application on:

```
x.x.x.x:PORT_I
```

Two API endpoints were identified:

```
/api/download?file=
/api/ping?host=
```

The download endpoint was the first confirmed vulnerability.

### 5.2 Directory Traversal

The `file` parameter was vulnerable to directory traversal.

The application constructed a filesystem path using the supplied parameter without properly normalizing it.

This allowed access beyond the intended public-share directory.

The investigation established that the application could read:

- `/etc/passwd`
    
- `/proc/self/status`
    
- Application files
    
- The user flag
    

The user flag was retrieved through the file-read vulnerability.

**Result:** User-level objective completed.

### 5.3 Connectivity and Tooling Changes

During the investigation, HTTP requests to the examination server were affected by ISP redirection.

A request recorded at:

```
2026-11-04@20:11:47
```

demonstrated that the problem was not simply a missing command-line tool.

Burp Suite was initially considered, but the existing Academy VPN workflow introduced a conflict with Burp's proxy configuration.

After discussing the situation with the instructor, the workflow changed to `curl`.

This also became an opportunity to understand the HTTP request parameters rather than relying exclusively on a GUI proxy.

A later request was recorded at:

```
2026-11-04@20:50:18
```

The investigation continued with terminal-based HTTP requests.

A Windscribe installation and routing investigation also took place. The downloaded package was initially invalid, a valid release package was subsequently located and verified, and its installation was simulated. The available record does not establish that Windscribe was installed or connected.

### 5.4 API Key Discovery and Command Injection

The file-read vulnerability was used to inspect the application's implementation and configuration.

The API key was recovered from the application configuration.

The `/api/ping` endpoint required the key through:

```
X-API-Key: <API_KEY>
```

Further source-code inspection revealed that the `host` parameter was concatenated into a shell command.

This created a command-injection vulnerability.

The supplied API key allowed the request to reach the vulnerable code path, resulting in command execution as:

```
svc
```

The significant discovery was not merely that the endpoint accepted a hostname. It was that untrusted input reached a shell command without safe argument handling.

### 5.5 Privilege Escalation

Capability enumeration identified:

```
/usr/local/bin/pyadmin cap_setuid=ep
```

The executable was root-owned but did not have the SUID permission.

Its dangerous capability was:

```
CAP_SETUID=ep
```

The Python-based executable could change its process UID.

The demonstrated transition was:

```
1000 1000
0 0
```

This established the change from the `svc` identity to UID 0.

The root flag was retrieved and submitted.

**Result:** Root objective completed.

### 5.6 Examination Notes

ME-01 was the first machine where the successful chain depended on connecting several application-level findings:

1. Directory traversal exposed application files.
    
2. Application configuration disclosed an API key.
    
3. The API key unlocked an endpoint containing command injection.
    
4. A Linux capability provided the privilege-escalation mechanism.
    

The machine demonstrated the value of inspecting application source and configuration rather than treating each endpoint as an isolated function.

**Detailed records:**

- [[Difficulty Levels/Medium/ME-01/ME-01 Overview]]
    
- [[Difficulty Levels/Medium/ME-01/user]]
    
- [[Difficulty Levels/Medium/ME-01/root]]
    

---

## 6. HA-01 — Hard

**Position:** Fourth machine in the examination.

**Investigation period:** November 4–5, 2026.

**Attack chain:**

```
Unauthenticated Redis
        |
        v
Redis Administrative Commands
        |
        v
Filesystem Persistence
        |
        v
SSH Public-Key Injection
        |
        v
SSH as devops
        |
        v
Local Privilege Enumeration
        |
        v
Root Cron Job
        |
        v
Tar Wildcard Injection
        |
        v
Root
```

### 6.1 Initial Reconnaissance

HA-01 exposed Redis and SSH.

The first recorded Nmap investigation began at:

```
2026-11-04@22:06:31
```

Redis was identified on the externally exposed port:

```
PORT_P/tcp
```

The Redis service was accessible without authentication.

Further enumeration identified:

```
Redis 7.0.15
```

The default ACL was unrestricted:

```
user default on nopass ~* &* +@all
```

This allowed administrative Redis commands, including configuration and persistence operations.

### 6.2 Initial Exploitation Investigations

Several possible Redis exploitation paths were investigated.

|Approach|Outcome|
|---|---|
|Redis RDB persistence and SSH key injection|Initially investigated; filesystem relationship remained uncertain|
|RediShell — CVE-2025-49844|PoC target profiles did not match Redis 7.0.15|
|DarkReplica — CVE-2026-23631|No matching target profile|
|Metasploit Redis replication|Target accepted the replication configuration, but the callback connection was not established|

The RediShell investigation included modifying the PoC's remote connection configuration. This confirmed remote connectivity but did not solve the binary-specific target-profile mismatch.

The Metasploit investigation demonstrated another important distinction:

**Kali reaching the target does not prove that the target can initiate a connection back to Kali.**

The target accepted the replication configuration, but the required callback did not arrive.

The investigation eventually moved away from callback-dependent exploitation.

### 6.3 Redis Persistence and Initial Access

The Redis instance was refreshed during the examination, changing the exposed ports.

The later investigation established that Redis could access:

```
/home/devops/.ssh
```

A controlled persistence write test was performed using a harmless filename.

Redis successfully wrote an RDB snapshot to the directory.

This established the filesystem-write prerequisite for the Redis-to-SSH technique.

The attack then used Redis persistence to place SSH public-key material in:

```
/home/devops/.ssh/authorized_keys
```

SSH access was established as:

```
devops
```

The final successful instance used the Redis and SSH endpoints recorded in the machine-specific notes.

**Result:** Linux user-level access established; user flag obtained and submitted (participant-confirmed).

### 6.4 Privilege-Escalation Enumeration

The target did not have `sudo` installed.

SUID enumeration did not reveal a useful escalation path.

Cron inspection identified a custom maintenance job:

```
/etc/cron.d/maint
```

The job executed as root every minute:

```
* * * * * root /opt/maint/backup.sh >/dev/null 2>&1
```

The backup script contained:

```
#!/bin/sh
cd /opt/maint/spool 2>/dev/null || exit 0
tar -czf /opt/maint/backup.tar.gz * 2>/dev/null
```

The spool directory was writable by `devops`.

The vulnerable combination was:

- A root-executed scheduled task.
    
- An unquoted wildcard.
    
- Attacker-controlled filenames.
    
- GNU tar interpreting specially named files as command-line options.
    

### 6.5 Root Compromise

The tar checkpoint mechanism was used to execute a command through the root cron job.

The specially named files were:

```
--checkpoint=1
--checkpoint-action=exec=sh root-flag.sh
```

The script retrieved:

```
/root/root.txt
```

The flag was obtained and submitted, as confirmed by the examination participant.

**Result:** Root objective completed.

### 6.6 Examination Notes

HA-01 required a significant change in direction.

The successful route was not the most sophisticated CVE investigated. It was the route supported by the actual Redis filesystem permissions and the SSH environment.

The privilege-escalation stage was also based on a concrete configuration flaw rather than a kernel exploit.

**Detailed records:**

- [[Difficulty Levels/Hard/HA-01/HA-01 Overview]]
    
- [[Difficulty Levels/Hard/HA-01/user]]
    
- [[Difficulty Levels/Hard/HA-01/root]]
    

---

## 7. IN-01 — Insane

**Position:** Fifth and final machine in the examination.

**Investigation date:** November 5, 2026.

**Attack chain:**

```
Public URL Preview
        |
        v
SSRF
        |
        v
Loopback Filter Bypass
        |
        v
Internal Admin API :9000
        |
        v
/admin/exec
        |
        v
Python Pickle Deserialization
        |
        v
Remote Code Execution as web
        |
        v
Sudo Enumeration
        |
        v
LD_PRELOAD Injection
        |
        v
Root
```

### 7.1 Initial Reconnaissance

The application exposed a URL-preview feature:

```
/fetch?url=
```

The endpoint performed server-side HTTP requests and returned the fetched content.

The initial page indicated that internal addresses were blocked.

The first successful baseline request established that SSRF functionality existed, but internal-address filtering remained an obstacle.

The first timestamped terminal request in the recorded IN-01 investigation was:

```
2026-11-05@11:07:52
```

### 7.2 SSRF Filter Bypass

Canonical loopback representations were rejected:

```
127.0.0.1
localhost
[::1]
```

Alternative representations were tested.

The most useful representation was:

```
127.1
```

Other tested representations included:

```
2130706433
0x7f000001
0177.0.0.1
```

The filter accepted the noncanonical loopback representation, allowing the URL-fetching service to reach internal services.

**Result:** SSRF filter bypass confirmed.

### 7.3 Internal Service Discovery

The investigation initially spent time exploring port 8080 and attempting broad path discovery.

A large FFUF scan produced insufficient useful information and was stopped.

The investigation shifted toward targeted internal port discovery.

The decisive result identified an internal service on:

```
127.1:9000
```

Its banner was:

```
IT GATE internal admin API (localhost only)
```

This established the existence of a localhost-restricted administrative API.

### 7.4 Administrative Endpoint Discovery

Generic API path enumeration returned identical 404 responses.

A targeted wordlist eventually identified:

```
/admin/exec
```

An empty request produced:

```
HTTP 400 BAD REQUEST

error: Ran out of input
```

The response was materially different from the generic 404 responses.

Further testing identified the request parameter:

```
data
```

An invalid value produced a Base64-related parsing error.

A valid encoded Python Pickle payload reached the deserialization process.

**Result:** The internal administrative endpoint's Pickle deserialization behavior was identified.

### 7.5 Python Pickle Remote Code Execution

A crafted Pickle object invoked operating-system commands during deserialization.

Command output was returned through the existing SSRF request path.

The execution identity was confirmed:

```
uid=1000(web) gid=1000(web) groups=1000(web)
```

Additional environment details:

```
Hostname: insane
Working directory: /opt/app
```

The user-flag retrieval command was issued through the in-band execution mechanism.

The participant confirms retrieval and submission of the user flag; the public value is `IT{FLAG-SECRET}`.

**Result:** Initial command execution as `web` confirmed; user flag obtained and submitted (participant-confirmed).

### 7.6 Reverse-Shell Attempts

Reverse-shell callbacks were attempted using two VPN addresses:

```
10.144.220.24
10.10.17.123
```

Neither attempt established an interactive shell.

The cause was not conclusively established.

Rather than continue repeating unsuccessful callback attempts, the investigation retained the working in-band Pickle RCE mechanism.

This was sufficient to complete the privilege-escalation stage.

### 7.7 Privilege-Escalation Enumeration

Sudo enumeration revealed:

```
User web may run the following commands:

(root) NOPASSWD: /usr/local/bin/healthcheck
```

The sudo Defaults included:

```
env_keep+=LD_PRELOAD
```

The allowed executable was:

```
/usr/local/bin/healthcheck
```

Inspection established that it was:

- Root-owned.
    
- Executable by the user.
    
- A dynamically linked ELF binary.
    
- Compatible with the available shared-library loading mechanism.
    

The target had GCC, `cc`, and `readelf`, but did not have the `file` utility.

The binary was inspected using available tools, including `strings`.

### 7.8 LD_PRELOAD Privilege Escalation

A C shared library was created and compiled on the target.

The resulting library was:

```
/tmp/in01_preload.so
```

It was loaded through the permitted sudo command:

```
sudo -n LD_PRELOAD=/tmp/in01_preload.so \
  /usr/local/bin/healthcheck
```

The constructor executed successfully.

Captured output:

```
[+] LD_PRELOAD constructor executed
[+] UID=0 EUID=0 GID=0 EGID=0
```

The root flag was successfully retrieved:

```
IT{FLAG-SECRET}
```

**Result:** Root compromise confirmed.

The available record does not confirm whether the temporary files under `/tmp` were removed afterward.

### 7.9 Examination Notes

IN-01 required the largest number of investigative pivots.

The important decisions were:

- Stop broad scanning when it produced no useful information.
    
- Distinguish the public application from internal services reachable through SSRF.
    
- Use response differences to identify a meaningful endpoint.
    
- Recognize the Pickle deserialization error.
    
- Continue with in-band execution when reverse-shell callbacks failed.
    
- Exploit the actual sudo configuration rather than relying on unrelated privilege-escalation checks.
    

**Detailed records:**

- [[Difficulty Levels/Insane/IN-01/IN-01 Overview]]
    
- [[Difficulty Levels/Insane/IN-01/user]]
    
- [[Difficulty Levels/Insane/IN-01/root]]
    

---

## 8. Examination-Wide Incidents and Difficulties

|Incident|Machine / Area|Impact|Resolution|
|---|---|---|---|
|ISP interference with HTTP-only examination access|ME-01|HTTP requests were redirected or obstructed|Instructor contacted; terminal-based HTTP workflow adopted|
|Burp and VPN routing conflict|ME-01|Burp was inconvenient within the active VPN setup|Switched to `curl`|
|Windscribe package validation|Kali environment|Initial download was HTML instead of a valid Debian package|Located and verified an official release package; installation not confirmed|
|Redis CVE target-profile mismatch|HA-01|Time spent investigating incompatible exploit profiles|Pivoted to Redis persistence|
|Redis replication callback failure|HA-01|Target did not connect back to Kali|Abandoned callback-dependent route|
|Multiple HA-01 instances|HA-01|Redis and SSH ports changed|Revalidated the active instance|
|Broad FFUF scan|IN-01|Approximately 15 minutes spent on a low-value scan|Shifted to targeted internal service discovery|
|Incorrect wordlist path|IN-01|Fuzzing command could not locate the intended list|Located the installed wordlist|
|Generic 404 responses|IN-01|API path discovery produced unhelpful results|Used a baseline response and targeted parameter discovery|
|Public HTTP service timeouts|IN-01|Requests connected but received no HTTP response|Continued after the application recovered|
|Zsh `path` variable collision|Kali environment|PATH became corrupted because `path` is a special Zsh array|Restored the PATH configuration|
|Reverse-shell callback failures|IN-01|No interactive shell established|Continued with in-band command execution|
|Nested Base64 and URL encoding|IN-01|Encoded request parameters were corrupted|Encoded the inner payload before URL encoding|
|Missing target utilities|IN-01|`file` was unavailable|Used `strings` and available ELF inspection tools|
|Non-UTF-8 output|IN-01|Binary output caused decoding failures|Used text-oriented and encoding-aware inspection|

---

## 9. Major Methodological Pivots

The following decisions materially changed the outcome of the examination.

|Initial Direction|Evidence or Problem|Final Direction|
|---|---|---|
|Blind file-upload payload testing|Need to establish actual server-side execution|Confirmed PHP execution and command execution|
|Database-engine assumptions|MySQL queries failed|Switched to SQLite metadata enumeration|
|Generic Linux privilege checks|Target-specific findings were more useful|Focused on `find`, capabilities, cron, and sudo rules|
|Burp-based HTTP workflow|VPN and proxy configuration conflict|Used `curl` with explicit parameter handling|
|Redis CVE exploitation|PoC profiles did not match the target binary|Redis filesystem persistence|
|Redis replication RCE|Target callback did not reach Kali|Redis-to-SSH key injection|
|Broad internal web fuzzing|Port behavior and responses were unproductive|Targeted internal port and API discovery|
|Reverse-shell dependency|Callback attempts failed|In-band Pickle RCE|
|Generic privilege-escalation search|Explicit `LD_PRELOAD` preservation was discovered|Focused on sudo shared-library injection|

---

## 10. Final Examination Status

All five machines were completed. The examination participant confirms that both user and root flags were obtained and submitted for every machine. Published flag values are masked as `IT{FLAG-SECRET}`.

|Machine|User Flag|Root Flag|Final Status|
|---|---|---|---|
|VE-01|Obtained and submitted|Obtained and submitted|Completed|
|EA-01|Obtained and submitted|Obtained and submitted|Completed|
|ME-01|Obtained and submitted|Obtained and submitted|Completed|
|HA-01|Obtained and submitted|Obtained and submitted|Completed|
|IN-01|Obtained and submitted|Obtained and submitted|Completed|

---

## 11. Final Observations

The five machines introduced progressively more interconnected attack chains:

|Difficulty|Main Learning Point|
|---|---|
|Very Easy|Server-side file upload execution and sudo misconfiguration|
|Easy|SQL injection, SQLite enumeration, SSH credential discovery, and SUID exploitation|
|Medium|Directory traversal, application configuration disclosure, command injection, and Linux capabilities|
|Hard|Redis administrative access, filesystem persistence, SSH access, and cron wildcard injection|
|Insane|SSRF filter bypass, internal service discovery, insecure deserialization, in-band RCE, and `LD_PRELOAD`|

The most important recurring principle was to follow the evidence rather than commit prematurely to an exploitation hypothesis.

Several successful compromises required abandoning an initially attractive route:

- Redis CVE exploitation was abandoned when the PoC's target assumptions did not match the machine.
    
- Redis replication was abandoned when callback connectivity failed.
    
- Broad internal fuzzing was replaced with targeted service discovery.
    
- Reverse-shell attempts were replaced with in-band execution.
    

The examination also exposed a distinction between achieving access and preserving proof of access. A completed objective is not fully documented until the relevant output, command, and result are retained.

---

## 12. Related Documentation

### Central Documentation

- [[Dashboard]]
    
- [[Exam Overview]]
    
- [[Lab Environment]]
    

### Machine Records

- [[Difficulty Levels/Very Easy/VE-01/VE-01 Overview]]
    
- [[Difficulty Levels/Easy/EA-01/EA-01 Overview]]
    
- [[Difficulty Levels/Medium/ME-01/ME-01 Overview]]
    
- [[Difficulty Levels/Hard/HA-01/HA-01 Overview]]
    
- [[Difficulty Levels/Insane/IN-01/IN-01 Overview]]
    

---

**Timeline status:** All five machines and their user/root objectives are completed, according to the examination participant. Times remain exact only where timestamps were preserved.