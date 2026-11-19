---
type: dashboard
project: OSCP-Exam-PoC
status: completed
updated: "2026-11-07"
exam: IT GATE Academy OSCP-Style Examination
machine_count: 5
tags:
  - penetration-testing
  - oscp
  - exam
  - poc
  - linux
  - web-security
  - dashboard
---

# OSCP Exam — Penetration Testing & PoC Vault

> [!abstract] Project objective  
> Preserve the complete technical record of the five-machine examination: reconnaissance, vulnerability discovery, exploitation, initial access, privilege escalation, evidence, failed attempts, troubleshooting, and reusable techniques.
> 
> This vault is both an examination record and a practical penetration-testing knowledge base. Every important conclusion should be supported by observed output or explicitly marked as an unverified hypothesis.

> [!success] Examination completed  
> All five machines and their user/root objectives were completed. The examination participant confirms all ten flags were obtained and submitted. Public values are masked as `IT{FLAG-SECRET}`. Those evidence gaps are identified below rather than reconstructed.

---

## 1. Exam Overview

### Examination Structure

|Difficulty|Machine|Initial Access|Privilege Escalation|
|---|---|---|---|
|Very Easy|[[Difficulty Levels/Very Easy/VE-01/VE-01 Overview]]|PHP file upload / command execution|Sudo `find`|
|Easy|[[Difficulty Levels/Easy/EA-01/EA-01 Overview]]|SQLite SQL injection / SSH credentials|SUID `find`|
|Medium|[[Difficulty Levels/Medium/ME-01/ME-01 Overview]]|Path traversal / command injection|`CAP_SETUID`|
|Hard|[[Difficulty Levels/Hard/HA-01/HA-01 Overview]]|Redis persistence / SSH authorized keys|Cron / tar wildcard injection|
|Insane|[[Difficulty Levels/Insane/IN-01/IN-01 Overview]]|SSRF / Python Pickle RCE|Sudo `LD_PRELOAD`|

### Machine Documentation

|Machine|Overview|User|Root|
|---|---|---|---|
|VE-01|[[Difficulty Levels/Very Easy/VE-01/VE-01 Overview]]|[[Difficulty Levels/Very Easy/VE-01/user]]|[[Difficulty Levels/Very Easy/VE-01/root]]|
|EA-01|[[Difficulty Levels/Easy/EA-01/EA-01 Overview]]|[[Difficulty Levels/Easy/EA-01/user]]|[[Difficulty Levels/Easy/EA-01/root]]|
|ME-01|[[Difficulty Levels/Medium/ME-01/ME-01 Overview]]|[[Difficulty Levels/Medium/ME-01/user]]|[[Difficulty Levels/Medium/ME-01/root]]|
|HA-01|[[Difficulty Levels/Hard/HA-01/HA-01 Overview]]|[[Difficulty Levels/Hard/HA-01/user]]|[[Difficulty Levels/Hard/HA-01/root]]|
|IN-01|[[Difficulty Levels/Insane/IN-01/IN-01 Overview]]|[[Difficulty Levels/Insane/IN-01/user]]|[[Difficulty Levels/Insane/IN-01/root]]|

---

## 2. Executive Summary

The examination covered five distinct initial-access and privilege-escalation scenarios.

The most important result was the progression from relatively direct vulnerabilities to chained application and operating-system weaknesses.

### Initial Access Techniques

|Machine|Entry Point|Result|
|---|---|---|
|VE-01|Unrestricted PHP file upload|Command execution as `www-data`|
|EA-01|SQLite UNION-based SQL injection|Credential disclosure and SSH access as `robert`|
|ME-01|Path traversal|Arbitrary file read, followed by authenticated command injection as `svc`|
|HA-01|Unauthenticated Redis access|Redis persistence abuse and SSH access as `devops`|
|IN-01|SSRF filter bypass|Internal Pickle deserialization and RCE as `web`|

### Privilege-Escalation Techniques

|Machine|Technique|Key Finding|
|---|---|---|
|VE-01|Sudo misconfiguration|`www-data` could execute `/usr/bin/find` as root|
|EA-01|SUID misconfiguration|`/usr/bin/find` had the SUID bit owned by root|
|ME-01|Linux capabilities|`/usr/local/bin/pyadmin` had `cap_setuid=ep`|
|HA-01|Cron / tar wildcard injection|Root cron job executed tar over a user-writable directory|
|IN-01|Sudo `LD_PRELOAD` injection|Root NOPASSWD command preserved `LD_PRELOAD`|

### Main Technical Takeaway

The five machines required five different privilege-escalation approaches.

The repeated lesson was to enumerate the actual execution context and identify the specific privilege boundary that could be crossed, rather than assume that the same technique would work on every Linux target.

---

## 3. Machine Results

### 3.1 Very Easy — VE-01

<badge color="success">Completed</badge>

**Initial access:** PHP file upload leading to command execution.

The uploaded PHP file was accessible through:

```
/uploads/file.php?cmd=
```

The command execution context was `www-data`.

The user account was identified through:

```
/home/user/
```

#### Privilege Escalation

Sudo enumeration revealed:

```
User www-data may run the following commands:

(ALL) NOPASSWD: /usr/bin/find
```

GNU `find` supports `-exec`, allowing command execution through the permitted root binary.

**Root cause:** Unrestricted sudo execution of `find`.

**Result:** Root access and the root objective were completed.

See [[Difficulty Levels/Very Easy/VE-01/VE-01 Overview]].

### 3.2 Easy — EA-01

<badge color="success">Completed</badge>

**Initial access:** SQLite SQL injection.

The application exposed a search parameter:

```
?q=
```

A two-column UNION injection was used to enumerate SQLite metadata through:

```
sqlite_master
```

The important table was:

```
users
```

It contained usernames and passwords. A usable credential was recovered for `robert`, which provided SSH access.

#### Privilege Escalation

Sudo was unavailable.

SUID enumeration identified:

```
-rwsr-xr-x 1 root root ... /usr/bin/find
```

The SUID permission allowed the user to execute commands with root effective privileges through `find -exec`.

**Root cause:** Root-owned SUID `find`.

**Result:** User and root objectives were completed.

See [[Difficulty Levels/Easy/EA-01/EA-01 Overview]].

### 3.3 Medium — ME-01

<badge color="success">Completed</badge>

**Initial access:** Path traversal followed by command injection.

The application exposed:

```
/api/download?file=
```

The `file` parameter was joined to the public directory without adequate path normalization.

This enabled arbitrary file read, including:

- `/etc/passwd`
    
- `/proc/self/status`
    
- `/proc/self/environ`
    
- `/proc/self/cmdline`
    
- Application source and configuration files
    

The application source exposed the API-key validation and the command-processing logic of:

```
/api/ping
```

The API key was recovered from the application configuration.

The ping endpoint concatenated user input into a shell command:

```
subprocess.getoutput("ping -c 1 -W 1 " + host)
```

This enabled command injection and remote execution as `svc`.

#### Privilege Escalation

Capability enumeration found:

```
/usr/local/bin/pyadmin cap_setuid=ep
```

`pyadmin` was a Python 3.11.18 executable.

Using Python's `os.setuid(0)` through the capability-bearing executable changed the process identity from UID 1000 to UID 0.

Observed result:

```
1000 1000
0 0
```

**Root cause:** Misconfigured `CAP_SETUID` capability on a Python interpreter.

**Result:** User and root objectives completed. The root flag was preserved.

See [[Difficulty Levels/Medium/ME-01/ME-01 Overview]].

### 3.4 Hard — HA-01

<badge color="success">Completed</badge>

**Initial access:** Unauthenticated Redis service.

The target exposed Redis 7.0.15 without authentication.

The investigation established that Redis allowed configuration changes and persistence operations.

The successful path used Redis RDB persistence to write an SSH public key into:

```
/home/devops/.ssh/authorized_keys
```

This established SSH access as:

```
devops
```

Several alternative Redis exploitation approaches were investigated and abandoned before the persistence route succeeded.

#### Privilege Escalation

A root cron job executed every minute:

```
* * * * * root /opt/maint/backup.sh >/dev/null 2>&1
```

The backup script contained:

```
cd /opt/maint/spool 2>/dev/null || exit 0
tar -czf /opt/maint/backup.tar.gz * 2>/dev/null
```

The spool directory was writable by `devops`.

GNU tar wildcard option injection allowed specially named files to be interpreted as options when the root cron job processed the directory.

The injected command copied:

```
/root/root.txt
```

into the user-writable spool directory.

**Root cause:** Root cron job using an unquoted wildcard in a directory controlled by the unprivileged user.

**Result:** User and root objectives completed.

See [[Difficulty Levels/Hard/HA-01/HA-01 Overview]].

### 3.5 Insane — IN-01

<badge color="success">Completed</badge>

**Initial access:** SSRF filter bypass followed by Python Pickle deserialization.

The public application exposed:

```
/fetch?url=
```

Canonical loopback values were blocked, but alternative loopback representations passed the application's apparent filter.

The most important representation was:

```
127.1
```

This allowed access to the internal administrative service on:

```
127.1:9000
```

The internal API exposed:

```
/admin/exec
```

The endpoint accepted a Base64-encoded Python Pickle object through:

```
data
```

A crafted Pickle payload enabled command execution as:

```
uid=1000(web)
```

#### Privilege Escalation

Sudo enumeration revealed:

```
(root) NOPASSWD: /usr/local/bin/healthcheck
```

The sudo configuration preserved:

```
env_keep+=LD_PRELOAD
```

A malicious shared library was compiled using GCC and loaded through the permitted sudo command.

Observed output:

```
[+] LD_PRELOAD constructor executed
[+] UID=0 EUID=0 GID=0 EGID=0
```

The constructor read `/root/root.txt`.

**Root cause:** Sudo environment preservation combined with a permitted root execution target.

**Result:** Root execution and root-flag retrieval confirmed.

See [[Difficulty Levels/Insane/IN-01/IN-01 Overview]].

---

## 4. Difficulties Encountered and Their Impact

This is a central part of the examination record.

The difficulties below are not all target vulnerabilities. Some originated from the network environment, some from the attacker tooling, and some from decisions made during enumeration.

Each item distinguishes the observed evidence from the explanation or suspected cause.

### 4.1 ISP Restrictions and HTTP-Only Exam Applications

<badge color="warning">Reported network restriction</badge>

The examination infrastructure exposed applications over plain HTTP rather than HTTPS.

I reported that the ISP was blocking access to the exam website because the site was not TLS-signed / HTTPS-enabled.

This created an access problem before exploitation could proceed normally.

#### Impact

- Normal browser access was affected.
    
- Burp-based interception was impractical in the existing VPN setup.
    
- The HTTP testing workflow had to be adapted.
    

#### Workaround

The situation was demonstrated to the instructor.

I explained the network restriction and received agreement to use `curl` for the affected testing workflow.

The investigation therefore used direct HTTP requests through the terminal instead of depending on Burp Proxy.

#### Evidence and qualification

The instructor discussion and my report are recorded in the examination record.

The examination record does not contain ISP logs, a packet capture, or a controlled comparison proving the ISP was the sole cause.

Therefore, this should be documented as a **user-reported ISP restriction**, not as an independently verified ISP filtering mechanism.

Related note: [[Difficulties & Lessons/Network and ISP Restrictions]]

### 4.2 Public Application Timeouts During IN-01

<badge color="warning">Observed connectivity incident</badge>

During IN-01, the public application temporarily stopped returning HTTP responses.

Captured output:

```
curl: (28) Operation timed out after 12002 milliseconds with 0 bytes received

HTTP: 000
Connect: 0.248585s
First byte: 0.000000s
Total: 12.002333s
```

The TCP connection was established, but no HTTP response data arrived.

Multiple application routes also timed out.

Later, the original `/fetch` endpoint returned the expected Example Domain HTML again.

#### Impact

- Interrupted reconnaissance.
    
- Made endpoint enumeration unreliable.
    
- Created uncertainty about whether the issue was caused by the network or the application.
    

#### Workaround

Outstanding scans were checked and stopped.

The SSH service was tested separately, and the original public fetch request was retried.

The endpoint recovered and exploitation continued.

#### Evidence and qualification

The timeout and later recovery are supported by captured command output.

The cause was not conclusively established. A stalled Gunicorn service or worker exhaustion was considered, but neither was proven. ISP involvement should not be inferred from this incident alone.

Related notes:

- [[Difficulties & Lessons/Network and ISP Restrictions]]
    
- [[HTTP Client and Connectivity Failures]]
    

### 4.3 Burp Suite and VPN Conflicts

<badge color="warning">Workflow limitation</badge>

During ME-01, Burp Suite interception was considered but the active VPN setup created a conflict with the desired proxy workflow.

I decided not to spend examination time modifying the network configuration just to force Burp into the path.

After explaining the situation to the instructor, the investigation continued with `curl`.

#### Impact

- Burp Proxy was not used for the affected workflow.
    
- HTTP requests and response inspection had to be handled manually.
    
- Understanding the request parameters and headers became more important.
    

#### Workaround

The workflow used:

```
curl -i
curl --get
curl --data-urlencode
curl -H
curl -w
```

This allowed precise request construction without relying on an intercepting proxy.

#### Lesson

Burp Suite is useful, but it is not a prerequisite for understanding or reproducing HTTP requests.

A penetration tester should be able to reconstruct requests using `curl`, Python Requests, browser DevTools, or raw HTTP when necessary.

Related note: [[Difficulties & Lessons/Tooling and Workflow Mistakes]]

### 4.4 Kali Zsh PATH Corruption

<badge color="danger">Tooling error with direct impact</badge>

A supplied command used:

```
for path in ...
```

In Zsh, `path` is a special array linked to the `PATH` environment variable.

Using it as an ordinary loop variable overwrote the command search path.

Observed states included:

```
PATH=/healthz
```

and:

```
PATH=/__random_test_94821
```

As a result, commands such as:

```
curl
head
grep
ffuf
```

could not be resolved even though they were installed.

#### Impact

- Interrupted reconnaissance.
    
- Prevented HTTP commands from executing.
    
- Required repeated shell repair.
    
- Consumed examination time.
    

#### Resolution

The current shell was repaired using:

```
typeset -U path
path=(/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin)
rehash
```

The `.zshrc` configuration was also updated with a persistent PATH safeguard and invalid-entry cleanup.

#### Prevention

Never use `path` as an ordinary variable in Zsh.

Use names such as:

```
endpoint
target_path
file_path
```

This was caused by a supplied command, not by a Kali package or system failure.

Related note: [[Difficulties & Lessons/Kali PATH and Zsh Issues]]

### 4.5 FFUF Enumeration Strategy and False Leads

<badge color="warning">Methodology issue</badge>

During IN-01, several FFUF scans were used to discover internal ports and API routes.

Some scans produced large numbers of identical 404 or 502 responses.

One internal web-service scan attempted more than 4,600 paths despite the service not providing a useful HTTP response.

#### Impact

- Unproductive requests.
    
- Long-running scans.
    
- Repeated analysis of identical responses.
    
- Time spent expanding wordlists without a sufficiently informative baseline.
    

#### Specific mistakes

- Using a broad directory wordlist against a service that had not been confirmed as a responsive HTTP application.
    
- Carrying a fixed response-size filter from an earlier instance.
    
- Using `-maxtime 60`, which terminated the entire scan after 60 seconds.
    
- Misinterpreting automatic calibration and empty results without first checking the raw response fingerprint.
    

#### What worked

The investigation became productive when it:

1. Established a negative-control response.
    
2. Identified internal port 9000.
    
3. Confirmed the internal API banner.
    
4. Fuzzed a focused list of API paths.
    
5. Identified `/admin/exec`.
    
6. Switched to parameter fuzzing and discovered `data`.
    

#### Lesson

Fuzz the right surface, not merely the largest wordlist.

Use response fingerprints, known baselines, and application evidence to decide what to enumerate next.

Related note: [[Difficulties & Lessons/Fuzzing Strategy and False Leads]]

### 4.6 Reverse-Shell Callback Failures on IN-01

<badge color="warning">Callback unsuccessful; cause unverified</badge>

The IN-01 Pickle vulnerability provided working in-band command execution as `web`.

Reverse-shell callbacks were attempted using:

|Interface|Address|
|---|---|
|`tun0`|`10.10.17.123`|
|`tun1`|`10.144.220.24`|

A Netcat listener was started on port `4444`.

Neither callback established an interactive connection.

#### Additional payload issue

The first reverse-shell payload also failed because the inner Base64 parameter was not URL-encoded separately.

The internal API returned:

```
Invalid base64-encoded string
```

The script was corrected to URL-encode the nested data value independently.

The corrected request returned HTTP 200 with an empty response, but the listener still received no callback.

#### Impact

The interactive-shell approach could not be used.

#### Resolution

The investigation returned to the already working in-band RCE.

Commands continued through the HTTP response, and the privilege escalation succeeded without an interactive shell.

#### Evidence and qualification

The failed callbacks are confirmed.

VPN routing was suspected, but the precise reason for the failures was not established.

**Important distinction:** RCE succeeded. Only the reverse-shell callbacks failed.

Related note: [[Difficulties & Lessons/VPN Routing and Reverse Shells]]

### 4.7 Nested URL and Base64 Encoding

<badge color="warning">Payload construction issue</badge>

The IN-01 exploit required a Base64-encoded Pickle object inside the `data` parameter of an internal URL.

That internal URL was itself passed through the public application's `url` parameter.

The first reverse-shell payload did not separately encode the nested Base64 value.

Characters such as `+` were therefore interpreted incorrectly when the inner query string was parsed.

#### Resolution

The correct sequence was:

1. Generate the Pickle object.
    
2. Base64-encode it.
    
3. URL-encode the Base64 value.
    
4. Construct the internal URL.
    
5. URL-encode the complete internal URL as the outer fetch parameter.
    

#### Lesson

Nested query strings require separate encoding at each layer.

Related note: [[HTTP Client and Connectivity Failures]]

### 4.8 Binary Output and UTF-8 Decoding

<badge color="warning">Output-handling issue</badge>

During IN-01 healthcheck inspection, an attempt to return binary executable content through the HTTP execution wrapper caused:

```
'utf-8' codec can't decode byte 0x98
```

A subsequent Base64-output wrapper also failed because the HTTP response was not exclusively Base64 data.

#### Resolution

The executable was inspected with text-oriented tools:

```
strings -a /usr/local/bin/healthcheck
```

The successful privilege-escalation execution wrapper used:

```
text=True, errors='replace'
```

#### Lesson

Do not assume arbitrary binary output can be transported through a text-oriented HTTP response.

Choose an inspection method appropriate for the file type.

Related note: [[Difficulties & Lessons/Tooling and Workflow Mistakes]]

### 4.9 Minimal Target Utilities

Several target environments lacked expected diagnostic utilities or text editors.

Examples:

|Machine|Missing utility|Workaround|
|---|---|---|
|HA-01|`vim`, `vi`, `nano`|Used shell `printf` to create the payload|
|IN-01|`file`|Used `strings`, dynamic-linker references, and available binary tools|
|IN-01|Interactive shell callback|Continued through in-band execution|

The missing utilities did not prevent exploitation.

#### Lesson

Check what is actually available before designing a workflow around a particular tool.

Related note: [[Difficulties & Lessons/Tooling and Workflow Mistakes]]

### 4.10 VPN Client Package Validation Detour

A separate network-access remediation attempt explored installing the Windscribe desktop application on Kali.

The machine architecture was verified:

```
x86_64
amd64
```

The first download was saved with a `.deb` filename but was actually HTML:

```
HTML document, Unicode text, UTF-8 text
```

It was not a valid Debian package.

A release asset was subsequently downloaded and checked:

```
Debian binary package (format 2.0)
```

The SHA-256 verification returned:

```
windscribe_2.24.13_amd64.deb: OK
```

APT simulation showed:

```
Installing:
  windscribe

Installing dependencies:
  iw
```

#### Impact

This was a separate environment-remediation detour rather than an exploitation failure.

#### Lesson

A filename and successful HTTP download do not establish that a package is valid.

Verify file type, checksum, architecture, metadata, and dependency resolution before installation.

**Evidence limitation:** The examination record preserves successful package validation and simulated installation, but does not establish that Windscribe was installed or connected.

---

## 5. Cross-Machine Technical Findings

### Initial Access

|Technique|Machine|Reusable Concept|
|---|---|---|
|Unrestricted file upload|VE-01|Upload validation and server-side execution|
|SQLite UNION SQL injection|EA-01|Schema enumeration and credential disclosure|
|Path traversal|ME-01|Arbitrary file read|
|Authenticated command injection|ME-01|Shell command construction from user input|
|Redis unauthenticated access|HA-01|Redis configuration and persistence|
|SSRF filter bypass|IN-01|Alternative address representations|
|Python Pickle deserialization|IN-01|Unsafe deserialization to RCE|

### Privilege Escalation

|Technique|Machine|Critical Condition|
|---|---|---|
|Sudo `find`|VE-01|NOPASSWD permission|
|SUID `find`|EA-01|Root-owned executable with SUID bit|
|`CAP_SETUID`|ME-01|Capability assigned to Python executable|
|Tar wildcard injection|HA-01|Root cron job processes attacker-controlled filenames|
|`LD_PRELOAD`|IN-01|Sudo preserves environment variable for permitted root executable|

### Techniques Worth Reproducing Independently

The highest-value techniques from this examination are:

1. SQLite schema enumeration with UNION injection.
    
2. Arbitrary file read through path traversal.
    
3. Shell command injection through unsafe command concatenation.
    
4. Redis RDB persistence and SSH authorized-key injection.
    
5. Tar wildcard option injection.
    
6. SSRF loopback filter bypass.
    
7. Python Pickle deserialization.
    
8. Linux `CAP_SETUID` exploitation.
    
9. Sudo `LD_PRELOAD` shared-library injection.
    

---

## 6. Evidence Integrity

The source for the machine records is the preserved examination record and the evidence kept in the machine-specific notes.

Use these rules when expanding the vault:

- Preserve commands as actually executed.
    
- Preserve important raw output.
    
- Distinguish a successful exploit from a successful flag submission.
    
- Mark missing flag values instead of inventing them.
    
- Do not label a suspected network cause as confirmed without supporting evidence.
    
- Keep failed attempts when they explain a meaningful change in methodology.
    
- Separate the target's vulnerability from mistakes in the attacker environment.
    
- Avoid replacing missing evidence with expected output.
    

### Flag Completion Status

The examination participant confirms retrieving and submitting the user and root flags for all five machines. The public report consistently masks flag values as `IT{FLAG-SECRET}`.

|Machine|User flag|Root flag|
|---|---|---|
|VE-01|Obtained and submitted|Obtained and submitted|
|EA-01|Obtained and submitted|Obtained and submitted|
|ME-01|Obtained and submitted|Obtained and submitted|
|HA-01|Obtained and submitted|Obtained and submitted|
|IN-01|Obtained and submitted|Obtained and submitted|

---

## 7. Obsidian Navigation

### Exam Context

- [[Exam Context/Exam Overview]]
    
- [[Exam Context/Lab Environment]]
    
- [[Exam Context/Network & Connectivity]]
    
- [[Exam Context/Exam Timeline]]
    

### Difficulty Levels

- [[Difficulty Levels/Very Easy/VE-01/VE-01 Overview]]
    
- [[Difficulty Levels/Easy/EA-01/EA-01 Overview]]
    
- [[Difficulty Levels/Medium/ME-01/ME-01 Overview]]
    
- [[Difficulty Levels/Hard/HA-01/HA-01 Overview]]
    
- [[Difficulty Levels/Insane/IN-01/IN-01 Overview]]
    

### Methodology

- [[Methodology/Reconnaissance]]
    
- [[Methodology/Web Enumeration]]
    
- [[Methodology/Initial Access]]
    
- [[Methodology/Linux Privilege Escalation]]
    
- [[Methodology/Evidence Collection]]
    

### Difficulties & Lessons

- [[Difficulties & Lessons/Network and ISP Restrictions]]
    
- [[Difficulties & Lessons/VPN Routing and Reverse Shells]]
    
- [[Difficulties & Lessons/Kali PATH and Zsh Issues]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Difficulties & Lessons/Fuzzing Strategy and False Leads]]
    
- [[Difficulties & Lessons/Tooling and Workflow Mistakes]]
    

### Reusable PoCs

- [[Reusable PoCs/Redis/Redis Persistence]]
    
- [[Reusable PoCs/SSRF/SSRF Filter Bypass]]
    
- [[Reusable PoCs/Python Pickle/Python Pickle RCE]]
    
- [[Reusable PoCs/Linux Privilege Escalation/CAP_SETUID]]
    
- [[Reusable PoCs/Linux Privilege Escalation/Tar Wildcard Injection]]
    
- [[Reusable PoCs/Linux Privilege Escalation/LD_PRELOAD]]
    
- [[PoC Scripts Index]]
    

    

---

## 8. Using Obsidian Effectively

This vault should use Obsidian's capabilities to connect evidence, machines, and techniques rather than merely store Markdown files.

|Obsidian feature|Intended use|
|---|---|
|Properties|Machine metadata, privilege stage, status, flags, tags|
|Bases|Dynamic machine inventory and technique index|
|Backlinks|Identify every machine using a particular technique|
|Templates|Standardize machine, user, root, and finding records|
|Canvas|Visualize exploitation chains and cross-machine relationships|
|Graph View|Explore relationships between machines, vulnerabilities, and reusable PoCs|
|Search|Find commands, outputs, errors, and indicators across the vault|

### Recommended machine properties

Use consistent properties in every machine record:

```
machine: IN-01
difficulty: Insane
phase: initial-access
status: completed
platform: Linux
initial_user: web
final_user: root
initial_access: "SSRF and Python Pickle deserialization"
privilege_escalation: "Sudo LD_PRELOAD injection"
tags:
  - oscp
  - linux
```

The machine-specific values will vary, but the property names should remain consistent. This makes later Bases views and filtering much easier.

---

## 9. Current Work Status

The examination record is reconstructed at the machine level.

The remaining work is knowledge-base organization, not further exploitation of the five targets.

|Task|Status|
|---|---|
|Establish vault structure|Completed|
|Create Dashboard|Updated|
|Create machine overview records|Completed|
|Create user-stage records|Completed|
|Create root-stage records|Completed|
|Reconcile evidence gaps|In progress|
|Update Exam Timeline|Completed (reconstructed; exact timestamps not preserved)|
|Create reusable PoC notes|Completed|
|Create methodology notes|Drafted|
|Create Obsidian Bases|Pending|
|Build attack-chain Canvas|Pending|

### Recommended Next Steps

1. Create Bases for the machine inventory, techniques, and evidence.
    
2. Build a Canvas showing the five attack chains and their shared concepts.
    
