---
type: difficulty-lesson
project: OSCP-Exam-PoC
status: documented
updated: "2026-11-07"
related_machines:
  - HA-01
  - IN-01
tags:
  - oscp
  - tooling
  - metasploit
  - redis
  - exploit-validation
  - workflow
---
# Tooling and Workflow Mistakes

## 1. Summary

Several investigation delays came from choosing tools or procedures before confirming that they matched the target, the vulnerability, or the available environment.

The most significant examples occurred during HA-01:

- Confusing different Redis vulnerabilities and exploit implementations.
    
- Treating a Metasploit vulnerability check as proof of successful exploitation.
    
- Spending time preparing local environments that were not required for the intended workflow.
    
- Encountering local Metasploit file-permission problems after exploitation had already been configured.
    
- Assuming tools were installed on the remote target.
    

IN-01 also exposed a simpler operational issue: commands and scripts must account for the actual environment in which they execute.

## 2. Redis Exploit and CVE Confusion

### 2.1 RediShell — CVE-2025-49844

HA-01 exposed an unauthenticated Redis 7.0.15 service. Lua scripting was enabled:

```
EVAL "return 1" 0
```

The next investigation considered RediShell, CVE-2025-49844, a Redis Lua use-after-free vulnerability.

The published PoC was cloned and inspected. Its available exploit profiles targeted specific Redis 8.2.1 builds, while HA-01 reported Redis 7.0.15.

The PoC depended on binary-specific memory offsets and exploitation assumptions. Running it against a different Redis build without matching those requirements was not a valid compatibility test.

The attempt failed during exploitation with:

```
Failed to UAF chunkname
```

This did not establish that HA-01 was patched or that the vulnerability was absent. It established that this particular exploit implementation did not successfully complete its expected use-after-free stage.

**Lesson:** A vulnerable version range does not guarantee that a published PoC supports the target binary. Check the exploit's supported builds, offsets, prerequisites, and patch status before execution.

### 2.2 Metasploit module was a different vulnerability

The investigation then moved to:

```
exploit/linux/redis/redis_replication_cmd_exec
```

This module uses Redis replication and module loading. It is associated with CVE-2018-11218, not RediShell.

These are different exploitation paths:

|Exploit|CVE|Technique|
|---|---|---|
|RediShell|CVE-2025-49844|Lua use-after-free|
|Metasploit `redis_replication_cmd_exec`|CVE-2018-11218|Redis replication and malicious module loading|
|DarkReplica|CVE-2026-23631|Redis Lua and replication-related use-after-free|

The local Metasploit search did not return a RediShell module:

```
msf > search cve:2025-49844
[-] No results from search
```

Other Redis modules in Metasploit were not interchangeable with RediShell.

**Lesson:** Match the CVE, exploitation primitive, and module implementation. A module targeting Redis does not automatically implement every Redis vulnerability.

### 2.3 DarkReplica — CVE-2026-23631

DarkReplica was subsequently investigated as another possible route.

The actual repository contained offset profiles for:

- Redis 8.6.2.
    
- A specific official `redis:latest` image digest.
    
- An empty example profile.
    

It did not contain a profile for HA-01's Redis 7.0.15 build.

The required symbol offsets therefore could not be selected safely from the available profiles.

The investigation did not establish a successful DarkReplica execution against HA-01.

**Lesson:** Inspect the actual exploit implementation and its target profiles. A repository's description or supported CVE does not prove compatibility with a particular target build.

## 3. Metasploit Check Was Not Exploit Confirmation

The Metasploit module returned:

```
[+] x.x.x.x:PORT_E - The target is vulnerable. Redis version is 7.0.15
```

This appeared conclusive, but the module's `check` method performed a relatively broad compatibility check:

- Redis allowed configuration access.
    
- The reported version was at least 4.0.0.
    

It did not prove that the complete replication, module transfer, loading, and payload execution sequence would work.

The actual exploitation attempt initially failed locally:

```
Errno::EACCES Permission denied
@ rb_sysopen -
/usr/share/metasploit-framework/data/exploits/redis/module.c
```

The problem was Metasploit trying to write its generated C module into a directory the current Kali user could not modify.

The module's `CUSTOM` option provided an alternative:

```
set CUSTOM false
```

This bypassed custom source generation and selected the bundled precompiled module path.

The replication server then started listening, but the target never completed the connection and no session was created.

The important distinction:

|Stage|Result|
|---|---|
|Metasploit check|Passed|
|Local custom module generation|Failed due to permissions|
|Precompiled module path|Started|
|Replication connection|Not established|
|Module transfer and execution|Not confirmed|
|Meterpreter session|Not obtained|

The network failure and packet-level investigation are documented separately in [[VPN Routing and Reverse Shells]].

**Lesson:** Validate each exploitation stage independently. A successful `check`, a listening handler, or a running exploit process is not proof of remote code execution.

## 4. Unnecessary Local Environment Preparation

During the RediShell and DarkReplica investigation, time was spent considering:

- Docker and Podman availability.
    
- Local Redis reproduction.
    
- Matching local container images.
    
- Rebuilding Redis 7.0.15.
    
- Deriving target-specific binary offsets.
    
- Additional local dependencies and environment preparation.
    

The technical motivation was to reproduce a matching binary and derive compatible exploit offsets.

However, this became a separate binary-research project rather than a direct examination workflow.

I chose to attack the remote lab instance directly and did not want to reproduce the target environment locally.

The correct operational boundary was:

- Use Kali as the attacking machine.
    
- Inspect the published exploit and its compatibility requirements.
    
- Test against the authorized remote instance when the prerequisites are understood.
    
- Stop pursuing local reproduction when it is not necessary or is outside the agreed workflow.
    

**Lesson:** Technical possibility does not automatically justify a side project. Every additional setup step must directly remove a blocker on the current attack path.

## 5. Assuming Tools Exist on the Remote Target

During HA-01 privilege escalation, the plan required creating a small script in:

```
/opt/maint/spool/
```

The first attempt to open the file used Vim:

```
vim /opt/maint/spool/root-flag.sh
```

The target returned:

```
-bash: vim: command not found
-bash: vi: command not found
-bash: nano: command not found
```

The remote target did not have the expected text editors installed.

The script was subsequently created using the shell's `printf` builtin instead.

This exposed an important distinction:

|Environment|Tool availability|
|---|---|
|Kali attacker machine|Use the installed preferred editor and tooling|
|Remote target|Must verify available commands and permissions|
|Minimal target shell|Prefer available builtins and existing utilities|

The target does not need to provide the same development environment as Kali.

**Lesson:** Never assume that a tool installed on the attacking machine is also available on the target. Check the target's actual capabilities before choosing an editing or execution method.

## 6. Operational Rules

### 6.1 Before using a published exploit

- Confirm the exact CVE and exploitation technique.
    
- Inspect the actual repository and entry point.
    
- Identify supported target versions and binary profiles.
    
- Check architecture and relevant prerequisites.
    
- Verify whether offsets or gadgets are build-specific.
    
- Understand what the exploit's `check` operation actually tests.
    
- Identify local requirements separately from remote target requirements.
    

### 6.2 Before switching tools

- Identify the blocker in the current approach.
    
- Confirm that the alternative tool addresses that blocker.
    
- Confirm that it implements the same intended vulnerability or attack primitive.
    
- Avoid switching merely because another tool appears more convenient.
    
- Preserve the evidence from the previous attempt.
    

### 6.3 During exploitation

Record each stage separately:

1. Local exploit preparation.
    
2. Target connection.
    
3. Exploit trigger.
    
4. Remote execution.
    
5. Callback or command output.
    
6. Session establishment.
    
7. User-level access.
    
8. Privilege escalation.
    

Do not label an exploit successful until the expected remote effect is confirmed.

### 6.4 Scope control

Stop a side task when it no longer advances the current objective.

Examples from HA-01:

- Do not build a local Redis environment when the agreed plan is remote exploitation.
    
- Do not configure a Metasploit module for a different CVE and treat it as a substitute.
    
- Do not keep modifying a PoC when its supported binary profiles do not match the target.
    
- Do not install a remote editor merely to create a small script when existing shell utilities are sufficient.
    

## 7. Lessons

1. **Exploit compatibility matters more than exploit popularity.** A public PoC must match the target's actual requirements.
    
2. **Different CVEs require different exploitation paths.** Do not conflate RediShell with Redis replication command execution.
    
3. **A vulnerability check is not an exploitation result.** Confirm the complete chain.
    
4. **Separate local failures from remote failures.** The Metasploit `module.c` error occurred on Kali before the target-side exploitation sequence progressed.
    
5. **Do not create unnecessary dependencies.** Local environment reproduction is a separate project unless it directly solves the current blocker.
    
6. **Verify tools on the machine where they will execute.** Kali and the remote target have different capabilities.
    
7. **Keep the objective visible.** HA-01 required a user foothold, `user.txt`, privilege escalation, and `root.txt`. Every technical decision should advance that sequence.
    

## Related Notes

- [[VPN Routing and Reverse Shells]]
    
- [[Kali PATH and Zsh Issues]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Fuzzing Strategy and False Leads]]
    
- [[Redis Persistence]]
    
- [[HA-01 Overview]]