---
type: technical-reference
project: OSCP-Exam-PoC
category: lab-environment
status: documented
created: "2026-11-05"
updated: "2026-11-07"
tags:
  - lab-environment
  - kali-linux
  - networking
  - vpn
  - infrastructure
---

# Lab Environment

## 1. Overview

The examination was conducted using Kali Linux against five disposable laboratory machines provided through the exam platform.

Each machine exposed services through externally accessible network endpoints. The assigned HTTP and SSH ports were provided by the lab platform and could change when an instance was restarted or replaced.

The working environment consisted of:

- A Kali Linux attacker machine.
    
- One or more active VPN interfaces.
    
- Disposable target instances.
    
- Publicly reachable forwarded service ports.
    
- Internal services accessible from within individual target environments.
    

The examination required both external service enumeration and internal service discovery through application-level vulnerabilities.

## 2. Attacker Environment

### Operating System

|Component|Value|
|---|---|
|Operating system|Kali Linux|
|Architecture|x86_64|
|Default shell|Zsh|
|Shell configuration|`~/.zshrc`|
|Primary workspace|`~/Desktop/`|
|IN-01 workspace|`~/Desktop/IN01/`|

### Tools Used

|Category|Tools|
|---|---|
|Network discovery|Nmap|
|HTTP requests|curl|
|Web fingerprinting|WhatWeb|
|Web and API fuzzing|FFUF|
|Network listeners|Netcat|
|Payload generation|Python 3|
|Native compilation|GCC|
|Binary inspection|readelf, strings|
|Output processing|jq|
|File editing|Vim|
|Shell scripting|Bash and Zsh|

### Important Local Configuration

The Kali shell used Zsh, whose special `path` array is linked to the `PATH` environment variable.

An incorrectly named loop variable overwrote the command search path during the examination.

Observed broken state:

```
PATH=/healthz
```

The command search path was restored using:

```
typeset -U path
path=(/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin $path)
rehash
```

A persistent safeguard was subsequently added to `~/.zshrc`.

**Operational rule:** Never use `path` as an ordinary variable or loop variable in Zsh. Use names such as `endpoint`, `target_path`, or `file_path`.

See [[Kali PATH and Zsh Issues]].

## 3. VPN Environment

Two VPN interfaces were observed during the examination.

|Interface|Observed IPv4 Address|Status at Observation|
|---|---|---|
|`tun0`|`10.10.17.123/23`|UNKNOWN|
|`tun1`|`10.144.220.24/22`|UP|

These addresses are historical observations. They are not guaranteed to remain assigned across VPN reconnections or examination sessions.

### VPN Routing and Reverse Connections

During IN-01, reverse-shell callbacks were attempted using both observed addresses:

```
10.144.220.24
10.10.17.123
```

Neither attempt produced an incoming connection on the Kali Netcat listener.

The precise cause was not established.

The investigation therefore switched to in-band command execution through the vulnerable HTTP application. This allowed continued enumeration and privilege escalation without requiring an interactive reverse shell.

See [[VPN Routing and Reverse Shells]].

## 4. Target Network Architecture

### General Connectivity Model

The observed laboratory setup exposed target services through externally assigned TCP ports.

The public IP address remained the same across multiple instances, while the assigned HTTP and SSH ports changed.

The distinction between external and internal addressing was important:

|Address Type|Description|
|---|---|
|Public IP|Externally reachable target endpoint|
|Forwarded port|Provider-assigned external port mapped to a target service|
|Loopback address|Service accessible from the target's own network namespace|
|Internal service port|Port used by services not necessarily exposed externally|

### Observed Public Address

```
x.x.x.x
```

This address was observed across multiple laboratory instances.

**Important:** Reuse of the public IP does not establish that every service on that IP belongs to the same target instance. Only the service mappings supplied by the lab platform should be treated as authoritative.

## 5. Machine-Specific Network Records

### HA-01 — Hard

Historical service mapping:

|Service|Public IP|External Port|
|---|---|---|
|Redis|`x.x.x.x`|`PORT_E`|
|SSH|`x.x.x.x`|`PORT_B`|

Redis service details:

|Attribute|Value|
|---|---|
|Version|Redis 7.0.15|
|Architecture|x86_64|
|Kernel|6.8.0-147-generic|
|Redis binary|`/redis-server`|
|Configuration|`/etc/oscp-redis.conf`|
|Build ID|`ae4d7c971a948f0`|

The Redis service was accessible through its externally assigned port.

See [[Difficulty Levels/Hard/HA-01/HA-01 Overview]].

### IN-01 — Insane

IN-01 used multiple disposable instances during the investigation.

Historical port mappings:

|Instance|HTTP Port|SSH Port|Status|
|---|---|---|---|
|Initial instance|PORT_O|PORT_C|Destroyed|
|Second instance|PORT_K|PORT_A|Replaced|
|Final instance|PORT_J|PORT_M|Exammed|

Public IP for the recorded instances:

```
x.x.x.x
```

The final instance exposed:

|Service|External Port|Service|
|---|---|---|
|HTTP|PORT_J|Gunicorn|
|SSH|PORT_M|OpenSSH|

External service identification:

```
HTTP:
Gunicorn

SSH:
OpenSSH 10.0p2 Debian 7+deb13u4
```

The public HTTP application exposed:

```
/fetch?url=https://example.com
```

The internal application was bound to loopback:

```
127.0.0.1:9000
```

Internal admin API identification:

```
IT GATE internal admin API (localhost only)
```

The internal service was not directly exposed through the public HTTP port mapping. It was reached through the SSRF vulnerability in the public application.

Alternative loopback representation:

```
127.1
```

See [[Difficulty Levels/Insane/IN-01/IN-01 Overview]].

## 6. Target-Side Execution Environment

The IN-01 target presented the following environment after initial access.

|Attribute|Value|
|---|---|
|Hostname|`insane`|
|Operating system|Debian GNU/Linux 13 (trixie)|
|Architecture|x86_64|
|Kernel|6.8.0-147-generic|
|Initial execution user|`web`|
|UID|1000|
|GID|1000|
|Working directory|`/opt/app`|
|Python runtime|Python 3.11|
|Web server|Gunicorn|

The public and internal Gunicorn services were launched using separate application bindings:

```
0.0.0.0:8080
127.0.0.1:9000
```

The process enumeration showed both services running under the `web` account, with their parent launch processes running as root.

The internal application was therefore reachable locally from within the target, but not directly exposed as an externally assigned service.

## 7. Disposable Instance Lifecycle

The lab machines were time-limited and could be automatically destroyed.

Consequences:

- Public port mappings could change after replacing an instance.
    
- Previous target state could be lost.
    
- Temporary files and changes inside an instance should not be assumed persistent.
    
- Evidence should be saved locally as soon as it is obtained.
    
- Scripts and payloads should be retained on Kali rather than relying exclusively on target-side files.
    

### Recommended Instance Record

For future laboratory sessions, preserve:

|Field|Description|
|---|---|
|Machine ID|VE-01, EA-01, ME-01, HA-01, or IN-01|
|Instance identifier|Provider-issued instance reference|
|Public IP|Target public address|
|HTTP port|Assigned external HTTP port|
|SSH port|Assigned external SSH port|
|Internal services|Discovered internal bindings|
|Start time|Instance creation time|
|Expiration|Automatic destruction time|
|VPN interface|Interface used during testing|
|Notes|Instance-specific observations|

## 8. Network and Application Connectivity Incidents

### HTTP Application Timeouts

During IN-01, requests to the public web application and several routes temporarily timed out.

Example:

```
curl: (28) Operation timed out after 12002 milliseconds with 0 bytes received

HTTP: 000
Connect: 0.248585s
First byte: 0.000000s
Total: 12.002333s
```

The TCP connection was established, but no HTTP response bytes were received.

The public endpoint later recovered and successfully returned the original Example Domain HTML.

**Conclusion:** The HTTP timeout was observed and documented. Its underlying cause was not conclusively attributed to the ISP, target application, or infrastructure.

### Internal Service Timeouts

Internal port 8080 consistently accepted connections but did not return HTTP responses within the fetcher's timeout period.

This was not sufficient evidence to identify a usable HTTP application.

Further directory fuzzing against this port was abandoned.

### Reverse-Shell Connectivity

Reverse-shell callbacks failed to arrive at the Kali listener.

In-band execution remained operational and was used to complete the examination.

See:

- [[Network and ISP Restrictions]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[VPN Routing and Reverse Shells]]
    

## 9. Operational Principles

The following practices emerged from the examination.

### Instance Awareness

Always verify the current service ports before using an old command or script.

### Connectivity Verification

Distinguish between:

- DNS resolution failures.
    
- TCP connection refusals.
    
- TCP connection timeouts.
    
- Successful TCP connections with HTTP timeouts.
    
- HTTP-level application errors.
    

These conditions represent different failure points and should not be treated interchangeably.

### Internal vs External Enumeration

An externally exposed service scan does not reveal every service available within the target's internal network.

Internal services may require application-level access, such as SSRF, to reach them.

### Interactive vs In-Band Execution

A reverse shell is useful but not mandatory.

When callback routing fails and an in-band command-execution primitive remains functional, continue using that primitive rather than abandoning a working foothold.

### Evidence Preservation

Save:

- Network scan outputs.
    
- HTTP request and response data.
    
- VPN interface and routing information.
    
- Exact instance mappings.
    
- Exploitation scripts.
    
- Target command output.
    
- Flag verification evidence.
    

---

## 10. Related Documentation

- [[Exam Overview]]
    
- [[Network and ISP Restrictions]]
    
- [[VPN Routing and Reverse Shells]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Kali PATH and Zsh Issues]]
    
- [[Fuzzing Strategy and False Leads]]
    
- [[Difficulty Levels/Hard/HA-01/HA-01 Overview]]
    
- [[Difficulty Levels/Insane/IN-01/IN-01 Overview]]
    

---

**Document classification:** Examination infrastructure and operational environment.

**Evidence status:** Based on observed examination outputs and recorded service mappings. Historical addresses and ports are not current connectivity guarantees.