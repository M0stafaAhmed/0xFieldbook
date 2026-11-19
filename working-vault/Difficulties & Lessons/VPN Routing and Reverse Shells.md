---
type: difficulty-lesson
project: OSCP-Exam-PoC
status: documented
updated: "2026-11-07"
related_machines:
  - HA-01
  - IN-01
tags:
  - difficulties
  - vpn
  - routing
  - reverse-shell
  - networking
  - troubleshooting
---

# VPN Routing and Reverse Shells

## 1. Overview

Multiple VPN interfaces were active during the examination. This created uncertainty about which local address should be used for connections initiated by the targets.

Two machines exposed this problem:

- **HA-01:** Redis replication required the target to connect to a Redis server hosted on Kali.
    
- **IN-01:** Reverse-shell payloads attempted to connect from the compromised target back to a Kali Netcat listener.
    

Neither approach established an interactive session.

However, the two failures must not be confused with failed exploitation. IN-01 had confirmed remote command execution, and its entire attack chain was completed using in-band execution.

## 2. Kali VPN Interfaces

During the examination, the following interfaces were observed:

|Interface|IPv4 address|Observed state|
|---|---|---|
|`tun0`|`10.10.17.123`|UNKNOWN|
|`tun1`|`10.144.220.24`|UP|

These are historical addresses. VPN assignments can change after reconnection.

The important distinction is that an interface having an assigned IP does not prove that an external target can reach that IP.

### Routing verification

The command used to inspect the route toward HA-01 was:

```
ip route get x.x.x.x
```

Observed result:

```
x.x.x.x via 10.144.220.1 dev tun1 src 10.144.220.24 uid 1000
```

This established that Kali used `tun1` to reach the public target at that time.

It did **not** establish that HA-01 could initiate a connection back to Kali through the same interface.

That distinction was central to both investigations.

## 3. HA-01 — Redis Replication Callback Failure

### Intended connection flow

The Metasploit module used Redis replication to transfer and load a module on the target.

Two separate target-to-Kali connections were involved:

```
HA-01 Redis
     |
     | TCP replication connection
     v
Kali: 10.144.220.24:6379
     |
     | Module transfer and loading
     v
Redis command execution
     |
     | TCP reverse payload callback
     v
Kali: 10.144.220.24:4444
```

Both connections depended on HA-01 being able to reach the advertised Kali address.

### Metasploit configuration

The relevant settings were:

|Option|Value|
|---|---|
|`RHOSTS`|`x.x.x.x`|
|`RPORT`|`PORT_E`|
|`SRVHOST`|`10.144.220.24`|
|`SRVPORT`|`6379`|
|`LHOST`|`10.144.220.24`|
|`LPORT`|`4444`|

The target accepted the replication configuration, but the connection did not complete.

Redis reported:

```
role:slave
master_host:10.144.220.24
master_port:6379
master_link_status:down
```

The local Metasploit listener was confirmed active:

```
LISTEN 0 256 10.144.220.24:6379
users:(("ruby",pid=1827824,fd=10))
```

Packet captures then returned:

```
0 packets captured
0 packets received by filter
0 packets dropped by kernel
```

The first capture was restricted to `tun1` and the target's public IP. A subsequent capture used all interfaces:

```
sudo tcpdump -ni any 'tcp port 6379'
```

That capture also recorded zero packets.

### Additional troubleshooting mistakes

Two problems complicated the investigation:

1. An initial Netcat command used an incorrect argument arrangement:
    
    ```
    nc -nlvp 10.144.220.24 6379
    ```
    
    Its output showed that Netcat was listening on port `10`, not the intended address and port.
    
2. After correcting the listener command, port `6379` was still occupied by the previous Metasploit Ruby process. The stale listener had to be terminated before Netcat could use that port.
    

A later manual connectivity attempt still did not produce a usable incoming connection.

Redis was restored using:

```
REPLICAOF NO ONE
```

The investigation eventually abandoned replication/module loading and moved to Redis persistence abuse, which successfully established SSH access as `devops`.

**What was confirmed:** Redis accepted the replication configuration, Kali had a listener, and no matching incoming connection was observed during the captures.

**What was not confirmed:** Whether the failure was caused by VPN routing, network filtering, target-side outbound restrictions, or another infrastructure condition.

## 4. IN-01 — Reverse-Shell Callback Failure

### Confirmed command execution

Before attempting a reverse shell, the SSRF and Python Pickle exploitation chain had already established command execution.

The target returned:

```
uid=1000(web) gid=1000(web) groups=1000(web)
web
/opt/app
```

The execution primitive was functional and returned command output through the HTTP response.

### First callback attempt — tun1

A Netcat listener was started on Kali:

```
nc -lvnp 4444
```

The first callback address was:

```
10.144.220.24
```

The initial payload encountered a separate problem: the nested Base64 value was not URL-encoded independently.

The internal API consequently returned:

```
error: Invalid base64-encoded string
```

The payload was corrected by encoding the inner `data` parameter before encoding the outer URL.

After that correction, the request returned:

```
[HTTP 200 | TIME 0.674576s]
```

However, the Netcat listener still received no incoming connection.

**Important:** HTTP 200 confirmed that the request was accepted by the fetch application. It did not prove that the reverse shell connected.

### Second callback attempt — tun0

The callback address was changed to:

```
10.10.17.123
```

The payload was retried with the listener running on port `4444`.

This attempt also failed to establish an interactive session.

The investigation then stopped pursuing reverse-shell access and returned to the working in-band execution mechanism.

### Final outcome

Remote command execution remained functional through the internal administrative API.

The same mechanism supported:

- User and filesystem enumeration.
    
- User flag retrieval.
    
- Sudo enumeration.
    
- Privilege-escalation investigation.
    
- Shared-library compilation and execution.
    
- Root flag retrieval.
    

The examination was completed without an interactive reverse shell.

**Confirmed:** Both callback addresses failed to produce an incoming session.

**Not confirmed:** The exact reason for either failure.

VPN routing was a reasonable troubleshooting hypothesis, but the available results do not prove that it was the cause.

## 5. Practical Troubleshooting Workflow

Before attempting another callback, establish the local network state.

### Check interfaces

```
ip -br -4 addr
```

### Check routes

```
ip route
```

Inspect the route to the callback address:

```
ip route get <CALLBACK_IP>
```

### Verify the listener

```
ss -lntp | grep ':4444'
```

### Capture incoming traffic

```
sudo tcpdump -ni any 'tcp port 4444'
```

For Redis replication, inspect port `6379` instead.

These checks answer different questions:

|Check|What it establishes|
|---|---|
|`ip -br -4 addr`|Which local addresses are assigned|
|`ip route`|Which networks have routing entries|
|`ip route get`|Which local route is selected for a destination|
|`ss -lntp`|Whether a local TCP listener exists|
|`tcpdump`|Whether matching packets reach the capture interface|

A local route to a target does not prove a return route from that target.

Likewise, a listener being active does not prove that the target can reach it.

## 6. Important Lessons

1. Never select `LHOST` merely because an interface has an IP address.
    
2. Verify the relevant network path before generating callback payloads.
    
3. Distinguish the target's outbound connection to Kali from Kali's outbound connection to the target.
    
4. Redis replication uses TCP. Switching to UDP does not solve a failed replication connection.
    
5. Check whether a listener's port is already occupied before starting another listener.
    
6. Correctly interpret Netcat output; a running listener does not imply an incoming session.
    
7. A successful HTTP response does not prove that a background reverse shell connected.
    
8. Fix payload-encoding errors separately from network-connectivity problems.
    
9. Do not repeatedly retry identical callback payloads without new diagnostic evidence.
    
10. Preserve a functioning in-band command-execution channel rather than making an interactive shell a prerequisite.
    

## 7. Final Assessment

|Machine|Callback mechanism|Result|Successful alternative|
|---|---|---|---|
|HA-01|Redis replication to Kali TCP/6379|No connection established|Redis persistence and SSH key authentication|
|IN-01|Reverse shell to Kali TCP/4444|No incoming session on either tested address|In-band Python Pickle command execution|

The most important lesson from these two machines is that **a failed callback does not invalidate a confirmed exploitation primitive**.

Use an interactive shell when connectivity supports it. When it does not, retain the working access channel and continue the examination.

## 8. Related Notes

- [[Network and ISP Restrictions]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Lab Environment]]
    
- [[Initial Access]]
    
- [[HA-01 Overview]]
    
- [[IN-01 Overview]]