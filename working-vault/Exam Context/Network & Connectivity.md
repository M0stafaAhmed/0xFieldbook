---
type: technical-reference
project: OSCP-Exam-PoC
category: network-connectivity
status: documented
created: "2026-11-05"
updated: "2026-11-07"
tags:
  - networking
  - connectivity
  - vpn
  - routing
  - port-forwarding
  - troubleshooting
---

# Network & Connectivity

## 1. Purpose

This document records the network architecture and connectivity behavior observed during the examination.

It covers:

- Attacker-to-target communication.
    
- VPN interfaces and routing.
    
- External service exposure.
    
- Port forwarding and disposable instance mappings.
    
- Internal service accessibility.
    
- SSRF-based access to internal network resources.
    
- Reverse-shell callback failures.
    
- HTTP timeouts and connection failures.
    
- Connectivity troubleshooting and workarounds.
    

The objective is to distinguish network-layer failures from application-layer failures and document how connectivity affected exploitation.

---

## 2. Network Architecture

### 2.1 General Communication Model

The examination involved communication between three principal environments:

1. **Attacker machine:** Kali Linux, running reconnaissance and exploitation tools.
    
2. **Laboratory infrastructure:** The provider's externally reachable infrastructure, exposing assigned service ports.
    
3. **Target environment:** The isolated laboratory machine hosting the vulnerable applications and internal services.
    

The observed target addressing model used a public IP address with externally assigned ports.

The same public IP was observed across multiple disposable instances, while the assigned HTTP and SSH ports changed.

#### External Connectivity

```
                  Kali Linux
                      |
                      |
                 VPN Interface
                      |
                      |
              Laboratory Network
                      |
                      |
             Public Target Address
               x.x.x.x
                      |
             Externally Assigned Ports
                      |
              Target Environment
                      |
           +----------+-----------+
           |                      |
       Public Web              SSH Service
        Service
           |
       Internal Network
           |
       127.0.0.1:9000
           |
       Internal Admin API
```

**Note:** This diagram represents the observed communication relationships. The provider's underlying forwarding implementation was not independently inspected.

### 2.2 Public Target Address

```
x.x.x.x
```

This public IP was observed throughout the recorded HA-01 and IN-01 instances.

The assigned service ports changed when instances were replaced.

**Operational distinction:**

The public IP is not sufficient to identify a particular machine instance. The associated port mapping must also be recorded.

---

## 3. VPN Interfaces

Two VPN interfaces were observed during IN-01.

|Interface|IPv4 Address|Prefix|Observed State|
|---|---|---|---|
|tun0|`10.10.17.123`|/23|UNKNOWN|
|tun1|`10.144.220.24`|/22|UP|

### Interface Enumeration

The following command was used:

```
ip -br -4 addr
```

Relevant output:

```
tun0    UNKNOWN    10.10.17.123/23
tun1    UP         10.144.220.24/22
```

These addresses are historical observations and should not be assumed to remain valid after VPN reconnection.

### 3.1 Multiple VPN Interfaces

Having multiple VPN interfaces introduced uncertainty when determining the correct reverse-shell callback address.

A callback address must be reachable from the target environment.

The presence of an IP address on a local VPN interface does not establish that the target can route traffic back to it.

#### Recommended Routing Verification

Before launching a reverse shell, inspect the local routing decision:

```
ip route get CALLBACK_IP
```

Inspect the interfaces:

```
ip -br -4 addr
```

Inspect available routes:

```
ip route
```

Record the interface and source address selected by the routing table.

---

## 4. External Port Mapping

### 4.1 HA-01

Historical instance mapping:

|Service|Public IP|External Port|
|---|---|---|
|Redis|`x.x.x.x`|PORT_E|
|SSH|`x.x.x.x`|PORT_B|

The Redis service was accessed through the externally assigned TCP port.

### 4.2 IN-01

Multiple disposable instances were used.

|Instance|HTTP Port|SSH Port|Status|
|---|---|---|---|
|Initial|PORT_O|PORT_C|Destroyed|
|Second|PORT_K|PORT_A|Replaced|
|Final|PORT_J|PORT_M|Used for exploitation|

Public IP:

```
x.x.x.x
```

#### Final Instance

HTTP:

```
http://x.x.x.x:PORT_J
```

SSH:

```
ssh user@x.x.x.x -p PORT_M
```

The final instance mapping was used throughout the successful IN-01 exploitation chain.

**Important:** The service ports from a previous instance must never be reused without checking the current lab configuration.

---

## 5. External Service Enumeration

### 5.1 Nmap

The following scan was conducted against the second IN-01 instance:

```
nmap -Pn -n -sV -sC \
  -p PORT_K,PORT_A \
  --script http-title,http-headers,http-server-header,http-methods,ssh-hostkey,ssh2-enum-algos \
  -oA ~/Desktop/IN01/nmap/initial-enum \
  x.x.x.x
```

Results:

|Port|State|Service|Version|
|---|---|---|---|
|PORT_A/tcp|Open|SSH|OpenSSH 10.0p2 Debian 7+deb13u4|
|PORT_K/tcp|Open|HTTP|Gunicorn|

HTTP findings:

```
Server: gunicorn
Content-Type: text/html; charset=utf-8
```

Supported methods:

```
HEAD OPTIONS GET
```

The Nmap results were collected before the final instance replacement. The final ports were different.

### 5.2 HTTP Fingerprinting

WhatWeb identified:

```
HTTPServer[gunicorn]
```

No additional framework or frontend technology was identified through that fingerprinting attempt.

---

## 6. IN-01 — Internal Network Discovery

### 6.1 Public Application

The public application exposed:

```
GET /fetch?url=https://example.com
```

The application fetched the requested URL and returned the response body.

A successful external request demonstrated that server-side HTTP fetching was operational.

Example:

```
curl -sS -G \
  --data-urlencode 'url=https://example.com' \
  'http://TARGET_IP:HTTP_PORT/fetch'
```

The returned body contained the Example Domain HTML.

### 6.2 Internal Address Filtering

The application rejected canonical loopback addresses.

Observed behavior:

|Submitted Address|Result|
|---|---|
|`127.0.0.1`|HTTP 403|
|`localhost`|HTTP 403|
|`[::1]`|HTTP 403|

Alternative loopback representations were accepted by the initial URL filter.

Examples:

```
127.1
2130706433
0x7f000001
0177.0.0.1
```

The important distinction was that the filter's handling of the submitted hostname was not equivalent to the operating system's address interpretation.

#### Confirmed Filter Bypass

The following destination was successfully used:

```
http://127.1:9000/
```

It returned:

```
IT GATE internal admin API (localhost only)
```

This established access to a service bound to the target's loopback interface.

See [[Difficulty Levels/Insane/IN-01/user]] and [[Methodology/SSRF]].

### 6.3 Internal Service Bindings

Target-side process enumeration identified these Gunicorn bindings:

```
0.0.0.0:8080
127.0.0.1:9000
```

The corresponding applications were:

```
public_app:app
internal_app:app
```

Both were executed under the `web` account.

The process output showed:

```
/usr/local/bin/gunicorn --access-logfile - -b 0.0.0.0:8080 public_app:app
```

and:

```
/usr/local/bin/gunicorn --access-logfile - -b 127.0.0.1:9000 internal_app:app
```

This was an important architectural discovery: the internal administrative application was bound to loopback and was not directly exposed through the public application.

### 6.4 Internal Port 8080 Investigation

Port 8080 accepted connections, but HTTP requests consistently timed out.

Example:

```
HTTP 502
fetch error:
HTTPConnectionPool(host='127.1', port=8080):
Read timed out. (read timeout=4)
```

Directory fuzzing produced no useful discoveries.

The service was not sufficiently identified to justify continuing the directory scan.

The investigation subsequently moved to targeted service discovery.

### 6.5 Internal Port 9000 Discovery

A targeted internal port scan identified port 9000.

The request:

```
http://127.1:9000/
```

returned:

```
IT GATE internal admin API (localhost only)
```

This was the first confirmed discovery of the intended internal administrative service.

The service was then enumerated and its execution endpoint discovered:

```
/admin/exec
```

The `data` query parameter was identified as the input parameter for Python Pickle deserialization.

See [[Difficulty Levels/Insane/IN-01/user]].

---

## 7. HTTP Connectivity Incidents

### 7.1 Public Application Timeouts

During IN-01, the public application temporarily stopped returning HTTP responses.

Observed output:

```
curl: (28) Operation timed out after 12002 milliseconds with 0 bytes received

HTTP: 000
Connect: 0.248585s
First byte: 0.000000s
Total: 12.002333s
```

Important observations:

- The TCP connection was established.
    
- The HTTP response did not arrive.
    
- No response bytes were received before the timeout.
    
- The application subsequently recovered.
    

The same public fetch endpoint eventually returned the Example Domain HTML again.

#### Impact

- Delayed reconnaissance.
    
- Prevented reliable endpoint testing during the affected period.
    
- Caused uncertainty about whether the problem was network-related or application-related.
    

#### Resolution

The original HTTP endpoint recovered and testing continued.

#### Attribution

The timeout is confirmed.

An ISP-specific cause was not conclusively established from the available evidence.

This incident should be classified as an observed connectivity failure, not a confirmed ISP outage.

See [[Difficulties & Lessons/Network and ISP Restrictions]].

### 7.2 Connection Refusal vs Timeout

These two responses must be distinguished.

**Connection refused:**

```
[Errno 111] Connection refused
```

This indicates that the connection attempt was actively rejected.

**Read timeout:**

```
Read timed out.
```

This indicates that the client did not receive the expected response within its configured timeout.

During IN-01:

- Many internal ports returned connection-refused errors.
    
- Port 8080 repeatedly produced read timeouts.
    
- Port 9000 successfully returned an HTTP response.
    

These results drove the decision to focus on port 9000.

### 7.3 Redirect Handling

Two redirect tests were performed using HTTPBin.

A public redirect request returned:

```
HTTP 302
Content-Length: 0
```

A redirect targeting canonical loopback returned:

```
HTTP 403 FORBIDDEN
Forbidden redirect target:
redirect target is an internal address
```

The internal redirect test established that redirect destinations were subject to additional validation.

The direct `127.1` bypass was more useful than the redirect approach, so redirect testing was abandoned.

---

## 8. Reverse-Shell Connectivity

### 8.1 Listener Configuration

The attempted listener was:

```
nc -lvnp 4444
```

Two callback addresses were tested.

|Attempt|Callback Address|Result|
|---|---|---|
|First|`10.144.220.24:4444`|No incoming connection|
|Second|`10.10.17.123:4444`|No incoming connection|

### 8.2 Effect on the Investigation

The reverse-shell attempts did not establish an interactive session.

However, this did not affect the underlying remote command execution primitive.

The target continued to accept requests to:

```
127.1:9000/admin/exec
```

The investigation therefore reverted to in-band command execution.

This method successfully supported:

- Target identification.
    
- User-context enumeration.
    
- Filesystem enumeration.
    
- Sudo privilege discovery.
    
- Shared-library compilation.
    
- Privilege escalation.
    
- Root flag retrieval.
    

#### Root Cause

The exact reason for callback failure was not established.

Possible causes include:

- Incorrect callback routing.
    
- VPN interface or address selection.
    
- Missing return route.
    
- Target-side outbound filtering.
    
- Network firewall restrictions.
    

These remain hypotheses, not confirmed findings.

#### Lesson

An interactive reverse shell is not a mandatory component of successful exploitation.

When in-band execution remains available, it can be sufficient to complete the full attack chain.

See [[Difficulties & Lessons/VPN Routing and Reverse Shells]].

---

## 9. Connectivity Troubleshooting Methodology

The following workflow is intended for future examination sessions.

### 9.1 Verify Local Network Interfaces

```
ip -br -4 addr
```

### 9.2 Inspect Routing Decisions

```
ip route
ip route get TARGET_IP
ip route get CALLBACK_IP
```

### 9.3 Verify a Local Listener

```
ss -lntp
```

For a specific port:

```
ss -lntp | grep ':4444'
```

### 9.4 Check External TCP Reachability

```
nc -vz -w 5 TARGET_IP TARGET_PORT
```

### 9.5 Measure HTTP Connectivity

```
curl -sS \
  --connect-timeout 3 \
  --max-time 10 \
  -o /dev/null \
  -w '
HTTP: %{http_code}
Connection: %{time_connect}s
First byte: %{time_starttransfer}s
Total: %{time_total}s
Downloaded: %{size_download} bytes
' \
  'http://TARGET_IP:TARGET_PORT/'
```

### 9.6 Interpret the Results

|Result|Interpretation|
|---|---|
|DNS failure|Hostname resolution problem|
|Connection refused|Destination actively rejected the TCP connection|
|Connection timeout|TCP connection was not established within the deadline|
|HTTP 403|Application-level or security-rule rejection|
|HTTP 404|Application responded but did not find the requested route|
|HTTP 502|Fetching application encountered an upstream error|
|HTTP 000|No HTTP response was successfully received|
|TCP connected, HTTP timeout|Connection established, but no HTTP response arrived|
|Successful HTTP response|Application-level communication confirmed|

---

## 10. Operational Lessons

### 10.1 Record the Full Endpoint

Record both the IP and assigned port.

An old port mapping should not be assumed valid after a reset.

### 10.2 Distinguish Network Layers

A successful TCP connection does not establish that an HTTP service is available.

Likewise, an HTTP 502 does not automatically mean that the original public application is unavailable.

### 10.3 Separate External and Internal Reconnaissance

External Nmap enumeration reveals externally reachable services.

Application-level SSRF can reveal services that are only accessible from the target's internal network.

These are separate attack surfaces.

### 10.4 Do Not Treat Every Timeout as a Filtering Result

A timeout is not the same as a 403 response.

The investigation of port 8080 demonstrated why response interpretation must be based on the actual error.

### 10.5 Preserve In-Band Execution

If reverse-shell callbacks fail, do not discard an otherwise working RCE primitive.

The IN-01 investigation was completed using in-band execution.

---

## 11. Related Documentation

- [[Exam Overview]]
    
- [[Lab Environment]]
    
- [[Network and ISP Restrictions]]
    
- [[VPN Routing and Reverse Shells]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Fuzzing Strategy and False Leads]]
    
- [[Methodology/Reconnaissance]]
    
- [[Methodology/SSRF]]
    
- [[Difficulty Levels/Hard/HA-01/HA-01 Overview]]
    
- [[Difficulty Levels/Insane/IN-01/IN-01 Overview]]
    

---

**Evidence classification:** Historical examination observations, actual command outputs, and verified exploitation behavior.

**Important:** The documented VPN addresses and public service mappings are historical. They should not be treated as current network configuration.