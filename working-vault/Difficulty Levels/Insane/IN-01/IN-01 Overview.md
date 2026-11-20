---
type: machine-overview
project: OSCP-Exam-PoC
machine: IN-01
difficulty: Insane
platform: Linux
status: completed
initial_user: web
final_user: root
initial_access: SSRF leading to Python Pickle deserialization RCE
privilege_escalation: Sudo LD_PRELOAD shared-library injection
tags:
  - oscp
  - exam
  - machine
  - insane
  - linux
  - ssrf
  - pickle
  - rce
  - privilege-escalation
  - ld-preload
user_flag_submitted: true
root_flag_submitted: true
---

# IN-01 — Machine Overview

> **Flag completion:** User and root flags obtained and submitted (confirmed by the examination participant). Public value: `IT{FLAG-SECRET}`.

> [!abstract] Machine Summary  
> **Machine:** IN-01
> 
> **Difficulty:** Insane
> 
> **Initial Access:** SSRF filter bypass → Internal Admin API → Python Pickle deserialization → RCE as `web`
> 
> **Privilege Escalation:** Sudo `LD_PRELOAD` injection through `/usr/local/bin/healthcheck`
> 
> **Final Privilege:** Root
> 
> **Root Flag:** Retrieved
> 
> **Machine Status:** Completed

---

## 1. Machine Information

|Property|Value|
|---|---|
|Machine ID|IN-01|
|Difficulty|Insane|
|Exam|IT GATE OSCP-Style Examination|
|Target Public IP|`x.x.x.x`|
|Final HTTP Port|`PORT_J`|
|Final SSH Port|`PORT_M`|
|Hostname|`insane`|
|Operating System|Debian GNU/Linux 13 (trixie)|
|Kernel|`6.8.0-147-generic`|
|Architecture|x86_64|
|Public Web Server|Gunicorn|
|Internal Service|IT GATE Internal Admin API|
|Internal Service Address|`127.1:9000`|
|Initial Execution User|`web`|
|Initial UID|`1000`|
|Final Privilege|`root`|

### Final Instance Endpoints

```
HTTP:
http://x.x.x.x:PORT_J

SSH:
x.x.x.x:PORT_M
```

The lab used disposable instances. Forwarded ports changed when instances were replaced, while the public IP remained the same.

The above port mappings refer to the final instance used for the successful exploitation chain.

**Operational note:** Never assume that a previous instance's forwarded ports remain valid after a reset.

## 2. Attack Chain

The machine required chaining multiple weaknesses across separate application and operating-system layers.

<figure class="attack-chain-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/in-01-attack-chain-mobile.svg" />
    <img src="/diagrams/in-01-attack-chain.svg" alt="IN-01 complete 21-stage attack chain: external URL fetch and SSRF, 127.1 loopback filter bypass into internal port 9000, Admin API /admin/exec and data parameter, Base64-encoded Python Pickle deserialization, command execution as web UID 1000, sudo privilege enumeration, root NOPASSWD healthcheck and preserved LD_PRELOAD, compiled shared library constructor, captured root UID/EUID, and root flag retrieval." width="760" height="3778" loading="lazy" decoding="async" />
  </picture>
  <figcaption>All <strong>21 original attack-chain stages</strong> are retained. The user-flag retrieval command and participant-confirmed submission are documented in section 3.5. Captured <code>UID=0 EUID=0</code> output establishes root execution through the <code>LD_PRELOAD</code> constructor and retrieval of <code>/root/root.txt</code>; <strong>no interactive root shell was established</strong>. Detailed payloads and evidence remain below.</figcaption>
</figure>

The critical feature of this machine was the combination of an SSRF vulnerability, an internally exposed insecure deserialization endpoint, and a sudo environment misconfiguration.

## 3. Initial Access — SSRF to Python Pickle RCE

**Starting point:** Public URL-preview application.

### 3.1 Public Attack Surface

The public application exposed a URL-fetching endpoint:

```
GET /fetch?url=https://example.com
```

The application fetched URLs supplied through the `url` parameter.

The interface indicated that internal addresses were blocked.

This restriction became the first obstacle to reaching the internal application.

### 3.2 SSRF Filter Bypass

Canonical loopback representations were blocked during initial testing.

The following alternative representation was used successfully:

```
127.1
```

This allowed the public application to access the internal service:

```
http://127.1:9000/
```

The internal service returned:

```
IT GATE internal admin API (localhost only)
```

The distinction was important: the internal API was reachable through the vulnerable server-side fetch functionality, even though it was not being accessed directly from Kali.

### 3.3 Internal API Discovery

The internal service was identified on port:

```
9000
```

Generic endpoint enumeration initially produced identical 404 responses.

A targeted endpoint wordlist eventually identified:

```
/admin/exec
```

The endpoint produced a different response from nonexistent routes:

```
HTTP/1.1 400 BAD REQUEST
```

Response:

```
error: Ran out of input
```

This suggested that the handler was attempting to deserialize an input value.

Parameter enumeration identified:

```
data
```

Testing `data=x` produced a Base64 decoding error:

```
error: Invalid base64-encoded string: number of data characters (1) cannot be 1 more than a multiple of 4
```

Together, these responses established that the endpoint consumed a Base64-encoded input.

Further testing identified Python Pickle deserialization as the relevant processing mechanism.

### 3.4 Remote Code Execution

A crafted Python Pickle object invoked command execution through Python's `subprocess` functionality.

The resulting command output was returned through the HTTP response.

Confirmed execution identity:

```
uid=1000(web) gid=1000(web) groups=1000(web)
web
/opt/app
```

This confirmed:

|Attribute|Confirmed Value|
|---|---|
|User|`web`|
|UID|`1000`|
|GID|`1000`|
|Hostname|`insane`|
|Working Directory|`/opt/app`|
|Execution|Remote command execution|

**Result:** Initial access was successfully established as `web`.

See [[Difficulty Levels/Insane/IN-01/user]] for the complete exploitation process, request construction, payload generation, commands, and responses.

### 3.5 User Flag Evidence

The following command was issued through the established in-band execution mechanism:

```
cat /home/$(whoami)/user.txt
```

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

Therefore:

- RCE as `web`: Confirmed.
    
- User-flag retrieval command: Recorded.
    
- **Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.
    

**Flag outcome:** Obtained and submitted (participant-confirmed). Public value: `IT{FLAG-SECRET}`.

## 4. Privilege Escalation — Sudo LD_PRELOAD

**Starting account:** `web` (UID 1000)

After establishing RCE, privilege-escalation enumeration was performed through the same in-band execution mechanism.

### 4.1 Enumeration Findings

The relevant findings were:

|Enumeration Area|Result|
|---|---|
|Sudo|Misconfigured privileged command identified|
|SUID|Standard system binaries|
|SGID|Standard system binaries|
|Linux capabilities|No entries returned|
|Cron|No entries returned|
|Systemd timers|Unavailable; systemd was not running as PID 1|
|Writable directories|No direct root-owned script replacement opportunity identified|
|Running processes|Public and internal Gunicorn applications running under `web`|

The most important result came from:

```
sudo -n -l
```

### 4.2 Sudo Configuration

Matching Defaults entries for `web`:

```
env_reset
mail_badpass
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin
use_pty
env_keep+=LD_PRELOAD
!requiretty
```

Allowed command:

```
User web may run the following commands on insane:
    (root) NOPASSWD: /usr/local/bin/healthcheck
```

Two conditions made this exploitable:

1. `web` could execute `/usr/local/bin/healthcheck` as root without a password.
    
2. Sudo explicitly preserved the `LD_PRELOAD` environment variable.
    

### 4.3 Healthcheck Binary

Target executable:

```
/usr/local/bin/healthcheck
```

Confirmed properties:

|Attribute|Value|
|---|---|
|Owner|root|
|Group|root|
|Permissions|`0755`|
|Size|15,960 bytes|
|Type|Dynamically linked ELF executable|
|Compiler information|GCC 14.2.0|
|Source filename embedded in binary|`healthcheck.c`|

The `file` utility was unavailable on the target. The ELF identification was supported by the embedded dynamic-linker references, libc references, symbols, and section names returned by binary inspection.

The target had the necessary development utilities:

```
/usr/bin/gcc
/usr/bin/cc
/usr/bin/readelf
```

This made it possible to compile the shared library directly on the target.

### 4.4 Shared-Library Injection

The exploitation process followed this sequence:

1. Create a C source file.
    
2. Implement a constructor that executes when the library is loaded.
    
3. Compile the source into a shared object.
    
4. Invoke the permitted root command using `sudo`.
    
5. Supply the compiled library through `LD_PRELOAD`.
    
6. Verify the effective execution identity.
    
7. Read `/root/root.txt`.
    

Compilation:

```
/usr/bin/gcc -Wall -Wextra -fPIC -shared \
    -o /tmp/in01_preload.so \
    /tmp/in01_preload.c
```

Execution:

```
sudo -n LD_PRELOAD=/tmp/in01_preload.so \
    /usr/local/bin/healthcheck
```

The library constructor executed successfully.

### 4.5 Root Execution Confirmation

Actual output:

```
[+] LD_PRELOAD constructor executed
[+] UID=0 EUID=0 GID=0 EGID=0
```

The constructor successfully read:

```
/root/root.txt
```

**Root flag:**

```
IT{FLAG-SECRET}
```

<badge color="success">Root confirmed</badge>

This confirms root-level code execution and successful retrieval of the root flag.

It does not establish that an interactive root shell was obtained; the successful escalation used the constructor executed by the permitted sudo command.

See [[Difficulty Levels/Insane/IN-01/root]] for the complete C source, compilation command, execution payload, and captured output.

## 5. Key Technical Findings

|Finding|Category|Result|
|---|---|---|
|Public URL-fetch endpoint|Web attack surface|Confirmed|
|Internal address filtering|SSRF protection|Present|
|`127.1` loopback representation|Filter bypass|Confirmed|
|Internal Admin API on port 9000|Internal service|Confirmed|
|`/admin/exec`|Administrative endpoint|Confirmed|
|`data` parameter|Input handling|Confirmed|
|Base64-encoded Python Pickle|Deserialization format|Confirmed|
|Pickle-driven command execution|Remote code execution|Confirmed|
|RCE as `web`|Initial access|Confirmed|
|`env_keep+=LD_PRELOAD`|Sudo configuration|Confirmed|
|NOPASSWD healthcheck execution|Privileged command|Confirmed|
|LD_PRELOAD constructor|Privilege escalation|Confirmed|
|Root flag retrieval|Final objective|Confirmed|

## 6. Difficulties Encountered

IN-01 involved several obstacles that affected investigation speed and execution strategy.

### 6.1 HTTP Reachability / Network Timeout

At one point, the public application stopped returning responses.

Observed output:

```
curl: (28) Operation timed out after 12002 milliseconds with 0 bytes received

HTTP: 000
Connect: 0.248585s
First byte: 0.000000s
Total: 12.002333s
```

Later, the original fetch endpoint returned the Example Domain HTML successfully again.

**Impact:**

- Delayed reconnaissance.
    
- Interrupted reliable endpoint enumeration.
    
- Created uncertainty about whether the application or network was responsible.
    

**Resolution:** The endpoint recovered and enumeration resumed.

**Evidence qualification:** The timeout is confirmed. An ISP-specific cause is not established by this output alone. It must not be presented as proven ISP filtering without additional supporting evidence.

### 6.2 Reverse-Shell Callback Failures

Reverse-shell attempts were made through both VPN interfaces.

Observed Kali addresses:

|Interface|Address|
|---|---|
|`tun0`|`10.10.17.123`|
|`tun1`|`10.144.220.24`|

A Netcat listener was started, but neither callback produced an incoming connection.

**Impact:** An interactive shell could not be established through the tested callback routes.

**Resolution:** The investigation returned to the existing in-band Pickle RCE mechanism.

This was sufficient to enumerate the system, compile the shared library, execute the privilege escalation, and retrieve the root flag.

The exact reason for the callback failures was not conclusively established.

### 6.3 Zsh PATH Corruption

A supplied command used `path` as a loop variable.

In Zsh, `path` is a special array tied to the `PATH` environment variable.

This caused the shell's command search path to be overwritten.

Observed state included:

```
PATH=/healthz
```

Later, another invalid value appeared:

```
/__random_test_94821
```

This prevented commands such as FFUF from being located even though the binaries existed.

**Resolution:** The system paths were restored:

```
typeset -U path
path=(/usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin)
rehash
```

The Zsh startup configuration was updated with a persistent safeguard and invalid PATH entries were removed.

**Lesson:** Commands and scripts intended for Zsh must not use `path` as an ordinary variable name.

This was a tooling mistake caused by a supplied command, not a target-side vulnerability.

### 6.4 Inefficient Endpoint Enumeration

The initial generic endpoint scan returned identical responses:

```
HTTP 404
Size: 207 bytes
```

A generic API wordlist also produced no useful results.

The investigation initially repeated scans while carrying over a response-size filter from an earlier instance. Automatic calibration also resulted in zero reported matches.

**Resolution:** Endpoint discovery was narrowed to administrative operations. The route:

```
/admin/exec
```

produced a different response:

```
HTTP 400
Content-Length: 23

error: Ran out of input
```

That response changed the investigation from route enumeration to input-parameter discovery.

### 6.5 Nested URL and Base64 Encoding

The internal endpoint required a Base64-encoded value inside a nested URL, which was itself passed as the outer `url` parameter.

Incorrect handling of this structure caused request parameter corruption.

**Correct handling:**

1. Generate the Pickle payload.
    
2. Base64-encode the serialized object.
    
3. URL-encode the inner `data` parameter value.
    
4. Construct the internal URL.
    
5. Pass the complete internal URL through the outer `/fetch` parameter.
    

This distinction was essential to reliable payload delivery.

### 6.6 Non-UTF-8 Command Output

An inspection attempt tried to return binary executable content through a response handler expecting UTF-8 text.

Observed error:

```
'utf-8' codec can't decode byte 0x98 in position 812: invalid start byte
```

A subsequent output-encoding attempt also failed because the returned HTTP content did not consist exclusively of Base64 data.

**Resolution:** The inspection process was adjusted to use text-oriented binary inspection, including `strings`, and to preserve the raw response instead of assuming its format.

### 6.7 Target Lacked Some Utilities

The target was a minimal environment.

For example:

```
/bin/sh: 19: file: not found
```

The missing utility did not prevent investigation because other available tools provided sufficient evidence.

GCC, `cc`, and `readelf` were available, which was especially important for the final privilege escalation.

## 7. Methodological Lessons

IN-01 demonstrated the value of following evidence across multiple application layers instead of treating each discovery in isolation.

1. **SSRF can provide access to internal application functionality.** A server-side request mechanism may expose services that are not directly reachable from the attacker.
    
2. **Address parsing and filtering must be evaluated separately.** Blocking canonical loopback representations does not guarantee that all loopback representations are blocked.
    
3. **Different error responses are useful evidence.** The transition from generic 404 responses to the Pickle-related errors exposed the actual administrative handler.
    
4. **Parameter enumeration can be more valuable than continued path enumeration.** Once `/admin/exec` was identified, discovering `data` was the critical next step.
    
5. **Insecure deserialization can turn an internal API into an RCE primitive.** The Base64-encoded Pickle input allowed command execution as the application user.
    
6. **A reverse shell is not mandatory.** In-band command execution remained fully functional after callback attempts failed.
    
7. **Sudo environment preservation matters.** `env_keep+=LD_PRELOAD`, combined with a root-executable NOPASSWD command, provided the privilege-escalation path.
    
8. **Compile shared libraries from source when required.** The C source was created first and compiled into a `.so` with GCC.
    
9. **Tooling failures must be distinguished from target failures.** PATH corruption and output-decoding problems affected the investigation but did not invalidate the vulnerabilities.
    
10. **Preserve raw evidence.** The root flag and root execution identity were captured; the user flag output remains an evidence gap.
    

## 8. Reusable Techniques

|Technique|Application|Future PoC Note|
|---|---|---|
|SSRF|Access internal HTTP services|[[Reusable PoCs/SSRF/SSRF Filter Bypass]]|
|Alternative loopback notation|Bypass weak internal-address filtering|[[Reusable PoCs/SSRF/SSRF Filter Bypass]]|
|Internal API discovery|Identify administrative routes and parameters|To be extracted|
|Python Pickle deserialization|Obtain RCE through unsafe deserialization|[[Reusable PoCs/Python Pickle/Python Pickle RCE]]|
|In-band command execution|Continue without a reverse shell|To be extracted|
|Sudo LD_PRELOAD|Execute a shared-library constructor as root|[[Reusable PoCs/Linux Privilege Escalation/LD_PRELOAD]]|
|C shared-library compilation|Build a `.so` using GCC|[[Reusable PoCs/Linux Privilege Escalation/LD_PRELOAD]]|

These are cross-machine knowledge-base references. The complete, machine-specific execution records belong in `user.md` and `root.md`.

## 9. Evidence Status

|Evidence|Status|
|---|---|
|Final target IP and forwarded ports|Recorded|
|Public URL-fetch endpoint|Confirmed|
|Internal API banner|Confirmed|
|Loopback filter bypass using `127.1`|Confirmed|
|`/admin/exec` route|Confirmed|
|`data` parameter and Base64 input|Confirmed|
|Python Pickle execution|Confirmed|
|RCE identity as `web`|Confirmed|
|User flag command|Recorded|
| Flag outcome | Obtained and submitted (participant-confirmed) |
|Sudo privilege configuration|Confirmed|
|Healthcheck binary characteristics|Recorded|
|C source and shared-library compilation|Recorded|
|Root execution identity|Confirmed|
|Root flag|Confirmed and preserved|
|Reverse-shell callback|Unsuccessful|
|Specific cause of callback failure|Unverified|
|ISP attribution for HTTP timeout|Unverified|

## 10. Final Result

|Objective|Result|
|---|---|
|Identify public attack surface|Completed|
|Exploit SSRF|Confirmed|
|Reach internal Admin API|Confirmed|
|Identify insecure deserialization|Confirmed|
|Achieve RCE as `web`|Confirmed|
|Retrieve `user.txt`| Obtained and submitted (participant-confirmed) |
|Identify privilege-escalation path|Confirmed|
|Execute shared-library constructor as root|Confirmed|
|Retrieve `/root/root.txt`|Confirmed|

**Root flag:**

```
IT{FLAG-SECRET}
```

**Final machine status:** Completed. Root compromise confirmed.

---

## 11. Related Documentation

### Machine Records

- [[Difficulty Levels/Insane/IN-01/user]]
    
- [[Difficulty Levels/Insane/IN-01/root]]
    

### Exam Context

- [[Dashboard]]
    
- [[Exam Context/Exam Overview]]
    
- [[Exam Context/Lab Environment]]
    
- [[Exam Context/Exam Timeline]]
    

### Difficulties and Lessons

- [[Difficulties & Lessons/Network and ISP Restrictions]]
    
- [[Difficulties & Lessons/VPN Routing and Reverse Shells]]
    
- [[Difficulties & Lessons/Kali PATH and Zsh Issues]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Difficulties & Lessons/Fuzzing Strategy and False Leads]]
    
- [[Difficulties & Lessons/Tooling and Workflow Mistakes]]
    

---

**Documentation status:** Overview reconstructed from the examination record. Detailed exploitation commands, payloads, and raw outputs belong in the separate user and root records.