---
type: methodology
project: OSCP-Exam-PoC
status: drafted
updated: "2026-11-07"
tags:
  - methodology
  - reconnaissance
  - nmap
  - service-enumeration
  - web-enumeration
  - oscp
---

# Reconnaissance

## 1. Purpose

Reconnaissance is the process of identifying the target's exposed attack surface before selecting an exploitation path.

The objective is to establish:

- Which services are reachable.
    
- Which ports and protocols are exposed.
    
- Which applications and technologies are running.
    
- Which HTTP endpoints, parameters, and functionalities are available.
    
- Which authentication requirements or access restrictions exist.
    
- Which findings are confirmed and which are still hypotheses.
    

The goal is not to run as many tools as possible. It is to obtain enough reliable information to choose the next enumeration step.

This document describes the initial reconnaissance workflow used throughout the IT GATE Academy OSCP-style examination.

## 2. Reconnaissance Workflow

The recommended sequence is:

1. Collect the machine information supplied by the Academy.
    
2. Establish the target scope and current instance details.
    
3. Perform targeted port and service enumeration.
    
4. Fingerprint exposed web applications.
    
5. Inspect the application manually.
    
6. Identify endpoints, parameters, and authentication requirements.
    
7. Establish baseline and negative-control responses.
    
8. Perform controlled discovery when evidence justifies it.
    
9. Record the results and select the next methodology.
    

<figure class="method-atlas-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/methodology-atlas-reconnaissance-process-mobile.svg" />
    <img src="/diagrams/methodology-atlas-reconnaissance-process.svg" alt="Reconnaissance / evidence-driven workflow: Academy Machine Information then Target Scope and Instance Details then Targeted Nmap Enumeration then Service and Technology Fingerprinting then Manual Application Inspection then Endpoint and Parameter Mapping then Baseline / Negative-Control Testing then Controlled Discovery then Document Findings and Select Next Step." width="960" height="1040" loading="lazy" decoding="async" />
  </picture>
  <figcaption>Nine-stage methodology funnel. All original steps and labels are retained; refer to the surrounding methodology for evidence and limitations.</figcaption>
</figure>

## 3. Establish Target Scope

Before running tools, collect the information presented on the Academy Machines page.

Record:

|Property|Description|
|---|---|
|Machine ID|Example: VE-01|
|Difficulty|Very Easy, Easy, Medium, Hard, or Insane|
|Public IP|Assigned target address|
|Web port|Externally exposed HTTP service port|
|SSH port|Externally exposed SSH service port, if present|
|Other services|Redis or other explicitly provided services|
|Instance start|When the current instance was started|
|Instance changes|New ports or addresses after a restart|

### Important: Instance details can change

The examination used a shared public IP with different externally assigned ports for different machine instances.

For example:

|Machine|Service|Observed endpoint|
|---|---|---|
|VE-01|HTTP|`x.x.x.x:PORT_L`|
|EA-01|HTTP|`x.x.x.x:PORT_N`|
|EA-01|SSH|`x.x.x.x:PORT_H`|
|ME-01|HTTP|`x.x.x.x:PORT_I`|
|HA-01|Redis, refreshed instance|`x.x.x.x:PORT_E`|
|HA-01|SSH, refreshed instance|`x.x.x.x:PORT_B`|
|IN-01|HTTP|`x.x.x.x:PORT_K`|

These are historical examination values, not permanent target addresses.

**Always use the current instance information supplied by the Academy.** Do not assume that a previously working port remains valid after restarting or replacing a machine.

### Define the authorized scanning scope

A containerized lab does not automatically imply that its public IP address is dedicated to that container.

During the examination, the same public IP was reused while the externally assigned ports changed. This is consistent with a port-forwarding arrangement.

Therefore:

- Start with the ports explicitly assigned to the current machine.
    
- Do not assume that every port on the public IP belongs to the current container.
    
- Do not run a full TCP port scan against a potentially shared public host unless the provider explicitly authorizes it.
    
- Expand the scan scope only when the authorization and network topology permit it.
    

## 4. Port and Service Enumeration with Nmap

Nmap establishes which supplied ports are reachable and helps identify the services behind them.

### 4.1 Initial targeted scan

Set the current target information:

```
TARGET_IP='x.x.x.x'
WEB_PORT='PORT_K'
SSH_PORT='PORT_A'

OUT="$HOME/Desktop/IN01/nmap"

mkdir -p "$OUT"
```

Run service and version detection:

```
nmap -Pn -n -sC -sV \
  -p "$WEB_PORT,$SSH_PORT" \
  --script http-title,http-headers,http-server-header,http-methods,ssh-hostkey,ssh2-enum-algos \
  -oA "$OUT/initial-enum" \
  "$TARGET_IP"
```

Replace the target and ports with the current machine's assigned values.

### 4.2 Parameter breakdown

|Option|Purpose|
|---|---|
|`-Pn`|Skip host discovery and treat the target as online|
|`-n`|Disable DNS resolution|
|`-sC`|Run Nmap's default safe script set|
|`-sV`|Detect service versions|
|`-p`|Restrict scanning to specified ports|
|`--script`|Select additional NSE scripts|
|`-oA`|Save output in normal, XML, and grepable formats|

The selected NSE scripts provide additional information:

|Script|Information|
|---|---|
|`http-title`|HTTP page title|
|`http-headers`|HTTP response headers|
|`http-server-header`|Web server identification|
|`http-methods`|Supported HTTP methods|
|`ssh-hostkey`|SSH host-key information|
|`ssh2-enum-algos`|SSH cryptographic algorithms|

### 4.3 Examination example: IN-01

The following scan was executed against the assigned web and SSH ports:

```
nmap -Pn -n -sV -sC \
  -p PORT_K,PORT_A \
  --script http-title,http-headers,http-server-header,http-methods,ssh-hostkey,ssh2-enum-algos \
  -oA ~/Desktop/IN01/nmap/initial-enum \
  x.x.x.x
```

Confirmed results:

|Port|Service|Detected information|
|---|---|---|
|`PORT_A/tcp`|SSH|OpenSSH 10.0p2, Debian 7+deb13u4|
|`PORT_K/tcp`|HTTP|Gunicorn|

The HTTP service also exposed:

```
Supported Methods: HEAD OPTIONS GET
```

This established the externally exposed services and provided an initial technology fingerprint.

The scan did not identify the internal admin API later reached through SSRF. That service was bound to localhost and required a different discovery approach.

See [[SSRF]] and [[IN-01 Overview]].

## 5. Web Application Fingerprinting

Once an HTTP service is identified, inspect its response before starting directory or parameter discovery.

### 5.1 Capture the initial response

```
BASE='http://x.x.x.x:PORT_K'

curl -sS -i --max-time 10 "$BASE/"
```

Useful response information includes:

- HTTP status code.
    
- Server header.
    
- Content-Type.
    
- Content-Length.
    
- Redirect behavior.
    
- HTML title and page content.
    
- Application-specific messages.
    
- Exposed routes or parameters.
    

### 5.2 Fingerprint the application

Use WhatWeb when additional technology identification is useful:

```
whatweb -v "$BASE/"
```

During IN-01, WhatWeb identified:

```
Status    : 200 OK
Title     : <None>

Summary   : HTTPServer[gunicorn]
```

The response headers also contained:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/html; charset=utf-8
Content-Length: 244
```

This identified Gunicorn as the exposed HTTP server.

A server header is a fingerprinting clue, not proof of the application's complete technology stack or framework version.

### 5.3 Inspect common application resources

A small initial check can reveal useful application structure:

```
for endpoint in \
    / \
    /robots.txt \
    /sitemap.xml \
    /favicon.ico \
    /static/ \
    /fetch
do
    printf '\n========== %s ==========\n' "$endpoint"

    curl -sS --max-time 6 -i \
        "$BASE$endpoint" | head -c 1200

    printf '\n'
done
```

This is an initial inspection, not an exhaustive directory scan.

Interpret responses individually:

|Response|Possible meaning|
|---|---|
|`200 OK`|Resource exists or application handled the request|
|`301` / `302`|Redirect; inspect the destination|
|`400 Bad Request`|Request reached the application but did not satisfy its input requirements|
|`401 Unauthorized`|Authentication required|
|`403 Forbidden`|Access denied|
|`404 Not Found`|Resource or route not found|
|`405 Method Not Allowed`|Route exists but does not accept the requested method|
|`500 Internal Server Error`|Application-side failure worth investigating|

Do not assume that an HTTP status code alone proves a vulnerability.

## 6. Identify Application Functionality and Attack Surface

Manual inspection is important because application descriptions often reveal the intended functionality and the parameters that deserve investigation.

Record:

- Forms and input fields.
    
- Query parameters.
    
- File upload functionality.
    
- Download functionality.
    
- Authentication requirements.
    
- API endpoints.
    
- Diagnostic functions.
    
- Error messages.
    
- Application-specific restrictions.
    

### 6.1 VE-01 — File Upload Application

The initial application exposed file-upload functionality.

The subsequent investigation identified the uploaded file at:

```
/uploads/file.php
```

The endpoint later accepted a `cmd` parameter.

The reconnaissance lesson is to identify the upload interface, understand its request structure, and determine where uploaded files are made available.

The exploitation and privilege-escalation details belong in:

- [[VE-01 Overview]]
    
- [[Initial Access]]
    
- [[Linux Privilege Escalation]]
    

### 6.2 EA-01 — HTTP and SSH

The Academy provided two externally exposed services:

```
HTTP:
http://x.x.x.x:PORT_N

SSH:
x.x.x.x:PORT_H
```

The targeted Nmap command was:

```
nmap -sC -sV \
  -p PORT_N,PORT_H \
  x.x.x.x
```

The web application exposed a search parameter:

```
/?q=
```

The SSH service represented a separate potential entry point.

Both services were relevant to the attack-surface map, even though the eventual initial-access path was discovered through the web application's SQL injection vulnerability.

See [[EA-01 Overview]] and [[Web Enumeration]].

### 6.3 ME-01 — API-Based File Service

The initial page exposed the application's functionality directly:

```
IT GATE File Service

GET /api/download?file=welcome.txt

GET /api/ping?host=1.1.1.1
(internal diagnostics — requires X-API-Key)
```

This immediately established two endpoints worth investigating.

|Endpoint|Identified functionality|Investigation direction|
|---|---|---|
|`/api/download?file=`|File download|File path handling and access restrictions|
|`/api/ping?host=`|Internal diagnostics|API authorization and host parameter handling|

The `X-API-Key` requirement was an important reconnaissance finding.

It indicated that access to the diagnostics functionality depended on an additional HTTP header.

The initial task was to establish the normal download response and understand the file parameter before investigating the protected endpoint.

See [[ME-01 Overview]] and [[Web Enumeration]].

### 6.4 HA-01 — Redis Service

The Academy exposed a cache-service port and an SSH port.

After the original instance timed out and was replaced, the updated connection information was:

```
Redis: x.x.x.x:PORT_E

SSH:
x.x.x.x:PORT_B
```

The initial Redis connection was established using:

```
redis-cli -h x.x.x.x -p PORT_E
```

The following commands provided useful service information:

```
INFO replication
INFO server
```

Observed results included:

```
role:master
connected_slaves:0
```

And:

```
redis_version:7.0.15
redis_mode:standalone
os:Linux 6.8.0-147-generic x86_64
tcp_port:6379
```

The service also disclosed its configured Redis executable and configuration file:

```
executable:/redis-server
config_file:/etc/oscp-redis.conf
```

This is an example of service-specific enumeration: after identifying a Redis endpoint, use Redis-native commands instead of treating it as an ordinary HTTP service.

See [[HA-01 Overview]] and [[Redis Persistence]].

### 6.5 IN-01 — Link Preview Application

The initial page exposed a URL-fetching function:

```
<h1>IT GATE Link Preview</h1>

<p>Preview any public URL:</p>

<p><code>GET /fetch?url=https://example.com</code></p>

<p><em>Internal addresses are blocked for security.</em></p>
```

The application therefore exposed:

```
GET /fetch?url=
```

The internal-address restriction was also explicitly disclosed.

The initial response contained:

```
Server: gunicorn
```

A request without the required URL parameter returned:

```
HTTP/1.1 400 BAD REQUEST
```

Response body:

```
only http(s) urls allowed
```

This established that the endpoint expected an HTTP or HTTPS URL.

A successful external baseline request later confirmed that the server fetched the supplied URL and returned its content.

See [[IN-01 Overview]] and [[SSRF]].

## 7. HTTP Request Construction with curl

Burp Suite is useful for intercepting and modifying HTTP traffic, but it should not be a requirement for understanding or reproducing requests.

The examination included circumstances where Burp traffic interception conflicted with VPN connectivity. Curl was therefore used to inspect and reproduce HTTP requests directly.

### 7.1 Basic request with response headers

```
curl -i 'http://x.x.x.x:PORT_I/api/download?file=welcome.txt'
```

|Parameter|Purpose|
|---|---|
|`curl`|Send an HTTP request|
|`-i`|Include response headers in the output|
|URL|Specify the target and request parameters|
|Single quotes|Prevent shell interpretation of special characters|

### 7.2 URL-encode query parameters

```
curl -i --get \
  --data-urlencode 'file=../../../../etc/passwd' \
  'http://x.x.x.x:PORT_I/api/download'
```

|Parameter|Purpose|
|---|---|
|`--get`|Place supplied data in the URL query string|
|`--data-urlencode`|Encode the parameter value|
|`\`|Continue the shell command on the next line|

### 7.3 Parameters useful during reconnaissance

|Option|Purpose|
|---|---|
|`-i`|Include response headers|
|`-sS`|Suppress progress output while still displaying errors|
|`-v`|Display connection and request details|
|`-I`|Send a HEAD request|
|`-G` / `--get`|Send supplied data in the query string|
|`--data-urlencode`|URL-encode a query parameter|
|`-H`|Add an HTTP header|
|`-b`|Send cookies|
|`-c`|Save received cookies|
|`-L`|Follow redirects|
|`-o`|Save the response body|
|`-w`|Display selected response metadata|
|`--max-time`|Set a maximum request duration|
|`--path-as-is`|Prevent curl from normalizing the URL path|

Important distinctions:

- `-i` includes response headers with the response body.
    
- `-I` sends a HEAD request.
    
- `-G` places supplied data in the URL query string.
    
- `-d` sends request-body data and should not be confused with query-string construction.
    

### 7.4 Record response metadata

For repeatable testing:

```
curl -sS --max-time 10 \
  -G \
  --data-urlencode 'url=https://example.com' \
  -w '\nHTTP=%{http_code} SIZE=%{size_download} TIME=%{time_total}s\n' \
  'http://x.x.x.x:PORT_K/fetch'
```

This provides three useful comparison values:

- HTTP status code.
    
- Response size.
    
- Total request duration.
    

These values become particularly useful when comparing normal responses, error responses, and fuzzing results.

## 8. Controlled Discovery and Response Fingerprinting

Automated discovery should begin only after the normal application behavior is understood.

Before using FFUF or another discovery tool, establish:

1. A valid response from a known resource.
    
2. A response from a deliberately nonexistent resource.
    
3. The status code, response size, and body of each.
    
4. Whether the application uses a generic error page or wildcard response.
    

### 8.1 Negative controls

A negative control is a request designed to produce a known unsuccessful result.

For example:

```
curl -sS --max-time 7 -G \
  --data-urlencode 'url=http://127.1:9000/definitely-not-a-real-route-94821' \
  -w '\nHTTP=%{http_code} SIZE=%{size_download} TIME=%{time_total}s\n' \
  'http://x.x.x.x:PORT_K/fetch'
```

The purpose is to establish what an ordinary nonexistent endpoint looks like.

Without this baseline, a scanner may report ordinary error responses as interesting discoveries.

### 8.2 Examination example: IN-01 FFUF results

After reaching the internal admin API through the SSRF functionality, a controlled list of candidate API routes was tested.

The negative-control response was:

```
HTTP=404 SIZE=207
```

The FFUF results showed the same response characteristics for all 34 tested paths:

```
Status: 404
Size:   207
Words:  27
Lines:  6
```

The initial FFUF command used:

```
-fs 90
```

That filter did not match the actual negative-control response size of 207 bytes.

Consequently, the output displayed all 34 paths, even though they produced the same generic 404 response.

**Interpretation:** These results did not establish that any of the tested routes existed.

The correct next step was to compare candidate responses against the negative control and distinguish genuine differences from generic error pages.

This is a critical reconnaissance lesson: a large number of scanner results does not necessarily mean a large number of discoveries.

### 8.3 Basic FFUF example

For a confirmed HTTP endpoint with an established response fingerprint:

```
ffuf \
  -w ~/Desktop/wordlist.txt \
  -u 'http://TARGET_IP:WEB_PORT/FUZZ' \
  -mc all \
  -of json \
  -o ~/Desktop/ffuf-results.json
```

Use response-size or other filters only after collecting a reliable baseline.

Relevant options:

|Option|Purpose|
|---|---|
|`-w`|Specify the wordlist|
|`-u`|Specify the target URL|
|`FUZZ`|Define the position replaced by each wordlist entry|
|`-mc all`|Match all HTTP status codes|
|`-fs`|Filter responses by size|
|`-fw`|Filter responses by word count|
|`-fl`|Filter responses by line count|
|`-t`|Set concurrent threads|
|`-rate`|Limit requests per second|
|`-timeout`|Set request timeout|
|`-of json`|Save results in JSON format|
|`-o`|Specify the output file|

Do not increase concurrency or wordlist size without a reason.

## 9. Reconnaissance Evidence and Documentation

Store reconnaissance output separately for each machine.

Suggested structure:

```
Evidence/
└── Reconnaissance/
    ├── nmap/
    │   ├── initial-enum.nmap
    │   ├── initial-enum.xml
    │   └── initial-enum.gnmap
    ├── http/
    │   ├── landing-page.txt
    │   └── response-headers.txt
    ├── fingerprinting/
    │   └── whatweb.txt
    └── discovery/
        └── ffuf-results.json
```

For each significant finding, preserve:

- The command or request used.
    
- The target and port.
    
- The timestamp where available.
    
- The complete relevant output.
    
- The interpretation.
    
- Whether the finding is confirmed, suspected, or inconclusive.
    
- The next action taken.
    

A useful distinction:

|Classification|Meaning|
|---|---|
|Provided|Information supplied by the Academy|
|Observed|Directly returned by the target|
|Confirmed|Reproduced and supported by evidence|
|Hypothesis|Plausible interpretation not yet verified|
|Inconclusive|Test did not establish a reliable conclusion|

Do not promote a hypothesis to a confirmed finding simply because it fits the expected attack path.

See [[Evidence Collection]].

## 10. Common Reconnaissance Mistakes

### 10.1 Scanning beyond the authorized scope

A shared public IP may expose services belonging to multiple instances or provider infrastructure.

Start with the assigned ports. Expand only when the permitted scope is clear.

### 10.2 Treating a server banner as a complete fingerprint

A `Server: gunicorn` header identifies the exposed server software, but it does not reveal every framework, dependency, or application component.

Use multiple sources of evidence.

### 10.3 Starting large wordlists without understanding the application

Large scans create noise when the endpoint, response behavior, or likely route structure is still unknown.

Start with:

- The landing page.
    
- Links and forms.
    
- Documented endpoints.
    
- Common application resources.
    
- A small hypothesis-driven candidate list.
    

Expand only when the results justify it.

### 10.4 Ignoring response-size baselines

An application may return the same generic 404 page for every nonexistent path.

Always compare fuzzing output against a deliberately nonexistent endpoint.

### 10.5 Confusing external and internal attack surfaces

The public target's Nmap results describe externally exposed services.

They do not automatically reveal services bound to localhost or otherwise inaccessible from outside the target.

IN-01 demonstrated this distinction: the externally exposed web application provided a URL-fetching function that subsequently reached an internal service on port 9000.

The internal-service investigation belongs to [[SSRF]].

### 10.6 Using stale instance information

Restarting a machine may change its externally assigned ports.

Always update the target variables and notes before resuming enumeration.

## 11. Reconnaissance Completion Criteria

Initial reconnaissance is complete when the following information is available:

- Current target IP and assigned ports recorded.
    
- Authorized scanning scope established.
    
- Exposed services identified.
    
- Service and version information collected where possible.
    
- Web application fingerprint recorded.
    
- Main page and exposed functionality inspected.
    
- Relevant endpoints and parameters identified.
    
- Authentication requirements and restrictions recorded.
    
- Baseline responses captured.
    
- Negative-control responses captured where automated discovery is used.
    
- Findings classified as provided, observed, confirmed, suspected, or inconclusive.
    
- Evidence saved and linked to the machine documentation.
    

Once these criteria are satisfied, move to the relevant specialized enumeration workflow.

## 12. Related Notes

### Machine Documentation

- [[VE-01 Overview]]
    
- [[EA-01 Overview]]
    
- [[ME-01 Overview]]
    
- [[HA-01 Overview]]
    
- [[IN-01 Overview]]
    

### Methodology

- [[Web Enumeration]]
    
- [[SSRF]]
    
- [[Initial Access]]
    
- [[Evidence Collection]]
    

### Difficulties and Lessons

- [[Network and ISP Restrictions]]
    
- [[VPN Routing and Reverse Shells]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Fuzzing Strategy and False Leads]]
    

