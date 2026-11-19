---
type: difficulty-lesson
project: OSCP-Exam-PoC
status: documented
updated: "2026-11-07"
related_machines:
  - ME-01
  - IN-01
tags:
  - oscp
  - http
  - curl
  - burp
  - url-encoding
  - troubleshooting
---
# HTTP Client and Connectivity Failures

## 1. Summary

Several examination steps involved distinguishing HTTP-client behavior from application behavior and transport failures.

The main issues were:

- Confusion between displaying an HTTP response and downloading it to disk.
    
- Incorrectly encoded nested query parameters.
    
- Upstream timeouts and HTTP 502 responses.
    
- Treating an HTTP status code as proof that the intended operation succeeded.
    
- Receiving binary output where the response wrapper expected UTF-8 text.
    
- Using misleading script messages that reported success without checking the HTTP response.
    

## 2. Choosing the HTTP Client

Both Burp Suite and `curl` are useful. They serve different workflows.

|Tool|Appropriate use|
|---|---|
|Burp Proxy|Capture browser-generated HTTP requests and inspect their structure.|
|Burp Repeater|Modify and replay requests interactively.|
|curl|Reproduce requests directly from the terminal.|
|curl scripts|Automate repeatable HTTP tests and parameter variations.|

During ME-01, Burp was initially considered for path-traversal testing. However, the investigation continued with `curl` so that requests could be reproduced, automated, and understood at the command-line level.

**Lesson:** Do not make the workflow dependent on one HTTP client. Choose the tool according to the task, and understand the actual HTTP request regardless of which tool generates it.

## 3. curl: Response Display vs File Download

An important distinction arose during ME-01.

### Display the response

```
curl -i 'http://TARGET/api/download?file=welcome.txt'
```

`-i` includes the response headers in terminal output. The response body is also printed to the terminal.

It does not save the response to disk.

### Save the response

```
curl -o welcome.txt 'http://TARGET/api/download?file=welcome.txt'
```

- `-o`: Save the response to the specified local filename.
    
- `-O`: Save using a filename derived from the URL.
    
- `-OJ`: Save using the filename supplied through the server's `Content-Disposition` header.
    

### Why the browser downloaded `/etc/passwd`

The browser received an HTTP response containing:

```
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="passwd"
```

The `Content-Disposition: attachment` header instructs the browser to treat the response as a downloadable file.

The browser was downloading the server's returned copy of `/etc/passwd`, not accessing the local filesystem of the attacking machine.

**Lesson:** Inspect `Content-Type` and `Content-Disposition` before deciding whether a response is being displayed or downloaded.

## 4. GET Parameters and URL Encoding

A recurring request pattern used during ME-01 and IN-01 was:

```
curl -i --get \
  --data-urlencode 'file=../../../../etc/passwd' \
  'http://TARGET/api/download'
```

Relevant options:

|Option|Purpose|
|---|---|
|`-i`|Include response headers.|
|`-G` / `--get`|Put supplied data parameters into the GET query string.|
|`--data-urlencode`|URL-encode the parameter and its value.|
|`-sS`|Suppress progress output while retaining error messages.|
|`--max-time`|Set the maximum duration of the request.|
|`-w`|Print selected transfer information, such as HTTP status and elapsed time.|

For example, the traversal value:

```
../../../../etc/passwd
```

is transmitted in encoded form:

```
..%2F..%2F..%2F..%2Fetc%2Fpasswd
```

This is useful when parameter values contain characters that have special meanings in URLs.

## 5. Nested URL-Encoding Failure

### IN-01 incident

The internal API accepted a Base64-encoded serialized payload through a nested query parameter:

```
http://127.1:9000/admin/exec?data=BASE64_VALUE
```

The outer SSRF endpoint received that entire URL through its own `url` parameter.

The first implementation encoded the outer `url` parameter but did not independently encode the nested `data` value.

This corrupted Base64 values containing:

- `+`
    
- `/`
    
- `=`
    

In particular, a `+` in a query parameter can be interpreted as a space when parsed as form-style query data.

The application consequently returned:

```
error: Invalid base64-encoded string
```

### Correction

Encode the inner value first:

```
ENC_DATA=$(DATA="$DATA" python3 -c \
'import os; from urllib.parse import quote; print(quote(os.environ["DATA"], safe=""))')
```

Construct the internal URL using the encoded value:

```
INTERNAL_URL="http://127.1:9000/admin/exec?data=${ENC_DATA}"
```

Then encode the complete internal URL as the outer parameter:

```
curl -sS --max-time 20 -G \
  --data-urlencode "url=${INTERNAL_URL}" \
  'http://TARGET/fetch'
```

**The encoding order matters:**

1. Generate the Base64 value.
    
2. URL-encode the nested `data` value.
    
3. Construct the internal URL.
    
4. URL-encode the complete internal URL as the outer `url` parameter.
    
5. Send the request.
    

Encoding the outer parameter does not replace the need to encode an inner query parameter before constructing the nested URL.

## 6. Interpreting HTTP Errors and Timeouts

### HTTP 502 with an SSH banner

During IN-01, requesting internal port 22 through the SSRF endpoint returned:

```
HTTP/1.1 502 BAD GATEWAY
```

The response body contained:

```
BadStatusLine('SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4')
```

This was not evidence that the SSH service was unavailable.

The fetcher reached an SSH service but attempted to interpret its response as HTTP. The protocol mismatch caused the upstream request to fail.

### HTTP 502 with a read timeout

Internal port 8080 returned:

```
HTTPConnectionPool(host='127.1', port=8080):
Read timed out. (read timeout=4)
```

This differs from connection refusal.

A read timeout means the client did not receive response data within the configured read-timeout period. In this investigation, the result was treated as evidence that the internal service was accepting connections but not providing a timely HTTP response.

It did not establish that the service was absent or that a particular endpoint existed.

### HTTP 302 with an empty body

The public redirect test returned a redirect response with an empty body. The fetcher appeared to return the redirect response rather than follow it.

The status alone was insufficient to establish whether the redirect reached its destination. The `Location` header and the fetcher's redirect behavior had to be examined.

### HTTP 200 is not proof of success

A `200 OK` response establishes that an HTTP response was returned. It does not automatically establish that:

- The intended internal resource was reached.
    
- The requested command executed.
    
- The application accepted the payload.
    
- A reverse-shell callback was established.
    

Inspect the response body and application-level output.

An asynchronous reverse-shell payload may return an HTTP response without producing an interactive session. Confirm the callback separately through the listener.

See [[VPN Routing and Reverse Shells]] for the callback failures and routing investigation.

### HTTP 000 and curl timeouts

When curl reports an HTTP status of `000`, it did not receive a final HTTP response code.

Inspect the curl error message and timing information rather than treating `000` as a server-generated status.

The distinction between connection establishment, response waiting, and an actual HTTP error is important. ISP interception and external routing incidents are documented separately in [[Network and ISP Restrictions]].

## 7. Binary Output and Response Decoding

During IN-01, a remote command produced output that could not be decoded as UTF-8:

```
error: 'utf-8' codec can't decode byte 0x98 in position 812:
invalid start byte
```

The execution wrapper expected text, but the returned output contained bytes outside valid UTF-8.

The initial response was not sufficient to determine whether the remote command had failed. The output transport itself was unsuitable for arbitrary binary data.

A subsequent wrapper attempted to Base64-encode remote output before returning it. However, the first decoding attempt then failed:

```
base64: invalid input
```

The assumption that the HTTP response contained only a Base64 string had not been verified.

### Lesson

When transporting arbitrary command output through an HTTP response:

1. Encode the remote output before returning it.
    
2. Inspect the raw HTTP response and confirm its format.
    
3. Extract the encoded data without including unrelated response content.
    
4. Decode only after validating the extracted value.
    

Do not assume that a failed local decoding operation proves remote command execution failed.

## 8. Script Reporting Must Reflect Actual Results

An earlier reverse-shell script printed:

```
[+] Payload submitted.
```

even when the application had returned HTTP 400.

This was misleading because the message described an assumed outcome rather than the observed HTTP result.

The corrected request included:

```
-w '\n[HTTP %{http_code} | TIME %{time_total}s]\n'
```

This exposed the HTTP status and request duration.

**Rule:** Scripts must distinguish between:

- Payload generated.
    
- HTTP request sent.
    
- HTTP response received.
    
- Application accepted the input.
    
- Requested operation completed.
    
- Expected callback or session established.
    

Do not report a later-stage success based only on an earlier-stage event.

## 9. Practical Checklist

Before treating an HTTP request as successful, verify:

- The command executed locally without shell or PATH errors.
    
- The request method and query parameters are correct.
    
- Nested query parameters are encoded independently.
    
- The expected target URL and port are being used.
    
- The HTTP status is recorded.
    
- Response headers and body are inspected.
    
- Timeout and protocol errors are distinguished from HTTP responses.
    
- Output decoding matches the actual response format.
    
- The intended application-level result is independently confirmed.
    

## Related Notes

- [[Network and ISP Restrictions]]
    
- [[VPN Routing and Reverse Shells]]
    
- [[Kali PATH and Zsh Issues]]
    
- [[Fuzzing Strategy and False Leads]]