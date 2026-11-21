---
type: difficulty-lesson
project: OSCP-Exam-PoC
status: documented
updated: "2026-11-07"
related_machines:
  - IN-01
tags:
  - oscp
  - ffuf
  - fuzzing
  - wordlists
  - api-enumeration
  - false-positives
  - troubleshooting
---
# Fuzzing Strategy and False Leads

## 1. Summary

IN-01 required discovering an internal service through an SSRF vulnerability. Several initial fuzzing attempts produced little useful information because the target service, response baseline, and filtering strategy had not been established correctly.

The investigation eventually succeeded by narrowing the scope:

1. Identify a reachable internal service.
    
2. Establish its normal and nonexistent-route responses.
    
3. Use a targeted API route wordlist.
    
4. Investigate an endpoint that returned a different error.
    
5. Fuzz parameter names rather than continuing to guess endpoint paths.
    
6. Follow the changed application responses until the expected input format was identified.
    

The important lesson was not to use larger wordlists or unlimited concurrency. It was to make each scan answer a specific question.

## 2. False Lead: Directory Fuzzing Port 8080

### Initial assumption

Internal port 8080 accepted connections through the SSRF endpoint, so it was treated as a potentially useful web application.

However, requests to both:

```
http://127.1:8080/
https://127.1:8080/
```

timed out while waiting for response data.

The HTTP fetcher returned errors similar to:

```
HTTPConnectionPool(host='127.1', port=8080):
Read timed out. (read timeout=4)
```

Changing the protocol to HTTPS did not reveal a working HTTPS service.

### Wordlist scan

A directory scan was attempted using a wordlist containing more than 4,600 entries.

Observed progress:

```
227 / 4600+
220 errors
15 minutes elapsed
```

The scan was stopped.

This was an inefficient use of time because the service had not been identified as a usable HTTP application.

### Additional mistakes

**Incorrect local wordlist path**

The initial command referenced:

```
/usr/share/wordlists/dirb/common.txt
```

The available file was actually found at:

```
/usr/share/dirb/wordlists/common.txt
```

The first FFUF execution therefore failed before the scan could begin.

**Unnecessary global time limit**

An earlier command used:

```
-maxtime 60
```

This imposed a 60-second limit on the entire FFUF process.

The later parameter scan stopped because of this configured limit, not because FFUF automatically stopped after encountering individual request errors.

**Wrong service assumption**

TCP connectivity did not establish that port 8080 was serving a usable HTTP application. Repeating directory requests against an unresponsive service could not compensate for that missing information.

### Lesson

Before directory fuzzing:

- Confirm that the target responds as an HTTP service.
    
- Establish a successful baseline request.
    
- Confirm the wordlist exists and is readable.
    
- Use a small initial list.
    
- Stop when the service behavior makes the scan unproductive.
    

Do not spend 15 minutes scanning thousands of paths against a service that does not return useful HTTP responses.

## 3. Pivot: Identify the Internal Service First

The investigation moved from directory fuzzing to targeted internal port discovery.

A smaller, prioritized port list identified TCP port `9000`.

The service returned:

```
IT GATE internal admin API (localhost only)
```

This was a materially better lead than port 8080 because the service identified itself as an internal administrative API.

The confirmed SSRF path was:

<figure class="lesson-incident-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/lesson-incident-service-discovery-mobile.svg" />
    <img src="/diagrams/lesson-incident-service-discovery.svg" alt="Internal service discovery: confirmed SSRF route: Public /fetch endpoint then Internal address validation bypass then 127.1:9000 then IT GATE internal admin API." width="960" height="580" loading="lazy" decoding="async" />
  </picture>
  <figcaption>Internal service discovery: confirmed SSRF route. The full evidence and interpretive qualifications remain in the report.</figcaption>
</figure>

**Lesson:** Discovering the correct service is more valuable than exhaustively fuzzing paths on an unidentified service.

## 4. API Route Fuzzing

### 4.1 Establish a negative control

Before fuzzing the API, a deliberately nonexistent route was requested:

```
curl -sS --max-time 7 -G \
  --data-urlencode 'url=http://127.1:9000/definitely-not-a-real-route-94821' \
  -w '\nHTTP=%{http_code} SIZE=%{size_download} TIME=%{time_total}s\n' \
  "$BASE"
```

The response was:

```
HTTP=404 SIZE=207
```

This established the generic negative-response fingerprint:

|Property|Baseline|
|---|---|
|HTTP status|404|
|Response size|207 bytes|
|Words|27|
|Lines|6|

### 4.2 Initial 34-path scan

A small list of common API routes was tested, including:

```
health
healthz
status
info
version
docs
openapi.json
swagger.json
api
admin
admin/flag
admin/users
flag
user
users
config
debug
metrics
internal
robots.txt
```

All 34 candidates returned the same generic response:

```
Status: 404
Size: 207
Words: 27
Lines: 6
```

No API route was discovered.

This scan was useful because it established that ordinary route names were not producing distinguishable responses. It was not a reason to keep expanding generic directory lists indefinitely.

### 4.3 SecLists API wordlist

A dedicated API endpoint wordlist from SecLists was then used instead of another generic directory list.

The scan used FFUF automatic calibration:

```
-ac
```

The resulting JSON contained no useful matches.

Automatic calibration can filter responses that resemble its negative-response baseline. Therefore, an empty result array must not automatically be interpreted as proof that no valid endpoint exists.

The next step was to use a smaller, challenge-specific list and inspect unusual responses.

### 4.4 Targeted route discovery

A targeted list included administrative operations such as:

```
admin/exec
admin/execute
admin/command
admin/run
admin/ssh
admin/keys
admin/config
admin/secrets
internal/exec
internal/command
execute
command
shell
run
credentials
```

The scan filtered ordinary HTTP 404 responses rather than discarding all responses of a particular size.

It produced the first useful result:

```
400    23    5    .../admin/exec
```

The route returned:

```
HTTP/1.1 400 BAD REQUEST

error: Ran out of input
```

This was different from the generic 404 response.

The endpoint was therefore worth investigating further. The error suggested that a handler was receiving the request and attempting to process input.

**Lesson:** An unusual error response can be more valuable than a conventional `200 OK` response. Compare application behavior, not just status codes.

## 5. Parameter Fuzzing

Once `/admin/exec` was identified, continuing to fuzz route names was no longer the best approach.

The next hypothesis was that the handler expected a query parameter or serialized input.

A parameter-name wordlist was obtained from:

```
Discovery/Web-Content/burp-parameter-names.txt
```

The scan supplied a harmless test value and filtered the known empty-input error:

```
ffuf \
  -w "$WL":PARAM \
  -u 'http://TARGET/fetch?url=http%3A%2F%2F127.1%3A9000%2Fadmin%2Fexec%3FPARAM%3Dx' \
  -enc 'PARAM:urlencode' \
  -mc all \
  -fr 'Ran out of input' \
  -t 40 \
  -rate 0 \
  -timeout 3 \
  -of json \
  -o admin-exec-parameters.json
```

The first attempt included:

```
-maxtime 60
```

That option limited the total scan duration. Removing it allowed the scan to continue without an overall time limit while retaining the per-request timeout.

### Results

Two parameters produced responses different from the baseline:

|Parameter|Status|Size|Response interpretation|
|---|---|---|---|
|`data=x`|400|105 bytes|Input reached Base64 validation|
|`dnslocalhost=x`|403|25 bytes|Likely triggered internal-address filtering|

The `dnslocalhost` result was a false lead. A different response alone did not establish that the parameter was part of the API's intended interface.

The `data` parameter was the useful discovery.

### Validation

Testing `data=x` returned:

```
error: Invalid base64-encoded string:
number of data characters (1) cannot be 1 more than a multiple of 4
```

Testing an empty value returned:

```
error: Ran out of input
```

These errors established that the handler was Base64-decoding the supplied input before attempting to deserialize it.

A subsequent harmless serialized Python object confirmed the expected Python Pickle format.

This led to the successful Python Pickle deserialization exploit and remote command execution as:

```
uid=1000(web)
gid=1000(web)
cwd=/opt/app
```

The route and parameter discovery had therefore established the actual exploitation path.

## 6. FFUF Filtering and Scan-Control Mistakes

### 6.1 Hardcoded response-size filters

The option:

```
-fs 207
```

filters responses with a size of exactly 207 bytes.

This was useful after measuring the negative-control response on the same instance.

However, the value was reused after the lab instance changed without first checking the new baseline. This could remove useful responses or distort the scan results.

**Rule:** Never carry a response-size filter into a new instance without measuring the new negative control.

### 6.2 Automatic calibration

The option:

```
-ac
```

enables automatic calibration.

It can be useful when the target has consistent generic responses, but it can also hide interesting results when the response behavior is unusual or indistinguishable from the calibration baseline.

When the result set is unexpectedly empty:

1. Verify that FFUF completed.
    
2. Check the JSON result count.
    
3. Recheck the baseline response.
    
4. Review the active filters.
    
5. Rerun with a deliberate filter strategy.
    

Do not immediately download a larger wordlist.

### 6.3 Status filtering

The option:

```
-fc 404
```

filters responses with HTTP status 404.

This was useful for the targeted route scan because the internal API's ordinary nonexistent routes returned 404, while `/admin/exec` returned 400.

For parameter fuzzing, filtering the known error string was more appropriate:

```
-fr 'Ran out of input'
```

The filter should match the negative response being removed, not an arbitrary value selected before examining the target.

### 6.4 Per-request timeout versus total scan time

These options do different things:

|Option|Effect|
|---|---|
|`-timeout 3`|Limits the duration of an individual request.|
|`-maxtime 60`|Limits the entire FFUF process to 60 seconds.|
|`-rate 0`|Does not impose an artificial requests-per-second limit.|
|`-t 40`|Runs up to 40 concurrent requests.|

The parameter scan initially stopped because `-maxtime 60` was configured. It was not necessary to disable error handling or assume FFUF could not tolerate individual failures.

Do not confuse an individual request timeout with a global scan deadline.

## 7. Practical Fuzzing Workflow

Use this sequence for API discovery.

### Stage 1 — Establish the service

- Confirm the service responds.
    
- Identify the protocol and application where possible.
    
- Record the normal response.
    
- Record a deliberately nonexistent route.
    

### Stage 2 — Select the right wordlist

|Target|Wordlist approach|
|---|---|
|Web directories|Directory and file discovery lists|
|REST API routes|API endpoint lists|
|API query parameters|Parameter-name lists|
|Known application|Small, application-specific candidate list|

Avoid using a generic directory list when the objective is discovering API parameters.

### Stage 3 — Configure filtering

Choose a filter based on observed negative responses:

- `-fc`: HTTP status codes.
    
- `-fs`: Response sizes.
    
- `-fw`: Response word counts.
    
- `-fl`: Response line counts.
    
- `-fr`: Response-body regular expression.
    
- `-ac`: Automatic calibration.
    

Record the baseline before applying any filter.

### Stage 4 — Interpret anomalies

A response that differs from the baseline is a candidate, not a confirmed vulnerability.

Inspect it manually with `curl` or Burp Repeater.

Look for:

- Different error messages.
    
- Input-validation behavior.
    
- Required parameters.
    
- Authentication requirements.
    
- Supported HTTP methods.
    
- Serialization or parsing errors.
    

### Stage 5 — Change the fuzzing target

Once a route has been identified, stop guessing route names and investigate its input contract.

That was the decisive pivot in IN-01:

<figure class="lesson-incident-figure">
  <picture>
    <source media="(max-width: 520px)" type="image/svg+xml" srcset="/diagrams/lesson-incident-route-to-parameter-pivot-mobile.svg" />
    <img src="/diagrams/lesson-incident-route-to-parameter-pivot.svg" alt="Route-to-parameter pivot: preserve input-contract clues: Generic route fuzzing then /admin/exec then &quot;Ran out of input&quot; then Parameter fuzzing then data then Base64 decoding then Python Pickle deserialization then Remote command execution." width="960" height="780" loading="lazy" decoding="async" />
  </picture>
  <figcaption>Route-to-parameter pivot: preserve input-contract clues. The full evidence and interpretive qualifications remain in the report.</figcaption>
</figure>

## 8. Lessons

1. **Do not fuzz unidentified services blindly.** Confirm the service behavior first.
    
2. **Measure the negative baseline.** Status, response size, words, and body content matter.
    
3. **Use the wordlist that matches the attack surface.** API routes and API parameters are different targets.
    
4. **Treat empty FFUF output as an investigation result, not a conclusion.** Check calibration, filters, completion, and JSON output.
    
5. **Avoid stale filters.** A response-size baseline is specific to the instance and endpoint being tested.
    
6. **Understand FFUF timing options.** Per-request timeout and total scan duration are separate controls.
    
7. **Follow meaningful errors.** The `400` from `/admin/exec` revealed more than dozens of generic 404 responses.
    
8. **Pivot when the evidence changes.** Once the endpoint was found, parameter fuzzing was more productive than further route enumeration.
    
9. **Speed is not the same as efficiency.** Forty threads cannot make an irrelevant wordlist useful.
    
10. **Stop when the scan stops answering a useful question.** The 8080 scan was abandoned because its underlying service behavior did not justify continuing.
    

## Related Notes

- [[Web Enumeration]]
    
- [[SSRF]]
    
- [[Deserialization]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Kali PATH and Zsh Issues]]
    
- [[IN-01 Overview]]