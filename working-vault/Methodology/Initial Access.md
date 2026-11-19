---
type: methodology
project: OSCP-Exam-PoC
status: drafted
updated: "2026-11-07"
tags:
  - methodology
  - initial-access
  - oscp
---

# Initial Access

> [!warning] Reconstructed document
> The original Initial Access note is missing, and this file previously held a duplicate copy of [[Methodology/Deserialization]]. This note was rebuilt on 2026-11-07 from the machine overview and user-foothold records, the other methodology notes and the reusable PoCs in this vault. It is a synthesis of those records, not recovered original material. Statements about a machine point to the record that supports them; anything not taken from a record is labelled general methodology.

## 1. Purpose

This note describes how initial access was obtained on each examination machine, how the resulting execution identity was established, and what the records do and do not preserve about each step.

Privilege escalation is outside its scope; see [[Methodology/Linux Privilege Escalation]].

## 2. Initial-Access Workflow

**General methodology.** The steps below are general guidance consistent with the lessons recorded in section 5. They are not a record of what was done on any one machine.

1. Map the exposed interface and its inputs ([[Methodology/Reconnaissance]], [[Methodology/Web Enumeration]]).
2. Identify the vulnerability class from the application's behavior and keep each test minimal.
3. Demonstrate the primitive with an observable result before building on it. Returned command output is stronger evidence than an upload or request success message.
4. Record the execution identity (`id`, `whoami` or equivalent) at the moment access is obtained.
5. Treat recovered credentials as candidates until authentication succeeds.
6. Retrieve the user-level objective evidence and record what was and was not preserved ([[Methodology/Evidence Collection]]).
7. Stop at the user-level objective and keep privilege escalation in its own record.

## 3. Initial Access by Machine

The table summarizes the machine records. Each row is supported by the linked notes.

| Machine | Technique | Identity at initial access | Evidence and limits | Records |
|---|---|---|---|---|
| VE-01 | File upload vulnerability: a PHP file was uploaded and executed by the server, giving command execution through the uploaded file | `www-data` | Execution was established by the returned output of a `pwd` request. The complete upload request, the server's validation logic and the exact bypass of the upload restrictions are not preserved in the examination record. | [[Difficulty Levels/Very Easy/VE-01/VE-01 Overview]], [[Difficulty Levels/Very Easy/VE-01/user]] |
| EA-01 | UNION-based SQL injection in the search parameter `q`, using SQLite; recovered credentials were then used over SSH | `robert` | MySQL/MariaDB syntax was tried first and failed before SQLite was identified. The `robert` credential was accepted over SSH. | [[Difficulty Levels/Easy/EA-01/EA-01 Overview]], [[Difficulty Levels/Easy/EA-01/user]] |
| ME-01 | Path traversal in a download endpoint (arbitrary file read), then `/proc` inspection, source-code disclosure and recovery of the API key from `config.py`, then OS command injection in the authenticated diagnostics endpoint | `svc` (UID 1000) | Identity was established by `id` output. The `GPG_KEY` environment variable was tested as the API key and rejected on the strength of the source code. A reported ISP restriction led to `curl` being used instead of Burp Suite; its cause was not proven. The user flag was obtained and submitted (participant-confirmed). | [[Difficulty Levels/Medium/ME-01/ME-01 Overview]], [[Difficulty Levels/Medium/ME-01/user]] |
| HA-01 | Unauthenticated Redis administration: the persistence directory and file were changed at runtime and an RDB save wrote a padded public key into the SSH account's authorized keys | `devops` over SSH | The private key stayed on the attacking machine. The original `id` output and SSH banner at first login are not available as raw artifacts. The user flag was obtained and submitted (participant-confirmed). A flag-formatted value found in Redis was a canary, not the user flag. | [[Difficulty Levels/Hard/HA-01/HA-01 Overview]], [[Difficulty Levels/Hard/HA-01/user]], [[Reusable PoCs/Redis/Redis Persistence]] |
| IN-01 | SSRF through the public `/fetch` parameter: alternative loopback representations passed the address filter, reaching an internal admin API; its `/admin/exec` endpoint accepted a Base64 `data` parameter that was deserialized with Python Pickle | `web` | Remote code execution was confirmed by command output. Reverse-shell callbacks did not work, so execution continued in-band. The user flag was obtained and submitted (participant-confirmed); the retrieval command is documented. | [[Difficulty Levels/Insane/IN-01/IN-01 Overview]], [[Difficulty Levels/Insane/IN-01/user]], [[Reusable PoCs/SSRF/SSRF Filter Bypass]], [[Reusable PoCs/Python Pickle/Python Pickle RCE]] |

The identity matters for the next phase. On VE-01 the first command execution ran as `www-data`, not as the account `user`, whose home directory holds the user flag ([[Difficulty Levels/Very Easy/VE-01/user]], section 8.5).

## 4. Techniques and Their Detailed Notes

| Technique | Detailed note |
|---|---|
| Reconnaissance and request construction | [[Methodology/Reconnaissance]] |
| File upload, path traversal, SQL injection, source and configuration inspection | [[Methodology/Web Enumeration]] |
| SSRF filter bypass and internal service discovery | [[Methodology/SSRF]], [[Reusable PoCs/SSRF/SSRF Filter Bypass]] |
| Python Pickle deserialization | [[Methodology/Deserialization]], [[Reusable PoCs/Python Pickle/Python Pickle RCE]] |
| Redis persistence abuse | [[Reusable PoCs/Redis/Redis Persistence]] |

## 5. Lessons Recorded in the Machine Notes

These lessons are taken from the user-foothold records, with the section that holds each one.

- A successful file upload does not prove remote command execution; the returned output of a command does (VE-01, section 8.1).
- An interactive shell is not required when an in-band execution channel is sufficient (VE-01, section 8.2). On IN-01 the reverse-shell callbacks failed and the in-band channel remained reliable (section 13.5).
- Do not persist with the wrong database syntax; failed queries can justify switching to another engine's enumeration (EA-01, section 10, item 2).
- Treat recovered credentials as candidates until authentication succeeds (EA-01, section 10, item 5).
- A file-download feature can become an arbitrary-file-read primitive when the path is not contained (ME-01, section 14, item 2).
- A runtime variable is not necessarily the application secret; the source identified `config.API_KEY` and not `GPG_KEY` (ME-01, section 14, item 4).
- Evaluate authentication separately from input handling; a 401 response meant the injection test had not reached the vulnerable code (ME-01, section 14, item 6).
- Do not treat a flag-formatted value as proof of completion; validate its context (HA-01, section 3).
- Response bodies and error messages can fingerprint the processing sequence even when the status code is unhelpful (IN-01, sections 13.1 and 13.4).
- Move from path fuzzing to parameter fuzzing when the evidence changes (IN-01, section 13.3; see also [[Difficulties & Lessons/Fuzzing Strategy and False Leads]]).

## 6. Evidence Gaps Relevant to Initial Access

Evidence classes are defined in [[Methodology/Evidence Collection]].

| Machine | Not preserved in the examination record |
|---|---|
| VE-01 | Complete upload request, validation logic and exact upload bypass; raw flag output |
| ME-01 | Raw user-flag response |
| HA-01 | SSH banner and raw `id` output at first login; raw user-flag output |
| IN-01 | Returned user-flag content |

EA-01 records its user flag in the user note.

## 7. Completion Criteria

**General methodology.** Initial access is documented when:

- the primitive is demonstrated by observable output;
- the execution identity is recorded;
- the user-level objective evidence is recorded, or its absence is stated;
- the technique is linked to its machine record and, where one exists, its reusable PoC.

## 8. Related Notes

- [[Dashboard]]
- [[Methodology/Reconnaissance]]
- [[Methodology/Web Enumeration]]
- [[Methodology/SSRF]]
- [[Methodology/Deserialization]]
- [[Methodology/Evidence Collection]]
- [[Methodology/Linux Privilege Escalation]]
- [[Difficulty Levels/Very Easy/VE-01/VE-01 Overview]]
- [[Difficulty Levels/Easy/EA-01/EA-01 Overview]]
- [[Difficulty Levels/Medium/ME-01/ME-01 Overview]]
- [[Difficulty Levels/Hard/HA-01/HA-01 Overview]]
- [[Difficulty Levels/Insane/IN-01/IN-01 Overview]]
- [[Difficulties & Lessons/Network and ISP Restrictions]]
- [[Difficulties & Lessons/VPN Routing and Reverse Shells]]
