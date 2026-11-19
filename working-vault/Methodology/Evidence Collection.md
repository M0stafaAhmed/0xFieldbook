---
type: methodology
project: OSCP-Exam-PoC
status: drafted
updated: "2026-11-07"
tags:
  - methodology
  - evidence-collection
  - documentation
  - oscp
---

# Evidence Collection

## 1. Purpose

Preserve the technical evidence from the examination in a clear, reproducible format.

The preserved examination record is the primary and only available PoC record. It contains the commands, requests, responses, discoveries, failures, and successful exploitation results.

No separate screenshots, packet captures, terminal recordings, or external evidence archives are assumed to exist.

The goal is to preserve what actually happened without creating unnecessary documentation overhead.

## 2. What to Preserve

For each machine, document the following where available:

|Stage|Information|
|---|---|
|Reconnaissance|Commands, discovered ports, services and versions|
|Enumeration|Requests, parameters, paths, configurations and useful responses|
|Initial Access|Vulnerability, exploitation command, response and execution identity|
|User Objective|User flag retrieval and submission confirmation|
|Privilege Escalation|Enumeration results, identified weakness and exploit|
|Root Objective|Root execution verification and flag submission confirmation|
|Failed Attempts|Relevant errors, unsuccessful payloads and reasons for changing direction|

Do not preserve every ordinary command or repetitive response. Keep the information that explains the attack chain and supports its conclusions.

## 3. Evidence Representation

Use the actual command and output in the relevant Markdown file.

Example:

### Finding: Command Execution

**Status:** Confirmed

**Command:**

```
id
```

**Observed output:**

```
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

**Conclusion:**

Remote command execution was established as the `svc` account.

This is sufficient documentation for the finding. There is no requirement to produce an additional screenshot or export.

## 4. Finding Status

Use four simple statuses consistently:

|Status|Meaning|
|---|---|
|`Confirmed`|Successfully demonstrated with recorded output|
|`Attempted`|Tested, but the intended result was not achieved|
|`Hypothesis`|Suspected explanation that was not verified|
|`Not Recorded`|The available examination record does not preserve enough evidence|

Do not describe a suspected vulnerability as successfully exploited.

Do not invent missing command output, credentials, timestamps, or flag values.

## 5. Evidence Organization

Keep the existing machine structure:

```
OSCP-Exam-PoC/
└── Difficulty Levels/
    ├── Very Easy/
    │   └── VE-01/
    │       ├── VE-01 Overview.md
    │       ├── user.md
    │       ├── root.md
    │       └── Evidence/
    ├── Easy/
    │   └── EA-01/
    ├── Medium/
    │   └── ME-01/
    ├── Hard/
    │   └── HA-01/
    └── Insane/
        └── IN-01/
```

The three Markdown files for each machine are the main documentation:

- `Overview.md`: machine summary and attack-chain overview.
    
- `user.md`: reconnaissance, initial access and user objective.
    
- `root.md`: privilege-escalation investigation and root objective.
    

The `Evidence/` folders can remain empty for now. They are available for additional artifacts should any become available later.

Do not create placeholder files or empty evidence indexes just to populate those folders.

## 6. Documentation Rules

1. Use recorded commands and outputs from the examination.
    
2. Preserve technically important errors and failed attempts.
    
3. Keep initial access and privilege escalation separate.
    
4. Distinguish confirmed results from hypotheses.
    
5. Preserve the actual execution identity and privilege level.
    
6. Record whether each objective was successfully submitted when that information is available.
    
7. Redact sensitive credentials from general-purpose documentation where appropriate.
    
8. Do not fabricate evidence to fill documentation gaps.
    

## 7. Completion Criteria

- Each machine's actual attack chain is documented.
    
- Important commands and outputs are preserved.
    
- User and root exploitation are documented separately.
    
- Successful and failed techniques are distinguished.
    
- Findings have accurate verification statuses.
    
- Missing evidence is explicitly identified rather than invented.
    

## 8. Related Notes

- [[Reconnaissance]]
    
- [[Web Enumeration]]
    
- [[Initial Access]]
    
- [[Linux Privilege Escalation]]
    
- [[Exam Timeline]]
    
- [[VE-01 Overview]]
    
- [[EA-01 Overview]]
    
- [[ME-01 Overview]]
    
- [[HA-01 Overview]]
    
- [[IN-01 Overview]]