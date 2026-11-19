---
type: exam-overview
project: OSCP-Exam-PoC
status: completed
documentation: in-progress
created: "2026-11-05"
updated: "2026-11-07"
tags:
  - penetration-testing
  - exam
  - overview
  - documentation
---

# Exam Overview

> **Examination result:** All five machines completed. User and root flags obtained and submitted on every machine (confirmed by the examination participant). All public flag values display as `IT{FLAG-SECRET}`.

## 1. Examination Description

This project documents a multi-level penetration-testing examination consisting of five independent targets, organized by increasing difficulty.

Each target requires two objectives:

1. Obtain initial access and retrieve the `user.txt` flag.
    
2. Escalate privileges and retrieve the `root.txt` flag.
    

The examination progresses through five difficulty levels:

- Very Easy
    
- Easy
    
- Medium
    
- Hard
    
- Insane
    

The purpose of this documentation is to preserve the complete technical process, including reconnaissance, enumeration, exploitation, privilege escalation, troubleshooting, failed attempts, successful techniques, and supporting evidence.

## 2. Examination Structure

|Difficulty|Machine ID|Objectives|
|---|---|---|
|Very Easy|VE-01|User + Root|
|Easy|EA-01|User + Root|
|Medium|ME-01|User + Root|
|Hard|HA-01|User + Root|
|Insane|IN-01|User + Root|

### Machine Documentation

|Machine|Overview|User|Root|
|---|---|---|---|
|VE-01|[[Difficulty Levels/Very Easy/VE-01/VE-01 Overview]]|[[Difficulty Levels/Very Easy/VE-01/user]]|[[Difficulty Levels/Very Easy/VE-01/root]]|
|EA-01|[[EA-01 Overview]]|[[Difficulty Levels/Easy/EA-01/user]]|[[Difficulty Levels/Easy/EA-01/root]]|
|ME-01|[[Difficulty Levels/Medium/ME-01/ME-01 Overview]]|[[Difficulty Levels/Medium/ME-01/user]]|[[Difficulty Levels/Medium/ME-01/root]]|
|HA-01|[[Difficulty Levels/Hard/HA-01/HA-01 Overview]]|[[Difficulty Levels/Hard/HA-01/user]]|[[Difficulty Levels/Hard/HA-01/root]]|
|IN-01|[[Difficulty Levels/Insane/IN-01/IN-01 Overview]]|[[Difficulty Levels/Insane/IN-01/user]]|[[Difficulty Levels/Insane/IN-01/root]]|

## 3. Examination Objectives

### User-Level Objective

Establish an initial foothold through the vulnerability or attack path exposed by the target.

Required documentation:

- Target reconnaissance.
    
- Service enumeration.
    
- Vulnerability identification.
    
- Exploitation methodology.
    
- Initial execution context.
    
- User-level access.
    
- `user.txt` retrieval.
    
- Evidence supporting the findings.
    

### Root-Level Objective

Escalate privileges from the initial foothold to root.

Required documentation:

- Local enumeration.
    
- Privilege-escalation vector.
    
- Identification of the vulnerable configuration or component.
    
- Exploitation methodology.
    
- Verification of root privileges.
    
- `root.txt` retrieval.
    
- Evidence supporting the findings.
    

## 4. Assessment Scope

The examination involved isolated, disposable laboratory instances.

The observed network architecture used externally forwarded ports to expose services running inside the laboratory environment.

The same public IP address was observed across different instances, while the assigned HTTP and SSH ports changed.

Therefore:

- Instance-specific ports must be recorded separately.
    
- Old port mappings must not be assumed valid after a reset.
    
- Internal service addresses must be distinguished from externally accessible addresses.
    
- Findings must be associated with the correct machine instance.
    

## 5. Technical Environment

### Attacker Platform

|Component|Description|
|---|---|
|Operating System|Kali Linux|
|Shell|Zsh|
|Primary scripting language|Python|
|Network enumeration|Nmap|
|Web enumeration|curl, WhatWeb|
|Fuzzing|FFUF|
|Network listeners|Netcat|
|Compilation|GCC|
|Data processing|jq|
|Documentation|Obsidian|

### Network Environment

Two VPN interfaces were observed during the examination:

|Interface|Observed Address|
|---|---|
|tun0|`10.10.17.123`|
|tun1|`10.144.220.24`|

These addresses are historical observations, not guaranteed permanent assignments.

## 6. Documentation Methodology

Every machine will be documented through three interconnected records.

### Machine Overview

Contains:

- Target description.
    
- Difficulty.
    
- Environment information.
    
- Initial attack-surface summary.
    
- Attack-chain summary.
    
- Important discoveries.
    
- Links to user and root documentation.
    

### User Documentation

Contains the complete initial-access process, from reconnaissance to the retrieval of `user.txt`.

### Root Documentation

Contains the privilege-escalation process, from local enumeration to the retrieval of `root.txt`.

### Evidence Preservation

Important findings should include:

|Evidence Type|Examples|
|---|---|
|Commands|Exact commands used during testing|
|Terminal output|Actual responses and execution results|
|Screenshots|Relevant terminal or application screenshots|
|Requests|HTTP requests, parameters, headers and responses|
|Files|Scripts, payloads, configurations and binaries|
|Notes|Interpretation, hypotheses and troubleshooting|

A finding must be classified appropriately:

- **Confirmed:** Directly demonstrated by output or successful exploitation.
    
- **Observed:** Directly observed, but its security significance is not yet established.
    
- **Hypothesis:** A possible explanation requiring further testing.
    
- **Rejected:** Tested and found not to explain the behavior.
    
- **Unverified:** Reported or inferred but lacking sufficient retained evidence.
    

## 7. Examination-Wide Lessons

The examination demonstrated that successful exploitation is not solely a matter of identifying vulnerabilities.

Other factors affected the investigation:

1. Network connectivity and application availability.
    
2. VPN interface selection and callback routing.
    
3. Shell configuration and environment integrity.
    
4. Fuzzing strategy and response interpretation.
    
5. Nested URL and payload encoding.
    
6. Choosing between interactive reverse shells and in-band execution.
    
7. Preserving evidence and distinguishing confirmed findings from assumptions.
    

These topics are documented separately under [[Difficulties & Lessons/Network and ISP Restrictions]], [[Difficulties & Lessons/VPN Routing and Reverse Shells]], [[Difficulties & Lessons/Kali PATH and Zsh Issues]], and related troubleshooting notes.

## 8. Final Documentation Objective

The final repository should serve as:

- A historical record of the examination.
    
- A reproducible technical walkthrough.
    
- A repository of reusable exploitation techniques.
    
- A collection of tested proof-of-concept scripts.
    
- A troubleshooting reference.
    
- A foundation for future penetration-testing engagements.
    

The emphasis is on understanding the complete attack chain, explaining why each technique worked, preserving supporting evidence, and identifying where the methodology can be improved.

---

**Project status:** Examination completed. Documentation and evidence organization in progress.