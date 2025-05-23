---
Title: Triaging with EDR
Description: Introduce post-compromise attack behaviors and EDR defenses
Author: Chris Gerritz, Datto
Created: 04/17/2025
Achievements:
Duration: 40
Range:
- None
Applications:
- Browser
- Datto EDR
External:
- allitshop.infocyte.com
- 
---

## Description

The purpose of these labs is to introduce post-compromise attack behaviors and EDR defenses. 

This next section will have us log into the Datto EDR console and review the attack behaviors we just conducted from the defender's point of view.

EDR is not perfect so we have to temper our expectations. A Windows host is buzzing with millions of internal, hidden events every minute. EDR, as a technology, has to be specific on what events to capture and to what level of detail. Process information we will review today is one of the most effective sources of information, especially for attacks involving malicious behaviors of known good operating systems utilities.


## Objectives
<!--
- List all objectives for this lab
- Need at least three objectives
- Use blooms taxonomy verbs 
-->
1. Understand the role of EDR in monitoring networks and attacker behaviors
2. Understand the difference between malware and behaviors
3. Demonstrate triage of alerts related to a potential attack
   

## Requirements

|                  |                             |
|------------------|-----------------------------|
| **Range**        | None |
| **Applications** | Browser |
| **Needed Files** | None |


## Instructions

1. In another browser window (outside the lab enviroment), log into the Datto EDR console:
   - https://allitshop.infocyte.com
   - We will go through the data we collected together

