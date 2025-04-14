---
title: ATT&CK - Discovery Phase
description: Introduce post-compromise attack behaviors and EDR defenses
author: Chris Gerritz, Datto
created: 04/07/2025
achievements:
duration: 15
range:
- Windows
applications:
- Terminal (Command prompt)
- PowerShell
- Datto EDR
- SysInternals
- Office
- Adobe Reader
external:
- attack.mitre.org
- rightofboom.infocyte.com
- 
---

## Description

The purpose of these labs is to introduce post-compromise attack behaviors and EDR defenses. We will perform post-compromise behaviors that an attacker would run once they compromised a system within the network.  This system has Datto EDR installed for monitoring so we will be able to view these commands from the defender's perspective as well.

Lab 3 will explore the Discovery phase of an attack. This phase is usually right after the attacker gains remote access to at least one beachhead system within the network and may continue to be revisited on new systems following lateral movement. Attackers generally don't know who they compromised so they need to run a series of recon to find out what they won.

Things the attacker might want to know are:

- Who owns the compromised system? Are they an administrator?
- Is this a server or workstation? What operating system?
- What is the role of this system? Does it have data worth stealing?
- What company is this? (this will determine how much bitcoin they can ransom them for)


<!--
The virtual machine has some dummy users and software to mimic a specific type of workstation that might be found in a business enviroment:

Dummy users:
- Joe from Accounting: 
  - `net user joe Password1! /ADD /FULLNAME:"Joe - Accounting'`
- Samson from Accounting
  - `net user samson Password1! /ADD /FULLNAME:"Samson - Accounting'`
- Brenda from IT
  - `net user brenda Password1! /ADD /FULLNAME:"Brenda - IT Helpdesk'`

Add some dummy software that might be found on an accountant's workstation:
- Office
- Adobe Reader
-->

---

## Objectives
<!--
- List all objectives for this lab
- Need at least three objectives
- Use blooms taxonomy verbs: KNOWLEDGE,UNDERSTAND, APPLY, ANALYZE, EVALUATE, CREATE
- https://www.teachthought.com/critical-thinking/blooms-taxonomy-verbs-2/
-->
1. Understand the Discovery phase activities an attacker might utilize
2. Demonstrate Discovery task skills to discover what type of system you are working on and what users are available to target
   

## Requirements

|                  |                             |
|------------------|-----------------------------|
| **Range**        | Windows |
| **Applications** | All applications needed     |
| **Needed Files** | None |


## Preparation Instructions

Ignore this if you already ran it in a previous lab and are re-using the same Powershell window.

1. Open powershell as an administrator
	- Right click Powershell
	- Click "Run as Administrator"
2. Prepare the enviroment with some variables we will use later
	- Run the following:
	```PowerShell
	#Define a random number (This will be used to force Datto EDR not to deduplicate repeated commands during testing)
	$n = 1000+$(Get-Random -Max 999)
	# Bypass signed script controls
	Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass
	```


## Instructions

For each of these labs, you will need your Powershell window open. You can use the same window for all labs. You will be copying and pasting commands into the terminal and then evaluating the output.

w> All labs require you to be running as an administrator. 


### 1. System Information Discovery
> *When an adversary first gains access to a system, they often gather detailed information about the compromised system and network including users, operating system, hardware, patches, and architecture. Adversaries may use the information to shape follow-on behaviors, including whether or not to fully infect the target and/or attempt specific actions like a ransom.*
> 

Perform **System Information Discovery** 
- MITRE ATT&CK Technique: [ATT&CK T1082 - Discovery - System Information Discovery](https://attack.mitre.org/techniques/T1082)
- Copy and paste this command into the terminal:
	```PowerShell
	# Powershell Download Hardness
	Write-Host -ForegroundColor Cyan "Initiating techniques T1082 - System Information Discovery"
	$outputFile = "$env:USERPROFILE\desktop\recon.txt"
	$cmd = @"
		'==== Hostname ====' > $outputFile
		Hostname >> $outputFile
		'' >> $outputFile
		'==== Whoami ====' >> $outputFile
		whoami >> $outputFile
		'' >> $outputFile
		'==== MachineGuid (best unique id to use) ====' >> $outputFile
		REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid >> $outputFile
		'' >> $outputFile
		'==== System Info ====' >> $outputFile
		Systeminfo >> $outputFile
		'' >> $outputFile
		'==== Antivirus Product ====' >> $outputFile
		WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,pathToSignedProductExe,pathToSignedReportingExe,productState 2>&1 >> $outputFile
		'' >> $outputFile
		'==== Terminal Services Remote Host List (who has this system remoted into?) ====' >> $outputFile
		reg query 'HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default' 2>&1 >> $outputFile
		'' >> $outputFile
		'==== Local Accounts ====' >> $outputFile
		net user 2>&1 >> $outputFile
		'' >> $outputFile
		'==== Local Administrators ====' >> $outputFile
		net localgroup administrators 2>&1 >> $outputFile 
		'' >> $outputFile
		'==== Domain Administrators ====' >> $outputFile
		net group 'domain admins' /domain 2>&1 >> $outputFile 
		'' >> $outputFile
		'==== Exchange Administrators ====' >> $outputFile
		net group 'Exchange Trusted Subsystem' /domain 2>&1 >> $outputFile  
		'' >> $outputFile
		'==== Installed Software ====' >> $outputFile
		Get-WmiObject -Class Win32_Product | select Name, Vendor, Version | Sort-Object Vendor, Name | ft -auto >> $outputFile
		Start-Sleep -m $n
	"@
	Powershell.exe -nop -command $cmd
	Get-Item $outputFile
	```
