---
title: ATT&CK - Defense Evasion Phase
description: Introduce post-compromise attack behaviors and EDR defenses
author: Chris Gerritz, Datto
created: 04/07/2025
achievements:
duration: 10
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

Lab 4 is a light touch on some Defense Evasion techniques (such as disabling antivirus or defensive products). These techniques are often layered on the other techniques and phases to help hide that activity. In any case, when it comes to EDR and continuous monitoring, oftentimes we can use the presence of these evasion techniques as detection or confirmation that the user performing suspicious behaviors is indeed a threat.

---

## Objectives
<!--
- List all objectives for this lab
- Need at least three objectives
- Use blooms taxonomy verbs: KNOWLEDGE,UNDERSTAND, APPLY, ANALYZE, EVALUATE, CREATE
- https://www.teachthought.com/critical-thinking/blooms-taxonomy-verbs-2/
-->
1. Understand the Defense Evasion phase activities an attacker might utilize
2. Demonstrate Defense Evasion skills to disable antivirus and allow us to bring down additional malware utilities without being detected
3. Understand how we can use Defense Evasion activities to identify or confirm malicious intent

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
	Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
	```

## Instructions
For each of these labs, you will need your Powershell window open. You can use the same window for all labs. You will be copying and pasting commands into the terminal and then evaluating the output.

w> All labs require you to be running as an administrator. 

### 1. Disabling Security Tools - Powershell
> *While most defensive evasion will be used alongside other techniques to hide them, an explicit defense evasion phase usually will happen where the attacker will disable security tools and logging.*
>
> *The method we'll demonstrate today is to disable Windows Defender but often an attacker will use a script to detect and disable whatever AV is on the system. This action requires administrator privileges. This command may not work directly if tamper protection is enabled but there are methods an attacker can use to bypass tamper protection as well.*

Use Powershell to perform a **Disable Security Tools** technique
- [ATT&CK T1089 - Defense Evasion - Disabling Security Tools](https://attack.mitre.org/techniques/T1089)
- Copy and paste this command into the terminal:
	```PowerShell
	Write-Host -ForegroundColor Cyan "Initiating Defense Evasion - T1089 - Disabling Security Tools"
	Write-Host "Disabling Defender..."
	$cmd = "Set-MpPreference -DisableRealtimeMonitoring `$true; Start-Sleep -m $n"
	powershell.exe -nop -command $cmd
	```

### 2. Disabling Security Tools - Service Control Manager
> *If the above method does not work, attackers can also disable the antivirus service from the service control manager using sc.exe*

Use the Service Control Manager (sc.exe) to perform a **Disable Security Tools** technique
- [ATT&CK T1089 - Defense Evasion - Disabling Security Tools](https://attack.mitre.org/techniques/T1089)
- Copy and paste this command into the terminal:
	```PowerShell
	Write-Host -ForegroundColor Cyan "Initiating Defense Evasion - T1089 - Disabling Security Tools"
	Write-Host "Disabling Defender..."
	& sc.exe config WinDefend start= disabled
	* sc.exe stop WinDefend
	```

	