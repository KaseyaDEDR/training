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
	Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
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
$outputFile = "$env:USERPROFILE\Desktop\recon.txt"

$cmd = @"
echo ==== Hostname ==== >> "$outputFile"
hostname >> "$outputFile"

echo ==== Whoami ==== >> "$outputFile"
whoami >> "$outputFile"

echo ==== MachineGuid ==== >> "$outputFile"
reg query "HKLM\SOFTWARE\Microsoft\Cryptography" /v MachineGuid >> "$outputFile"

echo ==== System Info ==== >> "$outputFile"
systeminfo >> "$outputFile"

echo ==== Antivirus Product ==== >> "$outputFile"
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, pathToSignedProductExe, pathToSignedReportingExe, productState >> "$outputFile"

echo ==== Terminal Services Remote Host List ==== >> "$outputFile"
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" 2>&1 >> "$outputFile"

echo ==== Local Accounts ==== >> "$outputFile"
net user >> "$outputFile"

echo ==== Local Administrators ==== >> "$outputFile"
net localgroup administrators >> "$outputFile"

echo ==== Domain Administrators ==== >> "$outputFile"
net group "domain admins" /domain 2>&1 >> "$outputFile"

echo ==== Exchange Administrators ==== >> "$outputFile"
net group "Exchange Trusted Subsystem" /domain 2>&1 >> "$outputFile"

echo ==== Installed Software ==== >> "$outputFile"
Get-CimInstance -ClassName Win32_Product | Select-Object Name, Vendor, Version | Sort-Object Vendor, Name >> "$outputFile"
"@
Invoke-Expression $cmd

# Output file info
Get-Item $outputFile

```
<!--SAMPLE OUTPUT - Domain Inquries will not return unless DC joined. 
====
Hostname
====
Vault-Tec
====
Whoami
====
vault-tec\testuser
====
MachineGuid
====

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography
    MachineGuid    REG_SZ    953b64dd-145d-4110-97dd-47d0ca3b8658

====
System
Info
====

Host Name:                     VAULT-TEC
OS Name:                       Microsoft Windows 11 Pro
OS Version:                    10.0.26100 N/A Build 26100
OS Manufacturer:               Microsoft Corporation
OS Configuration:              Standalone Workstation
OS Build Type:                 Multiprocessor Free
Registered Owner:              testuser
Registered Organization:       N/A
Product ID:                    00330-80000-00000-AA219
Original Install Date:         1/16/2025, 2:28:10 PM
System Boot Time:              4/11/2025, 2:14:19 PM
System Manufacturer:           VMware, Inc.
System Model:                  VMware20,1
System Type:                   x64-based PC
Processor(s):                  1 Processor(s) Installed.
                               [01]: Intel64 Family 6 Model 170 Stepping 4 GenuineIntel ~2995 Mhz
BIOS Version:                  VMware, Inc. VMW201.00V.24006586.B64.2406042154, 6/4/2024
Windows Directory:             C:\WINDOWS
System Directory:              C:\WINDOWS\system32
Boot Device:                   \Device\HarddiskVolume1
System Locale:                 en-us;English (United States)
Input Locale:                  en-us;English (United States)
Time Zone:                     (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:         8,191 MB
Available Physical Memory:     5,103 MB
Virtual Memory: Max Size:      8,703 MB
Virtual Memory: Available:     5,635 MB
Virtual Memory: In Use:        3,068 MB
Page File Location(s):         C:\pagefile.sys
Domain:                        WORKGROUP
Logon Server:                  \\VAULT-TEC
Hotfix(s):                     5 Hotfix(s) Installed.
                               [01]: KB5054979
                               [02]: KB5048779
                               [03]: KB5055523
                               [04]: KB5052915
                               [05]: KB5058538
Network Card(s):               1 NIC(s) Installed.
                               [01]: Intel(R) 82574L Gigabit Network Connection
                                     Connection Name: Ethernet0
                                     DHCP Enabled:    Yes
                                     DHCP Server:     10.25.10.1
                                     IP address(es)
                                     [01]: 10.25.11.102
                                     [02]: fe80::2915:3c5:ceeb:7992
Virtualization-based security: Status: Not enabled
                               App Control for Business policy: Enforced
                               App Control for Business user mode policy: Off
                               Security Features Enabled:
Hyper-V Requirements:          A hypervisor has been detected. Features required for Hyper-V will not be displayed.
====
Antivirus
Product
====

displayName      pathToSignedProductExe                                                            pathToSignedReportingExe                
-----------      ----------------------                                                            --------------------
Datto AV         \\?\C:\Program Files\infocyte\agent\dattoav\Endpoint Protection SDK\wsc_agent.exe C:\Program Files\...
Windows Defender windowsdefender://                                                                %ProgramFiles%\Wi...
Datto AV         \\?\C:\Program Files\infocyte\agent\dattoav\Endpoint Protection SDK\wsc_agent.exe C:\Program Files\...


====
Terminal
Services
Remote
Host
List
====
reg : ERROR: Invalid syntax.
At line:17 char:1
+ reg query HKCU\Software\Microsoft\Terminal Server Client\Default 2>&1 ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (ERROR: Invalid syntax.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 
Type "REG QUERY /?" for usage.
====
Local
Accounts
====

User accounts for \\VAULT-TEC

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
testuser                 WDAGUtilityAccount       
The command completed successfully.

====
Local
Administrators
====
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
testuser
The command completed successfully.

====
Domain
Administrators
====
net : The syntax of this command is:
At line:26 char:1
+ net group domain admins /domain 2>&1 >> C:\Users\testuser\Desktop\rec ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 

NET GROUP
[groupname [/COMMENT:"text"]] [/DOMAIN]
             groupname {/ADD [/COMMENT:"text"] | /DELETE}  [/DOMAIN]
             groupname username [...] {/ADD | /DELETE} [/DOMAIN]

====
Exchange
Administrators
====
net : The syntax of this command is:
At line:29 char:1
+ net group Exchange Trusted Subsystem /domain 2>&1 >> C:\Users\testuse ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
 

NET GROUP
[groupname [/COMMENT:"text"]] [/DOMAIN]
             groupname {/ADD [/COMMENT:"text"] | /DELETE}  [/DOMAIN]
             groupname username [...] {/ADD | /DELETE} [/DOMAIN]

====
Installed
Software
====
Name                                                           Vendor                     Version        
----                                                           ------                     -------        
DB Browser for SQLite                                          DB Browser for SQLite Team 3.13.1         
Microsoft .NET Host - 6.0.16 (x64)                             Microsoft Corporation      48.67.58427    
Microsoft .NET Host FX Resolver - 6.0.16 (x64)                 Microsoft Corporation      48.67.58427    
Microsoft .NET Runtime - 6.0.16 (x64)                          Microsoft Corporation      48.67.58427    
Microsoft Visual C++ 2022 X64 Additional Runtime - 14.36.32532 Microsoft Corporation      14.36.32532    
Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.36.32532    Microsoft Corporation      14.36.32532    
Microsoft Visual C++ 2022 X86 Additional Runtime - 14.36.32532 Microsoft Corporation      14.36.32532    
Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.36.32532    Microsoft Corporation      14.36.32532    
PowerShell 6-x64                                               Microsoft Corporation      6.2.2.0        
VMware Tools                                                   VMware, Inc.               12.4.5.23787635


>
