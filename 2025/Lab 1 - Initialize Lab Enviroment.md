---
Title: Initialize Lab Setup
Description: Introduce post-compromise attack behaviors and EDR defenses
Author: Chris Gerritz, Datto
Created: 04/24/2025
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
- Ransomware Simulator
External:
- allitshop.infocyte.com
- prismlearning.cloud
---

## Description

The purpose of these labs is to introduce post-compromise attack behaviors and EDR defenses. Lab 1 will help to initiate and login to the lab enviroment which consists of a cloud-hosted Windows virtual machine.

We will perform post-compromise behaviors that an attacker would run once they compromised a system within the network.  This system has Datto EDR installed for monitoring so we will be able to view these commands from the defender's perspective as well.

<!--
The virtual machine has some dummy users and software to mimic a specific type of workstation that might be found in a business enviroment:

Dummy users:
- Joe from Accounting: 
  - `net user joe Password1! /ADD /FULLNAME:"Joe - Accounting"`
- Samson from Accounting
  - `net user samson Password1! /ADD /FULLNAME:"Samson - Accounting"`
- Brenda from IT
  - `net user brenda Password1! /ADD /FULLNAME:"Brenda - IT Helpdesk"`
  - `net localgroup administrators brenda /ADD`

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
1. Create a Prism Cyber Learning Platform account
2. Familiarize yourself with the Prism Cyber Learning Platform
3. Create and understand the lab enviroment we will be working with
   

## Requirements

|                  |                             |
|------------------|-----------------------------|
| **Range**        | Windows |
| **Applications** | All applications needed     |
| **Needed Files** | None |

## Pre-Actions

1. Create a **Prism Cyber Learning Platform** Account 
   - Navigate to https://prismlearning.cloud 
   - Select 'Sign up now'
   - Enrollment code: **KSL2025**
     
2. You will need to verify your email by first clicking 'Send verification code' 
   
3. Look in your email for a **verification code** from Prism Cyber Learning
   - FROM: "Microsoft on behalf of Prism Cyber Learning" <msonlineservicesteam@microsoftonline.com>
   - Input the code in the 'Verification code' box and click '**Verify code**'

4. Follow the rest of the instructions for inputting account information and let the instructor know you are finished so they can ensure you are enrolled in the course.

	s> Your instructor will provision a virtual machine for you when before the class begins.
   
5. Give your email address to the instructor so they can add you to the Datto EDR instance we will be using.

## Instructions

*Once logged into Prism, we will now open up our range system and test it out. Each attendee will be given a virtual machine to use.*

1. Start your range virtual machine
   - From the dashboard, click '**Start**' on your virtual machine
   
   s> For 50+ students, this process can take up to 10 minutes so start it early in the session
  
2. Log into the range
   - Click 'Range' icon on the left
   - Click the 'Remote Access' icon to login
   
   > *You will automatically be logged in with the password. If this fails, the password is accessible by hovering your mouse over the 'Credentials' icon at the bottom*
   
3. Once logged in, open Powershell as an Administrator
	- Right click 'Powershell'
	- Click 'Run as Administrator'

	s> All labs require you to be running as an administrator.

4. Run a test command by copy and pasting this command into the terminal:
```PowerShell
Write-Host -ForegroundColor Cyan "Hello $(whoami). Lets test if you followed these instructions properly..."
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
	Write-Warning "[Error] You do not have Administrator rights to run this script!`nPlease re-run as an Administrator!"
} else {
	Write-Host -ForegroundColor Cyan "SUCCESS: Powershell is running as an administrator."
}
```
s> If you do not see the "SUCCESS" message in your powershell terminal, you did something wrong. Make sure you followed the instructions and copy/paste the ENTIRE command from the above code block.

5. In another browser window (outside the lab enviroment), log into the Datto EDR console:
   - https://allitshop.infocyte.com

## Virtual Machine Preparations

The virtual machine will need an EDR agent.  Install it using the following command:

```powershell
(new-object Net.WebClient).DownloadFile("https://traininglab-files.s3.us-west-1.amazonaws.com/agent.exe", "agent.exe")
.\agent.exe --url allitshop.infocyte.com --key iu60chsaeo --ignore-versioning --verbose
```
 
1. Log into the EDR Console: https://allitshop.infocyte.com (instance name: allitshop).  
2. Navigate to Organizations, click **Connect Global**, select location "**Las Vegas**".
3. You will find your agent there.


### Powershell

Everytime you open a Powershell window, we want a session id to be displayed (it will be stored as \$n and used by the commands we run to avoid de-duplication of alerts that Datto EDR does).

If you open powershell and do not see a session Id number printed, add this to your powershell profile (path is found in \$Profile)

1. Open powershell as an administrator
	- Right click Powershell
	- Click "Run as Administrator"
2. Run the following command:
	```Powershell
	if (!(Test-Path $Profile)) { New-Item -ItemType File -Path $Profile -Force }; notepad $Profile
	```
3. Copy and paste the below code into your profile found at $Profile:
	```PowerShell
	#Define a random number (This will be used to force Datto EDR not to deduplicate repeated commands during testing)
	$global:n = 1000+$(Get-Random -Max 999)
	Write-Host "New Session Id: $n"
	# Bypass signed script controls
	Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force
	```

### Simulated Remote Access Tool (RAT) / Powershell Interface

The labs begin at the post-compromise step of the attack where you, as the attacker, have achieved administrative privileges and have a running remote access tool (aka "RAT) which grants you a terminal session on the compromised system.

To simulate this, we will open Powershell via the binary found here: `C:\Users\Public\rat.exe`

Right-click rat.exe and choose Run as Administrator.

This binary opens powershell which will act as our simulated remote access tool (RAT).  All subsequent commands in the labs need to be run from this window for the best simulated experiance.

> Note: If this binary does not exist, run the following command in PowerShell:  
>
> ```powershell
> Copy-Item "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "C:\Users\Public\rat.exe"
> ```

<!--
	# H1
	## H2
	### H3

	Horizontal Rule	---
	Link	[title](https://www.example.com)
	Image	![alt text](image.jpg)

	![terminal](./assets/filehashes.png)

	term
	: definition

	?> Ask a question?

	> This is some additional information before the next instruction

1. Instruction #3
	- Do something here
	- Do another thing here
	- Do another another thing here

	w> **WARNING** add a warning here

	c> **CRITICAL** add a critical statement here (e.g. **DO NOT DO THIS!**)

	s> **NOTE** add a note here
-->

