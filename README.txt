OpenPhalanx excels at interacting with remote hosts in a manner which does not require the installation of an agent or taking the host offline when interrogation and intervention occur. Neither OpenPhalanx nor Sysmon should be seen as adequate alternatives to a modern EDR. OpenPhalanx steps in where preparation or execution have failed. Some mechanisms in this framework are helpful for daily security operations activities while others are likley only useful in an emergency. It is far more effective to familiarize yoruself with the interfaces and workflows before you encounter an emergency than to attempt to figure it out when the need arises. 

The windows event log threat hunting applications can trip AV and other endpoint security controls. DeepBlueCLI in perticular tends to trip alerts. You may only need to apply AV exceptions to the sripts and binaries that run these applicaitons. These exceptions only need to be aplied to the local workstation from which the tools are launched. 

Warning! Using the hybrid analyis feature is only recomended for items you do not believe to contain any sensitive information. I have set as many privacy configurations as we can use to keep submissions private, however screenshots and snippets within the report could still potentially contain sensitive information. Use at your own risk and I recommend reviewing all of your submissions immediately once they are available so you can identify anything for which you need to submit a request to remove.

*********Definitions*********
OpenPhalanx:  the framework for how we use the open source, or free and built on open source, tools within this colleciton - MWH

Defending Off the Land: this is the response interface to interact with hosts and intervene across your domain as necessary - MWH

Sysmon: "a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log" - Mark Russinovich and Thomas Garnier

DeepBlueCLI: "a PowerShell Module for Threat Hunting via Windows Event Logs" - Eric Conrad

Hayabusa: "a Windows event log fast forensics timeline generator and threat hunting tool" -  Yamato Security group, Japan

Python: "a programming language that lets you work quickly and integrate systems more effectively" - Guido van Rossum

ImportExcel: "PowerShell module to import/export Excel spreadsheets, without Excel" - Douglas Finke

VS Code: "a source-code editor made by Microsoft with the Electron Framework, for Windows, Linux and macOS" - Microsoft

EZTools: Eric Zimmerman's collection of forensic tools

*********Workflows*********
Setup 
	Interrctions required from user:
		Download and install VS Code from https://code.visualstudio.com/download
		Add SQLite viewer extension
		If you would like to use the sandbox submission features then aquire an api key from HA
		Execute setup script as admin from the desired root location of the workspace
   		If you do not have MS Excel, then you may want to grab an open source alternative like LibreOffice
        		https://www.libreoffice.org/download/download-libreoffice/
		If you would like to use the Hybrid-Analysis integration follow these setup steps:
			Copy the config_tpl.py and name it config.py.
			The configuration file specifies a triplet of api key/secret and server:
				api_key (should be compatible with API v2 - should contains at least 60 chars)
				server - full url of the WebService instance e.g. https://www.hybrid-analysis.com
				Please fill them with the appropriate data. You can generate a public (restricted) API key by 
				following these instructions:	
				https://www.hybrid-analysis.com/knowledge-base/issuing-self-signed-api-key
				If you have the full version of Falcon Sandbox, create any kind of API key in the admin area: 
				https://www.hybrid-analysis.com/apikeys
	Actions taken by setup script
		Builds directory workspaces:
 			"\OpenPhalanx\CopiedFiles",
    			"\OpenPhalanx\Logs",
    			"\OpenPhalanx\Logs\EVTX",
    			"\OpenPhalanx\Logs\Reports",
    			"\OpenPhalanx\Logs\Audit",
    			"\OpenPhalanx\Rules",
    			"\OpenPhalanx\Tools",
    			"\OpenPhalanx\Tools\DeepBlueCLI",
    			"\OpenPhalanx\Tools\EZTools",
    			"\OpenPhalanx\Tools\Hayabusa",
    			"\OpenPhalanx\Tools\Sysmon",
		Downloads tools and requirements
			Python
			ImportExcel
			Defending_Off_the_Land.ps1
			LICENSE
			README.txt
			regexes.txt
			safelists.txt
			DeepBlueCLI
			Hayabusa
			Sysmon
			EZTools
		Updates Hayabusa rules
			"\OpenPhalanx\Rules"
			
Usage
	Requirements
		PS Remoting must be enabled and the entity executing the script must be admin on the target host(s)
	Collect artifacts with Forensics On the Fly
		RapidTriage is a very fast artifact and telemetry gathering tool
		WinEventalyzer is a windows event log collection and threat hunting tool
		USN Journal Collection will gather the USN Journal from the remote host
	Analyze collections to identify malicious actions and potential payloads for sandboxing
		The RapidTriage output is a collection of worksheets in an xlsx workbook per host. Use your prefered tool 
			for viewing these file types. The browser histories collected are easily viewed by any sqlite viewer
			and vs code is a tool I consider essential for it's diverse capabilities.
		Threat hunting tools generate various outputs when the WinEventalyzer is deployed.
			DeepBlueCLI will generate alerts or threat hunting leads of interest to investigate furhter
			Hayabusa Timeline, various summaries, and metrics
		The USN Journal is a treasure trove of information about file changes. It's also not well formatted 
			due to how it is read from the remote host using the native file system utility tool. 
			It's the slowest collection of the 3. 
	Respond with Defending Off the Land
 		Shutting down or restarting a remote computer
		Getting basic information about a remote computer's system and users
 		Viewing and killing processes on a remote computer
 		Copying, deleting, placing and running files on a remote computer
		Executing single line commands on a remote computer
		Installing and running Sysmon on a remote computer with Olaf Hartong's default configuration
		Isolating a remote computer from the network by modifying its firewall rules
		Submitting URLs or files to Hybrid Analysis for malware analysis


*********Resources*********
Legend
"*" - prompts an investigative question
"{-} [-] (-) #>-<# &&-&&" - encapulsate recommended resources to answer investigative prompts

The onset of any endpoint directed cyber security investigation should prompt 5 questions - NAB CD
Now - is something malicious currently running on the host?
Again - has persistence been established so something malicious will run again?
Before - has something malicious previously executed?
Connections - what/who is communicating with the endpoint?
Disk - what's changed?

*What's running now?[

Command Analysis
https://attack.mitre.org/datasources/DS0017/
https://redcanary.com/blog/process-command-line/

Process Analysis
https://attack.mitre.org/datasources/DS0009/
https://esmyl.medium.com/windows-processes-memory-forensics-dfir-f5cf878d7b2a

*What will run again?{

Service Analysis
https://attack.mitre.org/datasources/DS0019/
https://forensafe.com/blogs/windowsservices.html
https://www.sans.org/blog/defense-spotlight-finding-hidden-windows-services/
]

Tasks Analysis
https://attack.mitre.org/datasources/DS0003/
https://www.kadircirik.com/behavior-analysis-task-scheduler/
https://redcanary.com/threat-detection-report/techniques/scheduled-task/

WMI Analysis
https://attack.mitre.org/datasources/DS0005/
https://www.hackthebox.com/blog/perseverance-biz-ctf-2022-forensics-writeup

Genreal Persistence
https://hackmag.com/security/persistence-cheatsheet/
}

*What ran before?(

Prefetch and Execution Analysis
https://isc.sans.edu/diary/Forensic+Value+of+Prefetch/29168/
https://frsecure.com/blog/windows-forensics-execution/

PowerShell History Analysis
https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics
)

*Who you talkin to?#>

Network Traffic Analysis
https://attack.mitre.org/datasources/DS0029/
https://resources.infosecinstitute.com/topic/network-traffic-analysis-for-ir-connection-analysis/

Network Share Analysis
https://attack.mitre.org/datasources/DS0033/

Browser History Analysis
https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/browser-artifacts
<#

*What's changed on disk?&&

File Analysis
https://attack.mitre.org/datasources/DS0022/
https://www.ironhack.com/us/en/blog/metadata-forensics-when-files-can-speak-and-reveal-the-truth

USN Journal Analysis
https://www.otorio.com/resources/usnjrnl-extraction-for-efficient-investigation/
https://blog.haboob.sa/blog/advanced-usn-journal-forensics

Magic Number Analysis
https://www.ibm.com/support/pages/what-magic-number
https://medium.com/asecuritysite-when-bob-met-alice/the-core-of-digital-forensics-magic-numbers-fd3e6d7a225
https://www.magnumdb.com/
&&

Everything Cheatsheet
https://www.jaiminton.com/cheatsheet/DFIR/

Defensive TTP Map
https://d3fend.mitre.org/

