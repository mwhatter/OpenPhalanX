# OpenPhalanX: No one stands alone

OpenPhalanX is a comprehensive toolkit designed to secure remote systems. Whether you're an IT professional seeking to automate system tasks, or a cybersecurity specialist handling incident response, OpenPhalanX offers an array of features to streamline your operations. This project is primarily written in PowerShell and I believe this is possibly the most beginner friendly language to work with. I hope it helps everyone feel comfortable digging into the code to understand how it works and how you might modify it to fit any of your needs.

## Table of Contents
- [Installation](#installation)
- [API Keys Configuration](#api-keys-configuration)
- [Features](#features)
- [Usage](#usage)
- [Resources](#resources)
    - [Core Components & Tools](#core-components--tools)
    - [Command Analysis](#command-analysis)
    - [Process Analysis](#process-analysis)
    - [Service Analysis](#service-analysis)
    - [Tasks Analysis](#tasks-analysis)
    - [WMI Analysis](#wmi-analysis)
    - [General Persistence](#general-persistence)
    - [Prefetch and Execution Analysis](#prefetch-and-execution-analysis)
    - [PowerShell History Analysis](#powershell-history-analysis)
    - [Network Traffic Analysis](#network-traffic-analysis)
    - [Network Share Analysis](#network-share-analysis)
    - [Browser History Analysis](#browser-history-analysis)
    - [File Analysis](#file-analysis)
    - [USN Journal Analysis](#usn-journal-analysis)
    - [Magic Number Analysis](#magic-number-analysis)
    - [General Resources](#general-resources)

- [Contribute](#contribute)
- [Contact](#contact)
- [License](#license)

## Installation

To install OpenPhalanX on a Windows host, you will need to execute a PowerShell script called "Deploy_Phalanx_Formation.ps1". Follow the steps below to install using Visual Studio Code (VSCode):

1. Clone the OpenPhalanX repository from GitHub to your local machine.

2. Open Visual Studio Code.

3. Navigate to the OpenPhalanX project directory using the File Explorer in VSCode.

4. Locate the script "Deploy_Phalanx_Formation.ps1" using the File Explorer and click on it to open.

5. With "Deploy_Phalanx_Formation.ps1" open in the editor, go to the Terminal menu and select "Run Active File". This will execute the installation script in the Terminal window.

   You will need the requisite permissions within AD to force a password reset, disable, or enable an account. You also need to have admin rights and powershell remoting must be enabled on the remote host.
   
   You will also need the ActiveDirectory powershell module. This module is part of RSAT and can be enabled by follow the instructions here - https://learn.microsoft.com/en-US/troubleshoot/windows-server/system-management-components/remote-server-administration-tools

## API Keys Configuration

OpenPhalanX utilizes several APIs to facilitate its operations, each of which require API keys. These keys should be added to the locations specified in the `API_Keys&Extensions.txt` file.

This repository has a directory titled "Integrations" which contains additional file submission python helpers and button click code. I do not have an api key for all of these integrations and the code you select may not have been tested. 

Comment out any api queries you want to exclude from the prompts for Get Intel and Sandbox URL/Retrieve Report. Add any api's you wish to query as needed(email mwhatter@openphalanx for assistance).

File submissions to sandboxes should be done with reverence to the potentially sensitive data within the sample being detonated. The default file sandbox integration with OpenPhalanX is Anomali's API with specification to use their integration with VMRay. I highly recommend using either a private account with one of the provided integration examples or standing up a private instance of Cuckoo.

You are responsible for complying with any API provider's usage requirements for your situation.

## Features

OpenPhalanX offers an array of features designed to facilitate remote system management, monitoring, and security. 

For a comprehensive list of features, please refer to the "?" button within Defending_Off_the_Land.ps1.

For tooltips, hover over each button.

## Usage

After installation, you can run the `Defending_Off_the_Land.ps1` script through VSCode. Here's how you can do this:

1. Open Visual Studio Code.

2. Navigate to the OpenPhalanX project directory using the File Explorer in VSCode.

3. Locate the script "Defending_Off_the_Land.ps1" using the File Explorer and click on it to open.

4. With "Defending_Off_the_Land.ps1" open in the editor, go to the Terminal menu and select "Run Active File". This will execute the script in the Terminal window.

Follow the instructions provided within the script for each feature. 

Example workflow: Enter remote computer name; run RapidTriage; run WinEventalyzer; run Intelligazer; investigate indicators; run ProcAsso; investigate execution chain.

## Resources

This project integrates or is inspired by a number of other projects and resources. Here are some that may help you better understand the mechanics, provide further insight or could be useful for other related purposes:

### Core Components & Tools
- [OpenPhalanX Repository](https://github.com/mwhatter/OpenPhalanX)
- [Visual Studio Code](https://code.visualstudio.com/)
- [Python Official Site](https://www.python.org/)
- [Olaf Hartong's Sysmon configuration](https://github.com/olafhartong/sysmon-modular)
- [DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)
- [Hayabusa](https://github.com/bigbangforensics/Hayabusa)    

### Command Analysis
- [Command Analysis Datasource](https://attack.mitre.org/datasources/DS0017/)
- [Command Line Analysis](https://redcanary.com/blog/process-command-line/)

### Process Analysis
- [Process Analysis Datasource](https://attack.mitre.org/datasources/DS0009/)
- [Windows Processes Memory Forensics](https://esmyl.medium.com/windows-processes-memory-forensics-dfir-f5cf878d7b2a)

### Service Analysis
- [Service Analysis Datasource](https://attack.mitre.org/datasources/DS0019/)
- [Windows Services Analysis](https://forensafe.com/blogs/windowsservices.html)
- [Finding Hidden Windows Services](https://www.sans.org/blog/defense-spotlight-finding-hidden-windows-services/)

### Tasks Analysis
- [Tasks Analysis Datasource](https://attack.mitre.org/datasources/DS0003/)
- [Behavior Analysis Task Scheduler](https://www.kadircirik.com/behavior-analysis-task-scheduler/)
- [Scheduled Task Analysis](https://redcanary.com/threat-detection-report/techniques/scheduled-task/)

### WMI Analysis
- [WMI Analysis Datasource](https://attack.mitre.org/datasources/DS0005/)
- [WMI Forensics Writeup](https://www.hackthebox.com/blog/perseverance-biz-ctf-2022-forensics-writeup)

### General Persistence
- [Persistence Cheatsheet](https://hackmag.com/security/persistence-cheatsheet/)

### Prefetch and Execution Analysis
- [TrustedSec Prefetch Blog](https://www.trustedsec.com/blog/prefetch-the-little-snitch-that-tells-on-you/)
- [Prefetch Forensics](https://isc.sans.edu/diary/Forensic+Value+of+Prefetch/29168/)
- [Windows Forensics Execution](https://frsecure.com/blog/windows-forensics-execution/)

### PowerShell History Analysis
- [PowerShell Command History Forensics](https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics)

### Network Traffic Analysis
- [Network Traffic Analysis Datasource](https://attack.mitre.org/datasources/DS0029/)
- [Network Traffic Analysis for IR Connection Analysis](https://resources.infosecinstitute.com/topic/network-traffic-analysis-for-ir-connection-analysis/)

### Network Share Analysis
- [Network Share Analysis Datasource](https://attack.mitre.org/datasources/DS0033/)

### Browser History Analysis
- [Browser Artifacts Forensics](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/browser-artifacts)

### File Analysis
- [File Analysis Datasource](https://attack.mitre.org/datasources/DS0022/)
- [Metadata Forensics](https://www.ironhack.com/us/en/blog/metadata-forensics-when-files-can-speak-and-reveal-the-truth)

### USN Journal Analysis
- [USN Journal Extraction for Efficient Investigation](https://www.otorio.com/resources/usnjrnl-extraction-for-efficient-investigation/)
- [Advanced USN Journal Forensics](https://blog.haboob.sa/blog/advanced-usn-journal-forensics)

### Magic Number Analysis
- [What is Magic Number](https://www.ibm.com/support/pages/what-magic-number)
- [Core of Digital Forensics - Magic Numbers](https://medium.com/asecuritysite-when-bob-met-alice/the-core-of-digital-forensics-magic-numbers-fd3e6d7a225)
- [MagnumDB](https://www.magnumdb.com/)

### General Resources
- [Everything Cheatsheet](https://www.jaiminton.com/cheatsheet/DFIR/)
- [Defensive TTP Map](https://d3fend.mitre.org/)


## Contribute

Contributions are always welcome! If you're interested in enhancing OpenPhalanX, please see our [contributing guidelines](CONTRIBUTING.md).

Special thanks to creators of other projects that help make OpenPhalanX what it is:
- [Eric Zimmerman](https://github.com/sponsors/EricZimmerman)
- [Zach Mathis](https://github.com/Yamato-Security)
- [Eric Conrad](https://www.ericconrad.com/)

## Contact

For any questions, feedback, or suggestions, please reach out to mwhatter@openphalanx.com.

## License

OpenPhalanX is licensed under GPL-3.0 License. Refer to the [LICENSE](LICENSE) file for more details.
