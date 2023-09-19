<#
.SYNOPSIS   
    This PowerShell script creates a Windows Form application that serves as a remote system management tool. 
    It enables users to view running processes, copy process binaries, manipulate firewall rules, perform 
    file operations, deploy Sysmon for system monitoring, and execute threat hunting tools on a remote computer. 
    The script is designed with a focus on security, making it a valuable tool for system administrators and 
    cybersecurity professionals.

.DESCRIPTION
    This PowerShell script is a comprehensive tool designed to facilitate remote system diagnostics and management. 
    It provides a robust interface that allows system administrators and cybersecurity professionals to interact 
    with a remote computer in a secure and efficient manner.


    The script's functionalities are manifold:

    Process Management: The script allows users to view the list of running processes on a remote computer. 
    It provides detailed information about each process, including its ID, name, and status. Furthermore, 
    it offers the ability to terminate any running process, providing a crucial tool for dealing with potentially 
    harmful or unnecessary processes.

    Binary Collection: The script can copy all uniquely pathed binaries associated with currently running 
    processes on the remote machine. These binaries are stored in a local directory named "OpenPhalanx\CopiedFiles". 
    This feature is particularly useful for malware analysis and threat hunting, as it allows investigators to 
    analyze the exact version of a binary that was running on a system.

    Firewall Manipulation: The script includes a feature dubbed the "Tractor Beam", which modifies the firewall 
    rules on the remote host to restrict communication to only the local host. This can be instrumental in 
    isolating a compromised system and preventing lateral movement within a network.

    File Operations: The script provides a suite of file operation tools, including the ability to copy, 
    place, and execute files on the remote system. These operations can be performed with specified arguments, 
    providing flexibility for a variety of tasks.

    Sysmon Deployment: The script can deploy Sysmon, a powerful system monitoring tool, on the remote host. The 
    deployment uses the Olaf Hartong default configuration, which is widely recognized for its effectiveness in 
    logging and tracking system activity.

    Threat Hunting Tools: The script includes the ability to run windows event log threat hunting tools, DeepBlueCLI 
    and Hayabusa. These tools generate various outputs, including timelines, summaries, and metrics, that can be 
    invaluable in identifying and investigating potential threats.

    Logging and Reporting: All activities performed by the script are logged for auditing and review. The script also 
    generates a detailed reports of its findings.

    Help Features: The script includes comprehensive help features that provide detailed explanations of each functionality. 

    This script is a powerful tool for any system administrator or cybersecurity professional, providing a wide range of 
    functionalities to manage, monitor, and secure remote systems.

.PARAMETER CWD
    This parameter specifies the current working directory.

.PARAMETER LogFile
    This parameter specifies the path where the log file will be saved.

.PARAMETER Username
    This parameter specifies the username of the current user.

.PARAMETER ComputerName
    Specifies the name of the remote computer that you want to manage.

.PARAMETER GetHostList
    Retrieves a list of all computers on the domain and populates a searchable drop-down list in the GUI.

.PARAMETER RemoteFilePath
    Specifies the path on the remote computer you are interracting with.

.PARAMETER LocalFilePath
    Specifies the path on the local computer you are working from.

.PARAMETER EVTXPath
    The path to save exported EVT log files.

.PARAMETER exportPath
    The path to save exported files.
#>

# Define necessary modules
$modules = @('ImportExcel', 'ActiveDirectory', 'PSSQLite')

# Check each module and install if not present
foreach ($module in $modules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
    	Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 | Out-Null
        Install-Module -Name $module -Force
    }
    Import-Module -Name $module
}

Import-Module Microsoft.PowerShell.Utility
# Add necessary assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Web
Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()


$logstart = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$CWD = (Get-Location).Path
New-Item -ItemType Directory -Path "$CWD\Logs\Audit" -Force | Out-Null
$LogFile = "$CWD\Logs\Audit\$logstart.DOL.auditlog.txt"
$Username = $env:USERNAME
$CopiedFilesDir = "$CWD\CopiedFiles"
$EVTXPath = "$CWD\Logs\EVTX"
$exportPath = "$CWD\Logs\Reports"
$script:allComputers = @()
$InformationPreference = 'SilentlyContinue'

function Log_Message {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $true)]
        [string]$LogFilePath
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $LogFilePath -Value "Time=[$timestamp] User=[$Username] Message=[$Message]"
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Defending Off the Land"
$form.Size = New-Object System.Drawing.Size(590, 715)
$form.StartPosition = "CenterScreen"
$form.ForeColor = [System.Drawing.Color]::lightseagreen   
$form.BackColor = [System.Drawing.Color]::Black
$Form.FormBorderStyle = 'Fixed3D'
$Font = New-Object System.Drawing.Font("Times New Roman",8,[System.Drawing.FontStyle]::Regular) # Font styles are: Regular, Bold, Italic, Underline, Strikeout
$Form.Font = $Font

$textboxResults = New-Object System.Windows.Forms.TextBox
$textboxResults.Location = New-Object System.Drawing.Point(15, 405)
$textboxResults.Size = New-Object System.Drawing.Size(540, 250)
$textboxResults.Multiline = $true
$textboxResults.ScrollBars = "Vertical"
$textboxResults.WordWrap = $true
$textboxResults.BackColor = [System.Drawing.Color]::Black
$textboxResults.ForeColor = [System.Drawing.Color]::lightseagreen
$form.Controls.Add($textboxResults)

$ScriptStartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Log_Message -Message "Session started at $ScriptStartTime" -LogFilePath $LogFile
$textboxResults.AppendText("Session started at $ScriptStartTime `r`n")

$labelComputerName = New-Object System.Windows.Forms.Label
$labelComputerName.Location = New-Object System.Drawing.Point(53, 32)
$labelComputerName.Size = New-Object System.Drawing.Size(95, 20)
$labelComputerName.Text = "Remote Computer"
$form.Controls.Add($labelComputerName)

$comboboxComputerName = New-Object System.Windows.Forms.ComboBox
$comboboxComputerName.Location = New-Object System.Drawing.Point(150, 30)
$comboboxComputerName.Size = New-Object System.Drawing.Size(150, 20)
$comboboxComputerName.BackColor = [System.Drawing.Color]::Black
$comboboxComputerName.ForeColor = [System.Drawing.Color]::lightseagreen
$comboBoxComputerName.AutoCompleteMode = 'Suggest'
$comboBoxComputerName.AutoCompleteSource = 'ListItems'
$form.Controls.Add($comboboxComputerName)

function Get-AllComputers {
    # Get a list of all domain in the forest
    $domains = (Get-ADForest).Domains

    # Use ForEach-Object -Parallel to process the domains in parallel
    $domaincomputers = $domains | ForEach-Object -Parallel {
        # For each domain, get a DC
        $domainController = (Get-ADDomainController -DomainName $_ -Discover -Service PrimaryDC).HostName

        # Check if $domainController is a collection and get the first hostname
        if ($domainController -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
            $domainController = $domainController[0]
        }

        # Get enabled computers from the DC
        Get-ADComputer -Filter {Enabled -eq $true} -Server $domainController | Select-Object -ExpandProperty Name
    } | Sort-Object

    return $domaincomputers
}

$buttonGetHostList = New-Object System.Windows.Forms.Button
$buttonGetHostList.Text = 'Get Host List'
$buttonGetHostList.Location = New-Object System.Drawing.Point(53, 50)
$buttonGetHostList.Size = New-Object System.Drawing.Size(90, 23)
$buttonGetHostList.Add_Click({
    $comboBoxComputerName.Items.Clear()
    $script:allComputers = Get-AllComputers
    $comboBoxComputerName.Items.AddRange($script:allComputers)
})
$Form.Controls.Add($buttonGetHostList)


function CollectForensicTimeline {
    param (
        [string[]]$Hostnames
    )
    
    foreach ($Hostname in $Hostnames) {
        try {
            $session = New-CimSession -ComputerName $Hostname -ErrorAction $InformationPreference

            if (-not $session) {
                [System.Windows.Forms.MessageBox]::Show("Failed to connect to $Hostname. Please check the hostname and try again.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                continue
            }

            New-Item -ItemType Directory -Path ".\Logs\Reports\$Hostname\RapidTriage" -Force | Out-Null
            $ExcelFile = Join-Path ".\Logs\Reports\$Hostname\RapidTriage" "$Hostname-RapidTriage.xlsx"

            $SystemUsers = Get-CimInstance -ClassName Win32_SystemUsers -CimSession $session
            if ($SystemUsers) {
                $colSystStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Write-Host "Collected System Users from $HostName at $colSystStart" -ForegroundColor Cyan 
                Log_Message -logfile $logfile -Message "Collected System Users from $HostName"
                $textboxResults.AppendText("Collected System Users from $HostName at $colSystStart `r`n")
                $ExcelSystemUsers = $SystemUsers | Export-Excel -Path $ExcelFile -WorksheetName 'SystemUsers' -AutoSize -AutoFilter -TableStyle Medium6 -Append -PassThru
                Close-ExcelPackage $ExcelSystemUsers
            }

            $Processes = Get-CimInstance -ClassName Win32_Process -CimSession $session | select-object -Property CreationDate,CSName,ProcessName,CommandLine,Path,ProcessId,ParentProcessId
			if ($Processes) {
				$colProcStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
				Write-Host "Collected Processes from $HostName at $colProcStart" -ForegroundColor Cyan 
				Log_Message -logfile $logfile -Message "Collected Processes from $HostName"
                $textboxResults.AppendText("Collected Processes from $HostName at $colProcStart `r`n")
				$ExcelProcesses = $Processes | Export-Excel -Path $ExcelFile -WorksheetName 'Processes' -AutoSize -AutoFilter -TableStyle Medium6 -Append -PassThru
				$worksheet = $ExcelProcesses.Workbook.Worksheets['Processes']
				$cmdLineCol = $worksheet.Dimension.Start.Column + ($worksheet.Dimension.End.Column - $worksheet.Dimension.Start.Column) - 3
				$pathCol = $worksheet.Dimension.Start.Column + ($worksheet.Dimension.End.Column - $worksheet.Dimension.Start.Column) - 2
				Set-Column -Worksheet $worksheet -Column $cmdLineCol -Width 75
				Set-Column -Worksheet $worksheet -Column $pathCol -Width 40
				Close-ExcelPackage $ExcelProcesses
				}

			$ScheduledTasks = Get-ScheduledTask -CimSession $session | select-object -Property Date,PSComputerName,Author,Description,TaskName,TaskPath
			if ($ScheduledTasks) {
				$colSchedTasksStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
				Write-Host "Collected Scheduled Tasks from $HostName at $colSchedTasksStart" -ForegroundColor Cyan 
				Log_Message -logfile $logfile -Message "Collected Scheduled Tasks from $HostName"
                $textboxResults.AppendText("Collected Scheduled Tasks from $HostName at $colSchedTasksStart `r`n")
				$ExcelScheduledTasks = $ScheduledTasks | Export-Excel -Path $ExcelFile -WorksheetName 'ScheduledTasks' -AutoSize -AutoFilter -TableStyle Medium6 -Append -PassThru
				$worksheett = $ExcelScheduledTasks.Workbook.Worksheets['ScheduledTasks']
				$descrCol = $worksheett.Dimension.Start.Column + ($worksheett.Dimension.End.Column - $worksheett.Dimension.Start.Column) - 2
				Set-Column -Worksheet $worksheett -Column $descrCol -Width 40
				Close-ExcelPackage $ExcelScheduledTasks
			}

			$Services = Get-CimInstance -ClassName Win32_Service -CimSession $session | select-object -Property PSComputerName,Caption,Description,Name,StartMode,PathName,ProcessId,ServiceType,StartName,State
			if ($Services) {
				$colServStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
				Write-Host "Collected Services from $HostName at $colServStart" -ForegroundColor Cyan 
				Log_Message -logfile $logfile -Message "Collected Services from $HostName"
                $textboxResults.AppendText("Collected Services from $HostName at $colServStart `r`n")
				$ExcelServices = $Services | Export-Excel -Path $ExcelFile -WorksheetName 'Services' -AutoSize -AutoFilter -TableStyle Medium6 -Append -PassThru
				$worksheets = $ExcelServices.Workbook.Worksheets['Services']
				$descr2Col = $worksheets.Dimension.Start.Column + ($worksheets.Dimension.End.Column - $worksheets.Dimension.Start.Column) - 7
				Set-Column -Worksheet $worksheets -Column $descr2Col -Width 40
				Close-ExcelPackage $ExcelServices
			}

            $WMIConsumer = Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer -CimSession $session 
            if ($WMIConsumer) {
                $colWMIContStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Write-Host "Collected WMI Consumer Events from $HostName at $colWMIContStart" -ForegroundColor Cyan 
                Log_Message -logfile $logfile -Message "Collected WMI Consumer Events from $HostName"
                $textboxResults.AppendText("Collected WMI Consumer Events from $HostName at $colWMIContStart `r`n")
                $ExcelWMIConsumer = $WMIConsumer | Export-Excel -Path $ExcelFile -WorksheetName 'WMIConsumer' -AutoSize -AutoFilter -TableStyle Medium6 -Append -PassThru
                Close-ExcelPackage $ExcelWMIConsumer
            }

            $WMIBindings = Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -CimSession $session 
            if ($WMIBindings) {
                $colWMIBindStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Write-Host "Collected WMI Bindings from $HostName at $colWMIBindStart" -ForegroundColor Cyan 
                Log_Message -logfile $logfile -Message "Collected WMI Bindings from $HostName"
                $textboxResults.AppendText("Collected WMI Bindings from $HostName at $colWMIBindStart `r`n")
                $ExcelWMIBindings = $WMIBindings | Export-Excel -Path $ExcelFile -WorksheetName 'WMIBindings' -AutoSize -AutoFilter -TableStyle Medium6 -Append -PassThru
                Close-ExcelPackage $ExcelWMIBindings
            }

			$WMIFilter = Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -CimSession $session 
			if ($WMIFilter) {
				$colWMIFiltStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
				Write-Host "Collected WMI Filters from $HostName at $colWMIFiltStart" -ForegroundColor Cyan 
				Log_Message -logfile $logfile -Message "Collected WMI Filters from $HostName"
                $textboxResults.AppendText("Collected WMI Filters from $HostName at $colWMIFiltStart `r`n")
				$ExcelWMIFilter = $WMIFilter | Export-Excel -Path $ExcelFile -WorksheetName 'WMIFilter' -AutoSize -AutoFilter -TableStyle Medium6 -Append -PassThru
				Close-ExcelPackage $ExcelWMIFilter
			}

			$Shares = Get-CimInstance -ClassName Win32_Share -CimSession $session
			if ($Shares) {
				$colSharesStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
				Write-Host "Collected Shares from $HostName at $colSharesStart" -ForegroundColor Cyan 
				Log_Message -logfile $logfile -Message "Collected Shares from $HostName"
                $textboxResults.AppendText("Collected Shares from $HostName at $colSharesStart `r`n")
				$ExcelShares = $Shares | Export-Excel -Path $ExcelFile -WorksheetName 'Shares' -AutoSize -AutoFilter -TableStyle Medium6 -Append -PassThru
				Close-ExcelPackage $ExcelShares
			}

			$ShareToDirectory = Get-CimInstance -ClassName Win32_ShareToDirectory -CimSession $session
			if ($ShareToDirectory) {
				$colShareToDirStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
				Write-Host "Collected ShareToDirectory from $HostName at $colShareToDirStart" -ForegroundColor Cyan 
				Log_Message -logfile $logfile -Message "Collected ShareToDirectory from $HostName"
                $textboxResults.AppendText("Collected ShareToDirectory from $HostName at $colShareToDirStart `r`n")
				$ExcelShareToDirectory = $ShareToDirectory | Export-Excel -Path $ExcelFile -WorksheetName 'ShareToDirectory' -AutoSize -AutoFilter -TableStyle Medium6 -Append -PassThru
				Close-ExcelPackage $ExcelShareToDirectory
			}

			$StartupCommand = Get-CimInstance -ClassName Win32_StartupCommand -CimSession $session | select-object -Property PSComputerName,User,UserSID,Name,Command,Location
			if ($StartupCommand) {
				$colStartupCmdStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
				Write-Host "Collected Startup Commands from $HostName at $colStartupCmdStart" -ForegroundColor Cyan 
				Log_Message -logfile $logfile -Message "Collected Startup Commands from $HostName"
                $textboxResults.AppendText("Collected Startup Commands from $HostName at $colStartupCmdStart `r`n")
				$ExcelStartupCommand = $StartupCommand | Export-Excel -Path $ExcelFile -WorksheetName 'StartupCommand' -AutoSize -AutoFilter -TableStyle Medium6 -Append -PassThru
				Close-ExcelPackage $ExcelStartupCommand
			}

			$NetworkConnections = Invoke-Command -ComputerName $Hostname -ScriptBlock { Get-NetTCPConnection } -ErrorAction $InformationPreference | select-object -Property CreationTime,State,LocalAddress,LocalPort,OwningProcess,RemoteAddress,RemotePort
            if ($NetworkConnections) {
                $colNetConnStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Write-Host "Collected Network Connections from $HostName at $colNetConnStart" -ForegroundColor Cyan 
                Log_Message -logfile $logfile -Message "Collected Network Connections from $HostName"
                $textboxResults.AppendText("Collected Network Connections from $HostName at $colNetConnStart `r`n")
                $ExcelNetworkConnections = $NetworkConnections | Export-Excel -Path $ExcelFile -WorksheetName 'NetworkConnections' -AutoSize -AutoFilter -TableStyle Medium6 -Append -PassThru
                Close-ExcelPackage $ExcelNetworkConnections
            }
        }
			catch {
                Write-Host "An error occurred while collecting data from $HostName $($_.Exception.Message)" -ForegroundColor Red
                Log_Message -logfile $logfile -Message "An error occurred while collecting data from $HostName $($_.Exception.Message)"
                $textboxResults.AppendText("An error occurred while collecting data from $HostName $($_.Exception.Message) `r`n")
            }            
}
}

function Get-PECmdPath {
    $possibleLocations = @(".\Tools\EZTools\PECmd.exe", ".\Tools\EZTools\net*\PECmd.exe")
    foreach ($location in $possibleLocations) {
        $resolvedPaths = Resolve-Path $location -ErrorAction $InformationPreference
        if ($resolvedPaths) {
            foreach ($path in $resolvedPaths) {
                if (Test-Path $path) {
                    return $path.Path
                }
            }
        }
    }
    throw "PECmd.exe not found in any of the known locations"
}

function Get_PrefetchMetadata {
    param(
        [string]$HostName,
        [string]$exportPath
    )

    if ([string]::IsNullOrEmpty($HostName)) {
        Write-Host "Error: ComputerName is null or empty" -ForegroundColor Red
        return
    }

    $driveLetters = Get_RemoteDriveLetters -HostName $HostName

    $ExcelFile = Join-Path $exportPath\$HostName\RapidTriage "$HostName-RapidTriage.xlsx"
    
    $copiedFilesPath = ".\CopiedFiles\$HostName\Prefetch"
    New-Item -Path $copiedFilesPath -ItemType Directory -Force

    $pecmdPath = Get-PECmdPath
    $csvOutputDir = "$exportPath\$HostName\RapidTriage\CSVOutput"
    New-Item -Path $csvOutputDir -ItemType Directory -Force

    foreach ($driveLetter in $driveLetters) {
        # Convert drive letter path to UNC format
        $prefetchPath = "\\$HostName\$driveLetter$\Windows\Prefetch\*.pf"
        $prefetchFiles = Get-ChildItem -Path $prefetchPath -ErrorAction SilentlyContinue

        foreach ($file in $prefetchFiles) {
            # Directly copy the file using UNC path
            Copy-Item -Path $file.FullName -Destination $copiedFilesPath -Force -ErrorAction SilentlyContinue
        }
    }

    # Process the copied prefetch files with PECmd
    & $pecmdPath -d $copiedFilesPath --csv $csvOutputDir

    # Collect the CSV results and import to the Excel workbook
    $csvFiles = Get-ChildItem -Path $csvOutputDir -Filter "*.csv" -File
    foreach ($csvFile in $csvFiles) {
        $csvData = Import-Csv -Path $csvFile.FullName
        $csvData | Export-Excel -Path $ExcelFile -WorksheetName $csvFile.BaseName -AutoSize -AutoFilter -FreezeFirstColumn -BoldTopRow -FreezeTopRow -TableStyle Medium6
    }

    Remove-Item -Path $csvOutputDir -Force -Recurse
    $colprestart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Collected Prefetch from $HostName at $colprestart" -ForegroundColor Cyan 
    Log_Message -logfile $logfile -Message "Collected Prefetch from $HostName"
    $textboxResults.AppendText("Collected Prefetch from $HostName at $colprestart `r`n")
}

function Copy_USNJournal {
    param(
        [string]$HostName,
        [string]$Destination,
        [string]$DriveLetter
    )
    New-Item -ItemType Directory -Path ".\Logs\Reports\$computerName\USN_Journal" -Force | Out-Null
    $LocalUSNJournalPath = Join-Path -Path ($Destination + '\' + "$HostName\USN_Journal") -ChildPath "UsnJrnl_$($HostName)-$DriveLetter.csv"
    $timestart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Starting USN Journal Extraction at $timestart" -Foregroundcolor Cyan
    $textboxResults.AppendText("Starting USN Journal Extraction at $timestart `r`n") | Out-Null

    try {
        # Executing fsutil and processing its output
        $scriptBlock = {
            param($DriveLetter)
            & "C:\Windows\System32\fsutil.exe" "usn" "readjournal" "$DriveLetter`:" | Out-String -Stream 
        }
                
        $remoteOutput = Invoke-Command -ComputerName $HostName -ScriptBlock $scriptBlock -ArgumentList $DriveLetter
        $timeend = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "Finished USN Journal Extraction from $DriveLetter at $timeend" -Foregroundcolor Cyan
        Write-Host "Tableling the data" -Foregroundcolor Cyan

        # Split the raw output into lines
        if ($null -ne $remoteOutput) {
            $lines = $remoteOutput -split "`r`n"
        } else {
            Write-Warning "No output from Invoke-Command."
            return
        }

        # Find the start of the journal entries
        $firstUsnLine = $lines | Where-Object { $_.StartsWith('Usn') } | Select-Object -First 1
        if ($null -ne $firstUsnLine) {
            $journalStartIndex = $lines.IndexOf($firstUsnLine)

        # Get only the journal entries (ignore metadata)
        $lines = $lines[$journalStartIndex..$lines.Count]

        # Prepare data collection
        $entry = @{}

        # Exporting data to CSV
        $lines | ForEach-Object {
            if ($_ -eq '') {
                if ($entry.Count -gt 0) {
                    $entry.PSObject.Copy() # Emit the entry
                    $entry.Clear()
                }
            } else {
                $parts = $_ -split ':', 2
                $entry[$parts[0].Trim()] = if ($parts.Length -gt 1) { $parts[1].Trim() } else { $null }
            }
        } | Export-Csv -Path $LocalUSNJournalPath -NoTypeInformation
        } else {
            Write-Warning "No lines starting with 'Usn' were found."
        }

        $timeend = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "USN Journal from drive $DriveLetter on $HostName finished processing at $Timeend" -ForegroundColor Green
        $textboxResults.AppendText("USN Journal from drive $DriveLetter on $HostName finished processing at $Timeend `r`n")
    } catch {
        return "Error copying USN Journal from $HostName on drive $DriveLetter $($_.Exception.Message)"
    }
}

function Get_RemoteDriveLetters {
    param(
        [string]$HostName
    )

    $driveLetters = Invoke-Command -ComputerName $HostName -ScriptBlock {
        Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | ForEach-Object { $_.DeviceID.TrimEnd(':') }
    }

    return $driveLetters
}

function Copy_BrowserHistoryFiles {
    param (
        [string]$RemoteHost,
        [string]$LocalDestination
    )

    $session = New-CimSession -ComputerName $RemoteHost -ErrorAction $InformationPreference

    if (-not $session) {
        [System.Windows.Forms.MessageBox]::Show("Failed to connect to $RemoteHost. Please check the hostname and try again.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    $UserProfiles = Get-CimInstance -ClassName Win32_UserProfile -CimSession $session
    $driveLetters = Get_RemoteDriveLetters -HostName $RemoteHost

    if (-not (Test-Path $LocalDestination)) {
        New-Item -ItemType Directory -Path $LocalDestination | Out-Null
    }

    foreach ($UserProfile in $UserProfiles) {
        $RemoteAccount = (Split-Path $UserProfile.LocalPath -Leaf)

        foreach ($driveLetter in $driveLetters) {
            $EdgeHistoryPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Local\Microsoft\Edge\User Data\Default\History"
            $FirefoxHistoryPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Roaming\Mozilla\Firefox\Profiles\*.default*\places.sqlite"
            $ChromeHistoryPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Local\Google\Chrome\User Data\Default\History"
            $ChromeProfilesPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Local\Google\Chrome\User Data"
            $PowerShellHistoryPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
            $OperaHistoryPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Roaming\Opera Software\Opera Stable\History"
            $BraveHistoryPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History"
            $VivaldiHistoryPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Local\Vivaldi\User Data\Default\History"
            $EpicHistoryPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Local\Epic Privacy Browser\User Data\Default\History"
            $BraveProfilesPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Local\BraveSoftware\Brave-Browser\User Data"
            $VivaldiProfilesPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Local\Vivaldi\User Data"
            $EpicProfilesPath = "\\$RemoteHost\$driveLetter$\Users\$RemoteAccount\AppData\Local\Epic Privacy Browser\User Data"


            $UserDestination = Join-Path -Path $LocalDestination -ChildPath $RemoteAccount
            if (-not (Test-Path $UserDestination)) {
                New-Item -ItemType Directory -Path $UserDestination | Out-Null
            }

	    $ChromeProfiles = Get-ChildItem -Path $ChromeProfilesPath -Filter "Profile*" -Directory -ErrorAction $InformationPreference | out-null

		$ChromeProfiles | ForEach-Object {
    		$ProfilePath = $_.FullName
    		$ChromeHistoryPathalt = "$ProfilePath\History"
    		$ProfileName = $_.Name
    		$DestinationPath = "$UserDestination\$ProfileName-Chrome.sqlite"
    
    		Copy-Item -Path $ChromeHistoryPathalt -Destination $DestinationPath -Force -ErrorAction $InformationPreference | out-null
		}

        $BraveProfiles = Get-ChildItem -Path $BraveProfilesPath -Filter "Profile*" -Directory -ErrorAction $InformationPreference | out-null

        $BraveProfiles | ForEach-Object {
    		$BProfilePath = $_.FullName
    		$BraveHistoryPathalt = "$BProfilePath\History"
    		$BProfileName = $_.Name
    		$DestinationPath = "$UserDestination\$BProfileName-Brave.sqlite"
    
    		Copy-Item -Path $BraveHistoryPathalt -Destination $DestinationPath -Force -ErrorAction $InformationPreference | out-null
		}

        $VivaldiProfiles = Get-ChildItem -Path $VivaldiProfilesPath -Filter "Profile*" -Directory -ErrorAction $InformationPreference | out-null

        $VivaldiProfiles | ForEach-Object {
    		$VProfilePath = $_.FullName
    		$VivaldiHistoryPathalt = "$VProfilePath\History"
    		$VProfileName = $_.Name
    		$DestinationPath = "$UserDestination\$VProfileName-Vivaldi.sqlite"
    
    		Copy-Item -Path $VivaldiHistoryPathalt -Destination $DestinationPath -Force -ErrorAction $InformationPreference | out-null
		}

        $EpicProfiles = Get-ChildItem -Path $EpicProfilesPath -Filter "Profile*" -Directory -ErrorAction $InformationPreference | out-null

        $EpicProfiles | ForEach-Object {
    		$EProfilePath = $_.FullName
    		$EpicHistoryPathalt = "$EProfilePath\History"
    		$EProfileName = $_.Name
    		$DestinationPath = "$UserDestination\$EProfileName-Epic.sqlite"
    
    		Copy-Item -Path $EpicHistoryPathalt -Destination $DestinationPath -Force -ErrorAction $InformationPreference | out-null
		}	
		
            Copy-Item -Path $EdgeHistoryPath -Destination $UserDestination\Edge.sqlite -Force -ErrorAction $InformationPreference | out-null
            Copy-Item -Path $FirefoxHistoryPath -Destination $UserDestination\FireFox.sqlite -Force -ErrorAction $InformationPreference | out-null
            Copy-Item -Path $ChromeHistoryPath -Destination $UserDestination\Chrome.sqlite -Force -ErrorAction $InformationPreference | out-null
            Copy-Item -Path $PowerShellHistoryPath -Destination $UserDestination\PSHistory.txt -Force -ErrorAction $InformationPreference | out-null
            Copy-Item -Path $OperaHistoryPath -Destination $UserDestination\Opera.sqlite -Force -ErrorAction $InformationPreference | out-null
            Copy-Item -Path $BraveHistoryPath -Destination $UserDestination\Brave.sqlite -Force -ErrorAction $InformationPreference | out-null
            Copy-Item -Path $VivaldiHistoryPath -Destination $UserDestination\Vivaldi.sqlite -Force -ErrorAction $InformationPreference | out-null
            Copy-Item -Path $EpicHistoryPath -Destination $UserDestination\Epic.sqlite -Force -ErrorAction $InformationPreference | out-null
            
        }
    $histstart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Collected browser/ps histories for $RemoteAccount at $histstart" -ForegroundColor Cyan 
    Log_Message -logfile $logfile -Message "Collected browser/ps console histories for $RemoteAccount"
    $textboxResults.AppendText("Collected browser/ps histories for $RemoteAccount at $histstart `r`n")
}
}

function Export_AllLogs {
    param (
        $EVTXPath,
        $HostName
    )

    Add-Type -AssemblyName System.Windows.Forms # Only required in PowerShell Core (7+) 

    $colhoststart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Wineventalyzing logs from $HostName to $EVTXPath at $colhoststart" -ForegroundColor Cyan 
    Log_Message -logfile $logfile -Message "Exporting logs from $HostName to $EVTXPath"
    $textboxResults.AppendText("Exporting logs from $HostName to $EVTXPath at $colhoststart `r`n")

    if (!(Test-Path $EVTXPath\$HostName)) {
        New-Item -Path $EVTXPath\$HostName -ItemType Directory
    }
    
    # Check and prompt for overwriting or proceeding with existing logs
    $localLogPath = Join-Path -Path $EVTXPath -ChildPath $HostName
    if(Test-Path $localLogPath){
        $files = Get-ChildItem -Path $localLogPath -File
        $fileCount = $files.Count
        Write-Host "There are $fileCount files in the $localLogPath directory." -ForegroundColor Cyan
        
        $userInput = [System.Windows.Forms.MessageBox]::Show("There are $fileCount files in the directory. Do you want to overwrite the logs?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel)
        if ($userInput -eq 'No') { 
            Write-Host "Re-analyzing $fileCount logs." -ForegroundColor Cyan
            Log_Message -logfile $logfile -Message "Re-analyzing $fileCount logs."
            $textboxResults.AppendText("Re-analyzing $fileCount logs. `r`n")
            return 
        }
        if ($userInput -eq 'Cancel') { exit }
    }

    # Get remote drive letters
    $driveLetters = Get_RemoteDriveLetters -HostName $HostName

    $logsCopied = 0

    foreach ($driveLetter in $driveLetters) {
        # Remote log path
        $remoteLogPath1 = "\\$ComputerName\$driveLetter$\Windows\System32\winevt\Logs"
        $remoteLogPath2 = "\\$ComputerName\$driveLetter$\Windows\System32\winevt\EventLogs"
        $remoteLogPath3 = "\\$ComputerName\$driveLetter$\Windows\System32\drivers\CrowdStrike"

        if ((Test-Path $remoteLogPath1) -or (Test-Path $remoteLogPath2)) {
            # Get all logs from remote host
            $logs = Get-ChildItem -Path $remoteLogPath1 -Filter *.evtx -ErrorAction SilentlyContinue
            $logs += Get-ChildItem -Path $remoteLogPath2 -Filter *.evtx -ErrorAction SilentlyContinue
            $logs += Get-ChildItem -Path $remoteLogPath3 -Filter *.log -ErrorAction SilentlyContinue

            # Copy the files
            $copiedLogs = $logs | ForEach-Object -ThrottleLimit 100 -Parallel {
	    
                # Skip logs of size 68KB and logs with "configuration" in the name
                if ($_.Length -ne 69632 -and $_.Name -notlike "*onfiguration*") {
                    $localLogPath = Join-Path $using:EVTXPath $using:ComputerName "$($_.Name)"
                    Copy-Item -LiteralPath $_.FullName -Destination $localLogPath -Force -ErrorAction SilentlyContinue
                    return $localLogPath
                }
            }
            # Count the copied files
            $logsCopied += $copiedLogs.Count
        }
    }
    
        $evTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "Collected $logsCopied logs from $HostName at $evTime" -ForegroundColor Cyan
        Log_Message -Message "Collected $logsCopied logs from $HostName" -LogFilePath $LogFile
        $textboxResults.AppendText("Collected $logsCopied logs from $HostName at $evTime `r`n")
    } 


function Process_Hayabusa {
    param (
        [string]$HostName
    )
    New-Item -Path "$exportPath\$HostName" -ItemType Directory -Force | Out-Null
    New-Item -Path "$exportPath\$HostName\Hayabusa" -ItemType Directory -Force | Out-Null  
    $hayabusaPath = "$CWD\Tools\Hayabusa\hayabusa.exe"

    & $hayabusaPath logon-summary -d "$EVTXPath\$HostName" -C -o "$exportPath\$HostName\Hayabusa\logon-summary.csv" 
    & $hayabusaPath metrics -d "$EVTXPath\$HostName" -C -o "$exportPath\$HostName\Hayabusa\metrics.csv" 
    & $hayabusaPath pivot-keywords-list -d "$EVTXPath\$HostName" -o "$exportPath\$HostName\Hayabusa\pivot-keywords-list.csv" 
    & $hayabusaPath csv-timeline -d "$EVTXPath\$HostName" -C -o "$exportPath\$HostName\Hayabusa\csv-timeline.csv" -p super-verbose 
    $colhayastart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Hayabusa analyzed logs from $HostName at $colhayastart" -ForegroundColor Cyan 
    Log_Message -logfile $logfile -Message "Hayabusa analyzed logs from $HostName"
    $textboxResults.AppendText("Hayabusa analyzed logs from $HostName at $colhayastart `r`n")
}

function Process_DeepBlueCLI {
    param (
        [string]$HostName
    )
    New-Item -Path "$exportPath\$HostName" -ItemType Directory -Force | Out-Null
    New-Item -Path "$exportPath\$HostName\DeepBlueCLI" -ItemType Directory -Force | Out-Null
    $deepBlueCLIPath = "$CWD\Tools\DeepBlueCLI\DeepBlue.ps1"
    
    $logFiles = @("security.evtx", "system.evtx", "Application.evtx", "Microsoft-Windows-Sysmon%4Operational.evtx", "Windows PowerShell.evtx", "Microsoft-Windows-AppLocker%4EXE and DLL.evtx")
    foreach($logFile in $logFiles) {
        $outFile = Join-Path "$exportPath\$HostName\DeepBlueCLI" "$($logFile -replace ".evtx", ".txt")"
        try {
            & $deepBlueCLIPath "$EVTXPath\$HostName\$logFile" -ErrorAction $InformationPreference | Out-File -FilePath $outFile
        }
        catch {
            # Suppress the error message by doing nothing
        }
    }

    $coldeepstart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "DeepBlueCLI analyzed logs from $HostName at $coldeepstart" -ForegroundColor Cyan 
    Log_Message -logfile $logfile -Message "DeepBlueCLI analyzed logs from $HostName"
    $textboxResults.AppendText("DeepBlueCLI analyzed logs from $HostName at $coldeepstart `r`n")
}


$RapidTriageButton = New-Object System.Windows.Forms.Button
$RapidTriageButton.Location = New-Object System.Drawing.Point(315, 100)
$RapidTriageButton.Size = New-Object System.Drawing.Size(80, 40)
$RapidTriageButton.Text = 'RapidTriage'
$RapidTriageButton.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }
    CollectForensicTimeline -HostName $computerName
    Get_PrefetchMetadata -HostName $computerName -exportPath $exportPath
    Copy_BrowserHistoryFiles -RemoteHost $computerName -LocalDestination "$exportPath\$computerName\RapidTriage\User_Browser&PSconsole"
    $colallstart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "RapidTriage of $computerName completed at $colallstart" -ForegroundColor Green 
    Log_Message -logfile $logfile -Message "RapidTriage of $computerName completed"
    $textboxResults.AppendText("RapidTriage of $computerName completed at $colallstart `r`n")
})
$form.Controls.Add($RapidTriageButton)

$WinEventalyzerButton = New-Object System.Windows.Forms.Button
$WinEventalyzerButton.Location = New-Object System.Drawing.Point(395, 100)
$WinEventalyzerButton.Size = New-Object System.Drawing.Size(80, 40)
$WinEventalyzerButton.Text = 'Win- Eventalyzer'
$WinEventalyzerButton.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    # Call the new function to export all logs
    Export_AllLogs -EVTXPath $EVTXPath -HostName $computerName

    Process_Hayabusa -HostName $computerName 
    Process_DeepBlueCLI -HostName $computerName

    $colwinstart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "WinEventalyzer of $computerName complete at $colwinstart" -ForegroundColor Green
    Log_Message -logfile $logfile -message "WinEventalyzer of $computerName complete"
    $textboxResults.AppendText("WinEventalyzer of $computerName complete at $colwinstart `r`n")
})
$form.Controls.Add($WinEventalyzerButton)

$UsnJrnlButton = New-Object System.Windows.Forms.Button
$UsnJrnlButton.Location = New-Object System.Drawing.Point(15, 355)
$UsnJrnlButton.Size = New-Object System.Drawing.Size(70, 40)
$UsnJrnlButton.Text = 'USN Jrnl Collection'
$UsnJrnlButton.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }
    $RemoteDriveLetters = Get_RemoteDriveLetters -HostName $computerName
        foreach ($DriveLetter in $RemoteDriveLetters) {
            $result = Copy_USNJournal -HostName $computerName -Destination $exportPath -DriveLetter $DriveLetter
            if ($result -and $result.StartsWith("Error")) {
                Write-Host $result -ForegroundColor Red
            } elseif ($result) {
                Write-Host $result -ForegroundColor Green
            }
            }
})
$form.Controls.Add($UsnJrnlButton)

$labelProcessId = New-Object System.Windows.Forms.Label
$labelProcessId.Location = New-Object System.Drawing.Point(53, 87)
$labelProcessId.Size = New-Object System.Drawing.Size(95, 20)
$labelProcessId.Text = "Select a Process"
$form.Controls.Add($labelProcessId)

$dropdownProcessId = New-Object System.Windows.Forms.ComboBox
$dropdownProcessId.Location = New-Object System.Drawing.Point(150, 85)
$dropdownProcessId.Size = New-Object System.Drawing.Size(150, 20)
$dropdownProcessId.BackColor = [System.Drawing.Color]::Black
$dropdownProcessId.ForeColor = [System.Drawing.Color]::lightseagreen
$form.Controls.Add($dropdownProcessId)

$labelRemoteFilePath = New-Object System.Windows.Forms.Label
$labelRemoteFilePath.Location = New-Object System.Drawing.Point(260, 142)
$labelRemoteFilePath.Size = New-Object System.Drawing.Size(50, 30)
$labelRemoteFilePath.Text = "Remote File Path"
$form.Controls.Add($labelRemoteFilePath)

$textboxremoteFilePath = New-Object System.Windows.Forms.TextBox
$textboxremoteFilePath.Location = New-Object System.Drawing.Point(310, 150)
$textboxremoteFilePath.Size = New-Object System.Drawing.Size(245, 20)
$textboxremoteFilePath.BackColor = [System.Drawing.Color]::Black
$textboxremoteFilePath.ForeColor = [System.Drawing.Color]::lightseagreen
$form.Controls.Add($textboxremoteFilePath)

$labelLocalFilePath = New-Object System.Windows.Forms.Label
$labelLocalFilePath.Location = New-Object System.Drawing.Point(258, 230)
$labelLocalFilePath.Size = New-Object System.Drawing.Size(50, 30)
$labelLocalFilePath.Text = "Local  File Path"
$form.Controls.Add($labelLocalFilePath)

$comboboxlocalFilePath = New-Object System.Windows.Forms.ComboBox
$comboboxlocalFilePath.Location = New-Object System.Drawing.Point(310, 237)
$comboboxlocalFilePath.Size = New-Object System.Drawing.Size(245, 20)
$comboboxlocalFilePath.BackColor = [System.Drawing.Color]::Black
$comboboxlocalFilePath.ForeColor = [System.Drawing.Color]::lightseagreen
$comboboxlocalFilePath.DrawMode = [System.Windows.Forms.DrawMode]::OwnerDrawFixed
$comboboxlocalFilePath.add_DrawItem({
    param($senderloc, $e)

    $e.DrawBackground()
    $text = $senderloc.Items[$e.Index]

    $textFormatFlags = [System.Windows.Forms.TextFormatFlags]::Right
    [System.Windows.Forms.TextRenderer]::DrawText($e.Graphics, $text, $e.Font, $e.Bounds, $e.ForeColor, $textFormatFlags)
    $e.DrawFocusRectangle()
})
$form.Controls.Add($comboboxlocalFilePath)

$labeladdargs = New-Object System.Windows.Forms.Label
$labeladdargs.Location = New-Object System.Drawing.Point(250, 328)
$labeladdargs.Size = New-Object System.Drawing.Size(60, 20)
$labeladdargs.Text = "Arguments"
$form.Controls.Add($labeladdargs)

$textboxaddargs = New-Object System.Windows.Forms.TextBox
$textboxaddargs.Location = New-Object System.Drawing.Point(310, 325)
$textboxaddargs.Size = New-Object System.Drawing.Size(245, 20)
$textboxaddargs.BackColor = [System.Drawing.Color]::Black
$textboxaddargs.ForeColor = [System.Drawing.Color]::lightseagreen
$form.Controls.Add($textboxaddargs)

$buttonSelectRemoteFile = New-Object System.Windows.Forms.Button
$buttonSelectRemoteFile.Text = "Browse Remote Files"
$buttonSelectRemoteFile.Size = New-Object System.Drawing.Size(80, 40)
$buttonSelectRemoteFile.Location = New-Object System.Drawing.Point(245, 180)
function Update-ListView {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string] $path
    )
    $listView.Items.Clear()
    $currentPathTextBox.Text = $path
    $items = Get-ChildItem -Path $path -Force -ErrorAction $InformationPreference
    foreach ($item in $items) {
        $listViewItem = New-Object System.Windows.Forms.ListViewItem($item.Name)
        $listViewItem.ImageIndex = if ($item.PSIsContainer) { 0 } else { 1 }
        
        if (-not $item.PSIsContainer) {
            # For files
            $listViewItem.SubItems.Add($item.Length.ToString())  # Size
        } else {
            # For directories
            $listViewItem.SubItems.Add("")  # Size
        }
        
        $listViewItem.SubItems.Add($item.LastWriteTime.ToString())  # Last Modified
        $listViewItem.SubItems.Add($item.LastAccessTime.ToString())  # Last Access Time
        $listViewItem.SubItems.Add($item.CreationTime.ToString())  # Creation Time
        $listViewItem.SubItems.Add($item.Attributes.ToString())  # Attributes

        $listViewItem.Tag = $item.FullName
        $listView.Items.Add($listViewItem) | Out-Null
    }
}

Function Get-RemoteResources {
    param($computerName)
    try {
        $resources = @()
        Invoke-Command -ComputerName $computerName -ScriptBlock {
            $drives = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root
            $drives
        } | ForEach-Object {
            $resources += $_
        }
        Invoke-Command -ComputerName $computerName -ScriptBlock {
            $shares = Get-CimInstance -ClassName Win32_Share | ForEach-Object {
                "\\$using:computerName\$($_.Name)"
            }
            $shares
        } | ForEach-Object {
            $resources += $_
        }
        return $resources
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Error: Failed to retrieve resources from the remote computer.")
        return @()
    }
}


$remoteComputer = ""
$remoteRootPath = ""
$script:currentPath = ""

$buttonSelectRemoteFile.Add_Click({
    $remoteComputer = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    if (-not $remoteComputer) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a remote computer name.")
        return
    }

    $remoteRootPath = "\\$remoteComputer\C$"
    $script:currentPath = $remoteRootPath

    $fileBrowserForm = New-Object System.Windows.Forms.Form
    $fileBrowserForm.Text = "Select a Remote File"
    $fileBrowserForm.ForeColor = [System.Drawing.Color]::lightseagreen   
    $fileBrowserForm.BackColor = [System.Drawing.Color]::Black
    $fileBrowserForm.Size = New-Object System.Drawing.Size(780, 590)
    $fileBrowserForm.FormBorderStyle = 'Fixed3D'
    $fileBrowserForm.StartPosition = "CenterScreen"

    $currentPathTextBox = New-Object System.Windows.Forms.TextBox
    $currentPathTextBox.Location = New-Object System.Drawing.Point(355, 510)
    $currentPathTextBox.Size = New-Object System.Drawing.Size(400, 23)
    $currentPathTextBox.ReadOnly = $true
    $fileBrowserForm.Controls.Add($currentPathTextBox)

    $listView = New-Object System.Windows.Forms.ListView
    $listView.View = [System.Windows.Forms.View]::Details
    $listView.BackColor = [System.Drawing.Color]::Black
    $listView.ForeColor = [System.Drawing.Color]::lightseagreen
    $listView.Size = New-Object System.Drawing.Size(750, 500) 
    $listView.Location = New-Object System.Drawing.Point(5, 5)
    $listView.FullRowSelect = $true
    $listView.Columns.Add("Name", 150) | Out-Null
    $listView.Columns.Add("Size", 75) | Out-Null
    $listView.Columns.Add("Last Modified", 140) | Out-Null
    $listView.Columns.Add("Last Access Time", 140) | Out-Null 
    $listView.Columns.Add("Creation Time", 140) | Out-Null
    $listView.Columns.Add("Attributes", 350) | Out-Null

    $listView.Add_DoubleClick({
        $selectedItem = $listView.SelectedItems[0]
        $selectedFile = $selectedItem.Tag
        if ($selectedItem.ImageIndex -eq 0) { # Directory
            $script:currentPath = $selectedFile
            Update-ListView -path $script:currentPath
        } else { # File
            $remotePath = $selectedFile.Replace($remoteRootPath, "C:")
            $textboxRemoteFilePath.Text = $remotePath
            $fileBrowserForm.Close()
        }
    })

    $backButton = New-Object System.Windows.Forms.Button
    $backButton.Text = "Back"
    $backButton.Location = New-Object System.Drawing.Point(5, 510)
    $backButton.Size = New-Object System.Drawing.Size(100, 23)

    $backButton.Add_Click({
        if (-not [String]::Equals($script:currentPath, $remoteRootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            $script:currentPath = Split-Path -Parent $script:currentPath
            Update-ListView -path $script:currentPath
        }
    })

    $driveComboBox = New-Object System.Windows.Forms.ComboBox
    $driveComboBox.Location = New-Object System.Drawing.Point(115, 510)
    $driveComboBox.Size = New-Object System.Drawing.Size(230, 23)
    $driveComboBox.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $driveComboBox.Add_SelectedIndexChanged({
    $script:currentPath = $driveComboBox.SelectedItem.ToString()
    Update-ListView -path $script:currentPath
    }) 

    $drives = Get-RemoteResources -computerName $remoteComputer
    $driveComboBox.Items.Clear()
    $driveComboBox.Items.AddRange($drives)

    if ($driveComboBox.Items.Count -gt 0) {
        $driveComboBox.SelectedIndex = 0
    }

$fileBrowserForm.Controls.Add($driveComboBox)
$fileBrowserForm.Controls.Add($backButton)
$fileBrowserForm.Controls.Add($listView)
$fileBrowserForm.Add_Shown({ Update-ListView -path $remoteRootPath })
$fileBrowserForm.ShowDialog()
})
$form.Controls.Add($buttonSelectRemoteFile)

$buttonSelectLocalFile = New-Object System.Windows.Forms.Button
$buttonSelectLocalFile.Text = "Browse Local Files"
$buttonSelectLocalFile.Size = New-Object System.Drawing.Size(80, 40)
$buttonSelectLocalFile.Location = New-Object System.Drawing.Point(245, 270)
$buttonSelectLocalFile.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "All files (*.*)|*.*"

    if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $selectedFile = $openFileDialog.FileName
        $comboboxlocalFilePath.Text = $selectedFile
    }
})

$form.Controls.Add($buttonSelectLocalFile)

# Create the JobIdLabel
$usernameLabel = New-Object System.Windows.Forms.Label
$usernameLabel.Location = New-Object System.Drawing.Point(53, 275)
$usernameLabel.Size = New-Object System.Drawing.Size(200, 15)
$usernameLabel.Text = "Enter or Select Username"
$form.Controls.Add($usernameLabel)

$comboboxUsername = New-Object System.Windows.Forms.ComboBox
$comboboxUsername.Location = New-Object System.Drawing.Point(15, 290)
$comboboxUsername.Size = New-Object System.Drawing.Size(215, 20)
$comboboxUsername.BackColor = [System.Drawing.Color]::Black
$comboboxUsername.ForeColor = [System.Drawing.Color]::lightseagreen
$form.Controls.Add($comboboxUsername)

# Password change button
$buttonPWChange = New-Object System.Windows.Forms.Button
$buttonPWChange.Location = New-Object System.Drawing.Point(15, 310)
$buttonPWChange.Size = New-Object System.Drawing.Size(55,40)
$buttonPWChange.Text = 'PW Reset'
$buttonPWChange.Add_Click({
    $selectedUser = if ($comboboxUsername.SelectedItem) {
        $comboboxUsername.SelectedItem.ToString()
    } else {
        $comboboxUsername.Text
    }
    Set-ADUser -Identity $selectedUser -ChangePasswordAtLogon $true
    $gotpwchng = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$Username forced a password change for $selectedUser at $gotpwchng" -ForegroundColor Cyan 
    Log_Message -logfile $logfile -Message "$Username forced a password change for $selectedUser"
    $textboxResults.AppendText("$Username forced a password change for $selectedUser at $gotpwchng")
})
$form.Controls.Add($buttonPWChange)

# Log off button
$buttonLogOff = New-Object System.Windows.Forms.Button
$buttonLogOff.Location = New-Object System.Drawing.Point(70, 310)
$buttonLogOff.Size = New-Object System.Drawing.Size(55, 40)
$buttonLogOff.Text = "Logoff"
$buttonLogOff.Add_Click({
    $selectedUser = if ($comboboxUsername.SelectedItem) {
        $comboboxUsername.SelectedItem.ToString()
    } else {
        $comboboxUsername.Text
    }
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }
    Invoke-Command -ComputerName $computerName -ScriptBlock {
        $username = $args[0]
        $userSessions = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
        foreach ($userSession in $userSessions) {
            if ($userSession -eq $username) {
                (Get-CimInstance -ClassName Win32_OperatingSystem -EnableAllPrivileges).Win32Shutdown(4)
            }
        }
    } -ArgumentList $selectedUser
    $gotlogoffusr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$Username logged $selectedUser off from $computerName at $gotlogoffusr" -ForegroundColor Cyan 
    Log_Message -logfile $logfile -Message "$Username logged $selectedUser off from $computerName"
    $textboxResults.AppendText("$Username logged $selectedUser off from $computerName at $gotlogoffusr")
})
$form.Controls.Add($buttonLogOff)

# Disable account button
$buttonDisableAcc = New-Object System.Windows.Forms.Button
$buttonDisableAcc.Location = New-Object System.Drawing.Point(125, 310)
$buttonDisableAcc.Size = New-Object System.Drawing.Size(55, 40)
$buttonDisableAcc.Text = "Disable"
$buttonDisableAcc.Add_Click({
    $selectedUser = if ($comboboxUsername.SelectedItem) {
        $comboboxUsername.SelectedItem.ToString()
    } else {
        $comboboxUsername.Text
    }
    Disable-ADAccount -Identity $selectedUser  
    $gotdisabusr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$Username disabled $selectedUser at $gotdisabusr" -ForegroundColor Cyan 
    Log_Message -logfile $logfile -Message "$Username disabled $selectedUser"
    $textboxResults.AppendText("$Username disabled $selectedUser at $gotdisabusr")
})
$form.Controls.Add($buttonDisableAcc)

# Enable account button
$buttonEnableAcc = New-Object System.Windows.Forms.Button
$buttonEnableAcc.Location = New-Object System.Drawing.Point(180, 310)
$buttonEnableAcc.Size = New-Object System.Drawing.Size(50, 40)
$buttonEnableAcc.Text = "Enable"
$buttonEnableAcc.Add_Click({
    $selectedUser = if ($comboboxUsername.SelectedItem) {
        $comboboxUsername.SelectedItem.ToString()
    } else {
        $comboboxUsername.Text
    }
    Enable-ADAccount -Identity $selectedUser
    $gotenabusr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "$Username enabled $selectedUser at $gotenabusr" -ForegroundColor Cyan 
    Log_Message -logfile $logfile -Message "$Username enabled $selectedUser"
    $textboxResults.AppendText("$Username enabled $selectedUser at $gotenabusr")
})
$form.Controls.Add($buttonEnableAcc)


$buttonSysInfo = New-Object System.Windows.Forms.Button
$buttonSysInfo.Location = New-Object System.Drawing.Point(315, 20)
$buttonSysInfo.Size = New-Object System.Drawing.Size(80, 40)
$buttonSysInfo.Text = "Recon"
$buttonSysInfo.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    if (![string]::IsNullOrEmpty($computerName)) {
        try {
            # Gather system info
            $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $computerName | Select-Object -Property Name,PrimaryOwnerName,Domain,Model,Manufacturer 
            $textboxResults.AppendText("System Information: `r`n$( $systemInfo | Out-String)")

            # Gather specified AD host info
            $adEntry = Get-ADComputer -Filter "Name -eq '$computerName'" -Properties Name, DNSHostName, IPv4Address, Created, Description, DistinguishedName, Enabled, OperatingSystem, OperatingSystemVersion, SID
            $textboxResults.AppendText("Host AD Information: `r`n$( $adEntry | Out-String)")

            # Enumerate all users known to the system
            $allUsers = Get-CimAssociatedInstance -CimInstance (Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $computerName) -ResultClassName Win32_UserAccount

            # Clear existing users from combobox
            $comboboxUsername.Items.Clear()

            # Gather specified user AD info for each user
            $adUserEntries = @()
            foreach ($user in $allUsers) {
                try {
                    $adUserEntry = Get-ADUser -Identity $user.Name -Properties SamAccountName, whenCreated, Description, Enabled, GivenName, Surname, DisplayName, EmailAddress
                    $textboxResults.AppendText("User AD Information for $($user.Name) `r`n$( $adUserEntry | Out-String)")

                    # Add user to combobox
                    $comboboxUsername.Items.Add($adUserEntry.SamAccountName)

                    # Append user info to array for later export
                    $adUserEntries += $adUserEntry
                } catch {
                    $textboxResults.AppendText("")
                }
            }

            New-Item -ItemType Directory -Path ".\Logs\Reports\$computerName\ADRecon" -Force | Out-Null

            # Export to Excel
            $systemInfo | Export-Excel -Path ".\Logs\Reports\$computerName\ADRecon\SysUserADInfo.xlsx"-WorksheetName 'System Info' -AutoSize -AutoFilter -TableStyle Medium6
            $adEntry | Export-Excel -Path ".\Logs\Reports\$computerName\ADRecon\SysUserADInfo.xlsx" -WorksheetName 'Host AD Info' -AutoSize -AutoFilter -TableStyle Medium6 -Append
            $adUserEntries | Export-Excel -Path ".\Logs\Reports\$computerName\ADRecon\SysUserADInfo.xlsx" -WorksheetName 'User AD Info' -AutoSize -AutoFilter -TableStyle Medium6 -Append

            # Print completion message
            $textboxResults.AppendText("System and User AD Information exported to Excel workbook at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n")
        } catch {
            $textboxResults.AppendText("Error obtaining system information: $_`r`n")
        }
    }    
})
$form.Controls.Add($buttonSysInfo)

$buttonViewProcesses = New-Object System.Windows.Forms.Button
$buttonViewProcesses.Location = New-Object System.Drawing.Point(395, 20)
$buttonViewProcesses.Size = New-Object System.Drawing.Size(80, 40)
$buttonViewProcesses.Text = "View Processes"
$buttonViewProcesses.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    if (![string]::IsNullOrEmpty($computerName)) {
        try {
            $processes = Get-CimInstance -ClassName Win32_Process -ComputerName $computerName -ErrorAction Stop | Select-Object ProcessId, Name, CommandLine
            $dropdownProcessId.Items.Clear()
            foreach ($process in $processes) {
                $dropdownProcessId.Items.Add("$($process.ProcessId) - $($process.Name)")
            }
            $processesString = $processes | Out-String
            $textboxResults.AppendText($processesString)
            $gotproc = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "Processes listed from $computerName at $gotproc" -ForegroundColor Cyan 
            Log_Message -logfile $logfile -Message "Processes listed from $computerName"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error while trying to retrieve processes: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})
$form.Controls.Add($buttonViewProcesses)

$buttonRestart = New-Object System.Windows.Forms.Button
$buttonRestart.Location = New-Object System.Drawing.Point(475, 20)
$buttonRestart.Size = New-Object System.Drawing.Size(80, 40)
$buttonRestart.Text = "Restart Host"
$buttonRestart.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    if (![string]::IsNullOrEmpty($computerName)) {
        try {
            $osInstance = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computerName -ErrorAction Stop
            $result = Invoke-CimMethod -CimInstance $osInstance -MethodName "Win32Shutdown" -Arguments @{Flags = 6} -ErrorAction Stop
            if ($result.ReturnValue -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("Restart command sent successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                $restart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Write-Host "Restarted $computerName at $restart" -ForegroundColor Cyan 
                Log_Message -logfile $logfile -Message "Restarted $computerName"
                $textboxResults.AppendText("Restarted $computerName at $restart")
            } else {
                [System.Windows.Forms.MessageBox]::Show("Failed to send restart command. Return value: $($result.ReturnValue)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error while trying to send restart command: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})
$form.Controls.Add($buttonRestart)

$buttonKillProcess = New-Object System.Windows.Forms.Button
$buttonKillProcess.Location = New-Object System.Drawing.Point(315, 60)
$buttonKillProcess.Size = New-Object System.Drawing.Size(80, 40)
$buttonKillProcess.Text = "Kill Process"
$buttonKillProcess.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }
    
    $selectedProcess = if ($dropdownProcessId.SelectedItem) {
        $dropdownProcessId.SelectedItem.ToString()
    } else {
        $dropdownProcessId.Text
    }

    if (![string]::IsNullOrEmpty($computerName) -and ![string]::IsNullOrEmpty($selectedProcess)) {
        $processId = $selectedProcess.split()[0]
        $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $processId" -ComputerName $computerName -ErrorAction $InformationPreference
        if ($process) {
            try {
                $result = Invoke-CimMethod -CimInstance $process -MethodName "Terminate" -ErrorAction Stop
                if ($result.ReturnValue -eq 0) {
                    [System.Windows.Forms.MessageBox]::Show("Process terminated successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                    $prockill = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Write-Host "Terminated $selectedProcess from $computerName at $prockill" -ForegroundColor Cyan 
                    Log_Message -logfile $logfile -Message "Terminated $selectedProcess from $computerName"
                } else {
                    [System.Windows.Forms.MessageBox]::Show("Failed to terminate the process. Return value: $($result.ReturnValue)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                }
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Error while trying to terminate the process: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        } else {
            [System.Windows.Forms.MessageBox]::Show("Process not found on the specified computer.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})
$form.Controls.Add($buttonKillProcess)

$buttonCopyBinaries = New-Object System.Windows.Forms.Button
$buttonCopyBinaries.Location = New-Object System.Drawing.Point(395, 60)
$buttonCopyBinaries.Size = New-Object System.Drawing.Size(80, 40)
$buttonCopyBinaries.Text = "Copy All Modules"
function CopyModules {
    param (
        [string]$computerName,
        [string]$CopiedFilesPath
    )

    $uniqueModules = Invoke-Command -ComputerName $computerName -ScriptBlock {
        Get-Process | ForEach-Object { $_.Modules } | Select-Object -Unique -ExpandProperty FileName
    }

    $uniqueModules | ForEach-Object -ThrottleLimit 100 -Parallel {
        $modulePath = $_
        if (![string]::IsNullOrEmpty($modulePath)) {
            # Convert the drive letter path to UNC format
            $driveLetter = $modulePath.Substring(0, 1)
            $uncPath = "\\$using:computerName\$driveLetter$" + $modulePath.Substring(2)

            $moduleFilename = [System.IO.Path]::GetFileName($modulePath)
            $destinationPath = Join-Path -Path $using:CopiedFilesPath -ChildPath $moduleFilename

            Copy-Item $uncPath -Destination $destinationPath -Force -ErrorAction $InformationPreference
        }
    }
}

$buttonCopyBinaries.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }
    $copytreestart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "Started copying all modules from $computerName at $copytreestart" -ForegroundColor Cyan 
            Log_Message -logfile $logfile -Message "Copied all modules from $computerName"

    $CopiedFilesPath = $CopiedFilesDir

    if (![string]::IsNullOrEmpty($computerName) -and ![string]::IsNullOrEmpty($CopiedFilesPath)) {
        try {
            CopyModules -computerName $computerName -CopiedFilesPath $CopiedFilesPath

            
            $copytreesend = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "Copied all modules from $computerName at $copytreesend" -ForegroundColor Cyan 
            [System.Windows.Forms.MessageBox]::Show("All uniquely pathed modules copied to the CopiedFiles folder.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            Log_Message -logfile $logfile -Message "Copied all modules from $computerName"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error while trying to copy modules to the CopiedFiles folder: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please enter a valid computer name and CopiedFiles path.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$form.Controls.Add($buttonCopyBinaries)


$buttonShutdown = New-Object System.Windows.Forms.Button
$buttonShutdown.Location = New-Object System.Drawing.Point(475, 60)
$buttonShutdown.Size = New-Object System.Drawing.Size(80, 40)
$buttonShutdown.Text = "Shutdown Host"
$buttonShutdown.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    if (![string]::IsNullOrEmpty($computerName)) {
        try {
            $osInstance = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computerName -ErrorAction Stop
            $result = Invoke-CimMethod -CimInstance $osInstance -MethodName "Win32Shutdown" -Arguments @{Flags = 12} -ErrorAction Stop
            if ($result.ReturnValue -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("Shutdown command sent successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                $shutdown = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Write-Host "Shutdown $computerName at $shutdown" -ForegroundColor Cyan 
                Log_Message -logfile $logfile -Message "Shutdown $computerName"
                $textboxResults.AppendText("Shutdown $computerName at $shutdown")
            } else {
                [System.Windows.Forms.MessageBox]::Show("Failed to send shutdown command. Return value: $($result.ReturnValue)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error while trying to send shutdown command: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    }
})
$form.Controls.Add($buttonShutdown)

$buttonCopyFile = New-Object System.Windows.Forms.Button
$buttonCopyFile.Location = New-Object System.Drawing.Point(330, 180)
$buttonCopyFile.Size = New-Object System.Drawing.Size(75, 40)
$buttonCopyFile.Text = "Copy"
$buttonCopyFile.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }
    
    # Trim trailing backslash if it exists
    $filePath = $textboxremoteFilePath.Text.TrimEnd('\')

    $filecopy = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Copied $filePath from $computerName at $filecopy" -ForegroundColor Cyan 
    Log_Message -logfile $logfile -Message "Copied $filePath from $computerName"

    if (![string]::IsNullOrEmpty($computerName) -and ![string]::IsNullOrEmpty($filePath)) {
        # Convert drive letter path to UNC format
        $driveLetter = $filePath.Substring(0, 1)
        $uncPath = "\\$computerName\$driveLetter$" + $filePath.Substring(2)
        try {
            if ((Test-Path -Path $uncPath) -and (Get-Item -Path $uncPath).PSIsContainer) {
                # It's a directory
                $copyDecision = [System.Windows.Forms.MessageBox]::Show("Do you want to copy the directory and all its child directories? Select No to only copy files from specified directory", "Copy Directory Confirmation", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Question)
                if ($copyDecision -eq "Yes") {
                    # Copy directory and child directories
                    Copy-Item -Path $uncPath -Destination $CopiedFilesDir -Force -Recurse
                } elseif ($copyDecision -eq "No") {
                    # Copy only the files in the directory, not any subdirectories
                    Get-ChildItem -Path $uncPath -File | ForEach-Object {
                        Copy-Item -Path $_.FullName -Destination $CopiedFilesDir -Force
                    }
                } else {
                    # Cancel operation
                    return
                }
            } else {
                # It's a file
                Copy-Item -Path $uncPath -Destination $CopiedFilesDir -Force
            }

            [System.Windows.Forms.MessageBox]::Show("File '$filePath' copied to local directory.", "Copy File Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            $textboxResults.AppendText("File '$filePath' copied to local directory.`r`n")
            $filecopy = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "Copied $filePath from $computerName at $filecopy" -ForegroundColor Cyan 
            Log_Message -logfile $logfile -Message "Copied $filePath from $computerName"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error copying file '$filePath' to local directory: $_", "Copy File Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            $textboxResults.AppendText("Error copying file '$filePath' to local directory: $_`r`n")
        }
    }
})
$form.Controls.Add($buttonCopyFile)

$buttonDeleteFile = New-Object System.Windows.Forms.Button
$buttonDeleteFile.Location = New-Object System.Drawing.Point(480, 180)
$buttonDeleteFile.Size = New-Object System.Drawing.Size(75, 40)
$buttonDeleteFile.Text = "Delete"
$buttonDeleteFile.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }
    $filePath = $textboxremoteFilePath.Text

    if (![string]::IsNullOrEmpty($computerName) -and ![string]::IsNullOrEmpty($filePath)) {
        # Extract filename from path
        $filename = [System.IO.Path]::GetFileName($filePath)
        try {
            $result = [System.Windows.Forms.MessageBox]::Show("Do you want to delete '$filePath'?", "Delete File or Directory", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
            if ($result -eq "Yes") {
                Invoke-Command -ComputerName $computerName -ScriptBlock { param($path) Remove-Item -Path $path -Recurse -Force -ErrorAction Stop } -ArgumentList $filePath
                [System.Windows.Forms.MessageBox]::Show("'$filename' deleted from remote host.", "Delete Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                $textboxResults.AppendText("'$filename' deleted from remote host.`r`n")
            }
            $filedelete = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "Deleted $filePath from $computerName at $filedelete" -ForegroundColor Cyan 
            Log_Message -logfile $logfile -Message "Deleted $filePath from $computerName"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error deleting '$filename' from remote host: $_", "Delete Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            $textboxResults.AppendText("Error deleting '$filename' from remote host: $_`r`n")
        }
    }
})
$form.Controls.Add($buttonDeleteFile)

$buttonHuntFile = New-Object System.Windows.Forms.Button
$buttonHuntFile.Location = New-Object System.Drawing.Point(405, 180)
$buttonHuntFile.Size = New-Object System.Drawing.Size(75, 40)
$buttonHuntFile.Text = "Hunt File"
$buttonHuntFile.Add_Click({
    $remoteComputer = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }
    $remoteFilePath = $textboxRemoteFilePath.Text
    $drivelessPath = Split-Path $remoteFilePath -NoQualifier
    $driveLetter = Split-Path $remoteFilePath -Qualifier
    $filehunt = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Hunting for file: $remoteFilePath at $filehunt" -ForegroundColor Cyan
    $textboxResults.AppendText("Hunting for file: $remoteFilePath at $filehunt `r`n")
    Log_Message -logfile $logfile -Message "Hunting for file: $remoteFilePath"
    if (![string]::IsNullOrEmpty($remoteComputer) -and ![string]::IsNullOrEmpty($remoteFilePath)) {
        $localPath = '.\CopiedFiles'
        if (!(Test-Path $localPath)) {
            New-Item -ItemType Directory -Force -Path $localPath
        }

        try {
            $fileExists = Invoke-Command -ComputerName $remoteComputer -ScriptBlock {
                param($path)
                Test-Path -Path $path
            } -ArgumentList $remoteFilePath -ErrorAction Stop
        } catch {
            Write-Error "Failed to check if the file exists on the remote computer: $_"
            return
        }

        if ($fileExists) {
            $destination = Join-Path -Path $localPath -ChildPath (Split-Path $remoteFilePath -Leaf)
            Copy-Item -Path "\\$remoteComputer\$($remoteFilePath.Replace(':', '$'))" -Destination $destination -Force
            $textboxResults.AppendText("$remoteFilePath copied from $remoteComputer.")
            Log_Message -Message "$remoteFilePath copied from $remoteComputer" -LogFilePath $LogFile
            Write-Host "$remoteFilePath copied from $remoteComputer" -ForegroundColor -Cyan
        } else {
            $foundInRecycleBin = $false

            try {
                $recycleBinItems = Invoke-Command -ComputerName $remoteComputer -ScriptBlock {
                    Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force | Where-Object { $_.PSIsContainer -eq $false -and $_.Name -like "$I*" } | ForEach-Object {
                        $originalFilePath = Get-Content $_.FullName -ErrorAction $InformationPreference | Select-Object -First 1
                        $originalFilePath = $originalFilePath -replace '^[^\:]*\:', '' # Remove non-printable characters before the colon
                        [PSCustomObject]@{
                            Name = $_.Name
                            FullName = $_.FullName
                            OriginalFilePath = $originalFilePath
                        }
                    }
                } -ErrorAction Stop
            } catch {
                Write-Error "Failed to retrieve the items from the recycle bin: $_ `r`n"
                return
            }

            $recycleBinItem = $recycleBinItems | Where-Object { $_.OriginalFilePath -eq "$drivelessPath" }
            if ($recycleBinItem) {
                Write-Host "Match found in Recycle Bin: $($recycleBinItem.Name)" -Foregroundcolor Cyan
                $textboxResults.AppendText("Match found in Recycle Bin: $($recycleBinItem.Name) `r`n")
                $foundInRecycleBin = $true
            }

            if (!$foundInRecycleBin) {
                $textboxResults.AppendText("File not found in the remote computer or recycle bin. `r`n")
            } else {
                try {
                    $vssServiceStatus = Invoke-Command -ComputerName $remoteComputer -ScriptBlock {
                        $service = Get-Service -Name VSS
                        $status = $service.Status
                        return $status
                    } 
                    
                    $statusCodes = @{
                        1 = "Stopped"
                        2 = "Start Pending"
                        3 = "Stop Pending"
                        4 = "Running"
                        5 = "Continue Pending"
                        6 = "Pause Pending"
                        7 = "Paused"
                    }
                    
                    # Use the hash table to get the corresponding status name
                    $vssServiceStatusName = $statusCodes[$vssServiceStatus]
                    
                    # Print the status name
                    Write-Host "VSS service status: $vssServiceStatusName" -ForegroundColor Cyan
                    $textboxResults.AppendText("VSS service status on $remoteComputer $vssServiceStatusName `r`n")

                    if ($vssServiceStatus -eq 'Running') {
                        $shadowCopyFileExists = Invoke-Command -ComputerName $remoteComputer -ScriptBlock {
                            param($path, $driveLetter)
                            $shadowCopies = vssadmin list shadows /for=$driveLetter | Where-Object { $_ -match 'GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\\d+' }
                            foreach ($shadowCopy in $shadowCopies) {
                                $shadowCopyPath = $shadowCopy -replace '.*?(GLOBALROOT\\Device\\HarddiskVolumeShadowCopy\\d+).*', '$1'
                                if (Test-Path -Path "$shadowCopyPath\$path") {
                                    return $shadowCopyPath
                                }
                            }
                        } -ArgumentList $drivelessPath, $driveLetter -ErrorAction Stop

                        if ($shadowCopyFileExists) {
                            Write-Host "Shadow copy found: $shadowCopyFileExists" -ForegroundColor Cyan
                            $textboxResults.AppendText("Shadow copy found: $shadowCopyFileExists `r`n")
                        } else {
                            Write-Host "No shadow copy found for the file." -ForegroundColor Red
                            $textboxResults.AppendText("No shadow copy found for the file. `r`n")
                        }
                    }
                } catch {
                    Write-Error "Failed to check VSS service or shadow copies: $_"
                    return
                }
            $restorePoints = Invoke-Expression -Command "wmic /Namespace:\\root\default Path SystemRestore get * /format:list"
            if ($restorePoints) {
                Write-Host "System Restore points exist on $remoteComputer" -ForegroundColor Cyan
                $textboxResults.AppendText("System Restore points exist on $remoteComputer `r`n")
            } else {
                Write-Host "No System Restore points found." -ForegroundColor Red
                $textboxResults.AppendText("No System Restore points found. `r`n")
            }
            $lastBackup = Invoke-Expression -Command "wbadmin get versions"
            if ($lastBackup) {
                Write-Host "Backups exist on $remoteComputer" -ForegroundColor Cyan
                $textboxResults.AppendText("Backups exist on $remoteComputer `r`n")
            } else {
                Write-Host "No backups found." -ForegroundColor Red
                $textboxResults.AppendText("No backups found. `r`n")
            }
            }
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please enter a remote computer name and file path.", "Missing Information", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    $fileput = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    write-host "File Hunt completed at $fileput" -ForegroundColor Green 
    Log_Message -logfile $logfile -Message "File Hunt completed"
    $textboxResults.AppendText("File Hunt completed at $fileput `r`n")
})
$form.Controls.Add($buttonHuntFile)


$buttonPlaceFile = New-Object System.Windows.Forms.Button
$buttonPlaceFile.Location = New-Object System.Drawing.Point(330, 355)
$buttonPlaceFile.Size = New-Object System.Drawing.Size(75, 40)
$buttonPlaceFile.Text = "Place File"
$buttonPlaceFile.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }
    $selectedFile = if ($comboboxlocalFilePath.SelectedItem) {
        $comboboxlocalFilePath.SelectedItem.ToString()
    } else {
        $comboboxlocalFilePath.Text
    }
    $remoteFilePath = $textboxRemoteFilePath.Text

    if (![string]::IsNullOrEmpty($computerName) -and ![string]::IsNullOrEmpty($selectedFile) -and ![string]::IsNullOrEmpty($remoteFilePath)) {
        $filename = [System.IO.Path]::GetFileName($selectedFile)
        $remoteDriveLetter = $remoteFilePath.Substring(0, 1)
        $remoteUncPath = "\\$computerName\$remoteDriveLetter$" + $remoteFilePath.Substring(2)

        try {
            Copy-Item -Path $selectedFile -Destination $remoteUncPath -Force
            [System.Windows.Forms.MessageBox]::Show("File '$filename' copied to remote directory.", "Place File Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            $textboxResults.AppendText("File '$filename' copied to remote directory.`r`n")
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error copying file '$filename' to remote directory: $($_.Exception.Message)", "Place File Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            $textboxResults.AppendText("Error copying file '$filename' to remote directory: $($_.Exception.Message)`r`n")
            $fileput = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "Copied $selectedFile from localhost to $remoteFilePath on $computerName at $fileput" -ForegroundColor Cyan 
            Log_Message -logfile $logfile -Message "Copied $selectedFile from localhost to $remoteFilePath on $computerName"
        }
    }
})
$form.Controls.Add($buttonPlaceFile)

$buttonPlaceAndRun = New-Object System.Windows.Forms.Button
$buttonPlaceAndRun.Location = New-Object System.Drawing.Point(405, 355)
$buttonPlaceAndRun.Size = New-Object System.Drawing.Size(75, 40)
$buttonPlaceAndRun.Text = "Place and Run"
$buttonPlaceAndRun.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }
    $localFilePath = if ($comboboxlocalFilePath.SelectedItem) {
        $comboboxlocalFilePath.SelectedItem.ToString()
    } else {
        $comboboxlocalFilePath.Text
    }
    $remoteFilePath = $textboxRemoteFilePath.Text
    $additionalArgs = $textboxaddargs.Text

    if (![string]::IsNullOrEmpty($computerName) -and ![string]::IsNullOrEmpty($localFilePath) -and ![string]::IsNullOrEmpty($remoteFilePath)) {
        $filename = [System.IO.Path]::GetFileName($localFilePath)
        $fileExtension = [System.IO.Path]::GetExtension($localFilePath).ToLower()
        $remoteDriveLetter = $remoteFilePath.Substring(0, 1)
        $remoteDirectoryPath = "\\$computerName\$remoteDriveLetter$" + $remoteFilePath.Substring(2)
        $remoteUncPath = Join-Path -Path $remoteDirectoryPath -ChildPath $filename

        try {
            if ($fileExtension -eq ".ps1") {
                $dialogResult = [System.Windows.Forms.MessageBox]::Show("Would you like to execute the script in-memory (fileless)?", "Fileless Execution", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)
                if ($dialogResult -eq "Yes") {
                    # Read PS1 file and convert to Base64
                    $scriptContent = Get-Content $localFilePath -Raw
                    # Create a script block that calls the original script with arguments
                    $scriptWithArgs = "$scriptContent; & { $scriptContent } $additionalArgs"
                    $bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptWithArgs)
                    $encodedCommand = [Convert]::ToBase64String($bytes)
                    $commandLine = "powershell.exe -EncodedCommand $encodedCommand"
                }
                else {
                    # Normal execution
                    Copy-Item -Path $localFilePath -Destination $remoteUncPath -Force
                    $commandLine = "powershell.exe -File $remoteUncPath $additionalArgs"
                }
            }
            else {
                Copy-Item -Path $localFilePath -Destination $remoteUncPath -Force
                switch ($fileExtension) {
                    ".cmd" { $commandLine = "cmd.exe /c $remoteUncPath $additionalArgs" }
                    ".bat" { $commandLine = "cmd.exe /c $remoteUncPath $additionalArgs" }
                    ".js" { $commandLine = "cscript.exe $remoteUncPath $additionalArgs" }
                    ".vbs" { $commandLine = "cscript.exe $remoteUncPath $additionalArgs" }
                    ".dll" { $commandLine = "rundll32.exe $remoteUncPath,$additionalArgs" }
                    ".py" { $commandLine = "python $remoteUncPath $additionalArgs" }
                    
                    default { $commandLine = "$remoteUncPath $additionalArgs" }
                }
            }
            $session = New-CimSession -ComputerName $computerName
            $newProcess = $session | Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $commandLine}
            $returnValue = $newProcess.ReturnValue
            if ($returnValue -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("File '$filename' executed successfully on the remote computer with additional arguments: $additionalArgs", "Execution Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
                $textboxResults.AppendText("File '$filename' executed successfully on the remote computer with additional arguments: $additionalArgs `r`n")
            } else {
                throw "Error executing file on remote computer. Error code: $returnValue"
            }
            $session | Remove-CimSession
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error executing file '$filename' on the remote computer: $($_.Exception.Message)", "Execution Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            $textboxResults.AppendText("Error executing file '$filename' on the remote computer: $($_.Exception.Message)`r`n")
        }
    }
})
$form.Controls.Add($buttonPlaceAndRun)

$executeCommandButton = New-Object System.Windows.Forms.Button
$executeCommandButton.Text = "Execute Oneliner"
$executeCommandButton.Location = New-Object System.Drawing.Point(480, 355)
$executeCommandButton.Size = New-Object System.Drawing.Size(75, 40)
$executeCommandButton.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    if (-not $computerName) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a remote computer name.")
        return
    }

    $command = $textboxaddargs.Text

    if (-not $command) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a command to execute.")
        return
    }

    try {
        $result = Invoke-Command -ComputerName $computerName -ScriptBlock {
            param($Command)
            $output = $null

            $processInfo = New-Object System.Diagnostics.ProcessStartInfo
            $processInfo.FileName = "powershell.exe"
            $processInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command $Command"
            $processInfo.RedirectStandardOutput = $true
            $processInfo.RedirectStandardError = $true
            $processInfo.UseShellExecute = $false
            $processInfo.CreateNoWindow = $true

            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $processInfo
            $process.Start() | Out-Null

            $stdout = $process.StandardOutput.ReadToEnd()
            $stderr = $process.StandardError.ReadToEnd()

            $process.WaitForExit()

            if ($stderr) {
                $output = "Error: $stderr"
            } elseif ($stdout) {
                $output = $stdout
            }

            $output
        } -ArgumentList $command

        if ($result -and $result.Trim()) {
            $textboxResults.AppendText("$command executed. $remoteComputer responded with:`n$result")
            Log_Message -Message "$remoteFilePath copied from $remoteComputer $result" -LogFilePath $LogFile
        } else {
            $textboxResults.AppendText("$command executed without a reported error from $remoteComputer but there is no response to display")
            Log_Message -Message  "$command executed without a reported error from $remoteComputer but there is no response to display" -LogFilePath $LogFile
        }
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        $textboxResults.AppendText("Error executing command: $ErrorMessage")
    }
})
$form.Controls.Add($executeCommandButton)

$buttonInstallSysmon = New-Object System.Windows.Forms.Button
$buttonInstallSysmon.Location = New-Object System.Drawing.Point(160, 140)
$buttonInstallSysmon.Size = New-Object System.Drawing.Size(70, 40)
$buttonInstallSysmon.Text = "Deploy Sysmon"
$buttonInstallSysmon.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    if (![string]::IsNullOrEmpty($computerName)) {
        try {
            # Set the local paths for Sysmon and the configuration file
            $sysmonPath = "$CWD\Tools\Sysmon\Sysmon64.exe"
            $configPath = "$CWD\Tools\Sysmon\sysmonconfig.xml"

            # Copy Sysmon and the config to the remote computer
            $remoteSysmonPath = "\\$computerName\C$\Windows\Temp\Sysmon64.exe"
            $remoteConfigPath = "\\$computerName\C$\Windows\Temp\sysmonconfig-export.xml"

            Copy-Item -Path $sysmonPath -Destination $remoteSysmonPath -Force
            Copy-Item -Path $configPath -Destination $remoteConfigPath -Force

            # Deploy and run Sysmon on the remote computer
            Invoke-Command -ComputerName $computerName -ScriptBlock {
                $sysmonPath = "C:\Windows\Temp\Sysmon64.exe"
                $configPath = "C:\Windows\Temp\sysmonconfig-export.xml"

                Start-Process -FilePath $sysmonPath -ArgumentList "-accepteula -i $configPath" -NoNewWindow -Wait -PassThru
            } -ErrorAction Stop

            [System.Windows.Forms.MessageBox]::Show("Sysmon installed and running with the configuration on the remote computer.", "Installation Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            $textboxResults.AppendText("Sysmon installed and running with the configuration on the remote computer.`r`n")
            $sysmonstart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "Sysmon started with the configuration on $computerName at $sysmonstart" -ForegroundColor Cyan
            Log_Message -logfile $logfile -Message "Sysmon started with the configuration on $computerName"
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error installing and running Sysmon on the remote computer: $_", "Installation Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            $textboxResults.AppendText("Error installing and running Sysmon on the remote computer: $_`r`n")
        }
    }
})
$form.Controls.Add($buttonInstallSysmon)

# Function to calculate SHA256 hash
function Get-FileHashSHA256 {
    param (
        [String]$FilePath
    )
    
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create("SHA256")
    $fileStream = New-Object -TypeName System.IO.FileStream -ArgumentList $FilePath, 'Open'
    $hash = $hasher.ComputeHash($fileStream)
    $fileStream.Close()
    return ([BitConverter]::ToString($hash)).Replace("-", "")
}

function Get-File($path) {
    $file = Get-Item $path
    $fileType = New-Object -TypeName PSObject -Property @{
        IsText = $file.Extension -in @(".txt", ".csv", ".log", ".evtx", ".xlsx", ".xml", ".json", ".html", ".htm", ".md", ".ps1", ".bat", ".css", ".js")  # Add any other text file extensions you want to support
    }
    return $fileType
}

$buttonIntelligizer = New-Object System.Windows.Forms.Button
$buttonIntelligizer.Location = New-Object System.Drawing.Point(160, 355)
$buttonIntelligizer.Size = New-Object System.Drawing.Size(70,40)
$buttonIntelligizer.Text = "Intelligazer"
$buttonIntelligizer.Add_Click({
    # Create an ArrayList for output
    $output = New-Object System.Collections.ArrayList
    $patterns = @{
        'HTTP/S' = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        'FTP' = 'ftp://(?:[a-zA-Z0-9]+:[a-zA-Z0-9]+@)?(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+(?::[0-9]{1,5})?(?:/[^\s]*)?'
        'SFTP' = 'sftp://(?:[a-zA-Z0-9]+:[a-zA-Z0-9]+@)?(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+(?::[0-9]{1,5})?(?:/[^\s]*)?'
        'SCP' = 'scp://(?:[a-zA-Z0-9]+:[a-zA-Z0-9]+@)?(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+(?::[0-9]{1,5})?(?:/[^\s]*)?'
        'DATA' = 'data://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        'SSH' = 'ssh://(?:[a-zA-Z0-9]+:[a-zA-Z0-9]+@)?(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+(?::[0-9]{1,5})?'
        'LDAP' = 'ldap://(?:[a-zA-Z0-9]+:[a-zA-Z0-9]+@)?(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+(?::[0-9]{1,5})?(?:/[^\s]*)?'
        'RFC 1918 IP Address' = '\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'
        'Non-RFC 1918 IP Address' = '\b((?!10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        'Email' = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    }

    # Prompt user to include File Path pattern
    $includeFilePath = [System.Windows.Forms.MessageBox]::Show("Do you want to include File Paths?", "Include File Paths", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)

    if ($includeFilePath -eq 'Yes') {
        $patterns['File Path'] = '(file:///)?(?![sSpP]:)[a-zA-Z]:[\\\\/].+?\.[a-zA-Z0-9]{2,5}(?=[\s,;]|$)'


    }    

    # Rest of your code continues here
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    Remove-Item .\Logs\Reports\$computerName\indicators.html -ErrorAction SilentlyContinue 
    New-Item -ItemType Directory -Path ".\Logs\Reports\$computerName\" -Force | Out-Null
    $Intelligazerstart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Intelligazer started at $Intelligazerstart" -ForegroundColor Cyan
    Log_Message -logfile $logfile -Message "Intelligazer started at "
    $textboxResults.AppendText("Intelligazer started at $Intelligazerstart `r`n")
    $logDirs = ".\Logs\Reports\$computerName\ProcessAssociations", ".\Logs\EVTX\$computerName", ".\Logs\Reports\$computerName\RapidTriage", ".\Logs\Reports\$computerName\ADRecon"
    
    
function processMatches($content, $file) {
    $matchList = New-Object System.Collections.ArrayList
    foreach ($type in $patterns.Keys) {
        $pattern = $patterns[$type]
        $matchResults = [regex]::Matches($content, $pattern) | ForEach-Object {$_.Value}
        foreach ($match in $matchResults) {
            $newObject = New-Object PSObject -Property @{
                'Source File' = $file
                'Data' = $match
                'Type' = $type
            }
            if ($null -ne $newObject) {
                [void]$matchList.Add($newObject)
            }

            # If the type is URL, extract the parent domain and add it as a separate indicator
            if ($type -eq 'HTTP/S' -and $match -match '(?i)(?:http[s]?://)?(?:www.)?([^/]+)') {
                $parentDomain = $matches[1]
                $domainObject = New-Object PSObject -Property @{
                    'Source File' = $file
                    'Data' = $parentDomain
                    'Type' = 'Domain'
                }
                if ($null -ne $domainObject) {
                    [void]$matchList.Add($domainObject)
                }
            }
        }
    }
    return $matchList
}

    foreach ($dir in $logDirs) {
        $files = Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName 
        foreach ($file in $files) {
            switch -regex ($file) {
                '\.sqlite$' {
                    $tableNames = Invoke-SqliteQuery -DataSource $file -Query "SELECT name FROM sqlite_master WHERE type='table';"
                    foreach ($tableName in $tableNames.name) {
                        try {
                            $query = "SELECT * FROM [$tableName]"
                            $data = Invoke-SqliteQuery -DataSource $file -Query $query -ErrorAction Stop
                            $content = $data | Out-String
                            $matchess = processMatches $content $file
                            if ($matchess -ne $null) {
                                $output.AddRange(@($matchess))
                            } 
                        } catch {
                            #Add error message if desired
                        }
                    }
                }
                '\.(csv|txt|json|evtx|html)$' {
                    if ($file -match "\.evtx$") {
                        try {
                            $content = Get-WinEvent -Path $file -ErrorAction Stop | Format-List | Out-String
                        } catch {
                            Write-Host "No events found in $file" -ForegroundColor Magenta
                            continue
                        }
                    } else {
                        $content = Get-Content $file
                    }
                    $matchess = processMatches $content $file
                    if ($matchess -ne $null) {
                        $output.AddRange(@($matchess))
                    }
                }
                '\.xlsx$' {
                    $excel = New-Object -ComObject Excel.Application
                    $workbook = $excel.Workbooks.Open($file)
                
                    foreach ($sheet in $workbook.Worksheets) {
                        try {
                            $range = $sheet.UsedRange
                            $content = $range.Value2 | Out-String
                            $matchess = processMatches $content $file
                            if ($matchess -ne $null) {
                                $output.AddRange($matchess)
                            } 
                        }
                        catch {
                            #Write-Host "An error occurred: $_"
                        }
                        finally {
                            # Any cleanup code goes here
                        }
                    }
                    
                
                    $excel.Quit()
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($workbook) | Out-Null
                    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
                } 
                default {
                    if ((Get-File $file).IsText) {
                        $content = Get-Content $file
                        $matchess = processMatches $content $file
                        if ($matchess -ne $null) {
                            $output.AddRange($matchess)
                        }
                    }
                }
            }
        }
    }     


# Process CopiedFiles for SHA256
$copiedFiles = Get-ChildItem $copiedFilesDir -Recurse -File | Select-Object -ExpandProperty FullName
foreach ($file in $copiedFiles) {
    $sha256 = Get-FileHashSHA256 -FilePath $file

    # Add new object to the ArrayList
    [void]$output.Add((New-Object PSObject -Property @{
        'Source File' = $file
        'Data' = $sha256
        'Type' = 'SHA256'
    }))
}

# Deduplicate the output
$output = $output | Sort-Object 'Data' -Unique

$Indicatordone = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$count = $output.Count
Write-Host "Indicators extracted at $Indicatordone. Total count: $count" -ForegroundColor Cyan
Log_Message -logfile $logfile -Message "Indicators extracted "
$textboxResults.AppendText("Indicators extracted at $Indicatordone. Total count: $count `r`n")
# Create an HTML file
$htmlFile = New-Item -Path ".\Logs\Reports\$computerName\indicators.html" -ItemType File -Force

# Write the start of the HTML file
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Indicator List Explorer</title>
    <style>
    body {
        font-family: Arial, sans-serif;
        font-size: 16px;
        background-color: #181818;
        color: #c0c0c0;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 0; /* Remove default padding */
        margin: 0; /* Remove default margin */
    }
    #controls {
        position: sticky;
        top: 0;
        z-index: 1;
        width: calc(100% - 20px);
        padding: 10px 0;
        display: flex;
        justify-content: space-between;
        align-items: center;
        height: 60px; 
        box-sizing: border-box;
        flex-direction: row;
    }
    #filter-type {
        height: 310px;
        width: auto;
        font-size: 16px;
        margin-right: 10px;
        z-index: 2; /* set z-index higher than the other controls */
    }
        .indicator {
            margin: 10px 0;
            text-align: left;
            width: 90%;
            color: #4dc5b5;
        }
        .indicator:hover {
            cursor: pointer;
        }
        .indicator-info {
            display: none;
            margin-top: 20px;
            text-align: center;
        }
        
        #controls h1 {
            margin: 0;
            color: #ffffff;
            font-size: 50px;
            margin-right: auto; 
        }
        #controls div {
            display: flex;
            gap: 10px;
            align-items: center;
            order: 1;  /* change order */
            align-self: center; 
            z-index: 1; /* set z-index lower than the select */
        }
        #indicators {
            margin-top: 60px;  /* add this line */
            width: 60vw; /* Set the width to 75% of the viewport width */
        }
        #controls-select {
            position: sticky;
            top: 60px;
            z-index: 1;
            width: 100%;
            display: flex;
            justify-content: flex-end;
            align-items: center;
            padding: 10px 0;
            box-sizing: border-box;
        }
        #filter-keyword {
            height: 35px;
            font-size: 20px;
        }
        #filter-type {
            order: 2;  /* change order */
            height: 325px;  /* adjust as needed */
            width: auto;
            font-size: 16px;
            margin-top: 10px;  /* add margin at the top */
            position: absolute; /* takes the element out of the normal document flow */
            right: 0; /* aligns it to the right of the #controls container */
            top: 100%; /* pushes it just below the #controls container */
            z-index: 2; /* set z-index higher than the other controls */
        }
        #filter-button {
            height: 35px;
            font-size: 20px; /* Adjust the size as you wish */
        }
        #reset-button {
            height: 35px;
            font-size: 20px; /* Adjust the size as you wish */
        }
        #scroll-button {
            height: 35px;
            font-size: 20px; /* Adjust the size as you wish */
        }
        .indicator-data {
            color: #66ccff;  /* adjust color as needed */
            font-size: 18px;  /* adjust font size as needed */
            word-wrap: break-word;  /* Wrap long words onto the next line */
        }
        .top-button {
            display: none;
            position: fixed;
            bottom: 20px;
            right: 30px;
            z-index: 99;
            border: none;
            outline: none;
            background-color: #555;
            color: white;
            cursor: pointer;
            border-radius: 4px;
        }
        .top-button:hover {
            background-color: #444;
        }
    </style>
</head>
<body>
<div id='controls'>
    <h1>Indicator List</h1>
    <div>
        <input type='text' id='filter-keyword' placeholder='Enter keyword'>
        <button id='filter-button' onclick='filter()'>Filter List</button>
        <button id='reset-button' onclick='resetFilters()'>Reset filters</button>
    </div>
</div>
<div id='controls-select'>
<select id='filter-type' onchange='filter()' multiple>
<option value=''>All (ctrl+click for multi-select)</option>
<option value='HTTP/S'>HTTP/S</option>
<option value='FTP'>FTP</option>
<option value='SFTP'>SFTP</option>
<option value='SCP'>SCP</option>
<option value='SSH'>SSH</option>
<option value='LDAP'>LDAP</option>
<option value='DATA'>DATA</option>
<option value='RFC 1918 IP Address'>RFC 1918 IP Address</option>
<option value='Non-RFC 1918 IP Address'>Non-RFC 1918 IP Address</option>
<option value='Email'>Email</option>
<option value='Domain'>Domain</option>
<option value='SHA256'>SHA256</option>
<option value='File Path'>File Path</option>
</select>
<button id='scroll-button' class='top-button' onclick='scrollToTop()'>Return to Top</button>

    </select>
</div>
<div id='indicators'>
"@

Add-Content -Path $htmlFile.FullName -Value $html

$index = 0
foreach ($indicator in $output) {
    $sourceFile = $indicator.'Source File'
    $data = $indicator.Data
    $type = $indicator.Type

    # Write the indicator as a div that shows the source file and type
    $indicatorHtml = @"
    <div class='indicator' data-type='$type'>
    <strong>Data:</strong> <span class='indicator-data'>$data</span><br>
    <strong>Type:</strong> $type <br>
    <strong>Source:</strong> $sourceFile
    </div>
"@
    Add-Content -Path $htmlFile.FullName -Value $indicatorHtml
    $index++
}

# Write the end of the HTML file
$html = @"
    </div>
    <script>
    function filter() {
        var filterKeyword = document.getElementById('filter-keyword').value.toLowerCase();
        var filterTypes = Array.from(document.getElementById('filter-type').selectedOptions).map(option => option.value.toLowerCase());
        var indicators = document.getElementsByClassName('indicator');
        for (var i = 0; i < indicators.length; i++) {
            var matchesKeyword = filterKeyword === '' || indicators[i].textContent.toLowerCase().includes(filterKeyword);
            var matchesType = filterTypes.includes(indicators[i].getAttribute('data-type').toLowerCase()) || filterTypes.includes('');
            if (matchesKeyword && matchesType) {
                indicators[i].style.display = 'block';
            } else {
                indicators[i].style.display = 'none';
            }
        }
    }

    function toggleInfo(index) {
        var indicatorInfo = document.getElementById('indicator-info-' + index);
        if (indicatorInfo.style.display === 'none') {
            indicatorInfo.style.display = 'block';
        } else {
            indicatorInfo.style.display = 'none';
        }
    }

    function resetFilters() {
        document.getElementById('filter-keyword').value = '';
        document.getElementById('filter-type').value = '';
    
        var indicators = document.getElementsByClassName('indicator');
        for (var i = 0; i < indicators.length; i++) {
            indicators[i].style.display = 'block';
        }
    }
    
    function expandAll() {
        var infos = document.getElementsByClassName('indicator-info');
        for (var i = 0; i < infos.length; i++) {
            infos[i].style.display = 'block';
        }
    }

    function collapseAll() {
        var infos = document.getElementsByClassName('indicator-info');
        for (var i = 0; i < infos.length; i++) {
            infos[i].style.display = 'none';
        }
    }

    function scrollToTop() {
        document.body.scrollTop = 0; // For Safari
        document.documentElement.scrollTop = 0; // For Chrome, Firefox, IE and Opera
      }
      
      window.onscroll = function() {scrollFunction()};
      
      function scrollFunction() {
        if (document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
          document.getElementById("scroll-button").style.display = "block";
        } else {
          document.getElementById("scroll-button").style.display = "none";
        }
      }
</script>
</body>
</html>
"@

Add-Content -Path $htmlFile.FullName -Value $html

Invoke-Item .\Logs\Reports\$computerName\indicators.html

$Intelligazerdone = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "Intelligazer completed at $Intelligazerdone" -ForegroundColor Cyan
Log_Message -logfile $logfile -Message "Intelligazer completed"
$textboxResults.AppendText("Intelligazer completed at $Intelligazerdone `r`n")

})
$form.Controls.Add($buttonIntelligizer)

$buttonBoxEmAll = New-Object System.Windows.Forms.Button
$buttonBoxEmAll.Location = New-Object System.Drawing.Point(85, 355)
$buttonBoxEmAll.Size = New-Object System.Drawing.Size(75,40)
$buttonBoxEmAll.Text = "BoxEmAll"
$buttonBoxEmAll.Add_Click({
    $directoryPath = ".\CopiedFiles"
    $pythonScript = "mass_submit_files_anomali.py"
    $pythonExe = "python"
    $apiKey = "redacted"
    
    # Get the number of files in the directory
    $fileCount = (Get-ChildItem -Path $directoryPath -File).Count

    # Ask for confirmation
    $confirmation = [System.Windows.Forms.MessageBox]::Show(
        "You are about to submit $fileCount files. Do you wish to continue?", 
        "Confirm Action", 
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question)

    if($confirmation -eq 'Yes') {
        $output = & $pythonExe $pythonScript $directoryPath $apiKey | Out-String
        $textboxResults.AppendText("Python script output: $output")
    }
})

$form.Controls.Add($buttonBoxEmAll)


$labelTractorBeam = New-Object System.Windows.Forms.Label
$labelTractorBeam.Location = New-Object System.Drawing.Point(53, 120)
$labelTractorBeam.Size = New-Object System.Drawing.Size(100, 20)
$labelTractorBeam.Text = "Tractor Beam"
$form.Controls.Add($labelTractorBeam)

$textboxURL = New-Object System.Windows.Forms.TextBox
$textboxURL.Location = New-Object System.Drawing.Point(15, 205)
$textboxURL.Size = New-Object System.Drawing.Size(215, 20)
$textboxURL.BackColor = [System.Drawing.Color]::Black
$textboxURL.ForeColor = [System.Drawing.Color]::lightseagreen
$form.Controls.Add($textboxURL)

$buttonSubmitUrl = New-Object System.Windows.Forms.Button
$buttonSubmitUrl.Location = New-Object System.Drawing.Point(90, 225)
$buttonSubmitUrl.Size = New-Object System.Drawing.Size(70, 40)
$buttonSubmitUrl.Text = "Sandbox URL"
$buttonSubmitUrl.Add_Click({
    $TextBoxUrlt = $TextBoxUrl.Text
    $sha256 = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
    $hash = [System.BitConverter]::ToString($sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($TextBoxUrl)))
    $hash = $hash -replace '-', '' # Remove dashes for a cleaner hash
    $time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $script:note = "Submitted on $time, URL: $TextBoxUrlt, SHA256: $hash"
    $script:virusTotalId = ""
    $script:pulsediveQid = ""
    # Anomali API
    $queryAnomali = [System.Windows.Forms.MessageBox]::Show("Do you want to submit URL to Anomali API?", "Anomali API", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel)
    if ($queryAnomali -eq 'Yes') {
        $response = Invoke-RestMethod -Uri "https://api.threatstream.com/api/v1/submit/new/" -Headers @{"Authorization" = "apikey redacted"} -Method Post -Body @{ "use_vmray_sandbox" = "true"; "vmray_max_jobs" = "3"; "report_radio-classification" = "private"; "report_radio-url" = "$TextBoxUrlt"; "report_radio-notes" = "$note" } -ContentType "application/x-www-form-urlencoded"
        $script:anomaliId = $response.reports.AUTOMATIC.id
        $textboxResults.AppendText("URL submitted to Anomali. Response: " + [Environment]::NewLine + ($response | ConvertTo-Json -Depth 100) + [Environment]::NewLine)
        $buttonRetrieveReport.Enabled = $true
        $script:includeanomalireport = $true
    } elseif ($queryAnomali -eq 'Cancel') {
        return
    }

    # VirusTotal API
    $queryVirusTotal = [System.Windows.Forms.MessageBox]::Show("Do you want to submit URL to VirusTotal API?", "VirusTotal API", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel)
    if ($queryVirusTotal -eq 'Yes') {
        $headers=@{}
        $headers.Add("accept", "application/json")
        $headers.Add("x-apikey", "redacted")
        $headers.Add("content-type", "application/x-www-form-urlencoded")
        $response = Invoke-RestMethod -Uri 'https://www.virustotal.com/api/v3/urls' -Method POST -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body "url=$TextBoxUrlt"
        $script:virusTotalId = $response.data.id
        #$script:virusTotalId = $response
        $textboxResults.AppendText("URL submitted to VirusTotal. Response: " + [Environment]::NewLine + ($response | ConvertTo-Json -Depth 100) + [Environment]::NewLine)
        $buttonRetrieveReport.Enabled = $true
        $script:includevtreport = $true
    } elseif ($queryVirusTotal -eq 'Cancel') {
        return
    }

    # Pulsedive API
    $queryPulsedive = [System.Windows.Forms.MessageBox]::Show("Do you want to submit URL to Pulsedive API?", "Pulsedive API", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel)
    if ($queryPulsedive -eq 'Yes') {
        $response = Invoke-RestMethod -Uri 'https://pulsedive.com/api/analyze.php' -Method POST -Body "value=$TextBoxUrlt&probe=1&pretty=1&key=redacted" -ContentType 'application/x-www-form-urlencoded'
        $script:pulsediveQid = $response.qid
        $textboxResults.AppendText("URL submitted to Pulsedive. Response: " + [Environment]::NewLine + ($response | ConvertTo-Json -Depth 100) + [Environment]::NewLine)
        $buttonRetrieveReport.Enabled = $true
        $script:includepulsereport = $true
    } elseif ($queryPulsedive -eq 'Cancel') {
        return
    }
})
$Form.Controls.Add($buttonSubmitUrl)

$buttonRetrieveReport = New-Object System.Windows.Forms.Button
$buttonRetrieveReport.Location = New-Object System.Drawing.Point(160, 225)
$buttonRetrieveReport.Size = New-Object System.Drawing.Size(70, 40)
$buttonRetrieveReport.Text = "Retrieve Report"
$buttonRetrieveReport.Enabled = $false
$buttonRetrieveReport.Add_Click({
    $TextBoxUrlt = $TextBoxUrl.Text
    if ($script:includeanomalireport -eq $true) {
    # Anomali API
    $ResponseAnomali = Invoke-RestMethod -Uri "https://api.threatstream.com/api/v1/submit/search/?q=$script:note" -Headers @{"Authorization" = "apikey redacted"} -Method Get
    $anomaliObjects = $ResponseAnomali.objects | Select-Object confidence, verdict, url, file, date_added, notes, sandbox_vendor, status

    # Sort Anomali objects by confidence in descending order
    $anomaliObjects = $anomaliObjects | Sort-Object date_added -Descending

    # Format Anomali objects as a CSS Grid
    $anomaliGrid = $anomaliObjects | ForEach-Object {
        if ($_.status -eq 'processing') {
            $_.verdict = 'processing'
        }
    $verdictClass = "verdict-$($_.verdict.ToLower())"
    @"
    <div class="grid-item">
        <table>
            <tr><th>Verdict</th><td class="$verdictClass">$($_.verdict)</td></tr>
            <tr><th>URL</th><td>$($_.url)</td></tr>
            <tr><th>Date Added</th><td>$($_.date_added)</td></tr>
            <tr><th>Notes</th><td>$($_.notes)</td></tr>
            <tr><th>Sandbox Vendor</th><td>$($_.sandbox_vendor)</td></tr>
            <tr><th>Status</th><td>$($_.status)</td></tr>
        </table>
    </div>
"@
}
    }
if ($script:includepulsereport -eq $true) {
    # Pulsedive API
    $ResponsePulsedive = Invoke-RestMethod -Uri "https://pulsedive.com/api/analyze.php?qid=$script:pulsediveQid&pretty=1&key=redacted" -Method GET 
    $pulsediveData = $ResponsePulsedive.data | Select-Object indicator, type, risk, risk_recommended, manualrisk, stamp_added, stamp_retired, recent, submissions, umbrella_rank, umbrella_domain, riskfactors, redirects, threats, feeds, comments, attributes
    # Extract and join riskfactors descriptions
    $riskFactors = ($pulsediveData.riskfactors | ForEach-Object { $_.description }) -join ', '
    # Define a hashtable to map risk to CSS classes
$riskClasses = @{
    "unknown" = "risk-unknown"
    "none" = "risk-none"
    "low" = "risk-low"
    "medium" = "risk-medium"
    "high" = "risk-high"
    "critical" = "risk-critical"
}
    # Format Pulsedive data as a table
    if ($pulsediveData.risk) {
$pulsediveTable = @"
<table>
    <tr>
        <th>Indicator</th>
        <td>$($pulsediveData.indicator)</td>
    </tr>
    <tr>
        <th>Type</th>
        <td>$($pulsediveData.type)</td>
    </tr>
    <tr>
        <th>Risk</th>
        <td class="$($riskClasses[$pulsediveData.risk])">$($pulsediveData.risk)</td>
    </tr>
    <tr>
        <th>Recommended Risk</th>
        <td class="$($riskClasses[$pulsediveData.risk_recommended])">$($pulsediveData.risk_recommended)</td>
    </tr>
    <tr>
        <th>Added Date</th>
        <td>$($pulsediveData.stamp_added)</td>
    </tr>
    <tr>
        <th>Recent</th>
        <td>$($pulsediveData.recent)</td>
    </tr>
    <tr>
        <th>Submissions</th>
        <td>$($pulsediveData.submissions)</td>
    </tr>
    <tr>
        <th>Umbrella Rank</th>
        <td>$($pulsediveData.umbrella_rank)</td>
    </tr>
    <tr>
        <th>Umbrella Domain</th>
        <td>$($pulsediveData.umbrella_domain)</td>
    </tr>
    <tr>
        <th>Risk Factors</th>
        <td>$riskfactors</td>
    </tr>
</table>
"@

# Check if redirects.from and redirects.to are arrays and join the elements
# Extract and join redirects
if ($pulsediveData.redirects) {
    $pulsediveRedirectsFrom = ($pulsediveData.redirects.from | ForEach-Object { $_.indicator }) -join ', '
    $pulsediveRedirectsTo = ($pulsediveData.redirects.to | ForEach-Object { $_.indicator }) -join ', '
}

$pulsediveTable += @"
<table>
    <tr>
        <th>Redirects From</th>
        <td>$pulsediveRedirectsFrom</td>
    </tr>
    <tr>
        <th>Redirects To</th>
        <td>$pulsediveRedirectsTo</td>
    </tr>
</table>
"@


# Include attributes in a separate table if they exist
if ($pulsediveData.attributes) {
$pulsediveAttributes = $pulsediveData.attributes.PSObject.Properties | ForEach-Object {
    @"
    <tr>
        <th>$($_.Name)</th>
        <td>$($_.Value -join ', ')</td>
    </tr>
"@
}

$pulsediveTable += @"
<table>
    <tr>
        <th>Attributes</th>
    </tr>
    $pulsediveAttributes
</table>
"@
}
}
}
if ($script:includevtreport -eq $true) {
    # VirusTotal API
    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("x-apikey", "redacted")
    $ResponseVirusTotal = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/analyses/$script:virusTotalId" -Method GET -Headers $headers 


    # Extracting VirusTotal metadata and creating an HTML table
    if ($ResponseVirusTotal.meta.url_info) {
$vtMeta = $ResponseVirusTotal.meta.url_info | ForEach-Object {
    @"
        <table>
            <tr>
                <th>URL</th>
                <td>$($_.url)</td>
            </tr>
            <tr>
                <th>ID</th>
                <td>$($_.id)</td>
            </tr>
        </table>
"@
    }
}
    # Selecting necessary attributes from VirusTotal data
    $dataAttributes = $ResponseVirusTotal.data.attributes | Get-Member -MemberType NoteProperty -ErrorAction $InformationPreference | Where-Object {$_.Name -ne "results"} | Select-Object -ExpandProperty Name | out-null
    
    # Creating a table with selected attributes
    $vtData = $ResponseVirusTotal.data.attributes | Select-Object $dataAttributes | ForEach-Object {
        $epochDate = $_.date
        $date = [DateTimeOffset]::FromUnixTimeSeconds($epochDate).DateTime
    
        @"
            <table>
                <tr>
                    <th>Date</th>
                    <td>$date</td>
                </tr>
                <tr>
                    <th>Harmless</th>
                    <td>$($_.stats.harmless)</td>
                </tr>
                <tr>
                    <th>Malicious</th>
                    <td>$($_.stats.malicious)</td>
                </tr>
                <tr>
                    <th>Suspicious</th>
                    <td>$($_.stats.suspicious)</td>
                </tr>
                <tr>
                    <th>Undetected</th>
                    <td>$($_.stats.undetected)</td>
                </tr>
                <tr>
                    <th>Timeout</th>
                    <td>$($_.stats.timeout)</td>
                </tr>
                <tr>
                    <th>Status</th>
                    <td>$($_.status)</td>
                </tr>
            </table>
"@
}


# Define a hashtable to map results to CSS classes
$resultClasses = @{
    "Clean" = "result-clean"
    "Unrated" = "result-unrated"
    "Malware" = "result-malware"
    "Phishing" = "result-phishing"
    "Malicious" = "result-malicious"
    "Suspicious" = "result-suspicious"
    "Spam" = "result-spam"
}

# Define a hashtable to map categories to CSS classes
$categoryClasses = @{
    "confirmed-timeout" = "category-confirmed-timeout"
    "failure" = "category-failure"
    "harmless" = "category-harmless"
    "undetected" = "category-undetected"
    "suspicious" = "category-suspicious"
    "malicious" = "category-malicious"
    "type-unsupported" = "category-type-unsupported"
}

# Format VirusTotal scanner results as a table
$vtResults = $ResponseVirusTotal.data.attributes.results.PSObject.Properties | ForEach-Object {
    $scannerName = $_.Name
    $result = $_.Value
    if ($null -ne $result.result -and $null -ne $result.category) {
        $resultClass = $resultClasses[$result.result] 
        $categoryClass = $categoryClasses[$result.category] 
    }
    @"
    <tr>
        <td>$scannerName</td>
        <td>$($result.method)</td>
        <td class="$categoryClass">$($result.category)</td>
        <td class="$resultClass">$($result.result)</td>
    </tr>
"@
} 

# Join the array of strings into a single string
$vtResults = $vtResults -join ""

# Wrap the VirusTotal results in a table
$vtResults = @"
<table>
    <tr>
        <th>Scanner Name</th>
        <th>Method</th>
        <th>Category</th>
        <th>Result</th>
    </tr>
    $vtResults
</table>
"@
}
    
    # Convert the results to HTML and save to a file
    $htmlContent = @"
    <html>
    <head>
    <style>
    body {
        font-family: Arial, sans-serif;
        font-size: 12px;     /* reduced from 16px */
        background-color: #181818;
        color: #c0c0c0;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 0;
        margin: 0;
    }
    pre {
        color: #66ccff;
        font-size: 14px;     /* reduced from 18px */
        white-space: pre-wrap;
        word-wrap: break-word;
        overflow-wrap: break-word;
        max-width: 50vw;
    }
    h1 {
        color: #ffffff;
        font-size: 40px;     /* reduced from 50px */
    }
    .grid-container {
		word-wrap: break-word;
		width: 50vw;
        max-width: 100%;  /* Ensures the grid doesn't exceed the screen width */
        margin: 0 auto;   /* Center the grid if it's less than screen width */
        box-sizing: border-box; /* Include padding and border in element's total width and height */
    }
    .vtgrid-container {
        max-width: 100%;  /* Ensures the grid doesn't exceed the screen width */
        margin: 0 auto;   /* Center the grid if it's less than screen width */
        box-sizing: border-box; /* Include padding and border in element's total width and height */
    }
    
    .grid-item {
        box-sizing: border-box; /* Include padding and border in element's total width and height */
        padding: 10px;  /* Inner spacing. Adjust as needed */
        width: 100%; /* Takes the full width of the grid column */
    }
    
    table {
        border-collapse: separate;
        border-spacing: 10px;   /* add space between cells */
        width: 100%;
    }
    th, td {
        border: 1px solid #ddd;
        padding: 8px;
        color: #66ccff;        /* color of text in table cells */
    }
    th {
        padding-top: 12px;
        padding-bottom: 12px;
        text-align: left;
        background-color: #242424;
        color: white;           /* color of text in table headers */
    }
    td {
		word-wrap: anywhere;
	}
    .result-clean { color: green; }
    .result-suspicious, .result-spam { color: yellow; }
    .result-unrated, .category-undetected, .category-type-unsupported { color: gray; }
    .result-malware, .result-phishing, .result-malicious { color: red; }
    .category-confirmed-timeout, .category-failure, .category-suspicious { color: yellow; }
    .category-harmless { color: green; }
    .category-malicious { color: red; }
    .verdict-benign { color: green; }
    .verdict-suspicious { color: yellow; }
    .verdict-malicious { color: red; }
    .risk-unknown, .risk-recommended-unknown { background-color: gray; }
    .risk-none, .risk-recommended-none { background-color: green; }
    .risk-low, .risk-recommended-low { background-color: yellow; }
    .risk-medium, .risk-recommended-medium { background-color: orange; }
    .risk-high, .risk-recommended-high { background-color: red; }
    .risk-critical, .risk-recommended-critical { background-color: brightred; }
    </style>
    </head>
    <body>
    <h1>Anomali Report</h1>
    <div class="grid-container">
    $anomaliGrid
    </div>
    <h1>VirusTotal Report</h1>
    <h2>Meta</h2>
    <pre>$vtMeta</pre>
    <h2>Data</h2>
    <pre>$vtData</pre>
    <h2>Results</h2>
    <div class="vtgrid-container">
    $vtResults
    </div>
    <h1>Pulsedive Report</h1>
    <pre>$pulsediveTable</pre>
    </body>
    </html>
"@
    # Check if TextBoxUrlt starts with http:// or https://
if ($TextBoxUrlt -notmatch '^(http|https)://') {
    $TextBoxUrlt = "http://$TextBoxUrlt"
}

# Create a new Uri object
try {
    $uri = New-Object System.Uri($TextBoxUrlt)
    # Get the base domain
    $baseDomain = $uri.Host
} catch {
    # Use the TextBoxUrlt itself if the URI cannot be determined
    $baseDomain = $TextBoxUrlt
}

# Output the base domain
Write-Output $baseDomain
New-Item -ItemType Directory -Path ".\Logs\Reports\Indicators\$baseDomain" -Force | Out-Null
$htmlContent | Out-File -FilePath .\Logs\Reports\Indicators\$baseDomain\urlscanreport.html

# Open the HTML file in the default web browser
Start-Process -FilePath .\Logs\Reports\Indicators\$baseDomain\urlscanreport.html

})

$Form.Controls.Add($buttonRetrieveReport)

$buttonGetIntel = New-Object System.Windows.Forms.Button
$buttonGetIntel.Location = New-Object System.Drawing.Point(15, 225)
$buttonGetIntel.Size = New-Object System.Drawing.Size(75, 40)
$buttonGetIntel.Text = "Get Intel"
$buttonGetIntel.Add_Click({
    $indicator = $TextBoxUrl.Text

    #Anomali API
    $queryThreatStream = [System.Windows.Forms.MessageBox]::Show("Do you want to query ThreatStream API?", "ThreatStream API", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel)
    if ($queryThreatStream -eq 'Yes') {
        $anomaliresponse = Invoke-RestMethod -Uri "https://api.threatstream.com/api/v2/intelligence/?value__contains=$indicator&limit=0" -Headers @{'Authorization' = 'apikey redacted'} 
        $selectedFields = $anomaliresponse.objects | ForEach-Object {
            New-Object PSObject -Property @{
                value = $_.value
                threatscore = $_.threatscore
                confidence = $_.confidence
                threat_type = $_.threat_type
                itype = $_.itype
                org = $_.org
                country = $_.country
                asn = $_.asn
                source = $_.source
                #tags = $_.tags
            }
        }
        # Convert each object to a HTML row
$htmlRows = $selectedFields | ForEach-Object {
    "<div class='grid-item'>
        <p><strong>Value:</strong> $($_.value)</p>
        <p><strong>Threatscore:</strong> $($_.threatscore)</p>
        <p><strong>Confidence:</strong> $($_.confidence)</p>
        <p><strong>Threat Type:</strong> $($_.threat_type)</p>
        <p><strong>Org:</strong> $($_.org)</p>
        <p><strong>Country:</strong> $($_.country)</p>
        <p><strong>ASN:</strong> $($_.asn)</p>
        <p><strong>Source:</strong> $($_.source)</p>
    </div>"
}

        # Join all the rows together
        $htmlGrid = $htmlRows -join "`n"
        $threatScoreStats = $selectedFields.threatscore | Measure-Object -Sum -Average -Maximum -Minimum
        $confidenceStats = $selectedFields.confidence | Measure-Object -Sum -Average -Maximum -Minimum

        $totalEntries = $selectedFields.Count

        $anomaliReport = @"
Total Entries: $totalEntries
Max ThreatScore: $($threatScoreStats.Maximum)
Min ThreatScore: $($threatScoreStats.Minimum)
Average ThreatScore: $($threatScoreStats.Average)
Max Confidence: $($confidenceStats.Maximum)
Min Confidence: $($confidenceStats.Minimum)
Average Confidence: $($confidenceStats.Average)
"@

        $textboxResults.AppendText($anomaliReport)
        $textboxResults.AppendText(($selectedFields | ConvertTo-Json -Depth 100))
    } elseif ($queryThreatStream -eq 'Cancel') {
        return
    }

    # Pulsedive API
    $queryPulsedive = [System.Windows.Forms.MessageBox]::Show("Do you want to query Pulsedive API?", "Pulsedive API", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel)
    if ($queryPulsedive -eq 'Yes') {
        $pulseresponse = Invoke-RestMethod -Uri "https://pulsedive.com/api/explore.php?q=ioc%3D$indicator&limit=0&pretty=1&key=redacted"
        $textboxResults.AppendText("Pulsedive Response: " + [Environment]::NewLine + ($pulseresponse | ConvertTo-Json -Depth 100))
        $pdhtmlTableRows = $pulseresponse.results | ForEach-Object {
            $pdresult = $_
            $pdcolor = switch ($pdresult.risk) {
                'high' { 'red' }
                'medium' { 'orange' }
                'low' { 'yellow' }
                'none' { 'green' }
                default { '#66ccff' }
            }
        
            $properties = $pdresult.summary.properties
        
            @"
            <tr style='color: $pdcolor'>
                <td>Indicator</td>
                <td>$($pdresult.indicator)</td>
            </tr>
            <tr style='color: $pdcolor'>
                <td>Risk</td>
                <td>$($pdresult.risk)</td>
            </tr>
            <tr style='color: $pdcolor'>
                <td>Type</td>
                <td>$($pdresult.type)</td>
            </tr>
            <tr style='color: $pdcolor'>
                <td>Added</td>
                <td>$($pdresult.stamp_added)</td>
            </tr>
            <tr style='color: $pdcolor'>
                <td>Status Code</td>
                <td>$($properties.http.'++code')</td>
            </tr>
            <tr style='color: $pdcolor'>
                <td>Content-Type</td>
                <td>$($properties.http.'++content-type')</td>
            </tr>
            <tr style='color: $pdcolor'>
                <td>Region</td>
                <td>$($properties.geo.region)</td>
            </tr>
            <tr style='color: $pdcolor'>
                <td>Country Code</td>
                <td>$($properties.geo.countrycode)</td>
            </tr>
            <tr style='color: $pdcolor'>
                <td>Country</td>
                <td>$($properties.geo.country)</td>
            </tr>
"@
        }
        
        # Join all the table rows together
        $pdhtmlTable = $pdhtmlTableRows -join "`n"
    } elseif ($queryPulsedive -eq 'Cancel') {
        return
    }

    # VirusTotal API
$queryVirusTotal = [System.Windows.Forms.MessageBox]::Show("Do you want to query VirusTotal API?", "VirusTotal API", [System.Windows.Forms.MessageBoxButtons]::YesNoCancel)
if ($queryVirusTotal -eq 'Yes') {
    $headers=@{}
    $headers.Add("accept", "application/json")
    $headers.Add("x-apikey", "redacted")
    $vtresponse = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/search?query=$indicator" -Method GET -Headers $headers

    $newTableFields = $vtresponse.data | ForEach-Object {
        New-Object PSObject -Property @{
            url = $_.id
            title = $_.attributes.title
            categories = $_.attributes.categories
            last_analysis_date = $_.attributes.last_analysis_date
            last_analysis_stats = $_.attributes.last_analysis_stats
            last_final_url = $_.attributes.last_final_url
            redirection_chain = $_.attributes.redirection_chain
            targeted_brand = $_.attributes.targeted_brand
            total_votes_harmless = $_.attributes.total_votes.harmless
            total_votes_malicious = $_.attributes.total_votes.malicious
        }
    }
    
    $vtselectedFields = $vtresponse.data | ForEach-Object {
        New-Object PSObject -Property @{
            id = $_.id
            lastAnalysisDate = $_.attributes.last_analysis_date
            lastAnalysisResults = $_.attributes.last_analysis_results
            categories = $_.attributes.categories
            totalVotes = $_.attributes.total_votes
        }
    }

$textboxResults.AppendText("VirusTotal Response: " + [Environment]::NewLine + ($vtselectedFields | ConvertTo-Json -Depth 100))
$epochDatevtint = $newTableFields.last_analysis_date
        $datevt = [DateTimeOffset]::FromUnixTimeSeconds($epochDatevtint).DateTime

$newHtmlTableRows = $newTableFields | ForEach-Object {
    "<tr><td style='color:#66ccff; text-align:right; font-weight:bold; text-decoration:underline;'>URL:</td><td style='color:#66ccff; text-align:center; word-wrap:break-word; max-width:30vw;'>$($_.url)</td></tr>
    <tr><td style='color:#66ccff; text-align:right; font-weight:bold; text-decoration:underline;'>Categories:</td><td style='color:#66ccff; text-align:center; word-wrap:break-word; max-width:30vw;'>$($_.categories | ConvertTo-Json)</td></tr>
    <tr><td style='color:#66ccff; text-align:right; font-weight:bold; text-decoration:underline;'>First Submission Date:</td><td style='color:#66ccff; text-align:center; word-wrap:break-word; max-width:30vw;'>$($_.first_submission_date)</td></tr>
    <tr><td style='color:#66ccff; text-align:right; font-weight:bold; text-decoration:underline;'>Last Analysis Date:</td><td style='color:#66ccff; text-align:center; word-wrap:break-word; max-width:30vw;'>$datevt</td></tr>
    <tr><td style='color:#66ccff; text-align:right; font-weight:bold; text-decoration:underline;'>Last Analysis Stats:</td><td style='color:#66ccff; text-align:center; word-wrap:break-word; max-width:30vw;'>$($_.last_analysis_stats | ConvertTo-Json)</td></tr>
    <tr><td style='color:#66ccff; text-align:right; font-weight:bold; text-decoration:underline;'>Last Final URL:</td><td style='color:#66ccff; text-align:center; word-wrap:break-word; max-width:30vw;'>$($_.last_final_url)</td></tr>
    <tr><td style='color:#66ccff; text-align:right; font-weight:bold; text-decoration:underline;'>Redirection Chain:</td><td style='color:#66ccff; text-align:center; word-wrap:break-word; max-width:30vw;'>$($_.redirection_chain | ConvertTo-Json)</td></tr>
    <tr><td style='color:#66ccff; text-align:right; font-weight:bold; text-decoration:underline;'>Targeted Brand:</td><td style='color:#66ccff; text-align:center; word-wrap:break-word; max-width:30vw;'>$($_.targeted_brand | ConvertTo-Json)</td></tr>
    <tr><td style='color:#66ccff; text-align:right; font-weight:bold; text-decoration:underline;'>Total Community Votes Harmless:</td><td style='color:#66ccff; text-align:center; word-wrap:break-word; max-width:30vw;'>$($_.total_votes_harmless)</td></tr>
    <tr><td style='color:#66ccff; text-align:right; font-weight:bold; text-decoration:underline;'>Total Community Votes Malicious:</td><td style='color:#66ccff; text-align:center; word-wrap:break-word; max-width:30vw;'>$($_.total_votes_malicious)</td></tr>"
}

$newHtmlTable = "<table style='width:100%;'>" + ($newHtmlTableRows -join "`n") + "</table>"

# Convert last_analysis_results to HTML table rows with conditional formatting
$htmlTableRows = $vtselectedFields | ForEach-Object {
    $_.lastAnalysisResults.PSObject.Properties | ForEach-Object {
        $scannerResult = $_.Value
        $color = switch ($scannerResult.category) {
            'harmless' { 'green' }
            'undetected' { 'grey' }
            'suspicious' { 'orange' }
            'malicious' { 'red' }
            default { 'gray' }
        }
        "<tr style='color: $color'>
            <td>$($_.Name)</td><br>
            <td>$($scannerResult.method)</td><br>
            <td>$($scannerResult.category)</td><br>
            <td>$($scannerResult.result)</td><br>
        </tr>"
    }
}

# Join all the table rows together
$htmlTable = $htmlTableRows -join "`n"
} elseif ($queryVirusTotal -eq 'Cancel') {
        return
    }
    
    # Convert the results to HTML and save to a file
    $htmlContent = @"
    <html>
    <head>
    <style>
    /* Your CSS styles go here */
    body {
        font-family: Arial, sans-serif;
        font-size: 16px;
        background-color: #181818;
        color: #c0c0c0;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 0; /* Remove default padding */
        margin: 0; /* Remove default margin */
    }
    pre {
        color: #66ccff;
        font-size: 18px;
        white-space: pre-wrap; /* Wrap text onto the next line */
        word-wrap: break-word; /* Break long words onto the next line */
        overflow-wrap: break-word; /* Same as 'word-wrap', but has better support */
        max-width: 50vw; /* Limit the width to 90% of the viewport width */
    }
    
    h1 {
        color: #ffffff;
        font-size: 50px;
    }
    .grid-container {
        display: grid;
        grid-template-columns: repeat(6, minmax(200px, 1fr));
        gap: 10px;
        padding: 10px;
        margin: 0 auto;   /* Center the grid if it's less than screen width */
    }
    .grid-item {
		word-wrap: break-word;
        padding: 10px;
        border-radius: 5px;
		color: #66ccff;
    }
    table {
        border-collapse: separate;
        border-spacing: 10px;   /* add space between cells */
        max-width: 30%;
    }
    </style>
    </head>
    <body>
        <h1>Anomali Report</h1>
        <pre>$anomaliReport</pre>
        <div class='grid-container'>
        $htmlGrid
        </div>
        <h1>VirusTotal Analysis Results</h1>
        <table>
    $newHtmlTable
    </table>
    <table>
    <tr>
        <th>Scanner</th><br>
        <th>Method</th><br>
        <th>Category</th><br>
        <th>Result</th><br>
    </tr>
    $htmlTable
    </table>
    <h1>Pulsedive Report</h1>
    <table>
    $pdhtmlTable
    </table>
    </body>
    </html>
"@
    
    # Check if TextBoxUrlt starts with http:// or https://
if ($indicator -notmatch '^(http|https)://') {
    $indicator = "http://$indicator"
}

# Create a new Uri object
try {
    $uri = New-Object System.Uri($indicator)
    # Get the base domain
    $baseDomainint = $uri.Host
} catch {
    # Use the TextBoxUrlt itself if the URI cannot be determined
    $baseDomainint = $indicator
}

    # Output the base domain
    Write-Output $baseDomainint
    New-Item -ItemType Directory -Path ".\Logs\Reports\Indicators\$baseDomainint" -Force | Out-Null
    $htmlContent | Out-File -FilePath .\Logs\Reports\Indicators\$baseDomainint\intelreport.html

    # Open the HTML file in the default web browser
    Start-Process -FilePath .\Logs\Reports\Indicators\$baseDomainint\intelreport.html
    
})
$Form.Controls.Add($buttonGetIntel)

# Create the JobIdLabel
$JobIdLabel = New-Object System.Windows.Forms.Label
$JobIdLabel.Location = New-Object System.Drawing.Point(53, 190)
$JobIdLabel.Size = New-Object System.Drawing.Size(200, 23)
$JobIdLabel.Text = "Enter URL, IP, or Hash"
$form.Controls.Add($JobIdLabel)

$buttonIsolateHost = New-Object System.Windows.Forms.Button
$buttonIsolateHost.Location = New-Object System.Drawing.Point(15, 140)
$buttonIsolateHost.Size = New-Object System.Drawing.Size(70, 40)
$buttonIsolateHost.Text = "Engage"
$buttonIsolateHost.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    if (![string]::IsNullOrEmpty($computerName)) {
        Invoke-Command -ComputerName $computerName -ScriptBlock {
            # Get the local host's IP addresses
            $localHostIPs = (Get-NetIPAddress -AddressFamily IPv4 -CimSession localhost).IPAddress | Where-Object { $_ -notlike "127.0.0.*" }
            
            # Check if Windows firewall is enabled
            $firewallProfiles = Get-NetFirewallProfile
            if ($firewallProfiles.Enabled -contains $false) {
                # Enable Windows Firewall for all profiles
                $firewallProfiles | Set-NetFirewallProfile -Enabled:True
            }
            
            # Create the isolation firewall rule if it doesn't exist
            $isolationRule = Get-NetFirewallRule -DisplayName "ISOLATION: Allowed Hosts" -ErrorAction $InformationPreference
            if (!$isolationRule) {
                New-NetFirewallRule -DisplayName "ISOLATION: Allowed Hosts" -Direction Outbound -RemoteAddress $localHostIPs -Action Allow -Enabled:True
            } else {
                Set-NetFirewallRule -DisplayName "ISOLATION: Allowed Hosts" -RemoteAddress $localHostIPs
            }
            
            # Set the default outbound action to block for all profiles
            $firewallProfiles | Set-NetFirewallProfile -DefaultOutboundAction Block

            Write-Host "$computerName isolated at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
            Log_Message -logfile $logfile -Message "$computerName isolated"
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please enter a valid computer name.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$form.Controls.Add($buttonIsolateHost)

$buttonUndoIsolation = New-Object System.Windows.Forms.Button
$buttonUndoIsolation.Location = New-Object System.Drawing.Point(85, 140)
$buttonUndoIsolation.Size = New-Object System.Drawing.Size(70, 40)
$buttonUndoIsolation.Text = "Release"
$buttonUndoIsolation.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    if (![string]::IsNullOrEmpty($computerName)) {
        Invoke-Command -ComputerName $computerName -ScriptBlock {
            # Remove the ISOLATION: Allowed Hosts firewall rule
            $isolationRule = Get-NetFirewallRule -DisplayName "ISOLATION: Allowed Hosts" -ErrorAction SilentlyContinue
            if ($isolationRule) {
                Remove-NetFirewallRule -DisplayName "ISOLATION: Allowed Hosts"
            }

            # Set the default outbound action to allow for all profiles
            $firewallProfiles = Get-NetFirewallProfile
            $firewallProfiles | Set-NetFirewallProfile -DefaultOutboundAction Allow

            Write-Host "$computerName isolation changes have been undone at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
            Log_Message -logfile $logfile -Message "$computerName isolated"
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please enter a valid computer name.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$form.Controls.Add($buttonUndoIsolation)

$buttonProcAsso = New-Object System.Windows.Forms.Button
$buttonProcAsso.Location = New-Object System.Drawing.Point(475, 100)
$buttonProcAsso.Size = New-Object System.Drawing.Size(80,40)
$buttonProcAsso.Text = "ProcAsso"
$buttonProcAsso.Add_Click({
    $computerName = if ($comboBoxComputerName.SelectedItem) {
        $comboBoxComputerName.SelectedItem.ToString()
    } else {
        $comboBoxComputerName.Text
    }

    New-Item -ItemType Directory -Path ".\Logs\Reports\$computerName\ProcessAssociations" -Force | Out-Null
    $colprocassStart = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Mapping Process Associations from $computerName at $colprocassStart" -ForegroundColor Cyan 
    Log_Message -logfile $logfile -Message "Mapped Process Associations from $computerName"
    $textboxResults.AppendText("Mapping Process Associations from $computerName at $colprocassStart `r`n")

    $scriptBlock = {
        function Get-ProcessAssociations {
            param(
                [Parameter(Mandatory=$false)]
                [int]$parentId = 0,
                [Parameter(Mandatory=$false)]
                [int]$depth = 0,
                [Parameter(Mandatory=$false)]
                [array]$allProcesses,
                [Parameter(Mandatory=$false)]
                [array]$allWin32Processes,
                [Parameter(Mandatory=$false)]
                [array]$allServices,
                [Parameter(Mandatory=$false)]
                [array]$allNetTCPConnections,
                [Parameter(Mandatory=$false)]
                [bool]$isChild = $false
            )
            
            if ($depth -gt 10) { return }
    
            if ($depth -eq 0) {
                $allProcesses = Get-Process | Where-Object { $_.Id -ne 0 }
                $allWin32Processes = Get-CimInstance -ClassName Win32_Process | Where-Object { $_.ProcessId -ne 0 } | Sort-Object CreationDate
                $allServices = Get-CimInstance -ClassName Win32_Service
                $allNetTCPConnections = Get-NetTCPConnection
            }
            
            $processes = if ($parentId -eq 0) {
                $allProcesses
            } else {
                $allWin32Processes | Where-Object { $_.ParentProcessId -eq $parentId } | ForEach-Object { $processId = $_.ProcessId; $allProcesses | Where-Object { $_.Id -eq $processId } }
            }
            
            $combinedData = @()
            
            $processes | ForEach-Object {
                $process = $_
    
                $processInfo = $allWin32Processes | Where-Object { $_.ProcessId -eq $process.Id } | Select-Object -Property CreationDate,CSName,ProcessName,CommandLine,Path,ParentProcessId,ProcessId
                
                $childProcesses = Get-ProcessAssociations -parentId $process.Id -depth ($depth + 1) -allProcesses $allProcesses -allWin32Processes $allWin32Processes -allServices $allServices -allNetTCPConnections $allNetTCPConnections -isChild $true
                
                $combinedObj = New-Object System.Collections.Specialized.OrderedDictionary
                    $combinedObj["ProcessInfo"] = $processInfo
                    $combinedObj["ChildProcesses"] = $childProcesses
    
                if (!$isChild) {
                    $associatedServices = $allServices | Where-Object { $_.ProcessId -eq $process.Id } | select-object -Property Caption,Description,Name,StartMode,PathName,ProcessId,ServiceType,StartName,State
                    $associatedModules = $process.Modules | Select-Object @{Name = "ProcessId"; Expression = {$process.Id}}, ModuleName, FileName
                    $associatedThreads = $process.Threads | Select-Object @{Name = "ProcessId"; Expression = {$process.Id}}, Id, TotalProcessorTime, ThreadState, WaitReason
                    $NetTCPConnections = $allNetTCPConnections | Where-Object { $_.OwningProcess -eq $process.Id } | select-object -Property CreationTime,State,LocalAddress,LocalPort,OwningProcess,RemoteAddress,RemotePort
    
                    $combinedObj["NetTCPConnections"] = $NetTCPConnections
                    $combinedObj["Modules"] = $associatedModules
                    $combinedObj["Services"] = $associatedServices
                    $combinedObj["Threads"] = $associatedThreads
                }
    
                $combinedData += $combinedObj
            }
    
            return $combinedData
        }
    
        return Get-ProcessAssociations -parentId $args[0] -depth $args[1]
    }
    
    $processData = Invoke-Command -ComputerName $computerName -ScriptBlock $scriptBlock -ArgumentList 0, 0

    $processData | ForEach-Object {
        $process = $_
        if ($process) {
            $processInfo = $process.ProcessInfo
            $processId = $processInfo.ProcessId
            $processName = $processInfo.ProcessName
            $creationDate = $processInfo.CreationDate
    
            if ($processName -ne $null -and $processId -ne $null -and $creationDate -ne $null) {
                $html += "<div class='process-line' timestamp='$creationDate'>"
                $html += "<a onclick=`"showProcessDetails('$processId'); return false;`">$processName ($processId) - Created on: $creationDate</a>"
                $html += "<div id='$processId' class='process-info' style='display: none;'>"
            }
    
            if ($process.ProcessInfo) {
                $html += "<pre>" + ($process.ProcessInfo | ConvertTo-Json -Depth 100) + "</pre>"
            }
    
            if ($processName -ne $null -and $processId -ne $null -and $creationDate -ne $null) {
                $html += "</div></div>"
            }
        }
    }

    function Build-HTMLProcessList {
        param(
            [Parameter(Mandatory=$true)]
            [array]$processData
        )
    
        $html = ''
    
        foreach ($process in ($processData | Sort-Object -Property @{Expression = { $_.ProcessInfo.ProcessId }; Ascending = $true})) {
            if ($null -eq $process) {
                continue
            }
            $processName = $process.ProcessInfo.ProcessName
            $processId = $process.ProcessInfo.ProcessId
            $creationDate = $process.ProcessInfo.CreationDate
    
            if ($null -ne $processName -and $null -ne $processId -and $null -ne $creationDate) {
                $html += "<div class='process-line' timestamp='$creationDate'>"
                $html += "<a onclick=`"showProcessDetails('$processId'); return false;`">$processName ($processId) - Created on: $creationDate</a><br>"
                $html += "<div id='$processId' class='process-info' style='display: none;'>"
            }
    
            $processInfo = $process.ProcessInfo | ConvertTo-Json -Depth 100
    
            # Checking if $processInfo is an empty object
            if ($processInfo -ne "{}") {
                $html += $processInfo
            }
    
            if ($null -ne $processName -and $null -ne $processId -and $null -ne $creationDate) {
    
                if ($process.NetTCPConnections) {
                    $html += "<br><a onclick=`"showNetworkConnections('$processId'); return false;`">Show Network Connections for Process ID: $processId</a><br>"
                    $html += "<div id='net-$processId' class='network-info' style='display: none;'>"
                    $html += ($process.NetTCPConnections | ConvertTo-Json -Depth 100)
                    $html += "</div>"
                }
        
                if ($process.Modules) {
                    $html += "<a onclick=`"showModules('$processId'); return false;`">Show Modules for Process ID: $processId</a><br>"
                    $html += "<div id='mod-$processId' class='module-info' style='display: none;'>"
                    $html += ($process.Modules | ConvertTo-Json -Depth 100)
                    $html += "</div>"
                }
        
                if ($process.Services) {
                    $html += "<a onclick=`"showServices('$processId'); return false;`">Show Services for Process ID: $processId</a><br>"
                    $html += "<div id='ser-$processId' class='service-info' style='display: none;'>"
                    $html += ($process.Services | ConvertTo-Json -Depth 100)
                    $html += "</div>"
                }
    
                if ($process.ChildProcesses) {
                    $html += "<a onclick=`"showChildProcesses('$processId'); return false;`">Show Child Processes for Process ID: $processId</a><br>"
                    $html += "<div id='child-$processId' class='child-process-info' style='display: none;'>"
                    $html += ($process.ChildProcesses | ConvertTo-Json -Depth 100)
                    $html += "</div>"
                }
        
                $html += "</div></div>"
        }
    }
    
        return $html
    }
    
    
    $processListHtml = Build-HTMLProcessList -processData $processData
    $outFilePath = ".\Logs\Reports\$computerName\ProcessAssociations\ProcessList.html"
    $outFileContent = @"
    <!DOCTYPE html>
<html>
<head>
    <title>Process List Explorer</title>
    <style>
        /* Include your CSS styles here */
        body {
            font-family: Arial, sans-serif;
            font-size: 16px;
            background-color: #181818;
            color: #c0c0c0;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        a {
            color: #66ccff;
        }
        h1 {
            text-align: center;
        }
        .process-info {
            white-space: pre-wrap; /* CSS3 */
            word-wrap: break-word; /* Internet Explorer 5.5+ */
            font-size: 14px;
            color: #4dc5b5;
            background-color: #333333;
            border: solid 1px #666666;
            margin: 5px;
            padding: 10px;
            overflow-wrap: break-word; /* Adds support for Firefox and other browsers */
            max-width: 50vw; /* Limit width to 50% of the viewport width */
            word-break: break-all; /* Breaks the words at the limit of the container width */
            overflow: auto; /* Adds a scrollbar if the content exceeds the max-width */
        }
        .child-process-info {
            white-space: pre-wrap; /* CSS3 */
            word-wrap: break-word; /* Internet Explorer 5.5+ */
            font-size: 14px;
            color: #4dc5b5;
            background-color: #333333;
            margin: 5px;
            padding: 10px;
            overflow-wrap: break-word; /* Adds support for Firefox and other browsers */
            max-width: 50vw; /* Limit width to 50% of the viewport width */
            word-break: break-all; /* Breaks the words at the limit of the container width */
            overflow: auto; /* Adds a scrollbar if the content exceeds the max-width */
        }
        module-info {
            white-space: pre-wrap; /* CSS3 */
            word-wrap: break-word; /* Internet Explorer 5.5+ */
            font-size: 14px;
            color: #4dc5b5;
            background-color: #333333;
            margin: 5px;
            padding: 10px;
            overflow-wrap: break-word; /* Adds support for Firefox and other browsers */
            max-width: 50vw; /* Limit width to 50% of the viewport width */
            word-break: break-all; /* Breaks the words at the limit of the container width */
            overflow: auto; /* Adds a scrollbar if the content exceeds the max-width */
        }
        .service-info {
            white-space: pre-wrap; /* CSS3 */
            word-wrap: break-word; /* Internet Explorer 5.5+ */
            font-size: 14px;
            color: #4dc5b5;
            background-color: #333333;
            margin: 5px;
            padding: 10px;
            overflow-wrap: break-word; /* Adds support for Firefox and other browsers */
            max-width: 50vw; /* Limit width to 50% of the viewport width */
            word-break: break-all; /* Breaks the words at the limit of the container width */
            overflow: auto; /* Adds a scrollbar if the content exceeds the max-width */
        }
        .netowrk-info {
            white-space: pre-wrap; /* CSS3 */
            word-wrap: break-word; /* Internet Explorer 5.5+ */
            font-size: 14px;
            color: #4dc5b5;
            background-color: #333333;
            margin: 5px;
            padding: 10px;
            overflow-wrap: break-word; /* Adds support for Firefox and other browsers */
            max-width: 50vw; /* Limit width to 50% of the viewport width */
            word-break: break-all; /* Breaks the words at the limit of the container width */
            overflow: auto; /* Adds a scrollbar if the content exceeds the max-width */
        }
        .process-line {
            display: block;
            text-align: center;
        }
        .controls {
            position: fixed;
            top: 0;
            width: 100%;
            background-color: #181818;
            padding: 10px;
            z-index: 100;
            display: flex;
            justify-content: space-around;
        }
        .controls > div {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }
        .controls > div > div {
            display: flex;
            align-items: center;
            justify-content: flex-end;
            gap: 10px;
        }
        .controls > div > label {
            margin-bottom: 10px;
            font-size: 18px;
            font-weight: bold;
        }
        .content {
            margin-top: 100px; /* Adjust this value based on the height of your controls */
        }
        .top-button {
            display: none;
            position: fixed;
            bottom: 20px;
            right: 30px;
            z-index: 99;
            border: none;
            outline: none;
            background-color: #555;
            color: white;
            cursor: pointer;
            padding: 15px;
            border-radius: 4px;
        }
        .top-button:hover {
            background-color: #444;
        }
    </style>
    <script>
    function addSoftHyphens(str, interval) {
        var result = '';
        while (str.length > 0) {
            result += str.substring(0, interval) + '&shy;';
            str = str.substring(interval);
        }
        return result;
    }
    function showChildProcesses(processId) {
        var infoElem = document.getElementById('child-' + processId);
        if (infoElem.style.display === "none") {
            infoElem.style.display = "block";
        } else {
            infoElem.style.display = "none";
        }
    }
    function showNetworkConnections(processId) {
        var infoElem = document.getElementById('net-' + processId);
        if (infoElem.style.display === "none") {
            infoElem.style.display = "block";
        } else {
            infoElem.style.display = "none";
        }
    }
    function showModules(processId) {
        var infoElem = document.getElementById('mod-' + processId);
        if (infoElem.style.display === "none") {
            infoElem.style.display = "block";
        } else {
            infoElem.style.display = "none";
        }
    }
    function showServices(processId) {
        var infoElem = document.getElementById('ser-' + processId);
        if (infoElem.style.display === "none") {
            infoElem.style.display = "block";
        } else {
            infoElem.style.display = "none";
        }
    }
            function showProcessDetails(processId) {
                var infoElem = document.getElementById(processId.toString());
                if (infoElem.style.display === "none") {
                    infoElem.style.display = "block";
                } else {
                    infoElem.style.display = "none";
                }
            }
            function openAllChildProcesses() {
                var coll = document.getElementsByClassName('child-process-info');
                for (var i = 0; i < coll.length; i++) {
                    coll[i].style.display = 'block';
                }
            }
            
            function closeAllChildProcesses() {
                var coll = document.getElementsByClassName('child-process-info');
                for (var i = 0; i < coll.length; i++) {
                    coll[i].style.display = 'none';
                }
            }

            function openAllProcesses() {
                var coll = document.getElementsByClassName('process-info');
                for (var i = 0; i < coll.length; i++) {
                    coll[i].style.display = 'block';
                }
            }
            function closeAllProcesses() {
                var coll = document.getElementsByClassName('process-info');
                for (var i = 0; i < coll.length; i++) {
                    coll[i].style.display = 'none';
                }
            }
            function filter() {
                var timeFrom = document.getElementById("timeFrom").value ? new Date(document.getElementById("timeFrom").value).getTime() : null;
                var timeTo = document.getElementById("timeTo").value ? new Date(document.getElementById("timeTo").value).getTime() : null;
                var keyword = document.getElementById("keyword").value;
            
                var coll = document.getElementsByClassName('process-line');
                for (var i = 0; i < coll.length; i++) {
                    var timestamp = new Date(coll[i].getAttribute('timestamp')).getTime();
                    var processName = coll[i].innerText;
            
                    // Hide element initially
                    coll[i].style.display = 'none';
            
                    // Show if within the time window (or no time window set)
                    if ((!timeFrom || timestamp >= timeFrom) && (!timeTo || timestamp <= timeTo)) {
                        // And show if keyword is empty or process name contains keyword
                        if (!keyword || processName.indexOf(keyword) !== -1) {
                            coll[i].style.display = 'block';
                        }
                    }
                }
            }
            function reset() {
                document.getElementById("timeFrom").value = "";
                document.getElementById("timeTo").value = "";
                document.getElementById("keyword").value = "";
                var coll = document.getElementsByClassName('process-line');
                for (var i = 0; i < coll.length; i++) {
                    coll[i].style.display = 'block';
                }
            }
            function openAllNetworks() {
                var coll = document.getElementsByClassName('network-info');
                for (var i = 0; i < coll.length; i++) {
                    coll[i].style.display = 'block';
                }
            }
            function closeAllNetworks() {
                var coll = document.getElementsByClassName('network-info');
                for (var i = 0; i < coll.length; i++) {
                    coll[i].style.display = 'none';
                }
            }
            function openAllModules() {
                var coll = document.getElementsByClassName('module-info');
                for (var i = 0; i < coll.length; i++) {
                    coll[i].style.display = 'block';
                }
            }
            function closeAllModules() {
                var coll = document.getElementsByClassName('module-info');
                for (var i = 0; i < coll.length; i++) {
                    coll[i].style.display = 'none';
                }
            }
            function openAllServices() {
                var coll = document.getElementsByClassName('service-info');
                for (var i = 0; i < coll.length; i++) {
                    coll[i].style.display = 'block';
                }
            }
            function closeAllServices() {
                var coll = document.getElementsByClassName('service-info');
                for (var i = 0; i < coll.length; i++) {
                    coll[i].style.display = 'none';
                }
            }
            function openAll() {
            openAllProcesses();
            openAllNetworks();
            openAllModules();
            openAllServices();
            openAllChildProcesses();
            }

            function closeAll() {
            closeAllProcesses();
            closeAllNetworks();
            closeAllModules();
            closeAllServices();
            closeAllChildProcesses();
            }

            window.onscroll = function() {scrollFunction()};

            function scrollFunction() {
              if (document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
                document.getElementById("topBtn").style.display = "block";
              } else {
                document.getElementById("topBtn").style.display = "none";
              }
            }
            
            function topFunction() {
              document.body.scrollTop = 0;
              document.documentElement.scrollTop = 0;
            }
        </script>
</head>
<body>
    <div class="controls">
        <h1>Process List</h1>
        <div>
            <label>Time Picker</label>
            <div>
                <label>From:</label>
                <input type="datetime-local" id="timeFrom">
            </div>
            <div>
                <label>To:</label>
                <input type="datetime-local" id="timeTo">
            </div>
        </div>
        <div>
            <label>Keyword</label>
            <input type="text" id="keyword">
            <div style="display: flex;">
                <button onclick="filter();">Apply Filter</button>
                <button onclick="reset();">Reset</button>
            </div>
        </div>
        <div>
            <label>Process Details</label>
            <button onclick="openAllProcesses();">Expand All</button>
            <button onclick="closeAllProcesses();">Collapse All</button>
        </div>
        <div>
            <label>Network Details</label>
            <button onclick="openAllNetworks();">Expand All</button>
            <button onclick="closeAllNetworks();">Collapse All</button>
        </div>
        <div>
            <label>Module Details</label>
            <button onclick="openAllModules();">Expand All</button>
            <button onclick="closeAllModules();">Collapse All</button>
        </div>
        <div>
            <label>Service Details</label>
            <button onclick="openAllServices();">Expand All</button>
            <button onclick="closeAllServices();">Collapse All</button>
        </div>
        <div>
            <label>Child Process Details</label>
            <button onclick="openAllChildProcesses();">Expand All</button>
            <button onclick="closeAllChildProcesses();">Collapse All</button>
        </div>
        <div>
            <label>All Details</label>
            <button onclick="openAll();">Expand All</button>
            <button onclick="closeAll();">Collapse All</button>
        </div>
    </div>
    <div class="content">
    $processListHtml
    <button onclick="topFunction()" id="topBtn" class="top-button">Return to Top</button>
</div>
</body>
</html>
"@
    
Set-Content -Path $outFilePath -Value $outFileContent
    

Invoke-Item $outFilePath


$colprocassEnd = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "Completed Mapping of Process Associations from $computerName at $colprocassEnd" -ForegroundColor Green
    Log_Message -logfile $logfile -Message "Completed Mapping of Process Associations from $computerName at $colprocassEnd"  
    $textboxResults.AppendText("Completed Mapping of Process Associations from $computerName at $colprocassEnd `r`n")
})

$form.Controls.Add($buttonProcAsso)

$submitfileButton = New-Object System.Windows.Forms.Button
$submitfileButton.Location = New-Object System.Drawing.Point(405, 270)
$submitfileButton.Size = New-Object System.Drawing.Size(75, 40)
$submitfileButton.Text = "Sandbox Local File"
$submitfileButton.Add_Click({
    $sampleFile = if ($comboboxlocalFilePath.SelectedItem) {
        $comboboxlocalFilePath.SelectedItem.ToString()
    } else {
        $comboboxlocalFilePath.Text
    }

    $pythonScript = "submit_file_anomali.py"
    $pythonExe = "python"
    $apiKey = "redacted"

    $output = & $pythonExe $pythonScript $sampleFile $apiKey
    $textboxResults.AppendText("Python script output: $output `r`n")

    $outputObject = $output | ConvertFrom-Json
    $script:Note = $outputObject.Note
    $textboxResults.AppendText("Tags added: $script:Note `r`n")

    if ($script:Note -ne $null) {
        $buttonRetrieveReportfile.Enabled = $true
    }
})     
$form.Controls.Add($submitfileButton)


$buttonRetrieveReportfile = New-Object System.Windows.Forms.Button
$buttonRetrieveReportfile.Location = New-Object System.Drawing.Point(480, 270)
$buttonRetrieveReportfile.Size = New-Object System.Drawing.Size(75, 40)
$buttonRetrieveReportfile.Text = "Retrieve Report"
$buttonRetrieveReportfile.Enabled = $false
$buttonRetrieveReportfile.Add_Click({
    $fileName = Split-Path $comboboxlocalFilePath.Text -Leaf
    $Response = Invoke-RestMethod -Uri "https://api.threatstream.com/api/v1/submit/search/?q=$script:Note" -Headers @{"Authorization" = "apikey redacted"} -Method Get 
    if ($Response.meta.total_count -gt 0) {
        $textboxResults.AppendText("Total Count: " + $Response.meta.total_count + [Environment]::NewLine)
        foreach ($report in $Response.objects) {
            $textboxResults.AppendText(($report | ConvertTo-Json -Depth 100) + [Environment]::NewLine)
        }
    } else {
        $textboxResults.AppendText("No reports found for file: $fileName. Please wait and try again.")
    }
})
$form.Controls.Add($buttonRetrieveReportfile)

$buttonListCopiedFiles = New-Object System.Windows.Forms.Button
$buttonListCopiedFiles.Location = New-Object System.Drawing.Point(330, 270)
$buttonListCopiedFiles.Size = New-Object System.Drawing.Size(75, 40)
$buttonListCopiedFiles.Text = "View Copied Files"
$buttonListCopiedFiles.Add_Click({
    $CopiedFilesPath = $CopiedFilesDir
    
    if (![string]::IsNullOrEmpty($CopiedFilesPath)) {
        try {
            $files = Get-ChildItem -Path $CopiedFilesPath -File | Select-Object -ExpandProperty FullName

            $textboxResults.AppendText(($files -join "`r`n") + "`r`n")
            $comboboxlocalFilePath.Items.Clear()
            foreach ($file in $files) {
                $comboboxlocalFilePath.Items.Add($file)
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Error while trying to list files in the CopiedFiles directory: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        }
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please enter a valid CopiedFiles path.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})
$form.Controls.Add($buttonListCopiedFiles)

function Reset-Form {
    $textboxURL.Clear()
    $textboxResults.Clear()
    $buttonSubmitUrl.Enabled = $true
    $buttonCheckStatus.Enabled = $false
    $buttonCheckStatus.Text = "Awaiting Job"
    $buttonRetrieveReport.Enabled = $false
    $buttonSubmitUrl.Enabled = $true
    $buttonCheckStatusfile.Enabled = $false
    $buttonCheckStatusfile.Text = "Awaiting Job"
    $buttonRetrieveReportfile.Enabled = $false
    $textboxaddargs.Clear()
    $comboboxlocalFilePath.Items.Clear()
    $comboboxlocalFilePath.SelectedIndex = -1 
    $comboboxlocalFilePath.Text = ""
    $textboxremoteFilePath.Clear()
    $comboboxComputerName.SelectedIndex = -1 
    $comboboxComputerName.Text = ""
    $dropdownProcessId.Items.Clear()
    $dropdownProcessId.SelectedIndex = -1 
    $dropdownProcessId.Text = ""
    $script:SubmissionId = ""
    $script:SubmissionId = ""
    $buttonCheckStatus.ForeColor = [System.Drawing.Color]::lightseagreen   
    $buttonCheckStatus.BackColor = [System.Drawing.Color]::Black 
    $buttonCheckStatusfile.ForeColor = [System.Drawing.Color]::lightseagreen   
    $buttonCheckStatusfile.BackColor = [System.Drawing.Color]::Black 
}

$buttonReset = New-Object System.Windows.Forms.Button
$buttonReset.Location = New-Object System.Drawing.Point(245, 370)
$buttonReset.Size = New-Object System.Drawing.Size(80, 23)
$buttonReset.Text = "Reset"
$buttonReset.Add_Click({
    Reset-Form
})
$form.Controls.Add($buttonReset)

function Show-ColoredMessage {
    param([string]$message, [string]$title)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $title
    $form.Size = New-Object System.Drawing.Size(950, 600)
    $form.StartPosition = 'CenterScreen'
    $form.BackColor = [System.Drawing.Color]::Black

    $panel = New-Object System.Windows.Forms.Panel
    $panel.Dock = 'Fill'
    $panel.AutoScroll = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $message
    $label.AutoSize = $true
    $label.Location = New-Object System.Drawing.Point(10, 10)
    $label.ForeColor = [System.Drawing.Color]::LightSeaGreen 
    $label.Font = New-Object System.Drawing.Font("Arial", 12) # Increase font size to 12

    $panel.Controls.Add($label)
    $form.Controls.Add($panel)

    $form.ShowDialog()
}

$helpButton = New-Object System.Windows.Forms.Button
$helpButton.Location = New-Object System.Drawing.Point(15, 20) 
$helpButton.Size = New-Object System.Drawing.Size(30, 20) 
$helpButton.Text = "?"
$helpButton.Add_Click({
    $helpText = @"
    Enter Remote Computer Name or Get Host List:

    Enter the name of the remote computer you want to interact with in the provided text box, or click on 
    "Get Host List" to retrieve a list of all hosts on the domain. The list will paginate and match characters 
    as you type. The selected or typed hostname will be the target for any remote actions.


    View Processes Button:

    Clicking this button will display the remote computer's process list in the lower display box. It also 
    populates the dropdown for selecting processes to terminate. The list includes the process ID, name, 
    and status.


    Copy All Process Binaries Button:

    This button will copy every uniquely pathed binary that is currently running a process on the remote machine. 
    The binaries are stored in the "OpenPhalanx\CopiedFiles" directory on your local host. The contents of this 
    directory are displayed when "View Copied Files" is clicked.


    Tractor Beam:

    Engaging the "Tractor Beam" will assign firewall rules to the remote host which prevent any IP addresses 
    other than those of the local host from communicating with the remote host. This is useful for isolating 
    a compromised system.


    Hunt File Button:

    This button will attempt to locate the file specified in the "Remote File Path" text box. If the file is not 
    found in the specified remote file path the recycle bin is queried. The status of the volume shadow copy 
    service is checked. The existence of system restore points and backups is also checked.


    Place File Button:

    This button takes the file specified in the "Local File Path" dropdown and places it at the location 
    specified in the "Remote File Path" text box.


    Place and Run Button:

    This button will place the file specified in the "Local File Path" dropdown at the location specified in the 
    "Remote File Path" text box and then execute it. If the "Arguments" text box is filled, those arguments will 
    be used when executing the file.


    Execute Oneliner Button:

    This button will attempt to execute the command specified in the "Arguments" text box on the remote machine.


    Deploy Sysmon Button:

    This button deploys Sysmon, a powerful system monitoring tool, on the remote host using the Olaf Hartong 
    default configuration.


    RapidTriage Button:

    This button runs the RapidTriage tool, which collects a wide range of data from the remote host and outputs it 
    in an xlsx workbook. The workbook includes several worksheets with different types of data, such as running 
    processes, network connections, and more.


    View Copied Files Button:

    This button displays the contents of the "OpenPhalanx\CopiedFiles" directory on your local host in the lower 
    display box. The "Local File Path" dropdown is populated with the copied files.


    Reset Button:

    This button clears all input fields and resets the state of the form. It also disables the "Retrieve Report" 
    and "Check Status" buttons until a new job is submitted.


    Submit URL Button:

    This button submits the URL specified in the "URL" text box to the VMRay sandbox for analysis. After 
    submission, the "Check Status" button is enabled.


    Retrieve Report Button:

    This button retrieves the report of the analysis of the submitted URL. The report includes detailed information 
    about the URL, such as its threat score, threat level, and more.


    Sandbox Local File Button:

    This button submits the file specified in the "Local File Path" dropdown to the VMRay sandbox for analysis. 
    After submission, the "Check Status" button is enabled.


    Retrieve Report (File) Button:

    This button retrieves the report of the analysis of the submitted file. The report includes detailed information 
    about the file, such as its threat score, threat level, and more.


    WinEventalyzer Button:

    This button runs the WinEventalyzer tool, which collects Windows event logs from the remote host and analyzes them 
    using several threat hunting tools, including DeepBlueCLI, and Hayabusa. The output includes timelines, 
    summaries, and metrics that can be used for threat hunting.

    
    USN Journal Button:

    This button retrieves the USN Journal from the remote host. The USN Journal is a log of all changes to files on the 
    remote host and can be used for forensic analysis.


    List Copied Files Button:

    This button lists all the files that have been copied from the remote host to the "OpenPhalanx\CopiedFiles" directory 
    on your local host. The list is displayed in the lower display box, and the "Local File Path" dropdown is populated 
    with the copied files.


    Select Remote File Button:

    This button opens a custom remote file system explorer. You can navigate through the file system of the remote computer 
    and select a file. The selected file's path will be displayed in the "Remote File Path" text box.


    Select Local File Button:

    This button opens a file dialog that allows you to select a file from your local machine. The selected file's path 
    will be displayed in the "Local File Path" text box.


    Force Password Change Button:

    This button forces the specified user to change their password at the next logon. This is useful for ensuring that 
    users regularly update their passwords.


    Log Off User Button:

    This button forces the specified user to log off from the remote computer. This can be useful for ending a user's 
    session without shutting down the computer.


    Disable Account Button:

    This button disables the specified user's account on the remote computer. This can be useful for preventing a user 
    from logging in to the computer.


    Enable Account Button:

    This button enables the specified user's account on the remote computer. This can be useful for allowing a user 
    who was previously disabled to log in to the computer.


    Retrieve System Info Button:

    This button retrieves Active Directory information about the specified remote host and all users who have logged into 
    this host. This information is displayed in the lower display box, and the "Username" dropdown is populated with the 
    usernames.


    Restart Button:

    This button sends a command to the remote computer to restart. This can be useful for applying updates or changes 
    that require a restart.


    Kill Process Button:

    This button kills the selected process on the remote computer. This can be useful for stopping a process that is 
    not responding or that is using too many resources.


    Shutdown Button:

    This button sends a command to the remote computer to shut down. This can be useful for turning off the computer 
    remotely.


    Copy File Button:

    This button copies the file specified in the "Remote File Path" text box from the remote computer to the 
    "OpenPhalanx\CopiedFiles" directory on your local host.


    Delete File Button:

    This button deletes the file specified in the "Remote File Path" text box from the remote computer. This can be 
    useful for removing unwanted or unnecessary files from the computer.


    Intelligizer Button:

    This button scrapes indicators from collected reports and logs for further analysis. This can be useful for 
    identifying patterns or anomalies in the data.


    BoxEmAll Button:

    This button submits all files in the "OpenPhalanx\CopiedFiles" directory to the VMRay sandbox for analysis. This 
    can be useful for analyzing multiple files at once.


    Get Intel Button:

    This button retrieves intelligence on the specified indicator. This can be useful for getting more information 
    about a potential threat.


    Undo Isolation Button:

    This button removes the firewall rules that were applied for isolation. This can be useful for restoring 
    communication with the remote host after it has been isolated.


"@

Show-ColoredMessage -message "$helpText" -title "Help - Defending Off the Land"
})
$form.Controls.Add($helpButton)

# Create a ToolTip object
$tooltip = New-Object System.Windows.Forms.ToolTip

# Set the tooltip for each button
$tooltip.SetToolTip($buttonViewProcesses, "Click to view the list of running processes on the selected remote computer. `r`n This button populates the Select a Process dropdown")
$tooltip.SetToolTip($buttonCopyBinaries, "Click to copy all uniquely pathed modules currently running on the remote computer.")
$tooltip.SetToolTip($buttonIsolateHost, "Click to isolate the remote computer by blocking all IP addresses except the local host.")
$tooltip.SetToolTip($buttonHuntFile, "Click to hunt for a remote file from the remote computer.")
$tooltip.SetToolTip($buttonPlaceFile, "Click to place the local file you want on the remote computer to the remote file path.")
$tooltip.SetToolTip($buttonPlaceAndRun, "Click to place and run the local file you want on the remote computer to the remote file path. `r`n Use the 'Arguments' textbox if any are required for execution.")
$tooltip.SetToolTip($executeCommandButton, "Enter the command you want to execute on the remote computer in the 'Arguments' text box, then click this button. `r`n Use set-location to execute outside of System32.")
$tooltip.SetToolTip($buttonInstallSysmon, "Click to deploy Sysmon on the remote computer using the Olaf Hartong default configuration.")
$tooltip.SetToolTip($RapidTriageButton, "Click to run the RapidTriage tool on the remote computer.")
$tooltip.SetToolTip($buttonReset, "Click to reset the form and clear all input fields.")
$tooltip.SetToolTip($helpButton, "Click to view a detailed explanation of each functionality of the script.")
$tooltip.SetToolTip($buttonSubmitUrl, "Enter the URL you want to analyze in the 'URL' text box, then click this button.")
$tooltip.SetToolTip($buttonRetrieveReport, "Click to retrieve the report of the analysis of the submitted URL.")
$tooltip.SetToolTip($submitfileButton, "Select the file you want to analyze in the 'Local File Path' dropdown, then click this button.")
$tooltip.SetToolTip($buttonRetrieveReportfile, "Click to retrieve the report of the analysis of the submitted file.")
$tooltip.SetToolTip($WinEventalyzerButton, "Click to copy and threat hunt windows event logs from remote computer.")
$tooltip.SetToolTip($UsnJrnlButton, "Click to retrieve the USN Journal from the remote computer.")
$tooltip.SetToolTip($buttonListCopiedFiles, "Click to view the list of files copied from the remote computer. `r`n This button populates the Local File Path dropdown.")
$tooltip.SetToolTip($buttonGetHostList, "Click to retrieve a list of all active hosts on the domain. `r`n This populates the Remote Computer dropdown.")
$tooltip.SetToolTip($buttonProcAsso, "Click to associate activity with each running process on the remote host.")
$tooltip.SetToolTip($UsnJrnlButton, "Click to copy the USN Journal from the remote host.")
$tooltip.SetToolTip($buttonSelectRemoteFile, "Click to open a custom remote file system exporer.")
$tooltip.SetToolTip($buttonSelectLocalFile, "Click to select a file from your local machine for use.")
$tooltip.SetToolTip($buttonPWChange, "Click to force the specified user to change their password.")
$tooltip.SetToolTip($buttonLogOff, "Click to force the spefified user off of the remote computer.")
$tooltip.SetToolTip($buttonDisableAcc, "Click to disable the specified user's account")
$tooltip.SetToolTip($buttonEnableAcc, "Click to enable the specified user's account.")
$tooltip.SetToolTip($buttonSysInfo, "Click to retrieve AD info on the specified remote host and all users who have logged into this host. `r`n This buttton populates the Username dropdown.")
$tooltip.SetToolTip($buttonRestart, "Click to command the remote computer to restart.")
$tooltip.SetToolTip($buttonKillProcess, "Click to kill the selected process from the remote computer.")
$tooltip.SetToolTip($buttonShutdown, "Click to command the remote computer to shutdown.")
$tooltip.SetToolTip($buttonCopyFile, "Click to copy the file specified in the Remote File Path to the CopiedFiles directory on the local host.")
$tooltip.SetToolTip($buttonDeleteFile, "Delete the file specified in the Remote File Path from the remote host.")
$tooltip.SetToolTip($buttonIntelligizer, "Click to scrape indicators from collected reports and logs")
$tooltip.SetToolTip($buttonBoxEmAll, "Click to sandbox all files in the CopiedFiles directory.")
$tooltip.SetToolTip($buttonGetIntel, "Click to retrieve intel on specified indicator.")
$tooltip.SetToolTip($buttonUndoIsolation, "Click to remove firewall rules applied for isolation.")

#MWH#

$Form.Add_FormClosing({
    $ScriptEndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Log_Message -Message "Your session ended at $ScriptEndTime" -LogFilePath $LogFile
    $textboxResults.AppendText("Your session ended at $ScriptEndTime")

})
$result = $Form.ShowDialog()
