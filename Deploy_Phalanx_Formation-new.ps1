<#
This script downloads and installs a variety of security tools, including PowerShell 7, 
the vmray-rest-api Python module, DeepBlueCLI, Hayabusa, Sysmon, and the Get-ZimmermanTools 
script. It also creates a set of directories to store the tools and their associated files.

The script first defines a set of variables, including the names of the directories to create 
and the download URLs for the various tools. It then loops through the directories and creates 
them if they do not already exist.

Next, the script retrieves the latest release information for PowerShell 7 and extracts the 
download URL for the latest MSI release. If the download URL is valid, the script downloads 
the MSI file and installs PowerShell 7.

The script then installs the vmray-rest-api Python module using the pip command.

Finally, the script downloads and installs the remaining tools.

The script also writes the success or failure of each action to the console. This makes it 
easier to track the progress of the script and troubleshoot any errors that may occur.

Here are some of the benefits of using this script:

    It can be used to quickly and easily download and install a variety of security tools.
    It can be used to create a consistent set of directories to store the tools and their 
    associated files. It can be used to track the success or failure of each action.

Here are some of the limitations of this script:

    It is not a comprehensive list of security tools.
    It does not include any instructions on how to use the tools.
    It is not a replacement for professional security advice.

Overall, this script is a useful tool for anyone who wants to quickly and easily download and 
install a variety of security tools.
#>

$directories = @(
    ".\CopiedFiles",
    ".\Logs",
    ".\Logs\EVTX",
    ".\Logs\Reports",
    ".\Logs\Audit",
    ".\Rules",
    ".\Tools",
    ".\Tools\Hayabusa",
    ".\Tools\Sysmon",
    ".\Tools\EZTools"
)

$downloadError = $null
$installError = $null

################## Workspace ##################
foreach ($directory in $directories) {
    try {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null

        Write-Host "Directory $directory created successfully."
    } catch {
        $downloadError = $_
    }
}

################## Downloads ##################
# Define the URL for the PowerShell 7 MSI installer
$downloadUrl = "https://github.com/PowerShell/PowerShell/releases/download/v7.3.5/PowerShell-7.3.5-win-x64.msi"

# Extract the filename from the download URL
$fileName = $downloadUrl -split '/' | Select-Object -Last 1

# Define the path to save the MSI file
$savePath = Join-Path -Path $env:TEMP -ChildPath $fileName

try {
    # Download the MSI file
    Invoke-WebRequest -Uri $downloadUrl -OutFile $savePath

    Write-Host "PowerShell 7 MSI download successful."

    # Install PowerShell 7 using the downloaded MSI file
    Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$savePath`" /qn" -Wait

    # Clean up the temporary MSI file
    Remove-Item -Path $savePath

    Write-Host "PowerShell 7 installation successful."
} catch {
    $installError = $_
    Write-Host "An error occurred during installation: $installError"
}

# Define the URL for the Python download page
$downloadUrl = "https://www.python.org/ftp/python/3.11.4/python-3.11.4-amd64.exe"

# Retrieve the download page
$response = Invoke-WebRequest -Uri $downloadUrl

# Extract the download URL for the latest stable release of Python 3
if ($response) {
    # Define the path to save the installer
    $installerPath = Join-Path -Path c:\Test -ChildPath "python_installer.exe"

    # Download the installer
    Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath

    # Install Python for all users
    Start-Process -FilePath $installerPath -ArgumentList "/quiet", "TargetDir=C:\Python", "AddToPath=1", "AssociateFiles=1", "Shortcuts=1" -Wait

    # Clean up the installer
    Remove-Item -Path $installerPath
    Write-Host "Python downloaded and installed successfully."
}
else {
    Write-Host "Unable to retrieve the download link for Python."
    $downloadError = $_
}
 
# Install the numscrypt Python module
try {
    Start-Process -FilePath python.exe -ArgumentList "-m pip install numscrypt" -Wait
    Write-Host "numscrypt Python module installation successful."
} catch {
    $installError = $_
}

# Install the vmray-rest-api Python module
try {
    Start-Process -FilePath python.exe -ArgumentList "-m pip install vmray-rest-api" -Wait
    Write-Host "vmray-rest-api Python module installation successful."
} catch {
    $installError = $_
}

################## Download and unzip DeepBlueCLI repository ##################
try {
    $deepBlueCLIZip = Invoke-WebRequest -URI https://github.com/sans-blue-team/DeepBlueCLI/archive/refs/heads/master.zip -OutFile DeepBlueCLI.zip
    Expand-Archive DeepBlueCLI.zip -DestinationPath ".\Tools\" -Force
    Remove-Item DeepBlueCLI.zip

    # Remove existing DeepBlueCLI directory if it exists
    if (Test-Path .\Tools\DeepBlueCLI) {
        Remove-Item .\Tools\DeepBlueCLI -Recurse -Force
    }

    Rename-Item .\Tools\DeepBlueCLI-master -NewName DeepBlueCLI -Force | Out-Null

    Write-Host "DeepBlueCLI download and unzip successful."
} catch {
    Write-Host "DeepBlueCLI download and unzip failed:`n$_"
    $downloadError = $_
}


################## Get the latest Hayabusa release page ##################
$hayabusaApiUrl = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
$hayabusaReleaseData = Invoke-RestMethod -Uri $hayabusaApiUrl

# Extract the download URL for the latest Hayabusa release
$hayabusaDownloadUrl = $hayabusaReleaseData.assets |
                       Where-Object { $_.browser_download_url -like "*-win-64-bit.zip" } |
                       Select-Object -First 1 -ExpandProperty browser_download_url

# Prepare the local paths for downloading and extracting the Hayabusa zip file
$hayabusaZipPath = Join-Path -Path ".\Tools" -ChildPath "hayabusa-win-x64.zip"
$hayabusaExtractPath = ".\Tools\Hayabusa"

################## Download and extract Hayabusa ##################
try {
    Invoke-WebRequest -Uri $hayabusaDownloadUrl -OutFile $hayabusaZipPath
    Write-Host "Hayabusa download successful."
} catch {
    Write-Host "Hayabusa download failed:`n$_"
    $downloadError = $_
}

################## Extract the Hayabusa files ##################
try {
    Expand-Archive -Path $hayabusaZipPath -DestinationPath $hayabusaExtractPath -Force
    Write-Host "Hayabusa files extracted successfully."
} catch {
    Write-Host "Hayabusa files extraction failed:`n$_"
}

################## Rename the executable to hayabusa.exe ##################
$hayabusaExecutable = Get-ChildItem -Path $hayabusaExtractPath -Filter "hayabusa-*" -Recurse -File | Select-Object -First 1
$hayabusaExecutable | Rename-Item -NewName "hayabusa.exe" -Force | Out-Null

################## Update the Hayabusa rules ##################
$rulesPath = ".\Rules"
$hayabusaExecutablePath = Join-Path -Path $hayabusaExtractPath -ChildPath "hayabusa.exe"

try {
    & $hayabusaExecutablePath update-rules -r $rulesPath | Out-Null
    Write-Host "Hayabusa rules updated successfully."

    # Clean up the downloaded zip file
    Remove-Item -Path $hayabusaZipPath -Force
} catch {
    Write-Host "Hayabusa rules update failed:`n$_"
}


################## Download and unzip Sysmon ##################
$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonconfigurl = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
$sysmonZip = ".\Tools\Sysmon.zip"
$sysmonPath = ".\Tools\Sysmon"
$sysmonConfigPath = ".\Tools\Sysmon\sysmonconfig.xml"

try {
    Invoke-WebRequest -URI $sysmonUrl -OutFile $sysmonZip
    Expand-Archive $sysmonZip -DestinationPath $sysmonPath -Force
    Remove-Item $sysmonZip

    Invoke-WebRequest -URI $sysmonconfigurl -OutFile $sysmonConfigPath

    Write-Host "Sysmon and sysmonconfig download and unzip successful."
} catch {
    Write-Host "Sysmon and sysmonconfig download and unzip failed:`n$_"
    $downloadError = $_
}


################## Download and execute Get-ZimmermanTools to retrieve Eric Zimmerman's toolset ##################
$zimmermanToolsZip = Invoke-WebRequest -URI "https://raw.githubusercontent.com/EricZimmerman/Get-ZimmermanTools/master/Get-ZimmermanTools.ps1" -OutFile ".\Tools\EZTools\Get-ZimmermanTools.ps1"

try {
    unblock-file ".\Tools\EZTools\Get-ZimmermanTools.ps1"
    .\Tools\EZTools\Get-ZimmermanTools.ps1 -Dest ".\Tools\EZTools" -Verbose:$false *> $null
    Write-Host "Get-ZimmermanTools download and execution successful."
} catch {
    Write-Host "Get-ZimmermanTools download and execution failed:`n$_"
    $downloadError = $_
}

################## Errors ##################
if ($downloadError) {
    Write-Host "Error downloading files:`n$downloadError"
}

if ($installError) {
    Write-Host "Error installing software:`n$installError"
}

################## Success ##################
if (!$downloadError -and !$installError) {
    Write-Host "All downloads and installations successful."
}