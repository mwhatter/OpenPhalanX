$submitfileButton.Add_Click({
    $sampleFile = if ($comboboxlocalFilePath.SelectedItem) {
        $comboboxlocalFilePath.SelectedItem.ToString()
    } else {
        $comboboxlocalFilePath.Text
    }

    $pythonScript = "submit_file_virustotal.py"
    $pythonExe = "python"

    $output = & $pythonExe $pythonScript $sampleFile
    $textboxResults.AppendText("Python script output: $output `r`n")

    $script:FileId = $output.Trim()

    if ($script:FileId -ne $null) {
        $buttonRetrieveReportfile.Enabled = $true
    }
})
$form.Controls.Add($submitfileButton)

$buttonBoxEmAll.Add_Click({
    $directoryPath = ".\CopiedFiles"
    $pythonScript = "mass_submit_files_virustotal.py"
    $pythonExe = "python"
    
    # Get the number of files in the directory
    $fileCount = (Get-ChildItem -Path $directoryPath -File).Count

    # Ask for confirmation
    $confirmation = [System.Windows.Forms.MessageBox]::Show(
        "You are about to submit $fileCount files. Do you wish to continue?", 
        "Confirm Action", 
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Question)

    if($confirmation -eq 'Yes') {
        $output = & $pythonExe $pythonScript $directoryPath | Out-String
        $textboxResults.AppendText("Python script output: $output")
    }
})

$form.Controls.Add($buttonBoxEmAll)

$buttonRetrieveReportfile.Add_Click({
    $fileId = $script:FileId
    $Response = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/files/$fileId" -Headers @{"x-apikey" = "YOUR_API_KEY"} -Method Get
    if ($Response.data.attributes.status -eq "completed") {
        $textboxResults.AppendText(($Response.data.attributes | ConvertTo-Json -Depth 100) + [Environment]::NewLine)
    } else {
        $textboxResults.AppendText("Report for file id: $fileId is not yet ready. Please wait and try again.")
    }
})
$form.Controls.Add($buttonRetrieveReportfile)
