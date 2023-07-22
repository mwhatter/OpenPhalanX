$submitfileButton.Add_Click({
    $sampleFile = if ($comboboxlocalFilePath.SelectedItem) {
        $comboboxlocalFilePath.SelectedItem.ToString()
    } else {
        $comboboxlocalFilePath.Text
    }

    $pythonScript = "submit_file_cuckoo.py"
    $pythonExe = "python"

    $output = & $pythonExe $pythonScript $sampleFile
    $textboxResults.AppendText("Python script output: $output `r`n")

    $script:TaskId = $output.Trim()

    if ($script:TaskId -ne $null) {
        $buttonRetrieveReportfile.Enabled = $true
    }
})
$form.Controls.Add($submitfileButton)

$buttonRetrieveReportfile.Add_Click({
    $fileName = Split-Path $comboboxlocalFilePath.Text -Leaf
    $Response = Invoke-RestMethod -Uri "http://cuckoo-host:8090/tasks/report/$script:TaskId" -Method Get 

    if ($Response) {
        $textboxResults.AppendText("Report for Task ID: $script:TaskId" + [Environment]::NewLine)
        $textboxResults.AppendText(($Response | ConvertTo-Json -Depth 100) + [Environment]::NewLine)
    } else {
        $textboxResults.AppendText("No reports found for file: $fileName. Please wait and try again.")
    }
})
$form.Controls.Add($buttonRetrieveReportfile)


$buttonBoxEmAll.Add_Click({
    $directoryPath = ".\CopiedFiles"
    $pythonScript = "mass_submit_files_cuckoo.py"
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
