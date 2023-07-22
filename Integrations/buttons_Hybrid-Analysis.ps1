$submitfileButton.Add_Click({
    $sampleFile = if ($comboboxlocalFilePath.SelectedItem) {
        $comboboxlocalFilePath.SelectedItem.ToString()
    } else {
        $comboboxlocalFilePath.Text
    }

    $pythonScript = "submit_file_falcon.py"
    $pythonExe = "python"

    $output = & $pythonExe $pythonScript $sampleFile
    $textboxResults.AppendText("Python script output: $output `r`n")

    $script:JobId = $output.Trim()

    if ($script:JobId -ne $null) {
        $buttonRetrieveReportfile.Enabled = $true
    }
})
$form.Controls.Add($submitfileButton)


$buttonBoxEmAll.Add_Click({
    $directoryPath = ".\CopiedFiles"
    $pythonScript = "mass_submit_files_falcon.py"
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
    $jobId = $script:JobId
    $Response = Invoke-RestMethod -Uri "https://www.hybrid-analysis.com/api/v2/report/$jobId/summary" -Headers @{"APIKEY" = "YOUR_API_KEY"} -Method Get
    if ($Response.job_status -eq "finished") {
        $textboxResults.AppendText(($Response | ConvertTo-Json -Depth 100) + [Environment]::NewLine)
    } else {
        $textboxResults.AppendText("Report for job id: $jobId is not yet ready. Please wait and try again.")
    }
})
$form.Controls.Add($buttonRetrieveReportfile)
