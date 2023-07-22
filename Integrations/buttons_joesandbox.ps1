$submitfileButton.Add_Click({
    $sampleFile = if ($comboboxlocalFilePath.SelectedItem) {
        $comboboxlocalFilePath.SelectedItem.ToString()
    } else {
        $comboboxlocalFilePath.Text
    }

    $pythonScript = "submit_file_joe.py"
    $pythonExe = "python"

    $output = & $pythonExe $pythonScript $sampleFile
    $textboxResults.AppendText("Python script output: $output `r`n")

    $script:WebId = $output.Trim()

    if ($script:WebId -ne $null) {
        $buttonRetrieveReportfile.Enabled = $true
    }
})
$form.Controls.Add($submitfileButton)

$buttonBoxEmAll.Add_Click({
    $directoryPath = ".\CopiedFiles"
    $pythonScript = "mass_submit_files_joe.py"
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
    $webId = $script:WebId
    $Response = Invoke-RestMethod -Uri "https://jbxcloud.joesecurity.org/api/v2/analysis/$webId" -Headers @{"Authorization" = "API_KEY"} -Method Get 
    if ($Response.status_code -eq 200) {
        $textboxResults.AppendText(($Response | ConvertTo-Json -Depth 100) + [Environment]::NewLine)
    } else {
        $textboxResults.AppendText("Report for webid: $webId is not yet ready. Please wait and try again.")
    }
})
$form.Controls.Add($buttonRetrieveReportfile)
