# T1071.001 - Web protocol beacon (lab simulation)
# Run in Admin PowerShell on the Windows VM.
# Expected: Sysmon Event 3 outbound from PowerShell

1..6 | ForEach-Object {
  Invoke-WebRequest "http://www.example.com" -UseBasicParsing | Out-Null
  Start-Sleep 3
}

Write-Host "Done. Verify in Splunk: index=endpoint EventCode=3 Image=*powershell.exe*"
