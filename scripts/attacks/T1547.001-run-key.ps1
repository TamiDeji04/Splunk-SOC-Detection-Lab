# T1547.001 - Registry Run key persistence (lab simulation)
# Run in Admin PowerShell on the Windows VM.
# Expected: Sysmon Event 13 under \Run\

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "AtomicRedTeamPersistence" `
  -Value "powershell.exe -WindowStyle Hidden -Command Start-Sleep 3600" -Force

Write-Host "Done. Verify in Splunk: index=endpoint EventCode=13 TargetObject=*\Run\*"
