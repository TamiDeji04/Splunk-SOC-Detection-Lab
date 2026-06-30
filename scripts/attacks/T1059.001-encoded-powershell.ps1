# T1059.001 - Encoded PowerShell execution (lab simulation)
# Run in Admin PowerShell on the Windows VM.
# Expected: Sysmon Event 1 with -EncodedCommand

$cmd = "Write-Host 'AtomicRedTeam T1059 test'"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -EncodedCommand $enc

Write-Host "Done. Verify in Splunk: index=endpoint EventCode=1 CommandLine=*EncodedCommand*"
