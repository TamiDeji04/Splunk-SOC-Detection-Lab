# T1110.001 - Brute force password guessing (lab simulation)
# Run in Admin PowerShell on the Windows VM.
# Expected: Security Event 4625 in Splunk (index=endpoint EventCode=4625)

1..12 | ForEach-Object {
  $p = ConvertTo-SecureString "WrongPass$_!" -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential("baduser", $p)
  Start-Process cmd.exe -Credential $cred -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 400
}

Write-Host "Done. Verify in Splunk: index=endpoint EventCode=4625"
