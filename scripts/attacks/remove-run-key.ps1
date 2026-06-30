# Lab cleanup - remove T1547.001 persistence entry

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
  -Name "AtomicRedTeamPersistence" -ErrorAction SilentlyContinue

Write-Host "Run key removed (if it existed)."
