$path = "C:\Users\JeremyMiller\OneDrive - iCapital Network\Documents\Projects\Automation\Process2Thread\FreezeDiscovery_V2.ps1"

# Backup
Copy-Item $path ($path + ".bak") -Force

# Decode HTML entities commonly introduced by Teams/Outlook/wiki editors
$content = Get-Content $path -Raw
$content = $content -replace '&lt;', '<'
$content = $content -replace '&gt;', '>'
$content = $content -replace '&amp;', '&'

# Write back (UTF8)
Set-Content -Path $path -Value $content -Encoding UTF8