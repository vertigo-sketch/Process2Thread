[CmdletBinding()]
param(
    # Tools folder (ProcDump/PsSuspend can live here; folder created if missing)
    [string]$ToolsFolder = "C:\Temp\Procdump",

    # Output bundles
    [string]$OutputRoot  = "C:\Temp\HungDumps",

    # Monitoring cadence
    [int]$ScanIntervalSeconds = 5,

    # Hybrid thresholds
    [int]$AllowListConfirmSeconds    = 30,
    [int]$NonAllowListConfirmSeconds = 60,

    # Dump series (time slices)
    [int]$DumpSeriesCount = 4,
    [int]$DumpSeriesIntervalSeconds = 10,

    # NEW: dump profile
    [ValidateSet("Mini","MiniWithHandles","Full")]
    [string]$DumpProfile = "MiniWithHandles",

    # Cooldown per PID
    [int]$PerProcessCooldownMinutes = 10,

    # WinDbg CLI debugger
    [string]$CdbPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",

    # Local symbol cache
    [string]$SymbolCache = "C:\Temp\Symbols",

    # NEW: cdb controls
    [int]$CdbTimeoutSeconds = 120,
    [switch]$EnableOnlineSymbols,

    # Total runtime
    [int]$MaxRunMinutes = 120,

    # TEST MODE
    [int]$TestPID = 0,

    [ValidateSet("None","Suspend")]
    [string]$TestAction = "Suspend",

    [switch]$ExitAfterTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# ============================================================
# Normalize inputs (avoid empty-string Test-Path binding issues)
# ============================================================
if ([string]::IsNullOrWhiteSpace($ToolsFolder)) { $ToolsFolder = "C:\Temp\Procdump" }
if ([string]::IsNullOrWhiteSpace($OutputRoot))  { $OutputRoot  = "C:\Temp\HungDumps" }
if ([string]::IsNullOrWhiteSpace($SymbolCache)) { $SymbolCache = "C:\Temp\Symbols" }

# ============================================================
# Hybrid allow/deny config
# ============================================================
$NoiseProcessDenyList = @(
  "dwm.exe","sihost.exe","runtimebroker.exe","applicationframehost.exe",
  "shellexperiencehost.exe","startmenuexperiencehost.exe",
  "searchhost.exe","searchapp.exe","textinputhost.exe",
  "lockapp.exe","ctfmon.exe","audiodg.exe"
) | ForEach-Object { $_.ToLower() }

$PreferredAllowList = @(
  "explorer.exe","widgets.exe","onedrive.exe",
  "winword.exe","excel.exe","powerpnt.exe","outlook.exe",
  "teams.exe","msedge.exe","chrome.exe"
) | ForEach-Object { $_.ToLower() }

$EvidenceIndicators = @("ntdll!NtReadFile","ntdll!NtCreateFile","FLTMGR!","cldflt!")

# ============================================================
# Helpers
# ============================================================
function Ensure-Dir {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Resolve-FolderSafe {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try { return (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path } catch { return $Path }
}

function Find-FirstExistingFile {
    param([string[]]$Candidates)
    foreach ($c in $Candidates) { if ($c -and (Test-Path -LiteralPath $c)) { return $c } }
    return $null
}

function Get-ProcDumpPath {
    param([string]$Folder)
    $f = Resolve-FolderSafe $Folder
    Find-FirstExistingFile @((Join-Path $f "procdump64.exe"), (Join-Path $f "procdump.exe"))
}

function Get-PsSuspendPath {
    param([string]$Folder)
    $f = Resolve-FolderSafe $Folder
    Find-FirstExistingFile @(
      (Join-Path $f "PsSuspend64.exe"), (Join-Path $f "pssuspend64.exe"),
      (Join-Path $f "PsSuspend.exe"),   (Join-Path $f "pssuspend.exe")
    )
}

# NEW: map DumpProfile -> ProcDump switch
function Get-ProcDumpDumpSwitch {
    param([ValidateSet("Mini","MiniWithHandles","Full")] [string]$Profile)

    switch ($Profile) {
        "Full"           { return "-ma" } # full memory [1](https://support.citrix.com/external/article/CTX124508/using-procdump-for-troubleshooting.html)
        "MiniWithHandles"{ return "-mp" } # threads/handles + read/write memory [1](https://support.citrix.com/external/article/CTX124508/using-procdump-for-troubleshooting.html)
        "Mini"           { return "" }    # minimal/default (smallest)
    }
}

# ============================================================
# Win32 IsHungAppWindow (no delegates)
# ============================================================
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Win32 {
  [DllImport("user32.dll")]
  public static extern bool IsHungAppWindow(IntPtr hwnd);
}
"@ -ErrorAction SilentlyContinue

# ============================================================
# Hung detection (process-centric)
# ============================================================
function Get-HungProcesses {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
        try {
            if ($p.MainWindowHandle -eq 0) { continue }
            $exe = ($p.ProcessName + ".exe").ToLower()
            if ($NoiseProcessDenyList -contains $exe) { continue }

            if ([Win32]::IsHungAppWindow([IntPtr]$p.MainWindowHandle)) {
                $out.Add([pscustomobject]@{
                    TargetPid  = [int]$p.Id
                    ProcessExe = $exe
                    WindowText = $p.MainWindowTitle
                })
            }
        } catch { }
    }
    return @($out)
}

# ============================================================
# ProcDump capture (binder-proof via cmd.exe /c)
# ============================================================
function Capture-DumpSeries {
    param(
        [string]$ProcDumpExe,
        [int]$TargetPid,
        [string]$OutDir,
        [ValidateSet("Mini","MiniWithHandles","Full")] [string]$Profile
    )

    Ensure-Dir $OutDir

    $dumpSwitch = Get-ProcDumpDumpSwitch -Profile $Profile

    # Multi-dump series uses -n (count) and -s (seconds between dumps) [2](https://www.veritas.com/support/en_US/article.100061081)
    # Dump type uses -ma (Full) or -mp (MiniWithHandles) [1](https://support.citrix.com/external/article/CTX124508/using-procdump-for-troubleshooting.html)
    $cmd = if ([string]::IsNullOrWhiteSpace($dumpSwitch)) {
        "`"$ProcDumpExe`" -n $DumpSeriesCount -s $DumpSeriesIntervalSeconds $TargetPid `"$OutDir`""
    } else {
        "`"$ProcDumpExe`" $dumpSwitch -n $DumpSeriesCount -s $DumpSeriesIntervalSeconds $TargetPid `"$OutDir`""
    }

    cmd.exe /c $cmd | Out-Null
}

# ============================================================
# cdb execution with timeout + reliable logging
# ============================================================
function Invoke-CdbWithTimeout {
    param(
        [string]$CdbExe,
        [string]$DumpFile,
        [string]$LogFile,
        [string]$SymbolPath,
        [int]$TimeoutSeconds
    )

    # We redirect stdout+stderr to guarantee non-empty logs even if -logo buffers
    $cmd = "`"$CdbExe`" -y `"$SymbolPath`" -z `"$DumpFile`" -c `".reload /f; ~* k 10; q`" > `"$LogFile`" 2>&1"

    $p = Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", $cmd) -NoNewWindow -PassThru
    $ok = $p.WaitForExit($TimeoutSeconds * 1000)

    if (-not $ok) {
        try { $p.Kill() } catch { }
        try { taskkill /IM cdb.exe /F | Out-Null } catch { }
        return $false
    }
    return $true
}

function Analyze-Dump {
    param(
        [string]$DumpFile,
        [string]$OutDir,
        [string]$CdbExe,
        [string]$SymCache,
        [switch]$OnlineSyms
    )

    Ensure-Dir $OutDir
    Ensure-Dir $SymCache

    $log = Join-Path $OutDir "cdb.log"

    # Offline symbols by default; enable online explicitly
    $symPath = $SymCache
    if ($OnlineSyms) {
        $symPath = "SRV*$SymCache*https://msdl.microsoft.com/download/symbols"
    }

    $finished = Invoke-CdbWithTimeout -CdbExe $CdbExe -DumpFile $DumpFile -LogFile $log -SymbolPath $symPath -TimeoutSeconds $CdbTimeoutSeconds

    $matches = @()
    if (Test-Path -LiteralPath $log) {
        foreach ($sig in $EvidenceIndicators) {
            $hits = Select-String -Path $log -Pattern $sig -SimpleMatch -ErrorAction SilentlyContinue
            if ($hits) { $matches += $hits.Line }
        }
    }

    [pscustomobject]@{
        Dump        = $DumpFile
        LogFile     = $log
        CdbFinished = $finished
        Evidence    = ($matches | Select-Object -Unique)
        DumpProfile = $DumpProfile
        SymbolPath  = $symPath
        TimeoutSec  = $CdbTimeoutSeconds
    } | ConvertTo-Json -Depth 6 |
      Out-File (Join-Path $OutDir "Evidence.json") -Encoding UTF8 -Force
}

# ============================================================
# TestPID mode
# ============================================================
function Invoke-TestPID {
    param(
        [int]$TestTargetPid,
        [string]$ProcDumpExe,
        [string]$PsSuspendExe,
        [string]$CdbExe
    )

    $proc = Get-Process -Id $TestTargetPid -ErrorAction Stop
    $exe = ($proc.ProcessName + ".exe").ToLower()

    if ($NoiseProcessDenyList -contains $exe) { throw "TestPID target '$exe' is denylisted." }

    $suspended = $false
    if ($TestAction -eq "Suspend" -and $PsSuspendExe) {
        cmd.exe /c "`"$PsSuspendExe`" $TestTargetPid" | Out-Null
        $suspended = $true
        Start-Sleep -Seconds 2
        Write-Host "[OK] Suspended target process."
    }

    try {
        $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $caseDir = Join-Path $OutputRoot ("TEST_Hang_{0}_PID{1}_{2}" -f $exe.Replace(".","_"), $TestTargetPid, $stamp)
        $dumpDir = Join-Path $caseDir "Dumps"
        $anaDir  = Join-Path $caseDir "Analysis"
        Ensure-Dir $caseDir; Ensure-Dir $dumpDir; Ensure-Dir $anaDir

        Write-Host ("[TEST CAPTURE] DumpProfile={0} Count={1} Interval={2}s" -f $DumpProfile, $DumpSeriesCount, $DumpSeriesIntervalSeconds)

        Capture-DumpSeries -ProcDumpExe $ProcDumpExe -TargetPid $TestTargetPid -OutDir $dumpDir -Profile $DumpProfile

        $dumps = Get-ChildItem -Path $dumpDir -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime
        $i = 0
        foreach ($d in $dumps) {
            $i++
            Write-Host ("[ANALYZE] Dump {0}/{1}: {2}" -f $i, @($dumps).Count, $d.Name)
            Analyze-Dump -DumpFile $d.FullName -OutDir (Join-Path $anaDir $d.BaseName) -CdbExe $CdbExe -SymCache $SymbolCache -OnlineSyms:$EnableOnlineSymbols
        }

        $zip = "$caseDir.zip"
        if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
        Compress-Archive -Path "$caseDir\*" -DestinationPath $zip -Force
        Write-Host ("[TEST DONE] Bundle: {0}" -f $zip)
    }
    finally {
        if ($suspended -and $PsSuspendExe) {
            cmd.exe /c "`"$PsSuspendExe`" -r $TestTargetPid" | Out-Null
            Write-Host "[OK] Resumed target process."
        }
    }
}

# ============================================================
# Setup + tool checks + diagnostics
# ============================================================
Ensure-Dir $ToolsFolder
Ensure-Dir $OutputRoot
Ensure-Dir $SymbolCache

$toolsResolved = Resolve-FolderSafe $ToolsFolder
$ProcDumpExe   = Get-ProcDumpPath -Folder $toolsResolved
$PsSuspendExe  = Get-PsSuspendPath -Folder $toolsResolved

if (-not (Test-Path -LiteralPath $CdbPath)) {
    $alt = Join-Path $toolsResolved "cdb.exe"
    if (Test-Path -LiteralPath $alt) { $CdbPath = $alt }
}

# Diagnostics
$diagPath = Join-Path $OutputRoot "ToolDetect_DIAG.txt"
@(
  "Tool detection diagnostics"
  ("Time: {0}" -f (Get-Date))
  ("ToolsFolder(resolved): {0}" -f $toolsResolved)
  ("ProcDump: {0}" -f $(if ($ProcDumpExe) { $ProcDumpExe } else { "<not found>" }))
  ("PsSuspend: {0}" -f $(if ($PsSuspendExe) { $PsSuspendExe } else { "<not found>" }))
  ("cdb.exe: {0}" -f $CdbPath)
  ("SymbolCache: {0}" -f $SymbolCache)
  ("EnableOnlineSymbols: {0}" -f $EnableOnlineSymbols)
  ("CdbTimeoutSeconds: {0}" -f $CdbTimeoutSeconds)
  ("DumpProfile: {0}" -f $DumpProfile)
) | Out-File $diagPath -Encoding UTF8 -Force

if (-not $ProcDumpExe) { throw "Missing ProcDump binary." }
if (-not (Test-Path -LiteralPath $CdbPath)) { throw "Missing cdb.exe." }

Write-Host "ProcDump: $ProcDumpExe"
Write-Host ("PsSuspend: {0}" -f $(if ($PsSuspendExe) { $PsSuspendExe } else { "<not found>" }))
Write-Host "cdb.exe : $CdbPath"
Write-Host "Output : $OutputRoot"
Write-Host "Diag   : $diagPath"
Write-Host ("DumpProfile: {0}" -f $DumpProfile)
Write-Host ""

# ============================================================
# Test mode entry
# ============================================================
if ($TestPID -gt 0) {
    Invoke-TestPID -TestTargetPid $TestPID -ProcDumpExe $ProcDumpExe -PsSuspendExe $PsSuspendExe -CdbExe $CdbPath
    if ($ExitAfterTest) { return }
}

# ============================================================
# Monitor mode
# ============================================================
Write-Host ("Monitoring for hung processes for up to {0} minute(s)..." -f $MaxRunMinutes)
$firstSeen = @{}
$lastDump  = @{}
$deadline  = (Get-Date).AddMinutes($MaxRunMinutes)

while ((Get-Date) -lt $deadline) {

    foreach ($h in Get-HungProcesses) {
        $targetPid  = [int]$h.TargetPid
        $processExe = [string]$h.ProcessExe

        if (-not $firstSeen.ContainsKey($targetPid)) {
            $firstSeen[$targetPid] = Get-Date
            continue
        }

        $elapsed = (New-TimeSpan -Start $firstSeen[$targetPid] -End (Get-Date)).TotalSeconds
        $threshold = if ($PreferredAllowList -contains $processExe) { $AllowListConfirmSeconds } else { $NonAllowListConfirmSeconds }
        if ($elapsed -lt $threshold) { continue }

        if ($lastDump.ContainsKey($targetPid)) {
            $mins = (New-TimeSpan -Start $lastDump[$targetPid] -End (Get-Date)).TotalMinutes
            if ($mins -lt $PerProcessCooldownMinutes) { continue }
        }

        $stamp   = Get-Date -Format "yyyyMMdd_HHmmss"
        $caseDir = Join-Path $OutputRoot ("Hang_{0}_PID{1}_{2}" -f $processExe.Replace(".","_"), $targetPid, $stamp)
        $dumpDir = Join-Path $caseDir "Dumps"
        $anaDir  = Join-Path $caseDir "Analysis"
        Ensure-Dir $caseDir; Ensure-Dir $dumpDir; Ensure-Dir $anaDir

        Write-Host ("[CAPTURE] {0} (PID {1}) hung for {2:n0}s -> DumpProfile={3}" -f $processExe, $targetPid, $elapsed, $DumpProfile)
        Capture-DumpSeries -ProcDumpExe $ProcDumpExe -TargetPid $targetPid -OutDir $dumpDir -Profile $DumpProfile
        $lastDump[$targetPid]  = Get-Date
        $firstSeen[$targetPid] = Get-Date

        $dumps = Get-ChildItem -Path $dumpDir -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime
        $i = 0
        foreach ($d in $dumps) {
            $i++
            Write-Host ("[ANALYZE] Dump {0}/{1}: {2}" -f $i, @($dumps).Count, $d.Name)
            Analyze-Dump -DumpFile $d.FullName -OutDir (Join-Path $anaDir $d.BaseName) -CdbExe $CdbPath -SymCache $SymbolCache -OnlineSyms:$EnableOnlineSymbols
        }

        $zip = "$caseDir.zip"
        if (Test-Path -LiteralPath $zip) { Remove-Item $zip -Force }
        Compress-Archive -Path "$caseDir\*" -DestinationPath $zip -Force
        Write-Host ("[DONE] Bundle: {0}" -f $zip)
    }

    Start-Sleep -Seconds $ScanIntervalSeconds
}

Write-Host "Monitoring complete."