<#
AutoCaptureAnalyze_Dump_V04.ps1

PURPOSE
- Monitor for hung ("Not Responding") GUI processes (hybrid allow/deny model)
- Capture a timed dump series with ProcDump
- Analyze dumps automatically with WinDbg cdb.exe and extract evidence
- Provide TestPID mode for deterministic end-to-end validation
- NEW: Automatic escalation (capture 1 Full dump if evidence from initial dumps is weak)

INSTALLATION (Tools)
1) Create folder: C:\Temp\Procdump   (script will create it if missing)
2) Place these binaries into C:\Temp\Procdump:
   - procdump64.exe (preferred) OR procdump.exe
   - pssuspend.exe (optional, for TestAction Suspend)
   - (optional) cdb.exe if you want to keep it with tools; otherwise use default Windows Kits path
3) Ensure WinDbg Debugging Tools are installed (cdb.exe), unless you copied cdb.exe into ToolsFolder.

DUMP PROFILES
- Mini            : smallest/default (no explicit -ma/-mp passed)
- MiniWithHandles : default minimal (maps to -mp)
- Full            : full memory (maps to -ma)

AUTO-ESCALATION (NEW IN V04)
- If evidence from the initial dump series is "weak", the script will capture ONE additional Full dump and analyze it.
- "Weak" means: no NtReadFile/NtCreateFile + no FLTMGR/cldflt indications found in Evidence.json files.

HISTORICAL CHANGES
V01 (baseline)
- Initial hang-monitor + ProcDump capture + cdb analysis pipeline.

V02 (stability hardening)
- Removed EnumWindows/delegate usage (PS 5.1 brittle)
- Process-centric hang detection using IsHungAppWindow
- Avoided PS native argument binder issues by using cmd.exe /c for ProcDump and cdb calls
- Added cdb timeout/kill and guaranteed log output via stdout/stderr redirection
- Hardened Ensure-Dir to ignore empty/whitespace paths
- Avoided $PID collisions by never using $Pid variable names
- Added TestPID mode

V03
- Added -DumpProfile Mini|MiniWithHandles|Full and set default to MiniWithHandles (applies to Monitor and TestPID)
- Added top-of-file historical change log
- Versioned filename convention begins at V03

V04 (current)
- Added automatic escalation: if evidence is weak, capture 1 additional Full dump and analyze it.
- Added escalation controls: -EnableEscalation, -EscalationMaxFullDumps
#>

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

    # Dump profile (DEFAULT MINIMAL applies to both monitoring and TestPID)
    [ValidateSet("Mini","MiniWithHandles","Full")]
    [string]$DumpProfile = "MiniWithHandles",

    # Automatic escalation
    [switch]$EnableEscalation = $true,
    [int]$EscalationMaxFullDumps = 1,

    # Cooldown per PID
    [int]$PerProcessCooldownMinutes = 10,

    # WinDbg CLI debugger
    [string]$CdbPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",

    # Local symbol cache
    [string]$SymbolCache = "C:\Temp\Symbols",

    # cdb controls
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
    foreach ($c in $Candidates) {
        if ($c -and (Test-Path -LiteralPath $c)) { return $c }
    }
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

function Get-CdbPathResolved {
    param([string]$Preferred, [string]$Folder)
    if ($Preferred -and (Test-Path -LiteralPath $Preferred)) { return $Preferred }
    $f = Resolve-FolderSafe $Folder
    $fallback = Join-Path $f "cdb.exe"
    if (Test-Path -LiteralPath $fallback) { return $fallback }
    return $Preferred
}

function Get-ProcDumpDumpSwitch {
    param([ValidateSet("Mini","MiniWithHandles","Full")] [string]$Profile)
    switch ($Profile) {
        "Full"            { return "-ma" }  # full memory
        "MiniWithHandles" { return "-mp" }  # default minimal
        "Mini"            { return "" }     # smallest/default
    }
}

function Get-EvidenceStrength {
    param([string[]]$EvidenceLines)

    # "Strong" if we see a file I/O syscall and at least one filter stack indicator
    $hasIo = $false
    $hasFilter = $false

    foreach ($l in $EvidenceLines) {
        if ($l -like "*NtReadFile*" -or $l -like "*NtCreateFile*") { $hasIo = $true }
        if ($l -like "*FLTMGR*" -or $l -like "*cldflt*") { $hasFilter = $true }
    }

    if ($hasIo -and $hasFilter) { return "Strong" }
    if ($hasIo -or $hasFilter)  { return "Medium" }
    return "Weak"
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

    # ProcDump multi-dump series: -n (count) and -s (seconds between dumps) [1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
    $cmd = if ([string]::IsNullOrWhiteSpace($dumpSwitch)) {
        "`"$ProcDumpExe`" -n $DumpSeriesCount -s $DumpSeriesIntervalSeconds $TargetPid `"$OutDir`""
    } else {
        "`"$ProcDumpExe`" $dumpSwitch -n $DumpSeriesCount -s $DumpSeriesIntervalSeconds $TargetPid `"$OutDir`""
    }

    cmd.exe /c $cmd | Out-Null
}

function Capture-SingleDump {
    param(
        [string]$ProcDumpExe,
        [int]$TargetPid,
        [string]$OutDir,
        [ValidateSet("Mini","MiniWithHandles","Full")] [string]$Profile
    )

    Ensure-Dir $OutDir

    $dumpSwitch = Get-ProcDumpDumpSwitch -Profile $Profile

    # Single dump (no -n/-s series)
    $cmd = if ([string]::IsNullOrWhiteSpace($dumpSwitch)) {
        "`"$ProcDumpExe`" $TargetPid `"$OutDir`""
    } else {
        "`"$ProcDumpExe`" $dumpSwitch $TargetPid `"$OutDir`""
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

    # Use stdout/stderr redirection so the log is never empty even if cdb buffers.
    # cdb supports -z and -c for scripted dump analysis. [2](https://community.progress.com/s/article/How-to-use-Sysinternals-Procdump)
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

    # Offline symbols by default; online optional.
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

    $unique = @($matches | Select-Object -Unique)
    $strength = Get-EvidenceStrength -EvidenceLines $unique

    [pscustomobject]@{
        Dump           = $DumpFile
        LogFile        = $log
        CdbFinished    = $finished
        Evidence       = $unique
        EvidenceStrength = $strength
        DumpProfile    = $DumpProfile
        SymbolPath     = $symPath
        TimeoutSec     = $CdbTimeoutSeconds
    } | ConvertTo-Json -Depth 7 |
      Out-File (Join-Path $OutDir "Evidence.json") -Encoding UTF8 -Force
}

function Summarize-EvidenceFolder {
    param([string]$AnalysisRoot)

    $allEvidence = @()
    $files = Get-ChildItem -Path $AnalysisRoot -Recurse -Filter Evidence.json -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        try {
            $obj = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json
            if ($obj -and $obj.Evidence) { $allEvidence += @($obj.Evidence) }
        } catch { }
    }

    $allEvidence = @($allEvidence | Select-Object -Unique)
    $strength = Get-EvidenceStrength -EvidenceLines $allEvidence

    return [pscustomobject]@{
        EvidenceStrength = $strength
        EvidenceLines    = $allEvidence
        EvidenceCount    = @($allEvidence).Count
        EvidenceFiles    = @($files | Select-Object -ExpandProperty FullName)
    }
}

# ============================================================
# Escalation logic (NEW)
# ============================================================
function Maybe-EscalateToFull {
    param(
        [string]$ProcDumpExe,
        [int]$TargetPid,
        [string]$CaseDir,
        [string]$CdbExe
    )

    if (-not $EnableEscalation) { return $null }
    if ($EscalationMaxFullDumps -lt 1) { return $null }

    $analysisDir = Join-Path $CaseDir "Analysis"
    $summary = Summarize-EvidenceFolder -AnalysisRoot $analysisDir

    if ($summary.EvidenceStrength -ne "Weak") {
        return [pscustomobject]@{
            Escalated = $false
            Reason    = "Evidence not weak; escalation not required."
            PreStrength= $summary.EvidenceStrength
            FullDumpCaptured = $false
        }
    }

    # Evidence weak -> capture 1 Full dump and analyze it
    $escDir = Join-Path $CaseDir "Escalation_Full"
    $escDumpDir = Join-Path $escDir "Dumps"
    $escAnaDir  = Join-Path $escDir "Analysis"
    Ensure-Dir $escDir; Ensure-Dir $escDumpDir; Ensure-Dir $escAnaDir

    Write-Host ("[ESCALATE] Evidence was WEAK -> capturing 1 Full dump (PID {0})..." -f $TargetPid)

    Capture-SingleDump -ProcDumpExe $ProcDumpExe -TargetPid $TargetPid -OutDir $escDumpDir -Profile "Full"

    $dumps = Get-ChildItem -Path $escDumpDir -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime
    foreach ($d in $dumps) {
        Analyze-Dump -DumpFile $d.FullName -OutDir (Join-Path $escAnaDir $d.BaseName) -CdbExe $CdbExe -SymCache $SymbolCache -OnlineSyms:$EnableOnlineSymbols
    }

    $post = Summarize-EvidenceFolder -AnalysisRoot $escAnaDir

    $result = [pscustomobject]@{
        Escalated = $true
        Reason    = "Pre evidence weak; captured Full dump for deeper analysis."
        PreStrength = $summary.EvidenceStrength
        PostStrength = $post.EvidenceStrength
        FullDumpCaptured = $true
        FullDumpCount = @($dumps).Count
        FullEvidenceCount = $post.EvidenceCount
    }

    $result | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $escDir "EscalationSummary.json") -Encoding UTF8 -Force

    return $result
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

        # Escalation step (optional)
        $esc = Maybe-EscalateToFull -ProcDumpExe $ProcDumpExe -TargetPid $TestTargetPid -CaseDir $caseDir -CdbExe $CdbExe
        if ($esc) {
            $esc | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $caseDir "EscalationResult.json") -Encoding UTF8 -Force
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
$CdbResolved   = Get-CdbPathResolved -Preferred $CdbPath -Folder $toolsResolved

# Diagnostics file
$diagPath = Join-Path $OutputRoot "ToolDetect_DIAG.txt"
@(
  "Tool detection diagnostics"
  ("Time: {0}" -f (Get-Date))
  ("ToolsFolder(resolved): {0}" -f $toolsResolved)
  ("ProcDump: {0}" -f $(if ($ProcDumpExe) { $ProcDumpExe } else { "<not found>" }))
  ("PsSuspend: {0}" -f $(if ($PsSuspendExe) { $PsSuspendExe } else { "<not found>" }))
  ("cdb.exe: {0}" -f $CdbResolved)
  ("SymbolCache: {0}" -f $SymbolCache)
  ("EnableOnlineSymbols: {0}" -f $EnableOnlineSymbols)
  ("CdbTimeoutSeconds: {0}" -f $CdbTimeoutSeconds)
  ("DumpProfile: {0}" -f $DumpProfile)
  ("EnableEscalation: {0}" -f $EnableEscalation)
  ("EscalationMaxFullDumps: {0}" -f $EscalationMaxFullDumps)
) | Out-File $diagPath -Encoding UTF8 -Force

if (-not $ProcDumpExe) { throw "Missing ProcDump binary." }
if (-not (Test-Path -LiteralPath $CdbResolved)) { throw "Missing cdb.exe." }

Write-Host "ProcDump: $ProcDumpExe"
Write-Host ("PsSuspend: {0}" -f $(if ($PsSuspendExe) { $PsSuspendExe } else { "<not found>" }))
Write-Host "cdb.exe : $CdbResolved"
Write-Host "Output : $OutputRoot"
Write-Host "Diag   : $diagPath"
Write-Host ("DumpProfile: {0}" -f $DumpProfile)
Write-Host ("EnableEscalation: {0}  MaxFullDumps: {1}" -f $EnableEscalation, $EscalationMaxFullDumps)
Write-Host ""

# ============================================================
# Test mode entry
# ============================================================
if ($TestPID -gt 0) {
    Invoke-TestPID -TestTargetPid $TestPID -ProcDumpExe $ProcDumpExe -PsSuspendExe $PsSuspendExe -CdbExe $CdbResolved
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
            Analyze-Dump -DumpFile $d.FullName -OutDir (Join-Path $anaDir $d.BaseName) -CdbExe $CdbResolved -SymCache $SymbolCache -OnlineSyms:$EnableOnlineSymbols
        }

        # Escalation step (optional)
        $esc = Maybe-EscalateToFull -ProcDumpExe $ProcDumpExe -TargetPid $targetPid -CaseDir $caseDir -CdbExe $CdbResolved
        if ($esc) {
            $esc | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $caseDir "EscalationResult.json") -Encoding UTF8 -Force
        }

        $zip = "$caseDir.zip"
        if (Test-Path -LiteralPath $zip) { Remove-Item $zip -Force }
        Compress-Archive -Path "$caseDir\*" -DestinationPath $zip -Force
        Write-Host ("[DONE] Bundle: {0}" -f $zip)
    }

    Start-Sleep -Seconds $ScanIntervalSeconds
}

Write-Host "Monitoring complete."