<#
AutoCaptureAnalyze_Dump_V06.ps1

PURPOSE
- Monitor for hung ("Not Responding") GUI processes (hybrid allow/deny model)
- Capture a timed dump series with ProcDump
- Analyze dumps automatically with WinDbg cdb.exe and extract evidence (incl. WdFilter/CSAgent)
- Automatic escalation: capture 1 Full dump if initial evidence is insufficient

INSTALLATION (Tools)
1) Create folder: C:\Temp\Procdump   (script will create it if missing)
2) Place these binaries into C:\Temp\Procdump:
   - procdump64.exe (preferred) OR procdump.exe
   - pssuspend.exe (optional, for controlled real-world validation)
   - (optional) cdb.exe if you want to keep it with tools; otherwise use default Windows Kits path
3) Ensure WinDbg Debugging Tools are installed (cdb.exe), unless you copied cdb.exe into ToolsFolder.

DUMP PROFILES
- Mini            : smallest/default (no explicit -ma/-mp passed)
- MiniWithHandles : default minimal (maps to -mp)  [DEFAULT]
- Full            : full memory (maps to -ma)

AUTO-ESCALATION (V05+)
- Escalates when EvidenceStrength is Weak OR (Medium AND SecurityDetected AND NOT IoSyscallDetected)
- Captures ONE additional Full dump (configurable) and analyzes it

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

V03
- Added -DumpProfile Mini|MiniWithHandles|Full and set default to MiniWithHandles
- Added top-of-file historical change log
- Versioned filename convention begins at V03

V04
- Added automatic escalation: if evidence is weak, capture 1 additional Full dump and analyze it.
- Added escalation controls: -EnableEscalation, -EscalationMaxFullDumps

V05
- Added WdFilter and CSAgent detection from cdb stack evidence
- Updated evidence classification and escalation rule (Medium+Security+noIo triggers escalation)

V06 (current)
- Removed TestPID mode (params + function + call site removed)
- Focus now is monitor-only for real-world validation scenarios
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

    # Dump profile (default minimal)
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
    [int]$MaxRunMinutes = 120
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

# Evidence signatures to spot in cdb output
$EvidenceIndicators = @(
  "ntdll!NtReadFile",
  "ntdll!NtCreateFile",
  "FLTMGR!",
  "cldflt!",
  "WdFilter!",
  "CSAgent!"
)

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
        "Full"            { return "-ma" }  # full memory (-ma) [2](https://support.tibco.com/external/article/78297/how-to-use-procdump-to-collect-logs-in-c.html)
        "MiniWithHandles" { return "-mp" }  # default minimal (-mp) [2](https://support.tibco.com/external/article/78297/how-to-use-procdump-to-collect-logs-in-c.html)
        "Mini"            { return "" }     # smallest/default
    }
}

function Classify-Evidence {
    param([string[]]$EvidenceLines)

    $io = $false
    $fltMgr = $false
    $cloud = $false
    $defender = $false
    $crowdstrike = $false

    foreach ($l in $EvidenceLines) {
        if ($l -like "*NtReadFile*" -or $l -like "*NtCreateFile*") { $io = $true }
        if ($l -like "*FLTMGR!*") { $fltMgr = $true }
        if ($l -like "*cldflt!*") { $cloud = $true }
        if ($l -like "*WdFilter!*") { $defender = $true }
        if ($l -like "*CSAgent!*")  { $crowdstrike = $true }
    }

    $security = ($defender -or $crowdstrike)
    $filterAny = ($fltMgr -or $cloud -or $security)

    $strength = "Weak"
    if ($io -and $filterAny) { $strength = "Strong" }
    elseif ($io -or $filterAny) { $strength = "Medium" }

    return [pscustomobject]@{
        IoSyscallDetected   = $io
        FilterMgrDetected   = $fltMgr
        CloudCldfltDetected = $cloud
        WdFilterDetected    = $defender
        CSAgentDetected     = $crowdstrike
        SecurityDetected    = $security
        FilterAnyDetected   = $filterAny
        EvidenceStrength    = $strength
    }
}

function Should-Escalate {
    param([pscustomobject]$Summary)

    if (-not $EnableEscalation) { return $false }
    if ($EscalationMaxFullDumps -lt 1) { return $false }

    # Rule 1: Weak -> escalate
    if ($Summary.EvidenceStrength -eq "Weak") { return $true }

    # Rule 2: Medium + Security detected + no I/O syscall -> escalate
    if ($Summary.EvidenceStrength -eq "Medium") {
        if ($Summary.Classification.SecurityDetected -and (-not $Summary.Classification.IoSyscallDetected)) {
            return $true
        }
    }

    return $false
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

    # ProcDump time series uses -n and -s [1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
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

    # cdb supports -z dump open and -c command string execution [3](https://community.progress.com/s/article/How-to-use-Sysinternals-Procdump)
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
    $class = Classify-Evidence -EvidenceLines $unique

    [pscustomobject]@{
        Dump           = $DumpFile
        LogFile        = $log
        CdbFinished    = $finished
        Evidence       = $unique
        Classification = $class
        DumpProfile    = $DumpProfile
        SymbolPath     = $symPath
        TimeoutSec     = $CdbTimeoutSeconds
    } | ConvertTo-Json -Depth 8 |
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
    $class = Classify-Evidence -EvidenceLines $allEvidence

    return [pscustomobject]@{
        EvidenceStrength = $class.EvidenceStrength
        Classification   = $class
        EvidenceLines    = $allEvidence
        EvidenceCount    = @($allEvidence).Count
        EvidenceFiles    = @($files | Select-Object -ExpandProperty FullName)
    }
}

function Maybe-EscalateToFull {
    param(
        [string]$ProcDumpExe,
        [int]$TargetPid,
        [string]$CaseDir,
        [string]$CdbExe
    )

    $analysisDir = Join-Path $CaseDir "Analysis"
    $summary = Summarize-EvidenceFolder -AnalysisRoot $analysisDir

    if (-not (Should-Escalate -Summary $summary)) {
        return [pscustomobject]@{
            Escalated = $false
            Reason    = "Escalation conditions not met."
            PreStrength= $summary.EvidenceStrength
            PreClassification = $summary.Classification
            FullDumpCaptured = $false
        }
    }

    $escDir = Join-Path $CaseDir "Escalation_Full"
    $escDumpDir = Join-Path $escDir "Dumps"
    $escAnaDir  = Join-Path $escDir "Analysis"
    Ensure-Dir $escDir; Ensure-Dir $escDumpDir; Ensure-Dir $escAnaDir

    Write-Host ("[ESCALATE] Evidence={0} (Sec={1}, Io={2}) -> capturing 1 Full dump (PID {3})..." -f `
        $summary.EvidenceStrength, $summary.Classification.SecurityDetected, $summary.Classification.IoSyscallDetected, $TargetPid)

    Capture-SingleDump -ProcDumpExe $ProcDumpExe -TargetPid $TargetPid -OutDir $escDumpDir -Profile "Full"

    $dumps = Get-ChildItem -Path $escDumpDir -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime
    foreach ($d in $dumps) {
        Analyze-Dump -DumpFile $d.FullName -OutDir (Join-Path $escAnaDir $d.BaseName) -CdbExe $CdbExe -SymCache $SymbolCache -OnlineSyms:$EnableOnlineSymbols
    }

    $post = Summarize-EvidenceFolder -AnalysisRoot $escAnaDir

    $result = [pscustomobject]@{
        Escalated = $true
        Reason    = "Escalation triggered; captured Full dump for deeper analysis."
        PreStrength = $summary.EvidenceStrength
        PreClassification = $summary.Classification
        PostStrength = $post.EvidenceStrength
        PostClassification = $post.Classification
        FullDumpCaptured = $true
        FullDumpCount = @($dumps).Count
        FullEvidenceCount = $post.EvidenceCount
    }

    $result | ConvertTo-Json -Depth 8 | Out-File -FilePath (Join-Path $escDir "EscalationSummary.json") -Encoding UTF8 -Force
    return $result
}

# ============================================================
# Setup + tool checks + diagnostics
# ============================================================
Ensure-Dir $ToolsFolder
Ensure-Dir $OutputRoot
Ensure-Dir $SymbolCache

$toolsResolved = Resolve-FolderSafe $ToolsFolder
$ProcDumpExe   = Get-ProcDumpPath -Folder $toolsResolved
$CdbResolved   = Get-CdbPathResolved -Preferred $CdbPath -Folder $toolsResolved

$diagPath = Join-Path $OutputRoot "ToolDetect_DIAG.txt"
@(
  "Tool detection diagnostics"
  ("Time: {0}" -f (Get-Date))
  ("ToolsFolder(resolved): {0}" -f $toolsResolved)
  ("ProcDump: {0}" -f $(if ($ProcDumpExe) { $ProcDumpExe } else { "<not found>" }))
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
Write-Host "cdb.exe : $CdbResolved"
Write-Host "Output : $OutputRoot"
Write-Host "Diag   : $diagPath"
Write-Host ("DumpProfile: {0}" -f $DumpProfile)
Write-Host ("Escalation: {0}  MaxFullDumps: {1}" -f $EnableEscalation, $EscalationMaxFullDumps)
Write-Host ""

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

        # Escalation step
        $esc = Maybe-EscalateToFull -ProcDumpExe $ProcDumpExe -TargetPid $targetPid -CaseDir $caseDir -CdbExe $CdbResolved
        $esc | ConvertTo-Json -Depth 8 | Out-File -FilePath (Join-Path $caseDir "EscalationResult.json") -Encoding UTF8 -Force

        $zip = "$caseDir.zip"
        if (Test-Path -LiteralPath $zip) { Remove-Item $zip -Force }
        Compress-Archive -Path "$caseDir\*" -DestinationPath $zip -Force
        Write-Host ("[DONE] Bundle: {0}" -f $zip)
    }

    Start-Sleep -Seconds $ScanIntervalSeconds
}

Write-Host "Monitoring complete."
