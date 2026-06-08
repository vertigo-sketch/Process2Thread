<#
AutoCaptureAnalyze_Dump_V07.ps1

V07 FIXES
- Fixes PS 5.1 "Argument types do not match" caused by comparing IntPtr window handles to integer 0
  - Uses (MainWindowHandle -eq [IntPtr]::Zero) instead of -eq 0
  - Passes IntPtr directly into IsHungAppWindow (no cast)
- Adds robust crash logging to: C:\Temp\HungDumps\AutoCaptureAnalyze_Dump_V07_ERROR.txt
  - Captures exception, stack trace, and position message when available
- No TestPID mode (removed in V06)
- Keeps: DumpProfile, WdFilter/CSAgent detection, classification, escalation

NOTES
- ProcDump series uses -n (count) and -s (seconds between) for timed snapshots. [1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
- cdb.exe is invoked to open dumps and run scripted commands; CDB supports dump open via -z and command execution via -c. [2](https://community.progress.com/s/article/How-to-use-Sysinternals-Procdump)
- DumpProfile mapping:
  - MiniWithHandles -> -mp, Full -> -ma (ProcDump dump type options). [3](https://support.tibco.com/external/article/78297/how-to-use-procdump-to-collect-logs-in-c.html)

HISTORICAL CHANGES
V03: Versioning + history log + DumpProfile support
V04: Added escalation (Full dump if weak evidence)
V05: Added WdFilter + CSAgent detection + escalation rule update
V06: Removed TestPID mode
V07: Fix IntPtr compare bug + add crash logging
#>

[CmdletBinding()]
param(
    [string]$ToolsFolder = "C:\Temp\Procdump",
    [string]$OutputRoot  = "C:\Temp\HungDumps",

    [int]$ScanIntervalSeconds = 5,
    [int]$AllowListConfirmSeconds    = 30,
    [int]$NonAllowListConfirmSeconds = 60,

    [int]$DumpSeriesCount = 4,
    [int]$DumpSeriesIntervalSeconds = 10,

    [ValidateSet("Mini","MiniWithHandles","Full")]
    [string]$DumpProfile = "MiniWithHandles",

    [switch]$EnableEscalation = $true,
    [int]$EscalationMaxFullDumps = 1,

    [int]$PerProcessCooldownMinutes = 10,

    [string]$CdbPath = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    [string]$SymbolCache = "C:\Temp\Symbols",

    [int]$CdbTimeoutSeconds = 120,
    [switch]$EnableOnlineSymbols,

    [int]$MaxRunMinutes = 120
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# ---------------------------
# Normalize inputs
# ---------------------------
if ([string]::IsNullOrWhiteSpace($ToolsFolder)) { $ToolsFolder = "C:\Temp\Procdump" }
if ([string]::IsNullOrWhiteSpace($OutputRoot))  { $OutputRoot  = "C:\Temp\HungDumps" }
if ([string]::IsNullOrWhiteSpace($SymbolCache)) { $SymbolCache = "C:\Temp\Symbols" }

# ---------------------------
# Ensure base dirs early (for crash log)
# ---------------------------
function Ensure-Dir {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}
Ensure-Dir $OutputRoot

$CrashLog = Join-Path $OutputRoot "AutoCaptureAnalyze_Dump_V07_ERROR.txt"

# Global trap: capture real line info when possible
trap {
    try {
        $msg = New-Object System.Collections.Generic.List[string]
        $msg.Add("=== AutoCaptureAnalyze_Dump_V07 ERROR ===")
        $msg.Add(("Time: {0}" -f (Get-Date)))
        $msg.Add(("Exception: {0}" -f $_.Exception.GetType().FullName))
        $msg.Add(("Message: {0}" -f $_.Exception.Message))
        if ($_.InvocationInfo) {
            $msg.Add("---- InvocationInfo.PositionMessage ----")
            $msg.Add($_.InvocationInfo.PositionMessage)
        }
        if ($_.ScriptStackTrace) {
            $msg.Add("---- ScriptStackTrace ----")
            $msg.Add($_.ScriptStackTrace)
        }
        if ($_.Exception.StackTrace) {
            $msg.Add("---- Exception.StackTrace ----")
            $msg.Add($_.Exception.StackTrace)
        }
        $msg.Add("=======================================")
        $msg.Add("")
        $msg | Out-File -FilePath $CrashLog -Encoding UTF8 -Append -Force
    } catch { }
    throw
}

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
        "Full"            { return "-ma" }  # full memory [3](https://support.tibco.com/external/article/78297/how-to-use-procdump-to-collect-logs-in-c.html)
        "MiniWithHandles" { return "-mp" }  # default minimal [3](https://support.tibco.com/external/article/78297/how-to-use-procdump-to-collect-logs-in-c.html)
        "Mini"            { return "" }
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

    if ($Summary.EvidenceStrength -eq "Weak") { return $true }

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
if (-not ("Win32" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Win32 {
  [DllImport("user32.dll")]
  public static extern bool IsHungAppWindow(IntPtr hwnd);
}
"@ -ErrorAction Stop
}

# ============================================================
# Hung detection (process-centric)  ***V07 FIX INSIDE***
# ============================================================
function Get-HungProcesses {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
        try {
            # V07 FIX: compare IntPtr to IntPtr.Zero (avoids PS binder issues)
            if ($p.MainWindowHandle -eq [IntPtr]::Zero) { continue }

            $exe = ($p.ProcessName + ".exe").ToLower()
            if ($NoiseProcessDenyList -contains $exe) { continue }

            # V07 FIX: pass IntPtr directly (no cast)
            if ([Win32]::IsHungAppWindow($p.MainWindowHandle)) {
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
# ProcDump capture (cmd.exe /c)
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

    # ProcDump series: -n and -s [1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)
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

    # cdb supports dump open and command execution [2](https://community.progress.com/s/article/How-to-use-Sysinternals-Procdump)
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
  ("CrashLog: {0}" -f $CrashLog)
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