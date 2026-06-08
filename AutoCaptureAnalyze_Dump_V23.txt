<#
AutoCaptureWhat it does (end-to-end):AutoCaptureAnalyze_Dump_V23.ps1
- Detects UI hangs (windowed process, Responding=false)
- Detects true suspension (>=80% threads WaitReason=Suspended)
- Tags dumps: UIHang / Suspend / UIHang+Suspend
- Captures dump with ProcDump (-r) and logs exit code + stdout/stderr
- Analyzes dump with cdb and saves .cdb.log
- Extracts "top blocked thread" section from cdb log (heuristic but deterministic)
- Correlates filter drivers (WdFilter / CSAgent) from blocked-thread + full cdb log
- Writes JSON evidence next to dump: .analysis.json

PowerShell:
- PS 5.1 safe
- Avoids ANY use of pid/Pid/PID variables/params
#>

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds   = 5,
    [int]$CooldownSeconds          = 600,
    [ValidateSet('Mini','MiniWithHandles','Full')]
    [string]$DumpProfile           = 'Mini',
    [switch]$SinglePass,

    # Console status lines
    [switch]$ConsoleStatus = $true
)

# ---------------------------
# Admin check (parser-safe)
# ---------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    throw "Run as Administrator (required for ProcDump attach)."
}

# Keep errors deterministic but do NOT enable StrictMode Latest (it breaks too easily on optional properties)
$ErrorActionPreference = 'Stop'

# ---------------------------
# Resolve paths
# ---------------------------
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$DumpRoot   = Join-Path $ScriptRoot 'Dumps'
$LogRoot    = Join-Path $ScriptRoot 'Logs'
New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null
$LogFile = Join-Path $LogRoot 'AutoCapture.log'

# ---------------------------
# Tool paths (EDIT if needed)
# ---------------------------
$ProcDumpPath = 'C:\Tools\Sysinternals\procdump.exe'
$CdbPath      = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'

if (-not (Test-Path $ProcDumpPath)) { throw "Missing ProcDump: $ProcDumpPath" }
if (-not (Test-Path $CdbPath))      { throw "Missing cdb.exe: $CdbPath" }

# ---------------------------
# Logging
# ---------------------------
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts $Message" | Out-File -Append -Encoding UTF8 $LogFile
}

function Write-Status {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    if (-not $ConsoleStatus) { return }
    Write-Host $Message -ForegroundColor $Color
}

# ---------------------------
# Optional deny list (noise reducer)
# Keep small. You asked "all processes"—this only excludes known Windows packaged/shell noise.
# Remove entries if you truly want everything.
# ---------------------------
$DenyNames = @(
    'LockApp','RuntimeBroker','SearchHost',
    'ShellExperienceHost','StartMenuExperienceHost',
    'ApplicationFrameHost','backgroundTaskHost'
)

function Is-DeniedProcessName {
    param([string]$Name)
    return ($DenyNames -contains $Name)
}

# ---------------------------
# Safe snapshot
# ---------------------------
function Get-SafeSnapshot {
    param([System.Diagnostics.Process]$Proc)

    $processId = $null
    $processName = $null
    try { $processId = [int]$Proc.Id } catch { return $null }
    try { $processName = [string]$Proc.Name } catch { $processName = 'Unknown' }

    if (Is-DeniedProcessName $processName) { return $null }

    $mwh = 0
    $resp = $null
    try { $mwh = [int64]$Proc.MainWindowHandle } catch { $mwh = 0 }
    if ($mwh -ne 0) {
        try { $resp = [bool]$Proc.Responding } catch { $resp = $null }
    }

    return [PSCustomObject]@{
        ProcessId  = $processId
        Name       = $processName
        MWH        = $mwh
        Responding = $resp
    }
}

# ---------------------------
# Detection: UI hang + true suspension
# ---------------------------
function Test-UIHang {
    param($Snap)
    return ($Snap.MWH -ne 0 -and $Snap.Responding -eq $false)
}

function Test-TrueSuspend {
    param([int]$TargetProcessId)

    try { $p = Get-Process -Id $TargetProcessId -ErrorAction Stop } catch { return $false }

    $threads = $null
    try { $threads = $p.Threads } catch { return $false }
    if (-not $threads -or $threads.Count -eq 0) { return $false }

    $suspended = 0
    foreach ($t in $threads) {
        try {
            if ($t.ThreadState -eq 'Wait' -and $t.WaitReason -eq 'Suspended') { $suspended++ }
        } catch { }
    }

    return ((($suspended / $threads.Count) * 100) -ge 80)
}

function Get-Tag {
    param([bool]$UIHang, [bool]$Suspend)
    if ($UIHang -and $Suspend) { return 'UIHang+Suspend' }
    if ($UIHang) { return 'UIHang' }
    if ($Suspend) { return 'Suspend' }
    return 'None'
}

# ---------------------------
# Cooldown tracking
# ---------------------------
$LastCaptureByProcessId = @{}

function In-Cooldown {
    param([int]$TargetProcessId)
    if ($LastCaptureByProcessId.ContainsKey($TargetProcessId)) {
        $age = (Get-Date) - $LastCaptureByProcessId[$TargetProcessId]
        return ($age.TotalSeconds -lt $CooldownSeconds)
    }
    return $false
}

function Mark-Captured {
    param([int]$TargetProcessId)
    $LastCaptureByProcessId[$TargetProcessId] = Get-Date
}

# ---------------------------
# Dump capture with ProcDump: exit code + stdout/stderr
# ---------------------------
function Capture-Dump {
    param(
        [int]$TargetProcessId,
        [string]$ProcessName,
        [string]$Tag
    )

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $base  = "{0}_{1}_{2}_{3}" -f $ProcessName, $TargetProcessId, $Tag, $stamp

    $dumpPath = Join-Path $DumpRoot ($base + '.dmp')
    $outPath  = Join-Path $DumpRoot ($base + '.procdump.out.log')
    $errPath  = Join-Path $DumpRoot ($base + '.procdump.err.log')

    $profileArgs = switch ($DumpProfile) {
        'Mini'            { @('-mm') }
        'MiniWithHandles' { @('-mm','-mh') }
        'Full'            { @('-ma') }
    }

    # -r = dump immediately (clone). This avoids "waiting for hang trigger" behavior.
    $args = @('-accepteula') + $profileArgs + @('-r', $TargetProcessId, $dumpPath)

    Write-Log "PROCDUMP START Name=$ProcessName ProcessId=$TargetProcessId Tag=$Tag Dump=$dumpPath Args=$($args -join ' ')"

    $p = Start-Process -FilePath $ProcDumpPath `
        -ArgumentList $args `
        -WindowStyle Hidden `
        -PassThru `
        -Wait `
        -RedirectStandardOutput $outPath `
        -RedirectStandardError  $errPath

    Write-Log "PROCDUMP END   ExitCode=$($p.ExitCode) DumpExists=$(Test-Path $dumpPath) Out=$outPath Err=$errPath"

    if (-not (Test-Path $dumpPath)) {
        throw "Dump not created. Exit=$($p.ExitCode). See: $errPath"
    }

    return $dumpPath
}

# ---------------------------
# cdb analysis
# ---------------------------
function Analyze-Dump {
    param([string]$DumpPath)

    $cdbLog = $DumpPath -replace '\.dmp$','.cdb.log'
    $cmd = '.symfix; .reload; !analyze -hang; ~* kb; q'

    Write-Log "CDB START Dump=$DumpPath Log=$cdbLog"
    $p = Start-Process -FilePath $CdbPath `
        -ArgumentList @('-z', $DumpPath, '-c', $cmd, '-logo', $cdbLog) `
        -WindowStyle Hidden `
        -PassThru `
        -Wait
    Write-Log "CDB END   ExitCode=$($p.ExitCode) LogExists=$(Test-Path $cdbLog)"

    return $cdbLog
}

# ---------------------------
# Extract top blocked thread (deterministic heuristic)
# ---------------------------
function Extract-TopBlockedThread {
    param([string]$CdbLogPath)

    if (-not (Test-Path $CdbLogPath)) { return $null }
    $lines = Get-Content $CdbLogPath

    # Prefer !analyze -hang "BLOCKED" indicators; fallback to waits/deadlocks.
    $patterns = @('(?i)\bblocked\b','(?i)waitreason','(?i)deadlock','(?i)!analyze -hang','(?i)hang')

    $idx = -1
    for ($i=0; $i -lt $lines.Count; $i++) {
        foreach ($pat in $patterns) {
            if ($lines[$i] -match $pat) { $idx = $i; break }
        }
        if ($idx -ge 0) { break }
    }

    if ($idx -lt 0) { return $null }

    $end = [math]::Min($idx + 80, $lines.Count - 1)
    return ($lines[$idx..$end] -join "`n")
}

# ---------------------------
# Filter-driver correlation
# ---------------------------
function Correlate-FiltersFromText {
    param([string]$Text)

    if (-not $Text) {
        return [pscustomobject]@{ WdFilter=$false; CSAgent=$false; Hits=@() }
    }

    $hits = @()
    if ($Text -match '(?i)\bWdFilter\b') { $hits += 'WdFilter' }
    if ($Text -match '(?i)\bCSAgent\b')  { $hits += 'CSAgent' }

    return [pscustomobject]@{
        WdFilter = ($hits -contains 'WdFilter')
        CSAgent  = ($hits -contains 'CSAgent')
        Hits     = $hits
    }
}

function Write-AnalysisJson {
    param(
        [string]$DumpPath,
        [string]$Tag,
        [string]$CdbLogPath,
        [string]$BlockedThreadText,
        $FilterCorrelation
    )

    $jsonPath = $DumpPath -replace '\.dmp$','.analysis.json'
    $obj = [pscustomobject]@{
        DumpPath          = $DumpPath
        Tag               = $Tag
        CdbLog            = $CdbLogPath
        BlockedThread     = $BlockedThreadText
        FilterCorrelation = $FilterCorrelation
        Created           = (Get-Date).ToString('o')
    }

    $obj | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 $jsonPath
    Write-Log "ANALYSIS JSON $jsonPath"
}

# ---------------------------
# MAIN LOOP
# ---------------------------
Write-Log "=== AutoCapture V27 START === ScriptRoot=$ScriptRoot DumpRoot=$DumpRoot DumpProfile=$DumpProfile"
Write-Status "AutoCapture V27 running (Admin OK). Logs: $LogFile" Cyan

do {
    Write-Log "PASS START"

    # Snapshot A
    $snapA = @{}
    foreach ($proc in Get-Process) {
        $s = Get-SafeSnapshot -Proc $proc
        if ($s) { $snapA[$s.ProcessId] = $s }
    }

    Start-Sleep -Seconds $ObservationWindowSeconds

    $triggers = 0

    foreach ($proc in Get-Process) {
        $b = Get-SafeSnapshot -Proc $proc
        if (-not $b) { continue }
        if (-not $snapA.ContainsKey($b.ProcessId)) { continue }
        if (In-Cooldown -TargetProcessId $b.ProcessId) { continue }

        $uiHang = Test-UIHang -Snap $b
        $suspend = $false
        if (-not $uiHang) {
            $suspend = Test-TrueSuspend -TargetProcessId $b.ProcessId
        }

        if (-not ($uiHang -or $suspend)) { continue }

        $tag = Get-Tag -UIHang $uiHang -Suspend $suspend
        $triggers++

        Write-Log "TRIGGER Name=$($b.Name) ProcessId=$($b.ProcessId) Tag=$tag"
        Write-Status ("TRIGGER {0}({1}) Tag={2}" -f $b.Name, $b.ProcessId, $tag) Red

        try {
            Mark-Captured -TargetProcessId $b.ProcessId

            $dump   = Capture-Dump -TargetProcessId $b.ProcessId -ProcessName $b.Name -Tag $tag
            $cdbLog = Analyze-Dump -DumpPath $dump

            $blocked = Extract-TopBlockedThread -CdbLogPath $cdbLog
            $fullText = ''
            try { $fullText = Get-Content $cdbLog -Raw } catch { $fullText = '' }

            $filters = Correlate-FiltersFromText -Text ($blocked + "`n" + $fullText)
            Write-AnalysisJson -DumpPath $dump -Tag $tag -CdbLogPath $cdbLog -BlockedThreadText $blocked -FilterCorrelation $filters

            Write-Status ("CAPTURED {0}" -f $dump) Green
        }
        catch {
            Write-Log "ERROR Name=$($b.Name) ProcessId=$($b.ProcessId) Tag=$tag Msg=$($_.Exception.Message)"
            Write-Status ("ERROR {0}({1}) {2}" -f $b.Name, $b.ProcessId, $_.Exception.Message) Yellow
        }
    }

    Write-Log ("PASS END Triggers={0}" -f $triggers)

    if (-not $SinglePass) {
        Start-Sleep -Seconds $MonitorIntervalSeconds
    }

} while (-not $SinglePass)