# ======================================================
# AutoCaptureAnalyze_Dump_V34_FIXED
# ======================================================

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds = 5,
    [int]$CooldownSeconds = 600,
    [ValidateSet('Mini','MiniWithHandles','Full')]
    [string]$DumpProfile = 'Mini',
    [switch]$SinglePass
)

# -----------------------------
# Admin check
# -----------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}

$ErrorActionPreference = 'Stop'

# -----------------------------
# Paths
# -----------------------------
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DumpRoot   = Join-Path $ScriptRoot 'Dumps'
$LogRoot    = Join-Path $ScriptRoot 'Logs'
$LogFile    = Join-Path $LogRoot 'AutoCapture.log'

New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null

# -----------------------------
# Tools
# -----------------------------
$ProcDumpPath = 'C:\Tools\Sysinternals\procdump.exe'
$CdbPath      = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'

if (-not (Test-Path $ProcDumpPath)) { throw "ProcDump not found." }
if (-not (Test-Path $CdbPath))      { throw "cdb.exe not found." }

# -----------------------------
# Logging
# -----------------------------
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts $Message" | Out-File -Append -Encoding UTF8 $LogFile
}

# -----------------------------
# Helpers
# -----------------------------
function Test-CdbOutputLooksValid {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $false }
    $head = Get-Content $Path -TotalCount 8 -ErrorAction SilentlyContinue
    if (-not $head) { return $false }
    $text = ($head -join "`n")
    if ($text -match 'Invalid switch') { return $false }
    if ($text -match '(?i)usage:\s*cdb') { return $false }
    return $true
}

# -----------------------------
# Snapshot
# -----------------------------
function Get-ProcessSnapshot {
    $map = @{}
    foreach ($p in Get-Process) {
        try {
            $map[$p.Id] = [pscustomobject]@{
                ProcessId  = $p.Id
                Name       = $p.Name
                MWH        = $p.MainWindowHandle
                Responding = $p.Responding
            }
        } catch {}
    }
    return $map
}

# -----------------------------
# Detection
# -----------------------------
function Test-UIHang {
    param($Before, $After)
    return (
        $Before.MWH -ne 0 -and
        $Before.Responding -eq $true -and
        $After.Responding -eq $false
    )
}

function Test-Suspend {
    param([int]$TargetProcessId)
    try { $p = Get-Process -Id $TargetProcessId } catch { return $false }
    if (-not $p.Threads) { return $false }

    $suspended = 0
    foreach ($t in $p.Threads) {
        try {
            if ($t.ThreadState -eq 'Wait' -and $t.WaitReason -eq 'Suspended') {
                $suspended++
            }
        } catch {}
    }

    return (($suspended / $p.Threads.Count) * 100 -ge 80)
}

# -----------------------------
# ProcDump
# -----------------------------
function Invoke-ProcDump {
    param(
        [int]$TargetProcessId,
        [string]$DumpPath,
        [string[]]$ExtraArgs
    )

    $args = @('-accepteula','-mm') + $ExtraArgs + @(
        '-r',
        $TargetProcessId.ToString(),
        "`"$DumpPath`""
    )

    $argLine = $args -join ' '
    Write-Log "PROCDUMP $argLine"

    Start-Process -FilePath $ProcDumpPath `
        -ArgumentList $argLine `
        -Wait `
        -WindowStyle Hidden | Out-Null

    return (Test-Path $DumpPath)
}

# -----------------------------
# CDB
# -----------------------------
function Write-CdbCmdFile {
    param([string]$DumpPath)
    $cmdFile = $DumpPath -replace '\.dmp$','.cdb.cmd.txt'
    @(
        '.symfix'
        '.reload'
        '!analyze -hang'
        '~* kb'
        'q'
    ) | Out-File -Encoding ASCII -Force $cmdFile
    return $cmdFile
}

function Invoke-Cdb {
    param([string]$DumpPath)

    $cmdFile = Write-CdbCmdFile $DumpPath
    $log     = $DumpPath -replace '\.dmp$','.cdb.log'
    $cap     = $DumpPath -replace '\.dmp$','.cdb.capture.log'

    $args1 = "-z `"$DumpPath`" -cf `"$cmdFile`" -logo `"$log`""
    Start-Process $CdbPath -ArgumentList $args1 -Wait -WindowStyle Hidden | Out-Null
    if (Test-CdbOutputLooksValid $log) { return $log }

    $args2 = "-z `"$DumpPath`" -cf `"$cmdFile`""
    Start-Process $CdbPath `
        -ArgumentList $args2 `
        -RedirectStandardOutput $cap `
        -Wait -WindowStyle Hidden | Out-Null

    if (Test-CdbOutputLooksValid $cap) { return $cap }
    return $null
}

# -----------------------------
# MAIN LOOP
# -----------------------------
Write-Log "=== AutoCapture V34 FIXED START ==="

do {
    $before = Get-ProcessSnapshot
    Start-Sleep $ObservationWindowSeconds
    $after = Get-ProcessSnapshot

    foreach ($ProcessId in $before.Keys) {
        if (-not $after.ContainsKey($ProcessId)) { continue }

        $uiHang  = Test-UIHang $before[$ProcessId] $after[$ProcessId]
        $suspend = Test-Suspend $ProcessId

        if (-not ($uiHang -or $suspend)) { continue }

        $tag = if ($uiHang -and $suspend) {'UIHang+Suspend'} elseif ($uiHang) {'UIHang'} else {'Suspend'}
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $dumpPath = Join-Path $DumpRoot "$($before[$ProcessId].Name)_$ProcessId`_$tag`_$stamp.dmp"

        Write-Log "TRIGGER $($before[$ProcessId].Name)($ProcessId) $tag"

        if (-not (Invoke-ProcDump $ProcessId $dumpPath @())) {
            Invoke-ProcDump $ProcessId $dumpPath @('-64') | Out-Null
        }

        if (Test-Path $dumpPath) {
            $cdbLog = Invoke-Cdb $dumpPath
            Write-Log "ANALYSIS $(if($cdbLog){'OK'}else{'FAILED'}) $dumpPath"
        }
    }

    if (-not $SinglePass) {
        Start-Sleep $MonitorIntervalSeconds
    }

} while (-not $SinglePass)

Write-Log "=== AutoCapture V34 FIXED END ==="