# ============================
# AutoCaptureAnalyze_Dump_V34
# ============================

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds = 5,
    [int]$CooldownSeconds = 600,
    [ValidateSet('Mini','MiniWithHandles','Full')]
    [string]$DumpProfile = 'Mini',
    [switch]$SinglePass
)

# ----------------------------
# Admin check
# ----------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run as Administrator."
}

$ErrorActionPreference = 'Stop'

# ----------------------------
# Paths
# ----------------------------
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DumpRoot   = Join-Path $ScriptRoot 'Dumps'
$LogRoot    = Join-Path $ScriptRoot 'Logs'
$LogFile    = Join-Path $LogRoot 'AutoCapture.log'

New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null

# ----------------------------
# Tools
# ----------------------------
$ProcDumpPath = 'C:\Tools\Sysinternals\procdump.exe'
$CdbPath      = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'

if (-not (Test-Path $ProcDumpPath)) { throw "ProcDump not found." }
if (-not (Test-Path $CdbPath))      { throw "cdb.exe not found." }

# ----------------------------
# Logging
# ----------------------------
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts $Message" | Out-File -Append -Encoding UTF8 $LogFile
}

# ----------------------------
# Helpers
# ----------------------------
function Convert-ExitCodeHex {
    param([int]$Code)
    $u = $Code -band 0xFFFFFFFF
    return ('0x{0:X8}' -f $u)
}

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

# ----------------------------
# Detection
# ----------------------------
function Get-Snapshot {
    $map = @{}
    foreach ($p in Get-Process) {
        try {
            $map[$p.Id] = [pscustomobject]@{
                Id         = $p.Id
                Name       = $p.Name
                MWH        = $p.MainWindowHandle
                Responding = $p.Responding
            }
        } catch {}
    }
    return $map
}

function Test-UIHang {
    param($A,$B)
    return ($A.MWH -ne 0 -and $A.Responding -eq $true -and $B.Responding -eq $false)
}

function Test-Suspend {
    param([int]$Pid)
    try { $p = Get-Process -Id $Pid } catch { return $false }
    $t = $p.Threads
    if (-not $t -or $t.Count -eq 0) { return $false }

    $s = 0
    foreach ($th in $t) {
        try {
            if ($th.ThreadState -eq 'Wait' -and $th.WaitReason -eq 'Suspended') {
                $s++
            }
        } catch {}
    }
    return (($s / $t.Count) * 100 -ge 80)
}

# ----------------------------
# ProcDump
# ----------------------------
function Invoke-ProcDump {
    param(
        [int]$Pid,
        [string]$DumpPath,
        [string[]]$ExtraArgs
    )

    $args = @('-accepteula','-mm') + $ExtraArgs + @('-r',"$Pid","`"$DumpPath`"")
    $argLine = $args -join ' '

    Write-Log "PROCDUMP $argLine"

    Start-Process -FilePath $ProcDumpPath `
        -ArgumentList $argLine `
        -Wait `
        -WindowStyle Hidden | Out-Null

    return (Test-Path $DumpPath)
}

# ----------------------------
# CDB
# ----------------------------
function Write-CdbCmd {
    param([string]$DumpPath)
    $cmd = $DumpPath -replace '\.dmp$','.cdb.cmd.txt'
    @(
        '.symfix'
        '.reload'
        '!analyze -hang'
        '~* kb'
        'q'
    ) | Out-File -Encoding ASCII -Force $cmd
    return $cmd
}

function Invoke-Cdb {
    param([string]$DumpPath)

    $cmdFile = Write-CdbCmd $DumpPath
    $log     = $DumpPath -replace '\.dmp$','.cdb.log'
    $cap     = $DumpPath -replace '\.dmp$','.cdb.capture.log'

    $args1 = "-z `"$DumpPath`" -cf `"$cmdFile`" -logo `"$log`""
    Write-Log "CDB $args1"

    Start-Process $CdbPath -ArgumentList $args1 -Wait -WindowStyle Hidden | Out-Null

    if (Test-CdbOutputLooksValid $log) { return $log }

    $args2 = "-z `"$DumpPath`" -cf `"$cmdFile`""
    Write-Log "CDB $args2"

    Start-Process $CdbPath -ArgumentList $args2 `
        -RedirectStandardOutput $cap `
        -Wait -WindowStyle Hidden | Out-Null

    if (Test-CdbOutputLooksValid $cap) { return $cap }

    return $null
}

# ----------------------------
# Main loop
# ----------------------------
Write-Log "=== AutoCapture V34 START ==="

do {
    $A = Get-Snapshot
    Start-Sleep $ObservationWindowSeconds
    $B = Get-Snapshot

    foreach ($id in $A.Keys) {
        if (-not $B.ContainsKey($id)) { continue }

        $ui = Test-UIHang $A[$id] $B[$id]
        $su = Test-Suspend $id

        if (-not ($ui -or $su)) { continue }

        $tag = if ($ui -and $su) {'UIHang+Suspend'} elseif ($ui) {'UIHang'} else {'Suspend'}
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $dump = Join-Path $DumpRoot "$($A[$id].Name)_$id`_$tag`_$stamp.dmp"

        Write-Log "TRIGGER $($A[$id].Name)($id) $tag"

        if (-not (Invoke-ProcDump $id $dump @())) {
            Invoke-ProcDump $id $dump @('-64') | Out-Null
        }

        if (Test-Path $dump) {
            $log = Invoke-Cdb $dump
            Write-Log "ANALYSIS $(if($log){'OK'}else{'FAILED'}) $dump"
        }
    }

    if (-not $SinglePass) {
        Start-Sleep $MonitorIntervalSeconds
    }

} while (-not $SinglePass)

Write-Log "=== AutoCapture V34 END ==="