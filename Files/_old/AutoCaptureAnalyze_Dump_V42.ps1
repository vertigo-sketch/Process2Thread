<#
AutoCaptureAnalyze_Dump_V42
Eliminates ALL $PID collisions
#>

# ==========================================================
# ETW HARD-PROOF SUPPORT (REQUIRED – DEFINED ONCE)
# ==========================================================

function Stop-IfEtwSessionExists {
    param([Parameter(Mandatory=$true)][string]$SessionName)

    $null = & logman query $SessionName -ets 2>$null
    if ($LASTEXITCODE -eq 0) {
        & logman stop  $SessionName -ets 1>$null 2>$null
        & logman delete $SessionName     1>$null 2>$null
    }
}

function Start-AutoCapEtwRollingTrace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SessionName,
        [int]$MaxMB = 256
    )

    Stop-IfEtwSessionExists -SessionName $SessionName

    # Kernel flags: File I/O + threads
    $kernelFlags = "PROC_THREAD+FILE_IO+FILE_IO_INIT+DISK_IO+DISK_IO_INIT"

    & logman create trace $SessionName -ets `
        -kn $kernelFlags `
        -bs 1024 `
        -nb 64 256 `
        -mode circular `
        -f bincirc `
        -max $MaxMB 1>$null

    if ($LASTEXITCODE -ne 0) {
        throw "ETW kernel trace start failed. Script must run elevated."
    }

    # Filter Manager provider
    $FilterMgrGuid = "{f3c5e28e-63f6-49c6-a204-e48a1bc4b09d}"
    & logman update trace $SessionName -ets `
        -p $FilterMgrGuid 0xFFFFFFFFFFFFFFFF 0x5 1>$null
}

function Stop-AutoCapEtwTrace {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$SessionName,
        [Parameter(Mandatory=$true)][string]$EtlPath
    )

    & logman stop $SessionName -ets -o $EtlPath 1>$null 2>$null
    & logman delete $SessionName 1>$null 2>$null
}

function Convert-EtlToXml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$EtlPath,
        [Parameter(Mandatory=$true)][string]$XmlPath
    )

    & tracerpt $EtlPath -of XML -o $XmlPath -y 1>$null
}

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds  = 5,
    [int]$CooldownSeconds         = 600,
    [switch]$SinglePass
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ===============================
# Admin check
# ===============================
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}

# ===============================
# Paths
# ===============================
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DumpRoot   = Join-Path $ScriptRoot 'Dumps'
$LogRoot    = Join-Path $ScriptRoot 'Logs'
$LogFile    = Join-Path $LogRoot 'AutoCapture.log'

New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null

# ===============================
# Tools
# ===============================
$ProcDumpPath = 'C:\Tools\Sysinternals\procdump.exe'
$CdbPath      = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'

if (-not (Test-Path $ProcDumpPath)) { throw "ProcDump not found." }
if (-not (Test-Path $CdbPath))      { throw "cdb.exe not found." }

# ===============================
# Logging
# ===============================
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts $Message" | Out-File -Append -Encoding UTF8 $LogFile
}

# ===============================
# Snapshot
# ===============================
function Get-ProcessSnapshot {
    $snap = @{}
    foreach ($proc in Get-Process) {
        try {
            $snap[$proc.Id] = [pscustomobject]@{
                ProcId      = $proc.Id
                Name        = $proc.ProcessName
                Responding  = $proc.Responding
                ThreadCount = $proc.Threads.Count
            }
        } catch {}
    }
    return $snap
}

# ===============================
# Detection
# ===============================
function Test-UIHang {
    param($Before,$After)
    return ($Before.Responding -and -not $After.Responding)
}

# ===============================
# ProcDump
# ===============================

function Invoke-ProcDump {
    param(
        [int]$TargetProcId,
        [string]$DumpPath
    )

    Write-Log "ProcDump starting PID=$TargetProcId Path=$DumpPath"

    $proc = Start-Process `
        -FilePath $ProcDumpPath `
        -ArgumentList @(
            '-accepteula',
            '-ma',
            $TargetProcId,
            $DumpPath
        ) `
        -Wait `
        -NoNewWindow `
        -PassThru

    Write-Log "ProcDump exit code: $($proc.ExitCode)"

    if ($proc.ExitCode -ne 0) {
        Write-Log "ProcDump FAILED (exit=$($proc.ExitCode))"
        return $false
    }

    if (-not (Test-Path $DumpPath)) {
        Write-Log "ProcDump FAILED (dump not created)"
        return $false
    }

    Write-Log "ProcDump SUCCESS: $DumpPath"
    return $true
}

# ===============================
# CDB
# ===============================

function Write-CdbCmdFile {
    param([string]$DumpPath)
    $cmd = [System.IO.Path]::ChangeExtension($DumpPath,'cdb.cmd.txt')
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

    $cmdFile = Write-CdbCmdFile $DumpPath
    $logFile = [System.IO.Path]::ChangeExtension($DumpPath,'cdb.log.txt')

    & $CdbPath -z "`"$DumpPath`"" -cf "`"$cmdFile`"" > $logFile 2>&1
    return (Test-Path $logFile)
}

# ===============================
# Cooldown
# ===============================
$LastCapture = @{}

function In-Cooldown {
    param([int]$ProcKey)
    if ($LastCapture.ContainsKey($ProcKey)) {
        return ((Get-Date) - $LastCapture[$ProcKey]).TotalSeconds -lt $CooldownSeconds
    }
    return $false
}

function Mark-Captured {
    param([int]$ProcKey)
    $LastCapture[$ProcKey] = Get-Date
}

# =========================================
# MAIN LOOP – AutoCapture V37.9 PIDSAFE + HARD PROOF
# =========================================

Write-Log "=== AutoCapture V37.9 PIDSAFE START ==="

# --- Start rolling ETW once (kernel File I/O + FilterManager) ---
$EtwSessionName = "AutoCapHangTrace"
Start-AutoCapEtwRollingTrace -SessionName $EtwSessionName

do {
    Write-Log "PASS START"

    $before = Get-ProcessSnapshot
    Start-Sleep $ObservationWindowSeconds
    $after  = Get-ProcessSnapshot

    foreach ($procKey in $before.Keys) {

        if (-not $after.ContainsKey($procKey)) { continue }
        if (In-Cooldown $procKey) { continue }

        if (Test-UIHang $before[$procKey] $after[$procKey]) {

            Write-Log "UIHANG DETECTED PID=$procKey"

            # -----------------------------
            # HARD PROOF: STOP ETW (pre-hang kernel evidence)
            # -----------------------------
            $etlPath = Join-Path $DumpRoot ("HangTrace_{0}_{1}.etl" -f `
                $procKey, (Get-Date -Format yyyyMMdd_HHmmss))

            Stop-AutoCapEtwTrace -SessionName $EtwSessionName -EtlPath $etlPath
            Write-Log "ETW TRACE SAVED: $etlPath"

            # -----------------------------
            # DUMP CAPTURE
            # -----------------------------
            $dumpPath = Join-Path $DumpRoot ("UIHang_{0}.dmp" -f $procKey)

            if (Invoke-ProcDump -TargetProcId $procKey -DumpPath $dumpPath) {

                Write-Log "DUMP CREATED: $dumpPath"

                # -----------------------------
                # CDB USER-MODE ANALYSIS
                # -----------------------------
                Invoke-Cdb -DumpPath $dumpPath | Out-Null
                Write-Log "CDB ANALYSIS COMPLETE"

                # -----------------------------
                # HARD PROOF: ETL → XML → FILTER SCORE
                # -----------------------------
                $xmlPath = [System.IO.Path]::ChangeExtension($etlPath, ".xml")
                Convert-EtlToXml -EtlPath $etlPath -XmlPath $xmlPath

                $filterScore = Get-FilterDelayRepetitionScoreFromEtlXml -XmlPath $xmlPath
                Write-FilterDelayScoreLogLine -Result $filterScore -LogPath $LogPath

                Mark-Captured $procKey
                Write-Log "CAPTURE MARKED PID=$procKey"
            }
            else {
                Write-Log "ERROR: ProcDump failed for PID=$procKey"
            }

            # -----------------------------
            # HARD PROOF: Restart rolling ETW
            # -----------------------------
            Start-AutoCapEtwRollingTrace -SessionName $EtwSessionName
        }
    }

} while ($true)


Write-Log "=== AutoCapture V37.9 PIDSAFE END ==="
