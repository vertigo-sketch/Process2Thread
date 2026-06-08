<# =====================================================================
 AutoCaptureAnalyze_Dump_V48.ps1
 Tier‑B Hang Analysis (PIDSAFE, ProcDump‑SAFE)
 ===================================================================== #>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ===============================
# CONFIG
# ===============================
$ObservationWindowSeconds = 15
$CooldownSeconds = 300

$ScriptRoot = $PSScriptRoot
$OutputRoot = Join-Path $ScriptRoot "TierB_Output"
$DumpRoot   = Join-Path $OutputRoot "Dumps"
$LogPath    = Join-Path $OutputRoot "AutoCapture.log"

New-Item -ItemType Directory -Path $DumpRoot -Force | Out-Null

# ===============================
# LOGGING
# ===============================
function Write-Log {
    param([string]$Message)
    $line = "{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $Message
    Add-Content -Path $LogPath -Value $line
    Write-Host $line
}

# ===============================
# PROC DUMP DISCOVERY
# ===============================
function Resolve-ProcDumpPath {
    $candidates = @(
        Join-Path $PSScriptRoot "procdump.exe"),
        "C:\tools\Sysinternals\procdump.exe"

    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }

    try {
        $cmd = Get-Command procdump.exe -ErrorAction Stop
        return $cmd.Source
    }
    catch {
        return $null
    }
}

$global:ProcDumpPath = Resolve-ProcDumpPath
if (-not $global:ProcDumpPath) {
    Write-Log "FATAL: ProcDump not found. Dumps will not be captured."
}

# ===============================
# PROCESS SNAPSHOT
# ===============================
function Get-ProcessSnapshot {
    $snap = @{}
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
        $snap[$p.Id] = @{
            Name       = $p.ProcessName
            CPU        = $p.CPU
            Threads    = $p.Threads.Count
            Responding = $p.Responding
        }
    }
    return $snap
}

# ===============================
# UI HANG DETECTION
# ===============================
function Test-UIHang {
    param($Before,$After)
    if (-not $After.Responding -and ($After.CPU - $Before.CPU) -lt 0.1) {
        return $true
    }
    return $false
}

# ===============================
# COOLDOWN
# ===============================
$global:CooldownTable = @{}
function In-Cooldown { param($ProcId)
    $global:CooldownTable.ContainsKey($ProcId) -and (Get-Date) -lt $global:CooldownTable[$ProcId]
}
function Mark-Captured { param($ProcId)
    $global:CooldownTable[$ProcId] = (Get-Date).AddSeconds($CooldownSeconds)
}

# ===============================
# PROC DUMP INVOCATION
# ===============================
function Invoke-ProcDumpSafe {
    param($ProcId,$DumpPath)

    if (-not $global:ProcDumpPath) {
        Write-Log "ERROR: ProcDump unavailable. Skipping dump for PID=$ProcId"
        return $false
    }

    & $global:ProcDumpPath -accepteula -ma -h $ProcId $DumpPath 1>$null 2>$null
    return (Test-Path $DumpPath)
}

# ===============================
# CDB ANALYSIS
# ===============================
function Invoke-Cdb {
    param($DumpPath,$OutPath)

    $cmds = ".symfix;.reload;~* kb;q"
    & cdb.exe -z $DumpPath -c $cmds > $OutPath 2>&1
}

# ===============================
# TIER‑B CORE
# ===============================
function Parse-CdbThreads {
    param($Path)
    $threads=@{};$tid=$null;$stack=@()
    foreach($l in Get-Content $Path){
        if($l -match '^\s*\.\s*(\d+)\s+Id:'){
            if($tid){$threads[$tid]=$stack}
            $tid=[int]$Matches[1];$stack=@()
        } elseif($tid -and $l -match 'ntdll!'){
            $stack+=$l.Trim()
        }
    }
    if($tid){$threads[$tid]=$stack}
    $threads
}

function Get-WaitInfo {
    param($Stack)
    foreach($f in $Stack){
        if($f -match 'ntdll!(Nt[A-Za-z]+)'){
            return $Matches[1]
        }
    }
    $null
}

# ===============================
# MAIN LOOP
# ===============================
Write-Log "=== AutoCaptureAnalyze_Dump_V48 START (Tier‑B, ProcDump‑SAFE) ==="

do{
    Write-Log "PASS START"
    $before=Get-ProcessSnapshot
    Start-Sleep $ObservationWindowSeconds
    $after=Get-ProcessSnapshot

    foreach($ProcId in $before.Keys){
        if(-not $after.ContainsKey($ProcId)) {continue}
        if(In-Cooldown $ProcId) {continue}

        if(Test-UIHang $before[$ProcId] $after[$ProcId]){
            Write-Log "UIHANG DETECTED ProcId=$ProcId ($($before[$ProcId].Name))"
            $ts=Get-Date -Format yyyyMMdd_HHmmss
            $dump=Join-Path $DumpRoot "UIHang_${ProcId}_$ts.dmp"
            $cdb =Join-Path $DumpRoot "UIHang_${ProcId}_$ts.cdb.log"

            if(Invoke-ProcDumpSafe $ProcId $dump){
                Invoke-Cdb $dump $cdb
                $threads=Parse-CdbThreads $cdb
                Write-Log "TIERB Threads=$($threads.Count)"
                Mark-Captured $ProcId
            }
        }
    }
}while($true)

Write-Log "=== AutoCapture V48 END ==="