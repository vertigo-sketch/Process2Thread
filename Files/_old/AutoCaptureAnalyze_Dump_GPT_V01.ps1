<#
AutoCaptureAnalyze_Dump_HARDENED.ps1

HARDENED implementation goals:
- ProcDump first, COMSVCS fallback
- Better avoidance of packaged / AppContainer-style processes
- Per-process isolation so one bad target never stops the scan
- Cooldown to avoid repeat dumps of the same PID in a short window
- Retention cleanup for old dumps/logs
- Honest success/failure logging based on actual dump file creation
- PowerShell 5.1 safe; no $PID collisions

Notes:
- UWP / AppContainer detection from pure PowerShell 5.1 is imperfect.
- This version uses multiple signals:
  * hardcoded process-name exclusions
  * executable path under WindowsApps
  * package identity via Get-AppxPackage for same executable path when possible
- Some protected/system processes may still be encountered; failures are logged and skipped.
#>

# -------------------------
# Admin check
# -------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Must run as Administrator."
}

$ErrorActionPreference = 'Stop'

# -------------------------
# Paths
# -------------------------
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$DumpRoot   = Join-Path $ScriptRoot "Dumps"
$LogRoot    = Join-Path $ScriptRoot "Logs"
$StateRoot  = Join-Path $ScriptRoot "State"

New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot, $StateRoot | Out-Null

$LogFile         = Join-Path $LogRoot   "AutoCapture.log"
$CooldownState   = Join-Path $StateRoot "DumpCooldown.json"

# -------------------------
# Config
# -------------------------
$ProcDump                 = "C:\Tools\Sysinternals\procdump.exe"
$CooldownMinutes          = 30
$DumpRetentionDays        = 14
$LogRetentionDays         = 30
$UseFullDumpWithProcDump  = $true   # $true = -ma, $false = -mm

if (-not (Test-Path $ProcDump)) {
    throw "Missing ProcDump.exe at: $ProcDump"
}

# -------------------------
# Logging
# -------------------------
function Write-Log {
    param([string]$Msg)

    try {
        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        "$ts $Msg" | Out-File -Append -Encoding UTF8 $LogFile
    }
    catch {
        Write-Warning "Failed to write log entry: $Msg"
    }
}

# -------------------------
# Retention cleanup
# -------------------------
function Invoke-RetentionCleanup {
    param(
        [int]$DumpDays,
        [int]$LogDays
    )

    try {
        $dumpCutoff = (Get-Date).AddDays(-1 * $DumpDays)
        Get-ChildItem -Path $DumpRoot -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $dumpCutoff } |
            ForEach-Object {
                try {
                    Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                    Write-Log "RETENTION DELETE DUMP $($_.FullName)"
                }
                catch {
                    Write-Log "RETENTION ERROR DUMP $($_.FullName) $_"
                }
            }
    }
    catch {
        Write-Log "RETENTION ERROR scanning dump folder $_"
    }

    try {
        $logCutoff = (Get-Date).AddDays(-1 * $LogDays)
        Get-ChildItem -Path $LogRoot -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $logCutoff } |
            ForEach-Object {
                try {
                    if ($_.FullName -ne $LogFile) {
                        Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop
                        Write-Log "RETENTION DELETE LOG $($_.FullName)"
                    }
                }
                catch {
                    Write-Log "RETENTION ERROR LOG $($_.FullName) $_"
                }
            }
    }
    catch {
        Write-Log "RETENTION ERROR scanning log folder $_"
    }
}

# -------------------------
# Cooldown state helpers
# -------------------------
function Get-CooldownState {
    if (-not (Test-Path $CooldownState)) {
        return @{}
    }

    try {
        $raw = Get-Content -LiteralPath $CooldownState -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) {
            return @{}
        }

        $obj = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
        $map = @{}

        if ($obj -is [System.Collections.IDictionary]) {
            foreach ($k in $obj.Keys) {
                $map[[string]$k] = [string]$obj[$k]
            }
        }
        else {
            foreach ($p in $obj.PSObject.Properties) {
                $map[[string]$p.Name] = [string]$p.Value
            }
        }

        return $map
    }
    catch {
        Write-Log "COOLDOWN LOAD ERROR $_"
        return @{}
    }
}

function Save-CooldownState {
    param([hashtable]$State)

    try {
        $json = $State | ConvertTo-Json -Depth 4
        $json | Out-File -LiteralPath $CooldownState -Encoding UTF8 -Force
    }
    catch {
        Write-Log "COOLDOWN SAVE ERROR $_"
    }
}

function Test-CooldownActive {
    param(
        [hashtable]$State,
        [int]$ProcessId,
        [int]$Minutes
    )

    $key = [string]$ProcessId
    if (-not $State.ContainsKey($key)) {
        return $false
    }

    try {
        $last = [datetime]::Parse($State[$key])
        return ((Get-Date) -lt $last.AddMinutes($Minutes))
    }
    catch {
        Write-Log "COOLDOWN PARSE ERROR PID=$ProcessId Value=$($State[$key]) $_"
        return $false
    }
}

function Set-CooldownActive {
    param(
        [hashtable]$State,
        [int]$ProcessId
    )

    $State[[string]$ProcessId] = (Get-Date).ToString("o")
}

function Remove-StaleCooldownEntries {
    param(
        [hashtable]$State,
        [int]$Minutes
    )

    $now = Get-Date
    $keysToRemove = New-Object System.Collections.ArrayList

    foreach ($k in $State.Keys) {
        try {
            $dt = [datetime]::Parse($State[$k])
            if ($now -ge $dt.AddMinutes($Minutes * 4)) {
                [void]$keysToRemove.Add($k)
            }
        }
        catch {
            [void]$keysToRemove.Add($k)
        }
    }

    foreach ($k in $keysToRemove) {
        [void]$State.Remove($k)
    }
}

# -------------------------
# Hard exclusions (known problematic modern shell/UWP-ish processes)
# -------------------------
$ExcludedProcessNames = @(
    'ApplicationFrameHost',
    'LockApp',
    'SearchApp',
    'SearchHost',
    'ShellExperienceHost',
    'StartMenuExperienceHost',
    'SystemSettings',
    'TextInputHost',
    'Widgets',
    'WinStore.App',
    'YourPhone',
    'PhoneExperienceHost'
)

function Is-ExcludedByName {
    param([string]$Name)
    return ($ExcludedProcessNames -contains $Name)
}

# -------------------------
# Packaged / UWP-ish detection helpers
# -------------------------
function Get-ProcessExecutablePathSafe {
    param([System.Diagnostics.Process]$Process)

    try {
        if ($Process.Path) {
            return [string]$Process.Path
        }
    }
    catch {}

    try {
        $cim = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f $Process.Id) -ErrorAction Stop
        if ($cim.ExecutablePath) {
            return [string]$cim.ExecutablePath
        }
    }
    catch {}

    return $null
}

function Test-IsWindowsAppsPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $false
    }

    return ($Path -match '^[A-Za-z]:\\Program Files\\WindowsApps\\')
}

function Test-IsPackagedExecutable {
    param([string]$ExecutablePath)

    if ([string]::IsNullOrWhiteSpace($ExecutablePath)) {
        return $false
    }

    if (Test-IsWindowsAppsPath -Path $ExecutablePath) {
        return $true
    }

    try {
        $packages = Get-AppxPackage -ErrorAction SilentlyContinue
        foreach ($pkg in $packages) {
            try {
                if ($pkg.InstallLocation) {
                    $installRoot = [string]$pkg.InstallLocation
                    if (-not [string]::IsNullOrWhiteSpace($installRoot)) {
                        $normalizedExe  = $ExecutablePath.TrimEnd('\')
                        $normalizedRoot = $installRoot.TrimEnd('\')
                        if ($normalizedExe.StartsWith($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                            return $true
                        }
                    }
                }
            }
            catch {}
        }
    }
    catch {}

    return $false
}

function Test-ShouldSkipProcess {
    param([System.Diagnostics.Process]$Process)

    if (Is-ExcludedByName -Name $Process.Name) {
        return @{
            Skip   = $true
            Reason = "NameExclusion"
            Path   = $null
        }
    }

    $exePath = Get-ProcessExecutablePathSafe -Process $Process

    if (Test-IsWindowsAppsPath -Path $exePath) {
        return @{
            Skip   = $true
            Reason = "WindowsAppsPath"
            Path   = $exePath
        }
    }

    if (Test-IsPackagedExecutable -ExecutablePath $exePath) {
        return @{
            Skip   = $true
            Reason = "PackagedExecutable"
            Path   = $exePath
        }
    }

    return @{
        Skip   = $false
        Reason = $null
        Path   = $exePath
    }
}

# -------------------------
# Dump helpers
# -------------------------
function Invoke-ProcDump {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Tag
    )

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $base  = "$ProcessName`_$ProcessId`_$Tag`_$stamp"

    $dump  = Join-Path $DumpRoot "$base.dmp"
    $out   = Join-Path $DumpRoot "$base.procdump.out.log"
    $err   = Join-Path $DumpRoot "$base.procdump.err.log"

    $dumpMode = if ($UseFullDumpWithProcDump) { '-ma' } else { '-mm' }

    Write-Log "PROCDUMP TRY $ProcessName($ProcessId) Mode=$dumpMode"

    try {
        $p = Start-Process `
            -FilePath $ProcDump `
            -ArgumentList @('-accepteula', $dumpMode, '-r', $ProcessId, $dump) `
            -PassThru -Wait -WindowStyle Hidden `
            -RedirectStandardOutput $out `
            -RedirectStandardError $err `
            -ErrorAction Stop

        if (Test-Path $dump) {
            Write-Log "PROCDUMP SUCCESS $dump"
            return $dump
        }

        $exitCode = $null
        try { $exitCode = $p.ExitCode } catch {}
        Write-Log "PROCDUMP FAILED Exit=$exitCode DumpMissing=$dump"
        return $null
    }
    catch {
        Write-Log "PROCDUMP ERROR $ProcessName($ProcessId) $_"
        return $null
    }
}

function Invoke-ComsvcsDump {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Tag
    )

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $dump  = Join-Path $DumpRoot "$ProcessName`_$ProcessId`_$Tag`_$stamp.comsvcs.dmp"

    Write-Log "COMSVCS TRY $ProcessName($ProcessId)"

    try {
        & "$env:SystemRoot\System32\rundll32.exe" `
          "$env:SystemRoot\System32\comsvcs.dll,MiniDump" `
          $ProcessId $dump full | Out-Null
    }
    catch {
        Write-Log "COMSVCS ERROR $ProcessName($ProcessId) $_"
        return $null
    }

    if (Test-Path $dump) {
        Write-Log "COMSVCS SUCCESS $dump"
        return $dump
    }

    Write-Log "COMSVCS FAILED $ProcessName($ProcessId) (no dump created)"
    return $null
}

# -------------------------
# Detection logic
# -------------------------
function Test-UIHang {
    param([System.Diagnostics.Process]$Process)

    try {
        return ($Process.MainWindowHandle -ne 0 -and $Process.Responding -eq $false)
    }
    catch {
        return $false
    }
}

function Test-Suspended {
    param([int]$ProcessId)

    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
    }
    catch {
        return $false
    }

    try {
        $threads = $proc.Threads
        if ($null -eq $threads -or $threads.Count -eq 0) {
            return $false
        }

        $suspendedCount = 0
        foreach ($t in $threads) {
            try {
                if ($t.ThreadState -eq 'Wait' -and $t.WaitReason -eq 'Suspended') {
                    $suspendedCount++
                }
            }
            catch {}
        }

        return ((($suspendedCount / $threads.Count) * 100) -ge 80)
    }
    catch {
        return $false
    }
}

# -------------------------
# Main
# -------------------------
Write-Log "=== AutoCapture HARDENED START ==="
Write-Host "AutoCapture HARDENED running. Logs: $LogFile"

Invoke-RetentionCleanup -DumpDays $DumpRetentionDays -LogDays $LogRetentionDays

$cooldown = Get-CooldownState
Remove-StaleCooldownEntries -State $cooldown -Minutes $CooldownMinutes

$allProcesses = @()
try {
    $allProcesses = Get-Process -ErrorAction Stop
}
catch {
    Write-Log "ENUMERATION ERROR $_"
    throw
}

foreach ($p in $allProcesses) {
    try {
        $procName = $null
        $procId   = $null

        try { $procName = $p.Name } catch { $procName = "<unknown>" }
        try { $procId   = $p.Id }   catch { $procId   = -1 }

        if ($procId -lt 0) {
            Write-Log "SKIP INVALID PROCESS Name=$procName Id=$procId"
            continue
        }

        $skipInfo = Test-ShouldSkipProcess -Process $p
        if ($skipInfo.Skip) {
            if ($skipInfo.Path) {
                Write-Log "SKIP PACKAGED $procName($procId) Reason=$($skipInfo.Reason) Path=$($skipInfo.Path)"
            }
            else {
                Write-Log "SKIP PACKAGED $procName($procId) Reason=$($skipInfo.Reason)"
            }
            continue
        }

        if (Test-CooldownActive -State $cooldown -ProcessId $procId -Minutes $CooldownMinutes) {
            Write-Log "SKIP COOLDOWN $procName($procId)"
            continue
        }

        $uiHang  = Test-UIHang -Process $p
        $suspend = Test-Suspended -ProcessId $procId

        if (-not ($uiHang -or $suspend)) {
            continue
        }

        $tag = if ($uiHang -and $suspend) {
            'UIHang+Suspend'
        }
        elseif ($uiHang) {
            'UIHang'
        }
        else {
            'Suspend'
        }

        Write-Log "TRIGGER $procName($procId) Tag=$tag"

        $dump = Invoke-ProcDump -ProcessId $procId -ProcessName $procName -Tag $tag

        if (-not $dump) {
            $dump = Invoke-ComsvcsDump -ProcessId $procId -ProcessName $procName -Tag $tag
        }

        if ($dump) {
            Set-CooldownActive -State $cooldown -ProcessId $procId
            Write-Log "DUMP CREATED $dump"
        }
        else {
            Write-Log "DUMP FAILED $procName($procId) - both methods failed"
        }
    }
    catch {
        try {
            Write-Log "PROCESS ERROR $($p.Name)($($p.Id)) $_"
        }
        catch {
            Write-Log "PROCESS ERROR <unreadable process> $_"
        }
    }
}

Save-CooldownState -State $cooldown

Write-Log "=== AutoCapture HARDENED END ==="
Write-Host "AutoCapture HARDENED complete."