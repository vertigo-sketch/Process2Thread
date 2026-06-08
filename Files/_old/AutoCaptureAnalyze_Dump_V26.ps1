<#
AutoCapture
What it does (end-to-end): AutoCaptureAnalyze_Dump_V23.ps1
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

Historical changes:
- V30: Fix native fallback reliability:
       * Initialize $script:MiniDumpNativeReady to avoid PS 5.1 unset-variable failure
       * Harden Ensure-MiniDumpNative (idempotent, logs success/failure)
       * Keep NO comsvcs.dll usage (blocked in environment) [1](https://icapitalnetwork.atlassian.net/wiki/spaces/DEVOPS/pages/4348641462/CrowdStrike+endpoints+hardening)
       * ProcDump retry sequence: normal -> -64 -> -wer [2](https://icapitalnetwork-my.sharepoint.com/personal/jmiller_icapitalnetwork_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={a8c8915f-6b87-4232-aba2-f8b09a805634}&wd=target(/Projects/process and handles.one/)&wdpartid={5276727a-0db4-44e0-a227-ca5b28bf705e}{1}&wdsectionfileid={fe5d4ba1-733f-4984-bc79-7a2c5154083e})
#>

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds = 5,
    [int]$CooldownSeconds = 600,
    [ValidateSet('Mini','MiniWithHandles','Full')]
    [string]$DumpProfile = 'Mini',
    [switch]$SinglePass,
    [switch]$ConsoleStatus = $true
)

# ---------------------------
# Admin check (parser-safe)
# ---------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    throw "Run as Administrator (required for dump attach)."
}

# Deterministic errors
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
# Native dump loader state (PS 5.1-safe initialization)
# ---------------------------
$script:MiniDumpNativeReady = $false

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

function Get-FileExcerpt {
    param(
        [string]$Path,
        [int]$MaxLines = 25
    )
    try {
        if (-not (Test-Path $Path)) { return $null }
        $lines = Get-Content -Path $Path -ErrorAction Stop
        if (-not $lines -or $lines.Count -eq 0) { return $null }
        $take = [Math]::Min($MaxLines, $lines.Count)
        return ($lines[0..($take-1)] -join "`n")
    } catch {
        return $null
    }
}

# ---------------------------
# Optional deny list (noise reducer)
# ---------------------------
$DenyNames = @(
    'LockApp','RuntimeBroker','SearchHost',
    'ShellExperienceHost','StartMenuExperienceHost',
    'ApplicationFrameHost','backgroundTaskHost'
)

# Hard "never dump" list for known packaged/UWP-ish components
$NeverDumpNames = @(
    'Microsoft.AAD.BrokerPlugin'
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

    $mwh  = 0
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
# Packaged/UWP-ish detection: image path + WindowsApps
# ---------------------------
function Get-ProcessImagePath {
    param([int]$TargetProcessId)
    try {
        $c = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $TargetProcessId) -ErrorAction Stop
        return [string]$c.ExecutablePath
    } catch {
        return $null
    }
}

function Is-NeverDumpTarget {
    param(
        [int]$TargetProcessId,
        [string]$ProcessName
    )

    if ($NeverDumpNames -contains $ProcessName) { return $true }

    $img = Get-ProcessImagePath -TargetProcessId $TargetProcessId
    if ($img) {
        if ($img -match '\\WindowsApps\\') { return $true }
    }

    return $false
}

# ---------------------------
# ProcDump helpers
# ---------------------------
function Invoke-ProcDump {
    param(
        [int]$TargetProcessId,
        [string]$DumpPath,
        [string[]]$ProfileArgs,
        [string]$OutPath,
        [string]$ErrPath,
        [string[]]$ExtraArgs
    )

    $args = @('-accepteula') + $ProfileArgs
    if ($ExtraArgs -and $ExtraArgs.Count -gt 0) { $args += $ExtraArgs }
    # -r = dump immediately (clone)
    $args += @('-r', $TargetProcessId, $DumpPath)

    Write-Log "PROCDUMP START ProcessId=$TargetProcessId Dump=$DumpPath Args=$($args -join ' ')"
    $p = Start-Process -FilePath $ProcDumpPath `
        -ArgumentList $args `
        -WindowStyle Hidden `
        -PassThru `
        -Wait `
        -RedirectStandardOutput $OutPath `
        -RedirectStandardError $ErrPath

    $exists = (Test-Path $DumpPath)
    Write-Log "PROCDUMP END ExitCode=$($p.ExitCode) DumpExists=$exists Out=$OutPath Err=$ErrPath"

    if (-not $exists) {
        $errEx = Get-FileExcerpt -Path $ErrPath -MaxLines 25
        $outEx = Get-FileExcerpt -Path $OutPath -MaxLines 25
        if ($errEx) { Write-Log ("PROCDUMP ERR EXCERPT:`n{0}" -f $errEx) }
        if ($outEx) { Write-Log ("PROCDUMP OUT EXCERPT:`n{0}" -f $outEx) }
    }

    return [pscustomobject]@{
        ExitCode   = $p.ExitCode
        DumpExists = $exists
        OutPath    = $OutPath
        ErrPath    = $ErrPath
    }
}

# ---------------------------
# Native fallback: MiniDumpWriteDump (dbghelp.dll)
# ---------------------------
function Ensure-MiniDumpNative {

    if ($script:MiniDumpNativeReady -eq $true) { return }

    $code = @"
using System;
using System.Runtime.InteropServices;

public static class MiniDumpNative {
    [Flags]
    public enum MINIDUMP_TYPE : uint {
        MiniDumpNormal = 0x00000000,
        MiniDumpWithFullMemory = 0x00000002,
        MiniDumpWithHandleData = 0x00000004
    }

    [Flags]
    public enum ProcessAccessFlags : uint {
        QueryInformation = 0x0400,
        VirtualMemoryRead = 0x0010,
        All = 0x001F0FFF
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr OpenProcess(ProcessAccessFlags access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("dbghelp.dll", SetLastError=true)]
    public static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        int processId,
        IntPtr hFile,
        MINIDUMP_TYPE dumpType,
        IntPtr exceptionParam,
        IntPtr userStreamParam,
        IntPtr callbackParam
    );
}
"@

    try {
        Add-Type -TypeDefinition $code -ErrorAction Stop | Out-Null
        $script:MiniDumpNativeReady = $true
        Write-Log "Native MiniDumpWriteDump loaded successfully (dbghelp.dll)"
    }
    catch {
        $script:MiniDumpNativeReady = $false
        throw ("Add-Type failed for native MiniDumpWriteDump: {0}" -f $_.Exception.Message)
    }
}

function Invoke-NativeMiniDump {
    param(
        [int]$TargetProcessId,
        [string]$DumpPath
    )

    Ensure-MiniDumpNative

    $dumpType = [MiniDumpNative+MINIDUMP_TYPE]::MiniDumpNormal
    if ($DumpProfile -eq 'MiniWithHandles') { $dumpType = [MiniDumpNative+MINIDUMP_TYPE]::MiniDumpWithHandleData }
    if ($DumpProfile -eq 'Full')           { $dumpType = [MiniDumpNative+MINIDUMP_TYPE]::MiniDumpWithFullMemory }

    $hProc = [IntPtr]::Zero
    $fs = $null

    try {
        $hProc = [MiniDumpNative]::OpenProcess([MiniDumpNative+ProcessAccessFlags]::All, $false, $TargetProcessId)
        if ($hProc -eq [IntPtr]::Zero) {
            $hProc = [MiniDumpNative]::OpenProcess(
                [MiniDumpNative+ProcessAccessFlags]::QueryInformation -bor [MiniDumpNative+ProcessAccessFlags]::VirtualMemoryRead,
                $false,
                $TargetProcessId
            )
        }
        if ($hProc -eq [IntPtr]::Zero) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw ("OpenProcess failed (Win32Error={0})" -f $err)
        }

        $fs = New-Object System.IO.FileStream($DumpPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $hFile = $fs.SafeFileHandle.DangerousGetHandle()

        $ok = [MiniDumpNative]::MiniDumpWriteDump(
            $hProc,
            $TargetProcessId,
            $hFile,
            $dumpType,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [IntPtr]::Zero
        )
        if (-not $ok) {
            $err2 = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw ("MiniDumpWriteDump failed (Win32Error={0})" -f $err2)
        }

    } finally {
        if ($fs) { try { $fs.Close() } catch { } }
        if ($hProc -ne [IntPtr]::Zero) { try { [MiniDumpNative]::CloseHandle($hProc) | Out-Null } catch { } }
    }

    return (Test-Path $DumpPath)
}

# ---------------------------
# Dump capture with ProcDump + Native fallback
# ---------------------------
function Capture-Dump {
    param(
        [int]$TargetProcessId,
        [string]$ProcessName,
        [string]$Tag
    )

    if (Is-NeverDumpTarget -TargetProcessId $TargetProcessId -ProcessName $ProcessName) {
        throw ("Skipped dump for packaged/UWP target: {0}({1})" -f $ProcessName, $TargetProcessId)
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $base  = "{0}_{1}_{2}_{3}" -f $ProcessName, $TargetProcessId, $Tag, $stamp

    $dumpPath = Join-Path $DumpRoot ($base + '.dmp')

    $profileArgs = switch ($DumpProfile) {
        'Mini'            { @('-mm') }
        'MiniWithHandles' { @('-mm','-mh') }
        'Full'            { @('-ma') }
    }

    # Attempt #1: ProcDump normal
    $out1 = Join-Path $DumpRoot ($base + '.procdump.out.log')
    $err1 = Join-Path $DumpRoot ($base + '.procdump.err.log')
    $r1 = Invoke-ProcDump -TargetProcessId $TargetProcessId -DumpPath $dumpPath -ProfileArgs $profileArgs -OutPath $out1 -ErrPath $err1 -ExtraArgs @()
    if ($r1.DumpExists) { return $dumpPath }

    # Attempt #2: ProcDump -64 [2](https://icapitalnetwork-my.sharepoint.com/personal/jmiller_icapitalnetwork_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={a8c8915f-6b87-4232-aba2-f8b09a805634}&wd=target(/Projects/process and handles.one/)&wdpartid={5276727a-0db4-44e0-a227-ca5b28bf705e}{1}&wdsectionfileid={fe5d4ba1-733f-4984-bc79-7a2c5154083e})
    $out2 = Join-Path $DumpRoot ($base + '.procdump64.out.log')
    $err2 = Join-Path $DumpRoot ($base + '.procdump64.err.log')
    $r2 = Invoke-ProcDump -TargetProcessId $TargetProcessId -DumpPath $dumpPath -ProfileArgs $profileArgs -OutPath $out2 -ErrPath $err2 -ExtraArgs @('-64')
    if ($r2.DumpExists) { return $dumpPath }

    # Attempt #3: ProcDump -wer [2](https://icapitalnetwork-my.sharepoint.com/personal/jmiller_icapitalnetwork_com/_layouts/15/Doc.aspx?action=edit&mobileredirect=true&wdorigin=Sharepoint&DefaultItemOpen=1&sourcedoc={a8c8915f-6b87-4232-aba2-f8b09a805634}&wd=target(/Projects/process and handles.one/)&wdpartid={5276727a-0db4-44e0-a227-ca5b28bf705e}{1}&wdsectionfileid={fe5d4ba1-733f-4984-bc79-7a2c5154083e})
    $out3 = Join-Path $DumpRoot ($base + '.procdumpwer.out.log')
    $err3 = Join-Path $DumpRoot ($base + '.procdumpwer.err.log')
    $r3 = Invoke-ProcDump -TargetProcessId $TargetProcessId -DumpPath $dumpPath -ProfileArgs $profileArgs -OutPath $out3 -ErrPath $err3 -ExtraArgs @('-wer')
    if ($r3.DumpExists) { return $dumpPath }

    # Attempt #4: Native fallback (dbghelp.dll)
    Write-Log "NATIVE DUMP START Name=$ProcessName ProcessId=$TargetProcessId Tag=$Tag Dump=$dumpPath"
    try {
        $okNative = Invoke-NativeMiniDump -TargetProcessId $TargetProcessId -DumpPath $dumpPath
        Write-Log "NATIVE DUMP END DumpExists=$okNative"
        if ($okNative) { return $dumpPath }
    } catch {
        Write-Log ("NATIVE DUMP ERROR: {0}" -f $_.Exception.Message)
    }

    throw ("Dump not created. ProcDump attempts failed (normal/-64/-wer) and native fallback failed. See: {0}" -f $LogFile)
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
    Write-Log "CDB END ExitCode=$($p.ExitCode) LogExists=$(Test-Path $cdbLog)"
    return $cdbLog
}

# ---------------------------
# Extract top blocked thread (deterministic heuristic)
# ---------------------------
function Extract-TopBlockedThread {
    param([string]$CdbLogPath)
    if (-not (Test-Path $CdbLogPath)) { return $null }
    $lines = Get-Content $CdbLogPath

    $patterns = @('(?i)\bblocked\b','(?i)waitreason','(?i)deadlock','(?i)!analyze -hang','(?i)hang')
    $idx = -1
    for ($i=0; $i -lt $lines.Count; $i++) {
        foreach ($pat in $patterns) {
            if ($lines[$i] -match $pat) { $idx = $i; break }
        }
        if ($idx -ge 0) { break }
    }
    if ($idx -lt 0) { return $null }

    $end = [Math]::Min($idx + 80, $lines.Count - 1)
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
Write-Log "=== AutoCapture V30 START === ScriptRoot=$ScriptRoot DumpRoot=$DumpRoot DumpProfile=$DumpProfile"
Write-Status "AutoCapture V30 running (Admin OK). Logs: $LogFile" Cyan

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

        $uiHang  = Test-UIHang -Snap $b
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