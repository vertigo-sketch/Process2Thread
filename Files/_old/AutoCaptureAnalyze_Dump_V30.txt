<#
Fixes:
- CDB: uses -cf command file AND passes arguments as a single quoted string (prevents "Invalid switch" caused by paths w/ spaces/hyphen).
- CDB: validates output/log isn’t just the usage banner; treats usage output as failure.
- ExitHex conversion fixed for negative HRESULT-style exit codes.
- ProcDump: also uses single quoted argument string for safety (paths with spaces/hyphen).
- NO comsvcs.dll / rundll32 usage.

Core behavior:
- Detects UI hangs (windowed process, Responding=false)
- Detects true suspension (>=80% threads WaitReason=Suspended)
- Tags dumps: UIHang / Suspend / UIHang+Suspend
- Captures dump with ProcDump (-r). If ProcDump fails, retries (-64) then (-wer). Final fallback uses MiniDumpWriteDump (dbghelp.dll).
- Analyzes dump with cdb and saves .cdb.log; if -logo fails, falls back to stdout capture log.
- Extracts "top blocked thread" section from whichever cdb output is valid
- Correlates filter drivers (WdFilter / CSAgent)
- Writes JSON evidence next to dump: .analysis.json
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
# Admin check
# ---------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    throw "Run as Administrator (required for dump attach)."
}

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
# Tool paths
# ---------------------------
$ProcDumpPath = 'C:\Tools\Sysinternals\procdump.exe'
$CdbPath      = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
if (-not (Test-Path $ProcDumpPath)) { throw "Missing ProcDump: $ProcDumpPath" }
if (-not (Test-Path $CdbPath))      { throw "Missing cdb.exe: $CdbPath" }

# ---------------------------
# Native dump loader state (PS 5.1-safe)
# ---------------------------
$script:MiniDumpNativeReady = $false

# ---------------------------
# Logging helpers
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
    } catch { return $null }
}

function Convert-ExitCodeHex {
    param($Code)
    try {
        $i64 = [int64]$Code
        $u32 = $i64 -band 0xFFFFFFFF
        return ('0x{0:X8}' -f $u32)
    } catch { return $null }
}

# Detects "usage banner / invalid switch" output so we don't treat it as success.
function Test-CdbOutputLooksValid {
    param([string]$Path)
    try {
        if (-not (Test-Path $Path)) { return $false }
        $head = Get-Content -Path $Path -TotalCount 8 -ErrorAction Stop
        if (-not $head) { return $false }
        $text = ($head -join "`n")

        if ($text -match 'cdb:\s*Invalid switch') { return $false }
        if ($text -match '(?im)^\s*usage:\s*cdb\b') { return $false }

        return $true
    } catch {
        return $false
    }
}

# ---------------------------
# Optional deny list (noise reducer) + UWP-ish skip
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

function Get-ProcessImagePath {
    param([int]$TargetProcessId)
    try {
        $c = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $TargetProcessId) -ErrorAction Stop
        return [string]$c.ExecutablePath
    } catch { return $null }
}

function Is-NeverDumpTarget {
    param(
        [int]$TargetProcessId,
        [string]$ProcessName
    )
    if ($NeverDumpNames -contains $ProcessName) { return $true }

    $img = Get-ProcessImagePath -TargetProcessId $TargetProcessId
    if ($img -and ($img -match '\\WindowsApps\\')) { return $true }

    return $false
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
# Detection
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
# Cooldown
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
# ProcDump invocation (single quoted arg string)
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

    # Build one safe command-line string.
    # Example: -accepteula -mm -r 1234 "C:\...\file.dmp"
    $parts = @('-accepteula')
    if ($ProfileArgs) { $parts += $ProfileArgs }
    if ($ExtraArgs)   { $parts += $ExtraArgs }
    $parts += @('-r', $TargetProcessId.ToString(), ('"{0}"' -f $DumpPath))

    $argLine = ($parts -join ' ')
    Write-Log "PROCDUMP START ProcessId=$TargetProcessId Dump=$DumpPath Args=$argLine"

    $p = Start-Process -FilePath $ProcDumpPath `
        -ArgumentList $argLine `
        -WindowStyle Hidden `
        -PassThru `
        -Wait `
        -RedirectStandardOutput $OutPath `
        -RedirectStandardError $ErrPath

    $exists = (Test-Path $DumpPath)
    Write-Log "PROCDUMP END ExitCode=$($p.ExitCode) DumpExists=$exists Out=$OutPath Err=$ErrPath"

    if (-not $exists) {
        $errEx = Get-FileExcerpt -Path $ErrPath -MaxLines 30
        if ($errEx) { Write-Log ("PROCDUMP STDERR EXCERPT:`n{0}" -f $errEx) }
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

    Add-Type -TypeDefinition $code -ErrorAction Stop | Out-Null
    $script:MiniDumpNativeReady = $true
    Write-Log "Native MiniDumpWriteDump loaded (dbghelp.dll)"
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
    }
    finally {
        if ($fs) { try { $fs.Close() } catch { } }
        if ($hProc -ne [IntPtr]::Zero) { try { [MiniDumpNative]::CloseHandle($hProc) | Out-Null } catch { } }
    }

    return (Test-Path $DumpPath)
}

# ---------------------------
# Dump capture
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
    $out1 = Join-Path $DumpRoot ($base + '.procdump.out.log')
    $err1 = Join-Path $DumpRoot ($base + '.procdump.err.log')

    $profileArgs = switch ($DumpProfile) {
        'Mini'            { @('-mm') }
        'MiniWithHandles' { @('-mm','-mh') }
        'Full'            { @('-ma') }
    }

    # Attempt 1: normal
    $r1 = Invoke-ProcDump -TargetProcessId $TargetProcessId -DumpPath $dumpPath -ProfileArgs $profileArgs -OutPath $out1 -ErrPath $err1 -ExtraArgs @()
    if ($r1.DumpExists) { return $dumpPath }

    # Attempt 2: -64
    $out2 = Join-Path $DumpRoot ($base + '.procdump64.out.log')
    $err2 = Join-Path $DumpRoot ($base + '.procdump64.err.log')
    $r2 = Invoke-ProcDump -TargetProcessId $TargetProcessId -DumpPath $dumpPath -ProfileArgs $profileArgs -OutPath $out2 -ErrPath $err2 -ExtraArgs @('-64')
    if ($r2.DumpExists) { return $dumpPath }

    # Attempt 3: -wer
    $out3 = Join-Path $DumpRoot ($base + '.procdumpwer.out.log')
    $err3 = Join-Path $DumpRoot ($base + '.procdumpwer.err.log')
    $r3 = Invoke-ProcDump -TargetProcessId $TargetProcessId -DumpPath $dumpPath -ProfileArgs $profileArgs -OutPath $out3 -ErrPath $err3 -ExtraArgs @('-wer')
    if ($r3.DumpExists) { return $dumpPath }

    # Attempt 4: native fallback
    Write-Log "NATIVE DUMP START Name=$ProcessName ProcessId=$TargetProcessId Tag=$Tag Dump=$dumpPath"
    $okNative = $false
    try {
        $okNative = Invoke-NativeMiniDump -TargetProcessId $TargetProcessId -DumpPath $dumpPath
        Write-Log "NATIVE DUMP END DumpExists=$okNative"
    } catch {
        Write-Log ("NATIVE DUMP ERROR: {0}" -f $_.Exception.Message)
    }

    if ($okNative -and (Test-Path $dumpPath)) { return $dumpPath }

    throw ("Dump not created. All capture methods failed. See: {0}" -f $LogFile)
}

# ---------------------------
# Write CDB script file for -cf
# ---------------------------
function Write-CdbCommandFile {
    param([string]$DumpPath)

    $cmdFile = $DumpPath -replace '\.dmp$','.cdb.cmd.txt'
    $lines = @(
        '.symfix',
        '.reload',
        '!analyze -hang',
        '~* kb',
        'q'
    )
    # ASCII is safest for debugger command files
    $lines | Out-File -Encoding ASCII -Force -FilePath $cmdFile
    return $cmdFile
}

# ---------------------------
# CDB analysis (safe quoting + -cf)
# ---------------------------
function Analyze-Dump {
    param([string]$DumpPath)

    $cdbLog      = $DumpPath -replace '\.dmp$','.cdb.log'
    $cdbOut1     = $DumpPath -replace '\.dmp$','.cdb.stdout.log'
    $cdbErr1     = $DumpPath -replace '\.dmp$','.cdb.stderr.log'
    $captureLog  = $DumpPath -replace '\.dmp$','.cdb.capture.log'
    $cdbErr2     = $DumpPath -replace '\.dmp$','.cdb.capture.stderr.log'

    $cmdFile = Write-CdbCommandFile -DumpPath $DumpPath

    # Attempt 1: -logo (single quoted arg string)
    $args1 = ('-z "{0}" -cf "{1}" -logo "{2}"' -f $DumpPath, $cmdFile, $cdbLog)
    Write-Log "CDB START (logo) Dump=$DumpPath Log=$cdbLog CmdFile=$cmdFile Args=$args1"

    $p1 = Start-Process -FilePath $CdbPath `
        -ArgumentList $args1 `
        -WindowStyle Hidden `
        -PassThru `
        -Wait `
        -RedirectStandardOutput $cdbOut1 `
        -RedirectStandardError $cdbErr1

    $hex1 = Convert-ExitCodeHex -Code $p1.ExitCode
    $logExists = (Test-Path $cdbLog)
    $logLooksValid = ($logExists -and (Test-CdbOutputLooksValid -Path $cdbLog))
    Write-Log "CDB END (logo) ExitCode=$($p1.ExitCode) ExitHex=$hex1 LogExists=$logExists LogLooksValid=$logLooksValid StdOut=$cdbOut1 StdErr=$cdbErr1"

    if ($logLooksValid) {
        return [pscustomobject]@{
            Success     = $true
            ExitCode    = [int]$p1.ExitCode
            ExitHex     = $hex1
            NonZeroExit = ([int]$p1.ExitCode -ne 0)
            LogPath     = $cdbLog
            Mode        = 'logo'
            StdOutPath  = $cdbOut1
            StdErrPath  = $cdbErr1
            CmdFile     = $cmdFile
        }
    }

    # Attempt 2: capture stdout (single quoted arg string)
    $args2 = ('-z "{0}" -cf "{1}"' -f $DumpPath, $cmdFile)
    Write-Log "CDB START (capture) Dump=$DumpPath CaptureLog=$captureLog CmdFile=$cmdFile Args=$args2"

    $p2 = Start-Process -FilePath $CdbPath `
        -ArgumentList $args2 `
        -WindowStyle Hidden `
        -PassThru `
        -Wait `
        -RedirectStandardOutput $captureLog `
        -RedirectStandardError $cdbErr2

    $hex2 = Convert-ExitCodeHex -Code $p2.ExitCode

    $capExists = (Test-Path $captureLog)
    $capLen = 0
    if ($capExists) { try { $capLen = (Get-Item $captureLog).Length } catch { $capLen = 0 } }
    $capLooksValid = ($capExists -and $capLen -gt 10 -and (Test-CdbOutputLooksValid -Path $captureLog))

    Write-Log "CDB END (capture) ExitCode=$($p2.ExitCode) ExitHex=$hex2 CaptureExists=$capExists CaptureLen=$capLen CaptureLooksValid=$capLooksValid StdErr=$cdbErr2"

    if ($capLooksValid) {
        return [pscustomobject]@{
            Success     = $true
            ExitCode    = [int]$p2.ExitCode
            ExitHex     = $hex2
            NonZeroExit = ([int]$p2.ExitCode -ne 0)
            LogPath     = $captureLog
            Mode        = 'stdout_capture'
            StdOutPath  = $captureLog
            StdErrPath  = $cdbErr2
            CmdFile     = $cmdFile
        }
    }

    return [pscustomobject]@{
        Success     = $false
        ExitCode    = [int]$p2.ExitCode
        ExitHex     = $hex2
        NonZeroExit = ([int]$p2.ExitCode -ne 0)
        LogPath     = $null
        Mode        = 'failed'
        StdOutPath  = $captureLog
        StdErrPath  = $cdbErr2
        CmdFile     = $cmdFile
        LogoStdOut  = $cdbOut1
        LogoStdErr  = $cdbErr1
    }
}

# ---------------------------
# Extract top blocked thread
# ---------------------------
function Extract-TopBlockedThread {
    param([string]$CdbLogPath)

    if (-not $CdbLogPath) { return $null }
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
        $CdbResult,
        [string]$BlockedThreadText,
        $FilterCorrelation
    )

    $jsonPath = $DumpPath -replace '\.dmp$','.analysis.json'
    $obj = [pscustomobject]@{
        DumpPath          = $DumpPath
        Tag               = $Tag

        CdbSuccess        = $CdbResult.Success
        CdbMode           = $CdbResult.Mode
        CdbExitCode       = $CdbResult.ExitCode
        CdbExitHex        = $CdbResult.ExitHex
        CdbNonZeroExit    = $CdbResult.NonZeroExit
        CdbLog            = $CdbResult.LogPath
        CdbStdOut         = $CdbResult.StdOutPath
        CdbStdErr         = $CdbResult.StdErrPath
        CdbCmdFile        = $CdbResult.CmdFile

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
Write-Log "=== AutoCapture V34 START === ScriptRoot=$ScriptRoot DumpRoot=$DumpRoot DumpProfile=$DumpProfile"
Write-Status "AutoCapture V34 running (Admin OK). Logs: $LogFile" Cyan

do {
    Write-Log "PASS START"

    # Snapshot A
    $snapA = @{}
    foreach ($proc in Get-Process) {
        $s = Get-SafeSnapshot -Proc $proc
        if ($s) { $snapA[$s.ProcessId] = $s }l
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
        if (-not $uiHang) { $suspend = Test-TrueSuspend -TargetProcessId $b.ProcessId }

        if (-not ($uiHang -or $suspend)) { continue }

        $tag = Get-Tag -UIHang $uiHang -Suspend $suspend
        $triggers++

        Write-Log "TRIGGER Name=$($b.Name) ProcessId=$($b.ProcessId) Tag=$tag"
        Write-Status ("TRIGGER {0}({1}) Tag={2}" -f $b.Name, $b.ProcessId, $tag) Red

        try {
            Mark-Captured -TargetProcessId $b.ProcessId

            $dump = Capture-Dump -TargetProcessId $b.ProcessId -ProcessName $b.Name -Tag $tag
            $cdbResult = Analyze-Dump -DumpPath $dump

            $blocked = $null
            $filters = [pscustomobject]@{ WdFilter=$false; CSAgent=$false; Hits=@() }

            if ($cdbResult.Success -eq $true -and $cdbResult.LogPath) {
                $blocked = Extract-TopBlockedThread -CdbLogPath $cdbResult.LogPath
                $fullText = ''
                try { $fullText = Get-Content $cdbResult.LogPath -Raw } catch { $fullText = '' }
                $filters = Correlate-FiltersFromText -Text ($blocked + "`n" + $fullText)
            }

            Write-AnalysisJson -DumpPath $dump -Tag $tag -CdbResult $cdbResult -BlockedThreadText $blocked -FilterCorrelation $filters
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