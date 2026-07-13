# Process2Thread

## Overview
This project contains a PowerShell-based monitoring utility that watches running processes for UI hangs and captures diagnostic artifacts when a hang is suspected. The main script, AutoCaptureAnalyze_Dump_V48.ps1, samples process state over time, looks for a non-responsive UI process, and then collects a dump plus a debugger log for later analysis.

## What the script does
The script performs the following workflow:

1. Creates an output folder structure under TierB_Output.
2. Starts a continuous monitoring loop.
3. Captures a snapshot of all currently running processes.
4. Waits for a short observation window.
5. Captures a second snapshot and compares it with the first.
6. If a process appears to be hung (for example, it is no longer responding and its CPU activity is effectively idle), it:
   - logs the event,
   - creates a dump file with ProcDump,
   - runs the Windows debugger (cdb.exe) against the dump,
   - parses the resulting thread stack information,
   - writes the result to the output folder.

## Output files
The script writes results into the following locations:

- TierB_Output/AutoCapture.log - main execution log
- TierB_Output/Dumps/ - dump and debugger log files

## Prerequisites
To run the script successfully, you will typically need:

- Windows PowerShell 5.1 or PowerShell 7+
- ProcDump available as procdump.exe in the project folder or on the system PATH
- cdb.exe from the Windows Debugging Tools
- Appropriate permissions to inspect target processes and create dumps

## How to run
From PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\AutoCaptureAnalyze_Dump_V48.ps1
```

The script runs continuously until you stop it with Ctrl+C.

## Notes
- This script is intended for diagnostic and troubleshooting scenarios.
- It may capture data for processes that are not directly related to your current issue, depending on the monitored state.
- Because it runs in a loop, it is best used in a controlled environment where you understand the process behavior being monitored.

## Suggested improvements
The current script is functional, but the following improvements would make it more robust:

1. Add parameters for observation window, cooldown, output path, and process filtering.
2. Improve error handling and logging around ProcDump and cdb failures.
3. Add support for optional process name filtering and duplicate suppression to reduce noise.
