r"""Checkpoint and resume for ExpLoading runs.

Before launching each binary, writes its path to a checkpoint file.
After it completes (or is killed by timeout), marks it as done.
On restart after a crash/reboot, reads the checkpoint to find:
  - The binary that was running when the crash happened (the culprit)
  - All completed binaries (skip these)
  - The next binary to resume from

The checkpoint file is a simple line-oriented log on rengy:
  STARTED|<timestamp>|<path>
  DONE|<timestamp>|<path>|<exit_code>
  SKIPPED|<timestamp>|<path>|<reason>
  CRASHED|<timestamp>|<path>|reboot_detected

On startup, if the last line is STARTED (no matching DONE), that binary
crashed us. Add it to the blocklist and continue from the next one.
"""

CHECKPOINT_SCRIPT = r'''
# Checkpoint functions — dot-source this from the harness

$script:CheckpointFile = $null

function Initialize-Checkpoint {
    param([string]$Path)
    $script:CheckpointFile = $Path

    # If file exists, check for crash recovery
    if (Test-Path $Path) {
        $lines = Get-Content $Path
        $lastStarted = $null
        $completed = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        $blocked = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)

        foreach ($line in $lines) {
            $parts = $line -split '\|', 4
            if ($parts.Count -lt 3) { continue }
            $action = $parts[0]
            $path = $parts[2]

            switch ($action) {
                'STARTED'  { $lastStarted = $path }
                'DONE'     { $completed.Add($path) | Out-Null; $lastStarted = $null }
                'SKIPPED'  { $completed.Add($path) | Out-Null; $lastStarted = $null }
                'CRASHED'  { $blocked.Add($path) | Out-Null; $completed.Add($path) | Out-Null; $lastStarted = $null }
            }
        }

        # If last entry is STARTED with no DONE — that binary crashed us
        if ($lastStarted) {
            $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            Add-Content -Path $Path -Value ('CRASHED' + '|' + $ts + '|' + $lastStarted + '|reboot_detected')
            $blocked.Add($lastStarted) | Out-Null
            $completed.Add($lastStarted) | Out-Null
            [Console]::Error.WriteLine("CRASH RECOVERY: $lastStarted caused the last crash - added to blocklist")
        }

        return [PSCustomObject]@{
            Completed = $completed
            Blocked = $blocked
            CrashCulprit = $lastStarted
            TotalProcessed = $completed.Count
        }
    }

    # Fresh start
    $null = New-Item -Path $Path -ItemType File -Force
    return [PSCustomObject]@{
        Completed = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        Blocked = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase)
        CrashCulprit = $null
        TotalProcessed = 0
    }
}

function Write-CheckpointStarted {
    param([string]$BinaryPath)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $script:CheckpointFile -Value ('STARTED' + '|' + $ts + '|' + $BinaryPath)
}

function Write-CheckpointDone {
    param([string]$BinaryPath, [int]$ExitCode)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $script:CheckpointFile -Value ('DONE' + '|' + $ts + '|' + $BinaryPath + '|' + $ExitCode)
}

function Write-CheckpointSkipped {
    param([string]$BinaryPath, [string]$Reason)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $script:CheckpointFile -Value ('SKIPPED' + '|' + $ts + '|' + $BinaryPath + '|' + $Reason)
}

function Get-CheckpointSummary {
    if (-not (Test-Path $script:CheckpointFile)) {
        return [PSCustomObject]@{ Total=0; Done=0; Skipped=0; Crashed=0 }
    }

    $lines = Get-Content $script:CheckpointFile
    $done = ($lines | Where-Object { $_ -match '^DONE\|' }).Count
    $skipped = ($lines | Where-Object { $_ -match '^SKIPPED\|' }).Count
    $crashed = ($lines | Where-Object { $_ -match '^CRASHED\|' }).Count
    $total = $done + $skipped + $crashed

    return [PSCustomObject]@{
        Total = $total
        Done = $done
        Skipped = $skipped
        Crashed = $crashed
    }
}
'''


# Shutdown watchdog — runs as a background job, polls for pending
# shutdown and fires shutdown /a to abort it
WATCHDOG_SCRIPT = r'''
# Shutdown watchdog — run as a background job
# Polls every 2 seconds for pending shutdown and aborts it
# Also monitors for the harness process dying unexpectedly

param([int]$HarnessPID)

while ($true) {
    Start-Sleep -Seconds 2

    # Check for pending shutdown via registry
    $shutdownInProgress = $false
    try {
        $val = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'RebootRequired' -ErrorAction SilentlyContinue
        if ($val) { $shutdownInProgress = $true }
    } catch {}

    # Also try to detect via shutdown event
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1074; StartTime=(Get-Date).AddSeconds(-5)} -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($events) {
            # Someone initiated a shutdown — abort it
            & shutdown /a 2>$null
            $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            [Console]::Error.WriteLine("WATCHDOG [$ts]: Shutdown detected and aborted!")
        }
    } catch {}

    # Check if harness is still running
    if ($HarnessPID -gt 0) {
        $proc = Get-Process -Id $HarnessPID -ErrorAction SilentlyContinue
        if (-not $proc) {
            [Console]::Error.WriteLine("WATCHDOG: Harness process $HarnessPID died — exiting")
            break
        }
    }
}
'''


def build_checkpoint_script() -> str:
    return CHECKPOINT_SCRIPT


def build_watchdog_script() -> str:
    return WATCHDOG_SCRIPT
