r"""ExpLoading harness — Procmon-based, resource-aware.

Every binary: cmd.exe /c "C:\full\path\to\binary" from m00 as CWD.
Procmon captures EVERYTHING — all NAME_NOT_FOUND in m00.

Procmon runs per batch (~200 binaries):
  1. Kill all Procmon (taskkill, verify zero)
  2. Start ONE Procmon with backing file
  3. Run all binaries in the batch (no per-binary Procmon management)
  4. Stop Procmon (taskkill, verify zero)
  5. Export PML to CSV
  6. Parse CSV for NAME_NOT_FOUND in m00
  7. Delete PML + CSV
  8. Resource check — throttle if >80%
  9. Next batch

Between binaries: clean m00, archive drops. No Procmon touch.
"""

HARNESS_SCRIPT = r'''
param(
    [string]$RunlistPath,
    [string]$CheckpointPath,
    [string]$OutputDir,
    [string]$Tier = 'safe',
    [int]$TimeoutSec = 5,
    [int]$BatchSize = 200,
    [int]$CpuThreshold = 80,
    [int]$RamThreshold = 80,
    [int]$ResumeThreshold = 60
)

$ErrorActionPreference = 'SilentlyContinue'

$m00 = "C:\Users\agent\Desktop\m00"
$procmon = "C:\Tools\sysinternals\Procmon64.exe"
$resultsFile = Join-Path $OutputDir "results.jsonl"
$resourceLog = Join-Path $OutputDir "resource.log"
$m00re = [regex]::Escape($m00)

if (-not (Test-Path $m00)) { New-Item -Path $m00 -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }

# --- Resource functions ---
function Get-ResourceUsage {
    $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    $os = Get-CimInstance Win32_OperatingSystem
    $ramTotal = $os.TotalVisibleMemorySize
    $ramFree = $os.FreePhysicalMemory
    $ramPct = [math]::Round((($ramTotal - $ramFree) / $ramTotal) * 100, 1)
    return [PSCustomObject]@{ Cpu = [math]::Round($cpu, 1); Ram = $ramPct; RamFreeMB = [math]::Round($ramFree / 1024, 0) }
}

function Log($msg) {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $r = Get-ResourceUsage
    $line = "$ts | CPU:$($r.Cpu)% RAM:$($r.Ram)% Free:$($r.RamFreeMB)MB | $msg"
    Add-Content -Path $resourceLog -Value $line
    [Console]::Error.WriteLine($line)
}

function Wait-ForResources {
    Log "THROTTLE: pausing..."
    Kill-AllProcmon
    $waited = 0
    do {
        Start-Sleep -Seconds 30
        $waited += 30
        $r = Get-ResourceUsage
        Log "WAITING: CPU=$($r.Cpu)% RAM=$($r.Ram)% (${waited}s)"
    } while (($r.Cpu -gt $ResumeThreshold -or $r.Ram -gt $ResumeThreshold) -and $waited -lt 600)
    Log "RESUMED"
}

# --- Procmon functions ---
function Kill-AllProcmon {
    taskkill /F /IM Procmon64.exe 2>$null
    Start-Sleep -Seconds 2
    taskkill /F /IM Procmon64.exe 2>$null
    Start-Sleep -Seconds 1
    $count = (Get-Process Procmon64 -ErrorAction SilentlyContinue).Count
    if ($count -gt 0) {
        Get-Process Procmon64 | Stop-Process -Force
        Start-Sleep -Seconds 2
    }
}

function Start-Procmon([string]$pmlPath) {
    Kill-AllProcmon
    Remove-Item $pmlPath -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath $procmon -ArgumentList "/Quiet","/Minimized","/BackingFile",$pmlPath,"/AcceptEula" -Wait:$false
    Start-Sleep -Seconds 4
    $count = (Get-Process Procmon64 -ErrorAction SilentlyContinue).Count
    return $count
}

function Stop-Procmon {
    Kill-AllProcmon
}

# --- Init ---
. C:\Users\agent\checkpoint.ps1
$state = Initialize-Checkpoint -Path $CheckpointPath
Log "START: checkpoint=$($state.TotalProcessed) processed"
if ($state.CrashCulprit) { Log "CRASH RECOVERY: $($state.CrashCulprit)" }
$runtimeBlocked = $state.Blocked

$runlist = (Get-Content $RunlistPath -Raw | ConvertFrom-Json).runlist
$targets = $runlist | Where-Object { $_.tier -eq $Tier }
Log "Targets: $($targets.Count) ($Tier tier)"

$watchdogJob = Start-Job -FilePath C:\Users\agent\watchdog.ps1 -ArgumentList $PID

$remaining = [System.Collections.Generic.List[PSObject]]::new()
foreach ($t in $targets) {
    if (-not $state.Completed.Contains($t.path) -and -not $runtimeBlocked.Contains($t.path)) {
        $remaining.Add($t)
    }
}
Log "Remaining: $($remaining.Count)"

Kill-AllProcmon

$totalProcessed = 0
$totalHits = 0
$batchNum = 0

for ($i = 0; $i -lt $remaining.Count; $i += $BatchSize) {
    $batchNum++
    $batchEnd = [math]::Min($i + $BatchSize, $remaining.Count)
    $batch = $remaining[$i..($batchEnd - 1)]

    Log "=== Batch $batchNum ($($batch.Count) binaries) ==="

    # Resource check before batch
    $r = Get-ResourceUsage
    if ($r.Cpu -gt $CpuThreshold -or $r.Ram -gt $RamThreshold) {
        Wait-ForResources
    }

    $pmlFile = Join-Path $OutputDir "batch_$batchNum.pml"
    $csvFile = Join-Path $OutputDir "batch_$batchNum.csv"

    # Clean m00
    Get-ChildItem $m00 -Force | Remove-Item -Recurse -Force

    # Start Procmon for this batch
    $pmCount = Start-Procmon $pmlFile
    if ($pmCount -eq 0) {
        Log "ERROR: Procmon failed to start, retrying..."
        Start-Sleep -Seconds 3
        $pmCount = Start-Procmon $pmlFile
        if ($pmCount -eq 0) {
            Log "ERROR: Procmon failed twice, skipping batch"
            continue
        }
    }
    Log "Procmon running ($pmCount instance(s))"

    # Track launches
    $launchLog = [System.Collections.Generic.List[PSObject]]::new()
    $batchArtifacts = Join-Path $OutputDir "artifacts\batch_$batchNum"
    New-Item -Path $batchArtifacts -ItemType Directory -Force | Out-Null

    # --- Run each binary ---
    foreach ($target in $batch) {
        $binPath = $target.path
        $binName = $target.name

        if (-not (Test-Path $binPath)) {
            Write-CheckpointSkipped -BinaryPath $binPath -Reason "file_not_found"
            continue
        }

        $beforeFiles = @(Get-ChildItem $m00 -Force | Select-Object -ExpandProperty FullName)
        Write-CheckpointStarted -BinaryPath $binPath

        # === EXPLOADING ===
        $exitCode = -1
        $cmdPid = -1
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = "cmd.exe"
            $psi.Arguments = "/c `"$binPath`""
            $psi.WorkingDirectory = $m00
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true

            $proc = [System.Diagnostics.Process]::Start($psi)
            $cmdPid = $proc.Id

            if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
                try {
                    Get-CimInstance Win32_Process -Filter "ParentProcessId = $($proc.Id)" -ErrorAction SilentlyContinue |
                        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
                    $proc.Kill()
                } catch {}
                $exitCode = -999
            } else {
                $exitCode = $proc.ExitCode
            }
        } catch {
            $exitCode = -998
        }

        # Archive drops
        $afterFiles = @(Get-ChildItem $m00 -Force | Select-Object -ExpandProperty FullName)
        $newFiles = @($afterFiles | Where-Object { $_ -notin $beforeFiles })
        $droppedNames = @()
        if ($newFiles.Count -gt 0) {
            $safeName = ($binName -replace '[\\/:*?"<>|]', '_')
            $artifactDir = Join-Path $batchArtifacts $safeName
            New-Item -Path $artifactDir -ItemType Directory -Force | Out-Null
            foreach ($f in $newFiles) {
                $droppedNames += [System.IO.Path]::GetFileName($f)
                Move-Item -Path $f -Destination $artifactDir -Force -ErrorAction SilentlyContinue
            }
        }

        Get-ChildItem $m00 -Force | Remove-Item -Recurse -Force

        $launchLog.Add([PSCustomObject]@{
            path = $binPath; name = $binName; pid = $cmdPid
            exit_code = $exitCode; dropped = $droppedNames
        })

        Write-CheckpointDone -BinaryPath $binPath -ExitCode $exitCode
        $totalProcessed++
    }

    # --- Stop Procmon and parse ---
    Log "Stopping Procmon..."
    Stop-Procmon

    $batchHits = 0
    if (Test-Path $pmlFile) {
        Log "Exporting CSV..."
        $exportProc = Start-Process -FilePath $procmon -ArgumentList "/OpenLog",$pmlFile,"/SaveAs",$csvFile,"/AcceptEula" -PassThru -NoNewWindow
        # Wait for export — no fixed timeout. Only kill if resources go critical.
        while (-not $exportProc.HasExited) {
            Start-Sleep -Seconds 10
            $r = Get-ResourceUsage
            if ($r.Ram -gt 90) {
                Log "Export killed - RAM at $($r.Ram)%"
                taskkill /F /IM Procmon64.exe 2>$null
                break
            }
        }
        Kill-AllProcmon
        Start-Sleep -Seconds 3
        Kill-AllProcmon

        if (Test-Path $csvFile) {
            $csvSize = [math]::Round((Get-Item $csvFile).Length / 1MB, 1)
            Log "Parsing CSV ($csvSize MB)..."

            $hitsByBinary = @{}

            $fs = [System.IO.FileStream]::new($csvFile, 'Open', 'Read', 'ReadWrite')
            $sr = [System.IO.StreamReader]::new($fs)
            $null = $sr.ReadLine()

            while (-not $sr.EndOfStream) {
                $line = $sr.ReadLine()
                if ($line -match 'NAME NOT FOUND' -and $line -match $m00re) {
                    if ($line -match '"([^"]+)","(\d+)","([^"]+)","([^"]+)"') {
                        $procName = $Matches[1]
                        $wantedPath = $Matches[4]
                        $wantedFile = [System.IO.Path]::GetFileName($wantedPath)
                        if (-not $wantedFile) { continue }

                        $binaryKey = $procName
                        if (-not $hitsByBinary.ContainsKey($binaryKey)) {
                            $hitsByBinary[$binaryKey] = [System.Collections.Generic.HashSet[string]]::new(
                                [System.StringComparer]::OrdinalIgnoreCase)
                        }
                        $hitsByBinary[$binaryKey].Add($wantedFile) | Out-Null
                    }
                }
            }
            $sr.Close(); $fs.Close()

            foreach ($procName in $hitsByBinary.Keys) {
                $wants = $hitsByBinary[$procName]
                $info = $launchLog | Where-Object {
                    $_.name -eq $procName -or
                    $_.name -eq "$procName.exe" -or
                    [System.IO.Path]::GetFileNameWithoutExtension($_.name) -eq $procName
                } | Select-Object -First 1

                $result = [PSCustomObject]@{
                    binary_path = if ($info) { $info.path } else { $procName }
                    binary_name = if ($info) { $info.name } else { $procName }
                    exit_code = if ($info) { $info.exit_code } else { -1 }
                    name_not_found = @($wants)
                    count = $wants.Count
                    dropped_files = if ($info) { @($info.dropped) } else { @() }
                    process_name = $procName
                    batch = $batchNum
                }
                ($result | ConvertTo-Json -Compress) | Add-Content -Path $resultsFile
                $batchHits++
            }

            Remove-Item $csvFile -Force -ErrorAction SilentlyContinue
        }
        Remove-Item $pmlFile -Force -ErrorAction SilentlyContinue
    }

    $totalHits += $batchHits
    Log "Batch $batchNum done: $($batch.Count) binaries, $batchHits hits, total $totalProcessed/$totalHits"

    # Resource check after batch
    $r = Get-ResourceUsage
    if ($r.Cpu -gt $CpuThreshold -or $r.Ram -gt $RamThreshold) {
        Wait-ForResources
    }
}

Kill-AllProcmon
Stop-Job $watchdogJob -ErrorAction SilentlyContinue
Remove-Job $watchdogJob -ErrorAction SilentlyContinue

$summary = Get-CheckpointSummary
[PSCustomObject]@{
    hostname = $env:COMPUTERNAME
    timestamp = (Get-Date -Format o)
    tier = $Tier; m00 = $m00; method = "Procmon"
    timeout_sec = $TimeoutSec; batch_size = $BatchSize
    total_processed = $totalProcessed; total_hits = $totalHits
    batches = $batchNum; checkpoint = $summary
} | ConvertTo-Json -Depth 4 | Out-File (Join-Path $OutputDir "exploading-summary-$Tier.json") -Encoding UTF8

Log "COMPLETE: $totalProcessed processed, $totalHits hits in $batchNum batches"
'''


def build_harness_script() -> str:
    return HARNESS_SCRIPT
