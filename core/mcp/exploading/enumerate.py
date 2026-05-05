r"""Enumerate ALL executables on a Windows system at SYSTEM level.

Full disk sweep across every drive for every executable extension.
Augmented with registry sources (App Paths, COM, Services, Tasks,
Shell Extensions, KnownDLLs, WMI Providers, assoc/ftype).

Runs via PsExec64 -s for SYSTEM/TrustedInstaller access.
"""

ENUMERATE_SCRIPT = r'''
$ErrorActionPreference = 'SilentlyContinue'

$results = [System.Collections.Generic.List[PSObject]]::new()
$seen = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)

function Add-Entry {
    param([string]$Path, [string]$Source)
    if (-not $Path) { return }
    $Path = $Path.Trim('"',' ')
    if (-not $Path -or $Path.Length -lt 3) { return }
    if (-not (Test-Path $Path -PathType Leaf)) { return }
    try { $resolved = (Resolve-Path $Path).Path } catch { return }
    if (-not $seen.Add($resolved)) { return }

    $owner = $null
    try { $owner = (Get-Acl $resolved).Owner } catch {}

    $sz = 0
    try { $sz = [math]::Round((Get-Item $resolved).Length / 1024, 1) } catch {}

    $results.Add([PSCustomObject]@{
        path      = $resolved
        name      = [System.IO.Path]::GetFileName($resolved)
        extension = [System.IO.Path]::GetExtension($resolved).ToLower()
        directory = [System.IO.Path]::GetDirectoryName($resolved)
        source    = $Source
        owner     = $owner
        size_kb   = $sz
    })
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$runningAs = $identity.Name
$isSystem = $identity.IsSystem

# --- Executable extensions: PATHEXT + loadable types ---
$pathext = ($env:PATHEXT -split ';') | Where-Object { $_ }
if (-not $pathext) {
    $pathext = @('.COM','.EXE','.BAT','.CMD','.VBS','.VBE','.JS','.JSE','.WSF','.WSH','.MSC','.PS1')
}
$loadable = @('.DLL','.CPL','.SCR','.DRV','.OCX','.AX','.TSP','.SYS')
$allExts = (($pathext + $loadable) | ForEach-Object { $_.ToLower() }) | Select-Object -Unique

# --- FULL DISK SWEEP: every fixed/removable drive ---
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -ne $null } |
    Select-Object -ExpandProperty Root

[Console]::Error.WriteLine("Scanning drives: $($drives -join ', ')")
[Console]::Error.WriteLine("Extensions: $($allExts -join ', ')")

$excludeDirs = @(
    "$env:SystemDrive\Users",
    "$env:SystemDrive\Tools",
    "$env:SystemDrive\Temp",
    "$env:SystemDrive\`$Recycle.Bin"
)

$diskCount = 0
foreach ($drive in $drives) {
    [Console]::Error.WriteLine("Scanning $drive ...")
    foreach ($ext in $allExts) {
        Get-ChildItem -Path $drive -Filter "*$ext" -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $dominated = $false
                foreach ($ex in $excludeDirs) {
                    if ($_.FullName.StartsWith($ex, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $dominated = $true; break
                    }
                }
                -not $dominated
            } |
            ForEach-Object {
                Add-Entry $_.FullName "DISK:$drive"
                $diskCount++
            }
    }
}
[Console]::Error.WriteLine("Disk sweep found $diskCount files ($($seen.Count) unique)")

# --- Registry: App Paths ---
foreach ($root in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths'
)) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        $default = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).'(Default)'
        if ($default) {
            $expanded = [System.Environment]::ExpandEnvironmentVariables($default).Trim('"')
            Add-Entry $expanded "APPPATH:$($_.PSChildName)"
        }
    }
}

# --- Registry: COM servers ---
foreach ($root in @('HKLM:\SOFTWARE\Classes\CLSID','HKCU:\SOFTWARE\Classes\CLSID')) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($subkey in @('InprocServer32','LocalServer32')) {
            $sk = Join-Path $_.PSPath $subkey
            if (Test-Path $sk) {
                $val = (Get-ItemProperty $sk -ErrorAction SilentlyContinue).'(Default)'
                if ($val) {
                    $expanded = [System.Environment]::ExpandEnvironmentVariables($val)
                    $expanded = ($expanded -replace '"','').Split(' ')[0]
                    Add-Entry $expanded "COM:$($_.PSChildName)\$subkey"
                }
            }
        }
    } | Out-Null
}

# --- Registry: Services ---
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.ImagePath } | ForEach-Object {
    $img = [System.Environment]::ExpandEnvironmentVariables($_.ImagePath)
    if ($img -match '^"([^"]+)"') { $p = $Matches[1] }
    elseif ($img -match '^(\S+\.\w{2,3})') { $p = $Matches[1] }
    else { return }
    Add-Entry $p "SERVICE:$($_.PSChildName)"
} | Out-Null

# --- Scheduled Tasks ---
$tasks = schtasks /query /fo CSV /v 2>&1 | ConvertFrom-Csv -ErrorAction SilentlyContinue
if ($tasks) {
    foreach ($t in $tasks) {
        $action = $t.'Task To Run'
        if (-not $action -or $action -eq 'N/A') { continue }
        if ($action -match '^"([^"]+)"') { $p = $Matches[1] }
        elseif ($action -match '^(\S+\.\w{2,3})') { $p = $Matches[1] }
        else { continue }
        Add-Entry ([System.Environment]::ExpandEnvironmentVariables($p)) "SCHTASK:$($t.TaskName)"
    }
}

# --- File associations (assoc + ftype) ---
$assocMap = @{}
cmd /c assoc 2>&1 | ForEach-Object {
    if ($_ -match '^(\.\w+)=(.+)$') { $assocMap[$Matches[1].ToLower()] = $Matches[2] }
}
$ftypeMap = @{}
cmd /c ftype 2>&1 | ForEach-Object {
    if ($_ -match '^([^=]+)=(.+)$') { $ftypeMap[$Matches[1]] = $Matches[2] }
}
foreach ($ext in $assocMap.Keys) {
    $cmdLine = $ftypeMap[$assocMap[$ext]]
    if (-not $cmdLine) { continue }
    if ($cmdLine -match '^"([^"]+)"') { $p = $Matches[1] }
    elseif ($cmdLine -match '^(\S+)') { $p = $Matches[1] }
    else { continue }
    Add-Entry ([System.Environment]::ExpandEnvironmentVariables($p)) "ASSOC:$ext"
}

# --- KnownDLLs ---
$kd = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
if (Test-Path $kd) {
    $props = Get-ItemProperty $kd -ErrorAction SilentlyContinue
    foreach ($name in $props.PSObject.Properties.Name) {
        if ($name -notmatch '^PS' -and $props.$name) {
            Add-Entry "$env:SystemRoot\System32\$($props.$name)" "KNOWNDLL:$name"
        }
    }
}

# --- Shell extensions ---
foreach ($root in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'
)) {
    if (-not (Test-Path $root)) { continue }
    $p2 = Get-ItemProperty $root -ErrorAction SilentlyContinue
    if ($p2) {
        foreach ($name in $p2.PSObject.Properties.Name) {
            if ($name -match '^\{') {
                $clsid = "HKLM:\SOFTWARE\Classes\CLSID\$name\InprocServer32"
                if (Test-Path $clsid) {
                    $val = (Get-ItemProperty $clsid -ErrorAction SilentlyContinue).'(Default)'
                    if ($val) {
                        $expanded = [System.Environment]::ExpandEnvironmentVariables($val)
                        $expanded = ($expanded -replace '"','').Split(' ')[0]
                        Add-Entry $expanded "SHELLEXT:$name"
                    }
                }
            }
        }
    }
}

# --- Summary ---
$summary = [PSCustomObject]@{
    total       = $results.Count
    running_as  = $runningAs
    is_system   = $isSystem
    drives      = $drives
    pathext     = $pathext
    assoc_count = $assocMap.Count
    sources     = ($results | Group-Object { ($_.source -split ':')[0] } |
        ForEach-Object { [PSCustomObject]@{ source=$_.Name; count=$_.Count } })
    extensions  = ($results | Group-Object extension | Sort-Object Count -Descending |
        ForEach-Object { [PSCustomObject]@{ ext=$_.Name; count=$_.Count } })
    owners      = ($results | Where-Object { $_.owner } | Group-Object owner |
        Sort-Object Count -Descending | Select-Object -First 15 |
        ForEach-Object { [PSCustomObject]@{ owner=$_.Name; count=$_.Count } })
}

[PSCustomObject]@{
    hostname=$env:COMPUTERNAME; timestamp=(Get-Date -Format o);
    summary=$summary; executables=$results
} | ConvertTo-Json -Depth 5 -Compress
'''


def build_enumerate_command() -> str:
    return ENUMERATE_SCRIPT
