r"""Merge all classification sources into a single run list.

Inputs:
  - rengy-inventory-full.json (all executables)
  - rengy-pe-classify.json (PE import scan results)
  - rengy-script-classify.json (script content scan results)
  - classify.py BLOCKED_NAMES / CAUTION_NAMES

Output: runlist.json — ordered list of binaries to ExpLoad, each tagged:
  tier: blocked | caution | safe
  reason: why it got that tier
  launch_method: name_only (System32) | quoted_path (elsewhere)
"""

BUILD_RUNLIST_SCRIPT = r'''
param(
    [string]$InventoryPath,
    [string]$PEClassifyPath,
    [string]$ScriptClassifyPath,
    [string]$OutputPath
)

$ErrorActionPreference = 'SilentlyContinue'

# --- Load inputs ---
$inventory = (Get-Content $InventoryPath -Raw | ConvertFrom-Json).executables
$peClassify = (Get-Content $PEClassifyPath -Raw | ConvertFrom-Json).results
$scriptClassify = (Get-Content $ScriptClassifyPath -Raw | ConvertFrom-Json).results

# --- Build lookup sets ---
$peBlockedPaths = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$peReasons = @{}
foreach ($r in $peClassify) {
    $apis = ($r.imports -join ', ')
    $reason = $r.reason
    if ($apis) { $reason = "$reason ($apis)" }
    $peBlockedPaths.Add($r.path) | Out-Null
    $peReasons[$r.path] = $reason
}

$scriptBlockedPaths = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$scriptReasons = @{}
foreach ($r in $scriptClassify) {
    $matches = ($r.matches -join ', ')
    $scriptBlockedPaths.Add($r.path) | Out-Null
    $scriptReasons[$r.path] = "SCRIPT_CONTENT ($matches)"
}

# --- Name blocklists ---
$blockedNames = @(
    'shutdown.exe','logoff.exe','slidetoshutdown.exe',
    'taskkill.exe','tskill.exe','kill.exe','pskill.exe','pskill64.exe',
    'format.com','diskpart.exe','cipher.exe',
    'bcdedit.exe','bcdboot.exe','bootsect.exe','bootcfg.exe',
    'reset.exe','resetengine.exe','sysreseterr.exe','systemreset.exe',
    'wpeutil.exe','wpeinit.exe','iisreset.exe','ntdsutil.exe',
    'pssuspend.exe','pssuspend64.exe','frida-kill.exe','gkill.exe',
    'passwordreset.bat','restartagent.exe'
)

$cautionNames = @(
    'mmc.exe','mstsc.exe','msconfig.exe','explorer.exe','taskmgr.exe',
    'regedit.exe','regedt32.exe','notepad.exe','write.exe','wordpad.exe',
    'calc.exe','charmap.exe','snippingtool.exe','mspaint.exe',
    'magnify.exe','narrator.exe','osk.exe','utilman.exe',
    'ping.exe','tracert.exe','nslookup.exe','telnet.exe','ftp.exe',
    'cmd.exe','powershell.exe','pwsh.exe','wscript.exe','cscript.exe',
    'bash.exe','wsl.exe','msiexec.exe','setup.exe','install.exe',
    'sc.exe','net.exe','net1.exe','wsreset.exe'
)

# Launchable extensions only
$launchable = @('.exe','.com','.bat','.cmd','.vbs','.vbe','.js','.jse',
                '.wsf','.wsh','.msc','.ps1','.cpl','.scr')

# System32 path for determining launch method
$sys32 = "$env:SystemRoot\System32"

# --- Classify each launchable binary ---
$runlist = [System.Collections.Generic.List[PSObject]]::new()

foreach ($exe in $inventory) {
    if ($exe.extension -notin $launchable) { continue }

    $tier = 'safe'
    $reason = ''
    $nameLower = $exe.name.ToLower()

    # Check name blocklist
    if ($nameLower -in $blockedNames) {
        $tier = 'blocked'
        $reason = "NAME_BLOCKLIST"
    }
    # Check PE imports
    elseif ($peBlockedPaths.Contains($exe.path)) {
        $peReason = $peReasons[$exe.path]
        if ($peReason -match 'NATIVE_SUBSYSTEM') {
            $tier = 'blocked'
            $reason = $peReason
        }
        elseif ($peReason -match 'Shutdown|ExitWindows|SetSuspendState|NtShutdown|NtSetSystemPower') {
            $tier = 'blocked'
            $reason = $peReason
        }
        elseif ($peReason -match 'FormatEx') {
            # FormatEx alone is usually string formatting, not disk format
            $tier = 'caution'
            $reason = $peReason
        }
    }
    # Check script content
    elseif ($scriptBlockedPaths.Contains($exe.path)) {
        $scrReason = $scriptReasons[$exe.path]
        if ($scrReason -match 'shutdown|Restart-Computer|Stop-Computer') {
            $tier = 'blocked'
            $reason = $scrReason
        } else {
            $tier = 'caution'
            $reason = $scrReason
        }
    }
    # Check name caution list
    elseif ($nameLower -in $cautionNames) {
        $tier = 'caution'
        $reason = "NAME_CAUTION"
    }

    # Determine launch method per ExpLoading technique
    $inSystem32 = $exe.directory -eq $sys32
    $launchMethod = if ($inSystem32) { 'name_only' } else { 'quoted_path' }
    $launchCmd = if ($inSystem32) {
        # Strip extension for System32 binaries
        [System.IO.Path]::GetFileNameWithoutExtension($exe.name)
    } else {
        "`"$($exe.path)`""
    }

    $runlist.Add([PSCustomObject]@{
        path = $exe.path
        name = $exe.name
        extension = $exe.extension
        directory = $exe.directory
        owner = $exe.owner
        tier = $tier
        reason = $reason
        launch_method = $launchMethod
        launch_cmd = $launchCmd
    })
}

# --- Summary ---
$tiers = $runlist | Group-Object tier
$summary = [PSCustomObject]@{
    total = $runlist.Count
    tiers = ($tiers | ForEach-Object { [PSCustomObject]@{ tier=$_.Name; count=$_.Count } })
    blocked_count = ($runlist | Where-Object { $_.tier -eq 'blocked' }).Count
    caution_count = ($runlist | Where-Object { $_.tier -eq 'caution' }).Count
    safe_count = ($runlist | Where-Object { $_.tier -eq 'safe' }).Count
}

[PSCustomObject]@{
    hostname = $env:COMPUTERNAME
    timestamp = (Get-Date -Format o)
    summary = $summary
    runlist = $runlist
} | ConvertTo-Json -Depth 4 -Compress | Out-File $OutputPath -Encoding UTF8

[Console]::Error.WriteLine("Runlist: $($summary.safe_count) safe, $($summary.caution_count) caution, $($summary.blocked_count) blocked (total $($summary.total))")
'''


def build_runlist_script() -> str:
    return BUILD_RUNLIST_SCRIPT
