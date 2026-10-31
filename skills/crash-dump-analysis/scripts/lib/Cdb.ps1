# cdb discovery, invocation and output parsing.

function Find-Cdb($Config) {
    $candidates = @()
    $configured = Expand-PathValue (Get-Cfg $Config 'debuggerPath' '')
    if ($configured) { $candidates += $configured }
    $candidates += @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\Debuggers\x64\cdb.exe",
        "$env:ProgramFiles\Windows Kits\10\Debuggers\x64\cdb.exe"
    )
    $onPath = Get-Command cdb.exe -ErrorAction SilentlyContinue
    if ($onPath) { $candidates += $onPath.Source }
    foreach ($candidate in $candidates) { if ($candidate -and (Test-Path -LiteralPath $candidate)) { return $candidate } }
    throw 'cdb.exe not found. Install "Debugging Tools for Windows" (Windows SDK) or set debuggerPath in the config.'
}

function Invoke-Cdb([string]$Cdb, [string]$Dump, [string]$SymbolPath, [string]$ImagePath, [string]$LogPath, [string[]]$Commands, [int]$TimeoutSeconds) {
    $argList = @('-z', "`"$Dump`"", '-y', "`"$SymbolPath`"", '-lines')
    if ($ImagePath) { $argList += @('-i', "`"$ImagePath`"") }
    $argList += @('-c', "`"$($Commands -join '; ')`"")
    $process = Start-Process -FilePath $Cdb -ArgumentList ($argList -join ' ') -NoNewWindow -PassThru `
        -RedirectStandardOutput $LogPath -RedirectStandardError "$LogPath.stderr"
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-Process -Id $process.Id -Force
        throw "cdb did not finish within $TimeoutSeconds s (log: $LogPath)."
    }
    $stderrPath = "$LogPath.stderr"
    if ((Test-Path -LiteralPath $stderrPath) -and (Get-Item -LiteralPath $stderrPath).Length -eq 0) { Remove-Item -LiteralPath $stderrPath -Force }
}

# Runs a command file (-cf), which avoids command-line quoting problems for long, structured queries.
function Invoke-CdbScript([string]$Cdb, [string]$Dump, [string]$SymbolPath, [string]$ImagePath, [string]$LogPath, [string]$CommandFile, [int]$TimeoutSeconds) {
    $argList = @('-z', "`"$Dump`"", '-y', "`"$SymbolPath`"", '-lines')
    if ($ImagePath) { $argList += @('-i', "`"$ImagePath`"") }
    $argList += @('-cf', "`"$CommandFile`"")
    $process = Start-Process -FilePath $Cdb -ArgumentList ($argList -join ' ') -NoNewWindow -PassThru `
        -RedirectStandardOutput $LogPath -RedirectStandardError "$LogPath.stderr"
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-Process -Id $process.Id -Force
        throw "cdb did not finish within $TimeoutSeconds s (log: $LogPath)."
    }
    $stderrPath = "$LogPath.stderr"
    if ((Test-Path -LiteralPath $stderrPath) -and (Get-Item -LiteralPath $stderrPath).Length -eq 0) { Remove-Item -LiteralPath $stderrPath -Force }
}

function Split-CdbSections([string[]]$Lines) {
    $sections = @{}
    $current = $null
    foreach ($line in $Lines) {
        if ($line -match '^<<<SECTION:(\w+)>>>\s*$') {
            $current = $Matches[1]
            $sections[$current] = New-Object Collections.Generic.List[string]
            continue
        }
        if ($current) { $sections[$current].Add($line) }
    }
    return $sections
}

function Get-Section([hashtable]$Sections, [string]$Name) {
    if ($Sections.ContainsKey($Name)) { return @($Sections[$Name]) }
    return @()
}

function ConvertFrom-CdbStack([string[]]$Lines) {
    $regex = '^(?<num>[0-9a-f]{2,})\s+(?:(?<sp>[0-9a-f]{8}(?:`[0-9a-f]{8})?)\s+(?<ret>[0-9a-f]{8}(?:`[0-9a-f]{8})?)|\(Inline Function\)\s+[-`]+)\s+(?<site>.+?)(?:\s+\[(?<file>[^\]]+?) @ (?<line>\d+)\])?\s*$'
    $frames = @()
    foreach ($line in $Lines) {
        if ($line -notmatch $regex) { continue }
        $m = $Matches.Clone()
        $site = $m['site']
        $module = if ($site -match '^([^!+\s]+)[!+]') { $Matches[1] } else { $null }
        $function = $site -replace '^[^!]+!', '' -replace '\+0x[0-9a-f]+$', ''
        $frames += [pscustomobject][ordered]@{
            index      = [Convert]::ToInt32([string]$m['num'], 16)
            inline     = -not $m['sp']
            module     = $module
            function   = $function
            callSite   = $site
            retAddr    = if ($m['ret']) { '0x' + ($m['ret'] -replace '`', '') } else { $null }
            sourceFile = if ($m['file']) { $m['file'] } else { $null }
            sourceLine = if ($m['line']) { [int]$m['line'] } else { $null }
            repoPath   = $null
            buildSnippet = $null
            functionFoundAtBuildCommit = $null
            thirdParty = $null
        }
    }
    return $frames
}

# Symbol-independent frame addresses (module+RVA) from the exception address and the return addresses of 'kn'.
# Used instead of function names when the PDB is not verified: export-symbol names are nearest exports, not functions.
function Get-RawStack($Frames, [string]$ExceptionAddress, $Modules) {
    $ranges = @($Modules | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Base = [Convert]::ToUInt64(($_.Base -replace '^0x', ''), 16); Size = [uint64]$_.Size } })
    $nextIp = if ($ExceptionAddress) { [Convert]::ToUInt64(($ExceptionAddress -replace '^0x', ''), 16) } else { $null }
    $raw = @()
    foreach ($f in $Frames) {
        $ip = $nextIp
        if (-not $f.inline) { $nextIp = if ($f.retAddr) { [Convert]::ToUInt64(($f.retAddr -replace '^0x', ''), 16) } else { $null } }
        $text = $null
        if ($null -ne $ip) {
            $mod = $ranges | Where-Object { $ip -ge $_.Base -and $ip -lt ($_.Base + $_.Size) } | Select-Object -First 1
            $text = if ($mod) { '{0}+0x{1:x}' -f $mod.Name, ($ip - $mod.Base) } else { '0x{0:x}' -f $ip }
        }
        $raw += [pscustomobject][ordered]@{ index = $f.index; inline = $f.inline; address = $text }
    }
    return $raw
}
