<#
.SYNOPSIS
Runs read-only debugger commands against a dump of a finished collector run (cdb for Windows minidumps, gdb in WSL
for Linux cores) with the verified symbols of that run. Use it when the report/digest does not contain a fact you need.

.DESCRIPTION
The dump, symbol path, image path, sysroot and debug file come from summary.json, so no debugger command line has to be
built by hand. -Frame selects a stack frame first (decimal frame number as shown in the report and digest).
Separate several debugger commands with ';' in one -Command string (works for cdb and gdb).
Prints the command output between QUERY_OUTPUT_BEGIN and QUERY_OUTPUT_END, then QUERY_LOG=<full log>.

Refused: dumps without verified symbols (BLOCKED) and commands that could run programs or write files
(cdb: .shell, .create, .attach, .writemem, .dump, .load...; gdb: shell, !, pipe, python, source, dump...).

.EXAMPLE
.\Invoke-DumpQuery.ps1 -SummaryJson C:\runs\summary.json -Frame 5 -Command 'dx -r2 this'
.EXAMPLE
.\Invoke-DumpQuery.ps1 -SummaryJson C:\runs\summary.json -Dump 2 -Frame 3 -Command 'info locals; p *this'
.EXAMPLE
.\Invoke-DumpQuery.ps1 -SummaryJson C:\runs\summary.json -Command '~* kn 20' -Filter 'inmation!'
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][string]$SummaryJson,
    [Parameter(Mandatory = $true)][string[]]$Command,
    # Dump file name, full path, or number (1 = first dump of the run). Default: the first dump with verified symbols.
    [string]$Dump,
    # Frame number (decimal) as in the report; -1 = no frame selection.
    [int]$Frame = -1,
    # Regular expression: print only matching output lines.
    [string]$Filter,
    [int]$MaxLines = 300,
    [string]$ConfigPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'lib\Common.ps1')
. (Join-Path $PSScriptRoot 'lib\Cdb.ps1')
. (Join-Path $PSScriptRoot 'lib\Frames.ps1')
. (Join-Path $PSScriptRoot 'lib\LinuxCore.ps1')

$summary = Get-Content -LiteralPath $SummaryJson -Raw -Encoding UTF8 | ConvertFrom-Json
$dumps = @($summary.dumps | ForEach-Object { $_ })
if ($dumps.Count -eq 0) { throw "No dumps in $SummaryJson." }

function Get-Field($Object, [string]$Path) {
    $value = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $value) { return $null }
        $p = $value.PSObject.Properties[$part]
        $value = if ($p) { $p.Value } else { $null }
    }
    return $value
}

$entry = $null
if (-not $Dump) { $entry = $dumps | Where-Object { Get-Field $_ 'symbols.trusted' } | Select-Object -First 1 }
elseif ($Dump -match '^\d+$') { $n = [int]$Dump; if ($n -ge 1 -and $n -le $dumps.Count) { $entry = $dumps[$n - 1] } }
else { $entry = $dumps | Where-Object { (Get-Field $_ 'dump.path') -eq $Dump -or [IO.Path]::GetFileName([string](Get-Field $_ 'dump.path')) -eq $Dump } | Select-Object -First 1 }
if (-not $entry) {
    $list = for ($i = 0; $i -lt $dumps.Count; $i++) { "$($i + 1) = $([IO.Path]::GetFileName([string](Get-Field $dumps[$i] 'dump.path')))$(if (Get-Field $dumps[$i] 'blocked') { ' (BLOCKED)' })" }
    throw "Dump '$Dump' not found in the run. Dumps: $($list -join '; ')."
}
$dumpPath = [string](Get-Field $entry 'dump.path')
if ((Get-Field $entry 'blocked') -or -not (Get-Field $entry 'symbols.trusted')) {
    throw "$([IO.Path]::GetFileName($dumpPath)) has no verified symbols (BLOCKED): debugger output would show wrong function names. Supply the matching symbol file and rerun the collector."
}
$log = [string](Get-Field $entry 'files.cdbLog')
if (-not $log) { throw "The run has no debugger log for $dumpPath (the dump was not analyzed)." }
$dumpOut = Split-Path $log -Parent
$linux = (Get-Field $entry 'dump.platform') -eq 'linux'

$windowsBlocked = '^\s*(\.shell|\.create|\.attach|\.writemem|\.dump|\.load|\.loadby|\.logopen|\.logappend|\.kill|\.detach|\.restart|\.opendump|\.server|\.send_file|\.tlist|\.cordll|\.extpath|\.sympath|\.exepath|\.srcpath|\.symfix|\$\$?><|\$\$?<|\$\$>a<)'
$linuxBlocked = '^\s*(shell\b|!|pipe\b|\||python|py\b|pi\b|guile|gu\b|source\b|dump\b|append\b|restore\b|compile\b|make\b|run\b|r\b|start\b|starti\b|attach\b|kill\b|set\s+logging|cd\b|file\b|core-file\b|exec-file\b|symbol-file\b|add-symbol-file|define\b|document\b|target\b|remote\b)'
# One command per line; ';' separates commands (cdb understands it natively, gdb gets one line per command).
$commands = @($Command | ForEach-Object { $_ -split "`r?`n" } | ForEach-Object { if ($linux) { $_ -split ';(?=(?:[^"]*"[^"]*")*[^"]*$)' } else { $_ } } | Where-Object { $_.Trim() } | ForEach-Object { $_.Trim() })
foreach ($c in $commands) {
    $pieces = if ($linux) { @($c) } else { @($c -split '[;{}]') }
    if (@($pieces | Where-Object { $_ -match $(if ($linux) { $linuxBlocked } else { $windowsBlocked }) }).Count) {
        throw "Command refused (not read-only or runs programs): $c"
    }
}

$configInfo = Read-AnalyzerConfig $ConfigPath $PSScriptRoot
$config = $configInfo.Config
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$queryLog = Join-Path $dumpOut "query-$stamp.log"
$marker = '<<<QUERY_OUTPUT>>>'

if ($linux) {
    $problem = Test-WslGdb $config
    if ($problem) { throw $problem }
    $base = Join-Path $dumpOut 'gdb.cmd'
    if (-not (Test-Path -LiteralPath $base)) { throw "gdb.cmd of the run not found: $base" }
    $setup = New-Object Collections.Generic.List[string]
    foreach ($line in [IO.File]::ReadAllLines($base)) { $setup.Add($line); if ($line -like 'core-file *') { break } }
    # One command file per command: gdb stops a file at its first error but runs the next file.
    $chunks = New-Object Collections.Generic.List[object]
    $chunks.Add([string[]]$setup)
    $first = @("echo $marker\n")
    if ($Frame -ge 0) { $first += "frame $Frame" }
    $chunks.Add([string[]]$first)
    foreach ($c in $commands) { $chunks.Add([string[]]@($c)) }
    $run = Invoke-GdbChunks $config $chunks.ToArray() $dumpOut "query-$stamp"
    Set-Content -LiteralPath $queryLog -Value $run.Lines -Encoding UTF8
    $lines = @($run.Lines)
}
else {
    $cdb = Find-Cdb $config
    $cmd = New-Object Collections.Generic.List[string]
    $cmd.Add('.ecxr')
    if ($Frame -ge 0) { $cmd.Add(".frame 0n$Frame") }
    $cmd.Add(".echo $marker")
    foreach ($c in $commands) { $cmd.Add($c) }
    $cmd.Add('q')
    $cmdFile = Join-Path $dumpOut "query-$stamp.cdb.txt"
    [IO.File]::WriteAllText($cmdFile, (($cmd -join "`r`n") + "`r`n"), [Text.UTF8Encoding]::new($false))
    Invoke-CdbScript $cdb $dumpPath ([string](Get-Field $entry 'symbols.cdbSymbolPath')) ([string](Get-Field $entry 'symbols.cdbImagePath')) $queryLog $cmdFile ([int](Get-Cfg $config 'cdbTimeoutSeconds' 900))
    $lines = @(Get-Content -LiteralPath $queryLog -Encoding UTF8)
}

$start = -1
for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match "^\s*$([regex]::Escape($marker))\s*$") { $start = $i + 1; break } }
$output = if ($start -ge 0) { @($lines[$start..($lines.Count - 1)]) } else { @($lines) }
$output = @($output | Where-Object { $_ -notmatch '^(quit:|0:\d+> q$|NatVis script unloaded)' -and $_ -notmatch '^\[New LWP \d+\]$' })
if ($Filter) { $output = @($output | Where-Object { $_ -match $Filter }) }
Write-Host "QUERY_DUMP=$dumpPath"
if ($start -lt 0) { Write-Host 'QUERY_WARNING=The debugger did not reach the query (frame selection or symbol loading failed); the full log is shown.' }
Write-Host 'QUERY_OUTPUT_BEGIN'
$output | Select-Object -First $MaxLines | ForEach-Object { Write-Host $_ }
if ($output.Count -gt $MaxLines) { Write-Host "... $($output.Count - $MaxLines) more line(s) in the log" }
Write-Host 'QUERY_OUTPUT_END'
Write-Host "QUERY_LOG=$queryLog"
