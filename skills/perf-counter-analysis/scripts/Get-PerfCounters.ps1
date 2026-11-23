<#
.SYNOPSIS
Reads the performance counters of inmation objects from a Windows dump of inmation.exe and plots them.

.DESCRIPTION
Performance counters are kept in memory per object (CObject::performance_): per counter and timebase (second, minute,
hour, day) a buffer of buckets with the aggregates sum, num, avg, min and max. The script
  1. finds the matching PDB like the crash analyzer (-PdbPath, next to the dump, in its zip, build shares) and verifies
     it (symbol gate: without verified private symbols nothing is read - PERF_RESULT=blocked);
  2. runs cdb once with PerfDump.js: finds the objects in inmation::model::_maps (paths, case-insensitive) and reads all
     their counter buffers into perf-data.json (+ perf-data.csv);
  3. without -Counters: lists the counters of the objects (PERF_COUNTER_AVAILABLE=) and stops;
     with -Counters: one PNG chart per object and counter (a panel per timebase), perf-report.md, perf-summary.md.
-PerfJson re-plots other counters from an earlier run without running the debugger again.
Counters of several objects are compared with Measure-PerfCorrelation.ps1 on the perf-data.json.

Output: KEY=value lines. PERF_RESULT= tells what happened: ok, listed-counters, listed-objects, object-not-found,
no-counters, counter-not-found, blocked, error.

.EXAMPLE
.\Get-PerfCounters.ps1 -DumpPath C:\dumps\inmation.exe.1234.dmp -ObjectPath /System/Core -Counters CPU,MemoryLoad
.EXAMPLE
.\Get-PerfCounters.ps1 -DumpPath C:\dumps\inmation.exe.1234.dmp -ObjectPath "/System/Core;/System/Core/Stores/VQT"
.EXAMPLE
.\Get-PerfCounters.ps1 -DumpPath C:\dumps\inmation.exe.1234.dmp -ListObjects -Filter Connector
.EXAMPLE
.\Get-PerfCounters.ps1 -PerfJson C:\runs\perf-20261120-101500\perf-data.json -Counters "/System/Core:CPU,TimeSeriesLoad" -Aggregates avg,max,num
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    # Windows minidump (.dmp) of inmation.exe, or a zip with one dump.
    [string]$DumpPath,
    # Canonical object paths, e.g. /System/Core. Case-insensitive. Several: separated by ';'.
    [string[]]$ObjectPath,
    # Counter names (CPU, TimeSeriesLoad, MODEL_PERF_CPU), codes, unique name parts, or * for all; comma-separated.
    # A name applies to every object; '/object/path:Counter' to one object only.
    [string[]]$Counters,
    # Aggregates to plot: avg, min, max, sum, num. min+max are drawn as a band.
    [string[]]$Aggregates = @('avg,min,max'),
    # perf-data.json of an earlier run (no debugger run). With -ObjectPath: only these objects of the file.
    [string]$PerfJson,
    # List the objects that have performance counters.
    [switch]$ListObjects,
    # With -ListObjects: only paths containing this text (case-insensitive).
    [string]$Filter,
    [int]$MaxObjects = 300,
    [string]$PdbPath,
    [string]$OutDir,
    [string]$ConfigPath,
    [switch]$NoCharts
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

$crashScripts = Join-Path $PSScriptRoot '..\..\crash-dump-analysis\scripts'
if (-not (Test-Path -LiteralPath (Join-Path $crashScripts 'lib\Symbols.ps1'))) {
    throw "The crash-dump-analysis skill must be installed next to this skill (shared libraries): $crashScripts"
}
$crashScripts = (Resolve-Path -LiteralPath $crashScripts).Path
foreach ($lib in 'Common', 'Minidump', 'BuildLookup', 'Cdb', 'Archives', 'LinuxCore', 'Symbols') { . (Join-Path $crashScripts "lib\$lib.ps1") }
foreach ($lib in 'PerfData', 'PerfChart', 'PerfReport') { . (Join-Path $PSScriptRoot "lib\$lib.ps1") }

function Write-Key([string]$Key, [string]$Value) { Write-Host "$Key=$Value" }

function Stop-Perf([string]$Result, [int]$Code, [string]$Message) {
    if ($Message) { Write-Key 'PERF_ERROR' $Message }
    Write-Key 'PERF_RESULT' $Result
    exit $Code
}

function Get-QuotedArg([string]$Value) { return '"' + $Value + '"' }

function Get-CountText($Object) { if ($Object.HasCounters) { return "$($Object.CounterCount) counters" } return 'no counters' }

$configInfo = Read-AnalyzerConfig $ConfigPath $crashScripts
$config = $configInfo.Config
$toolVersion = Get-ToolVersion $crashScripts
$counterRequest = @(Split-ListValue $Counters)
$requestedPaths = @(Split-ObjectPathList $ObjectPath)

try {
    if ($PerfJson) {
        $PerfJson = (Resolve-Path -LiteralPath $PerfJson).Path
        $data = Read-PerfData $PerfJson
        $runDir = Split-Path $PerfJson -Parent
        $dataPath = $PerfJson
        $objects = @($data.objects)
        if ($requestedPaths.Count) {
            $objects = @($objects | Where-Object { $requestedPaths -contains $_.path })
            foreach ($p in @($requestedPaths | Where-Object { @($objects | ForEach-Object { $_.path }) -notcontains $_ })) {
                Write-Key 'PERF_OBJECT_NOT_FOUND' "$p (not in $PerfJson; objects there: $(@($data.objects | ForEach-Object { $_.path }) -join ', '))"
            }
            if ($objects.Count -eq 0) { Stop-Perf 'object-not-found' 0 $null }
        }
    }
    else {
        if (-not $DumpPath) { Stop-Perf 'error' 1 'Pass -DumpPath (a .dmp file or a zip with one dump), or -PerfJson of an earlier run.' }
        if (-not $ListObjects -and $requestedPaths.Count -eq 0) { Stop-Perf 'error' 1 'Pass -ObjectPath (the objects whose counters to read, separated by ;), or -ListObjects to see the objects with counters.' }
        if (-not (Test-Path -LiteralPath $DumpPath -PathType Leaf)) { Stop-Perf 'error' 1 "Dump file not found (pass one .dmp file or a zip with one dump): $DumpPath" }
        $dumpFile = (Resolve-Path -LiteralPath $DumpPath).Path
        $bundledPdbs = @()
        $dumpDirs = @()
        if ($dumpFile -match '\.zip$') {
            $extractRoot = Expand-PathValue (Get-Cfg $config 'extractRoot' "$env:LOCALAPPDATA\inmation-crash-analysis\extracted")
            $expansion = Expand-DumpArchives @($dumpFile) $extractRoot @()
            $inZip = @($expansion.Dumps)
            if ($inZip.Count -ne 1) { Stop-Perf 'error' 1 "The zip must contain exactly one dump; it contains $($inZip.Count)." }
            $bundledPdbs = @($expansion.Symbols)
            $dumpDirs = @((Split-Path $dumpFile -Parent))
            $dumpFile = $inZip[0].DumpPath
            Write-Key 'EXTRACTED_DIR' (Split-Path $dumpFile -Parent)
        }
        $isElf = $false
        try { $isElf = Test-ElfCoreFile $dumpFile } catch { }
        if ($isElf) { Stop-Perf 'error' 1 'Linux core dumps are not supported yet; performance counters can be read from Windows dumps of inmation.exe.' }

        $runDir = if ($OutDir) { $OutDir } else { Join-Path (Expand-PathValue (Get-Cfg $config 'workRoot' "$env:LOCALAPPDATA\inmation-crash-analysis\runs")) ('perf-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
        New-Item -ItemType Directory -Force -Path $runDir | Out-Null
        $runDir = (Resolve-Path -LiteralPath $runDir).Path

        $sym = Resolve-WindowsDumpSymbols $config $dumpFile $PdbPath $dumpDirs $bundledPdbs
        $module = $sym.Module
        if (-not $sym.Symbols) {
            Write-Key 'PERF_BLOCKED' "$($sym.PdbName) GUID $($module.PdbGuid) age $($module.PdbAge), $($module.Name) $($module.FileVersion): $($sym.SymbolError)"
            Stop-Perf 'blocked' 2 $null
        }
        if (-not $sym.Info.FullMemory) { Write-Key 'PERF_WARNING' 'The dump has no full-memory stream; object data on the heap may be missing (create the dump with full memory, e.g. procdump -ma).' }

        $cdb = Find-Cdb $config
        $mod = $sym.ModuleName
        $js = Join-Path $PSScriptRoot 'PerfDump.js'
        $cmd = New-Object Collections.Generic.List[string]
        if ($sym.Wow64) { $cmd.Add('.load wow64exts'); $cmd.Add('!sw') }
        $cmd.Add('.echo <<<SECTION:modules>>>'); $cmd.Add("ld $mod"); $cmd.Add("lmv m $mod")
        $cmd.Add('.echo <<<SECTION:perfenum>>>'); $cmd.Add("dt ${mod}!inmation::model::CModelPerformance::CODEENUM")
        $cmd.Add('.echo <<<SECTION:classenum>>>'); $cmd.Add("dt ${mod}!inmation::model::CModelClasses::CODEENUM")
        $cmd.Add('.echo <<<SECTION:perf>>>')
        $cmd.Add(".scriptload $(Get-QuotedArg $js)")
        if ($ListObjects) {
            $cmd.Add("dx -r0 Debugger.State.Scripts.PerfDump.Contents.perfList(`"$mod`", `"$(ConvertTo-Utf8Hex $Filter)`", $MaxObjects)")
        }
        else {
            $hexList = @($requestedPaths | ForEach-Object { ConvertTo-Utf8Hex $_ }) -join ','
            $cmd.Add("dx -r0 Debugger.State.Scripts.PerfDump.Contents.perfDump(`"$mod`", `"$hexList`", 25)")
        }
        $cmd.Add('.echo <<<SECTION:end>>>')
        $cmd.Add('q')
        $cmdFile = Join-Path $runDir 'perf.cdb.txt'
        [IO.File]::WriteAllText($cmdFile, (($cmd -join "`r`n") + "`r`n"), (New-Object Text.UTF8Encoding($false)))
        $cdbLog = Join-Path $runDir 'cdb-perf.log'
        Write-Host 'Running cdb ...'
        Invoke-CdbScript $cdb $dumpFile $sym.SymbolPath $sym.ImagePath $cdbLog $cmdFile ([int](Get-Cfg $config 'cdbTimeoutSeconds' 900))
        $lines = @(Get-Content -LiteralPath $cdbLog -Encoding UTF8)
        $sections = Split-CdbSections $lines

        # Symbol gate: the object layout is read from PDB types; only a verified private PDB is trusted.
        $loadStatus = Get-SymbolLoadStatus (Get-Section $sections 'modules')
        if (-not (Test-PrivateSymbolStatus $loadStatus)) {
            Write-Key 'PERF_BLOCKED' "$($sym.PdbName) GUID $($module.PdbGuid) age $($module.PdbAge): cdb loaded '$loadStatus', not private PDB symbols (log: $cdbLog)"
            Stop-Perf 'blocked' 2 $null
        }
        $perfNames = ConvertFrom-EnumLines (Get-Section $sections 'perfenum') 'MODEL_PERF_'
        $classNames = ConvertFrom-EnumLines (Get-Section $sections 'classenum') 'MODEL_CLASS_'
        $parsed = ConvertFrom-PerfDumpOutput (Get-Section $sections 'perf')
        foreach ($w in $parsed.Warnings) { Write-Key 'PERF_WARNING' $w }
        if ($parsed.Errors.Count -or -not $parsed.Done) {
            $why = if ($parsed.Errors.Count) { $parsed.Errors -join '; ' } else { "PerfDump.js did not finish (see $cdbLog)" }
            if ($why -match 'memory|read') { $why += ' - the dump probably does not contain the heap (full-memory dump needed).' }
            Stop-Perf 'error' 1 $why
        }
        $className = { param($code) if ($classNames.ContainsKey([int64]$code)) { $classNames[[int64]$code] } else { "class $code" } }
        Write-Key 'PERF_MAP_ENTRIES' "$($parsed.MapEntries) (scanned in $($parsed.ScanMs) ms)"

        if ($ListObjects) {
            foreach ($o in $parsed.Listed) { Write-Key 'PERF_OBJECT' "$($o.Path)|$(& $className $o.ClassCode)|$($o.CounterCount) counters" }
            Write-Key 'PERF_OBJECTS_WITH_COUNTERS' "$($parsed.WithCounters) (listed: $($parsed.ListedShown)$(if ($parsed.ListedShown -ge $MaxObjects) { ", limit -MaxObjects $MaxObjects" }))"
            Write-Key 'PERF_RESULT' 'listed-objects'
            exit 0
        }

        $warnings = @($parsed.Warnings)
        $objectList = @()
        $seenObjects = @{}
        $notFound = 0
        for ($i = 0; $i -lt $requestedPaths.Count; $i++) {
            $req = if ($parsed.Requests.ContainsKey($i)) { $parsed.Requests[$i] } else { [pscustomobject]@{ Matches = @(); Candidates = @(); Dumped = $null } }
            $wanted = $requestedPaths[$i]
            if (@($req.Matches).Count -eq 0) {
                $notFound++
                Write-Key 'PERF_OBJECT_NOT_FOUND' $wanted
                foreach ($c in $req.Candidates) { Write-Key 'PERF_OBJECT_CANDIDATE' "$($c.Path)|$(& $className $c.ClassCode)|$(Get-CountText $c)" }
                $similar = @($req.Candidates | Select-Object -First 3 | ForEach-Object { $_.Path })
                $warnings += "Object $wanted not found$(if ($similar.Count) { " (similar: $($similar -join ', '))" })."
                continue
            }
            foreach ($m in $req.Matches) { Write-Key 'PERF_OBJECT_MATCH' "$($m.Path)|$(& $className $m.ClassCode)|$($m.Address)|$(Get-CountText $m)" }
            if (-not $req.Dumped) {
                Write-Key 'PERF_OBJECT_WITHOUT_COUNTERS' "$wanted (its class defines no performance counters)"
                $warnings += "Object $wanted has no performance counters (its class defines none)."
                continue
            }
            if ($seenObjects.ContainsKey($req.Dumped)) { continue }
            $seenObjects[$req.Dumped] = $true
            $target = $req.Matches | Where-Object { $_.Address -eq $req.Dumped } | Select-Object -First 1
            if (@($req.Matches).Count -gt 1) { $warnings += "$(@($req.Matches).Count) objects have the path $wanted; counters are from $($target.Address) (the first with counters)." }
            $objectList += [ordered]@{
                requestedPath = $wanted; path = $target.Path; address = $target.Address; classCode = $target.ClassCode; className = (& $className $target.ClassCode); counterCount = $target.CounterCount
                samePath = @($req.Matches | ForEach-Object { [ordered]@{ path = $_.Path; address = $_.Address; className = (& $className $_.ClassCode); counters = $_.CounterCount } })
                counters = @(New-PerfCounterList $parsed.Objects[$req.Dumped] $perfNames)
            }
        }
        if ($objectList.Count -eq 0) {
            if ($notFound) { Stop-Perf 'object-not-found' 0 $null }
            Stop-Perf 'no-counters' 0 'None of the objects has performance counters (their classes define none).'
        }

        $data = [ordered]@{
            schema       = 1
            tool         = 'perf-counter-analyzer'
            toolVersion  = $toolVersion
            createdUtc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            dump         = [ordered]@{ path = $dumpFile; sizeBytes = $sym.Info.SizeBytes; dumpTimeUtc = $sym.Info.CrashTimeUtc; processId = $sym.Info.ProcessId; uptime = $sym.Info.Uptime; fullMemory = $sym.Info.FullMemory }
            module       = [ordered]@{ name = $module.Name; fileVersion = $module.FileVersion; pdbGuid = $module.PdbGuid; pdbAge = $module.PdbAge }
            symbols      = [ordered]@{ pdbPath = $sym.Symbols.PdbPath; source = $sym.Symbols.Source; loadStatus = $loadStatus; trusted = $true }
            map          = [ordered]@{ entries = $parsed.MapEntries; scanMs = $parsed.ScanMs }
            timebases    = @($script:PerfTimebases | ForEach-Object { [ordered]@{ name = $_.Name; periodMs = $_.PeriodMs; retention = $_.Retention } })
            counterNames = [ordered]@{}
            objects      = $objectList
            warnings     = $warnings
            files        = [ordered]@{ cdbLog = $cdbLog; commands = $cmdFile }
        }
        foreach ($k in @($perfNames.Keys | Sort-Object)) { $data.counterNames["$k"] = $perfNames[$k] }
        $dataPath = Join-Path $runDir 'perf-data.json'
        [IO.File]::WriteAllText($dataPath, ($data | ConvertTo-Json -Depth 9 -Compress), (New-Object Text.UTF8Encoding($false)))
        Write-PerfCsv $data (Join-Path $runDir 'perf-data.csv')
        # Continue with the same shape as a re-read file (PSCustomObjects), so both paths behave the same.
        $data = Read-PerfData $dataPath
        $objects = @($data.objects)
    }

    foreach ($o in $objects) { Write-Key 'PERF_OBJECT' "$($o.path)|$($o.className)|$($o.counterCount) counters" }
    Write-Key 'PERF_JSON' $dataPath
    Write-Key 'PERF_CSV' (Join-Path $runDir 'perf-data.csv')
    $allNames = @{}
    foreach ($p in $data.counterNames.PSObject.Properties) { $allNames[[int64]$p.Name] = [string]$p.Value }

    if ($counterRequest.Count -eq 0) {
        foreach ($o in $objects) {
            foreach ($c in @($o.counters)) { Write-Key 'PERF_COUNTER_AVAILABLE' "$($o.path)|$($c.name)|$($c.code)|$(Get-PerfActivity $c)" }
        }
        Write-Key 'NEXT_STEP' ("powershell -NoProfile -ExecutionPolicy Bypass -File $(Get-QuotedArg (Join-Path $PSScriptRoot 'Get-PerfCounters.ps1')) -PerfJson $(Get-QuotedArg $dataPath) -Counters <names>")
        Write-Key 'NEXT_STEP_CORRELATION' ("powershell -NoProfile -ExecutionPolicy Bypass -File $(Get-QuotedArg (Join-Path $PSScriptRoot 'Measure-PerfCorrelation.ps1')) -PerfJson $(Get-QuotedArg $dataPath) -Counters <names or *>")
        Write-Key 'PERF_RESULT' 'listed-counters'
        exit 0
    }

    $selection = Resolve-PerfSelection $objects $counterRequest $allNames
    foreach ($issue in $selection.Issues) { Write-Key 'PERF_COUNTER_ISSUE' "$($issue.Request)|$($issue.Kind)|$($issue.Object)|$(@($issue.Candidates) -join ', ')" }
    if (@($selection.Selected).Count -eq 0) { Stop-Perf 'counter-not-found' 0 $null }

    $chartDir = Join-Path $runDir 'charts'
    $aggs = @(Split-ListValue $Aggregates)
    $selected = @()
    foreach ($s in $selection.Selected) {
        $chart = $null
        if (-not $NoCharts) {
            $dir = Join-Path $chartDir (Get-PerfFileName $s.Object.path)
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
            $chart = Join-Path $dir ((Get-PerfFileName $s.Counter.name) + '.png')
            New-PerfCounterChart $data $s.Object $s.Counter $aggs $chart
        }
        $selected += [pscustomobject]@{ Object = $s.Object; Counter = $s.Counter; Chart = $chart }
        $note = if ($s.Partial) { " (matched '$($s.Request)')" } else { '' }
        Write-Key 'PERF_COUNTER' "$($s.Object.path)|$($s.Counter.name)|$($s.Counter.code)|$(if ($chart) { $chart } else { 'no chart' })$note"
    }
    $reportPath = Join-Path $runDir 'perf-report.md'
    $summaryPath = Join-Path $runDir 'perf-summary.md'
    [IO.File]::WriteAllText($reportPath, (New-PerfReportMarkdown $data $selected $runDir), (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($summaryPath, (New-PerfSummaryMarkdown $data $selected $reportPath), (New-Object Text.UTF8Encoding($false)))
    Write-Key 'PERF_REPORT' $reportPath
    Write-Key 'PERF_SUMMARY' $summaryPath
    Write-Key 'PERF_RESULT' 'ok'
}
catch {
    Write-Key 'PERF_ERROR' "$($_.Exception.Message) at $([IO.Path]::GetFileName($_.InvocationInfo.ScriptName)):$($_.InvocationInfo.ScriptLineNumber)"
    Write-Key 'PERF_RESULT' 'error'
    exit 1
}
