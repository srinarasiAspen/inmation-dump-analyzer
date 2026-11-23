<#
.SYNOPSIS
Finds correlations between performance counters of one or more inmation objects (phase 2 of the perf analysis).

.DESCRIPTION
Input: perf-data.json of Get-PerfCounters.ps1 (one or more files, separated by ';' - e.g. two dumps of different
processes taken at the same time). Which counters are compared:
  -Counters a,b,c       pairs among these (the user's hints); '*' = every counter of every object in the file(s)
  -Counters a -Against * each hinted counter against every other counter (or against a list)
Names apply to every object; '/object/path:Counter' to one object. Buckets of different objects line up because they
start at multiples of the period (UTC).

Per pair and timebase (complete buckets only): r (Pearson of the bucket values), changes r (Pearson of the
bucket-to-bucket changes), rank r (Spearman), the best lag of the changes, p-value. A deterministic pre-verdict per pair
(strong, lagged, moderate, inconsistent, trend-only, same-signal, none; see references/correlation.md) ranks the pairs.
Per counter: anomalies (spike, step, trend). Only the dump data is used; no source code is needed or read.

Output: correlation.md (report), correlation-summary.md (chat answer), correlation.json, a heat map and one chart per
top pair; KEY=value lines, PERF_RESULT=ok | no-pairs | counter-not-found | error.

.EXAMPLE
.\Measure-PerfCorrelation.ps1 -PerfJson C:\runs\perf-20261120-101500\perf-data.json -Counters "CPU,InmationMemoryUsage,TimeSeriesLoad"
.EXAMPLE
.\Measure-PerfCorrelation.ps1 -PerfJson C:\runs\perf-20261120-101500\perf-data.json -Counters "/System/Core:CPU" -Against *
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][string[]]$PerfJson,
    [string[]]$Counters = @('*'),
    [string[]]$Against,
    # Only these objects of the file(s); separated by ';'.
    [string[]]$ObjectPath,
    [string[]]$Timebases = @('second,minute,hour,day'),
    [ValidateSet('avg', 'min', 'max', 'sum', 'num')][string]$Aggregate = 'avg',
    [int]$MinPoints = 8,
    [int]$MaxLag = 3,
    [int]$TopPairs = 10,
    [string]$OutDir,
    [switch]$NoCharts
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$crashScripts = Join-Path $PSScriptRoot '..\..\crash-dump-analysis\scripts'
if (-not (Test-Path -LiteralPath (Join-Path $crashScripts 'lib\Common.ps1'))) {
    throw "The crash-dump-analysis skill must be installed next to this skill (shared libraries): $crashScripts"
}
$crashScripts = (Resolve-Path -LiteralPath $crashScripts).Path
. (Join-Path $crashScripts 'lib\Common.ps1')
foreach ($lib in 'PerfData', 'PerfStats', 'PerfChart', 'PerfReport', 'PerfCorrelationReport') { . (Join-Path $PSScriptRoot "lib\$lib.ps1") }

function Write-Key([string]$Key, [string]$Value) { Write-Host "$Key=$Value" }

function Stop-Perf([string]$Result, [int]$Code, [string]$Message) {
    if ($Message) { Write-Key 'PERF_ERROR' $Message }
    Write-Key 'PERF_RESULT' $Result
    exit $Code
}

try {
    $files = @($PerfJson | ForEach-Object { $_ -split ';' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { (Resolve-Path -LiteralPath $_).Path } | Select-Object -Unique)
    $datasets = @($files | ForEach-Object { [pscustomobject]@{ Path = $_; Data = (Read-PerfData $_) } })
    $tbList = @(Split-ListValue $Timebases | ForEach-Object { $_.ToLowerInvariant() } | Where-Object { @($script:PerfTimebases | ForEach-Object { $_.Name }) -contains $_ })
    if ($tbList.Count -eq 0) { Stop-Perf 'error' 1 'No valid -Timebases (second, minute, hour, day).' }

    # Objects of all files; labels name the dump when objects come from different dumps.
    $dumpPaths = @($datasets | ForEach-Object { [string]$_.Data.dump.path } | Select-Object -Unique)
    $objects = @()
    $allNames = @{}
    foreach ($ds in $datasets) {
        foreach ($p in $ds.Data.counterNames.PSObject.Properties) { $allNames[[int64]$p.Name] = [string]$p.Value }
        foreach ($o in @($ds.Data.objects)) {
            $label = if ($dumpPaths.Count -gt 1) { "$($o.path) [$([IO.Path]::GetFileName([string]$ds.Data.dump.path))]" } else { [string]$o.path }
            $o | Add-Member -NotePropertyName label -NotePropertyValue $label -Force
            $o | Add-Member -NotePropertyName dataset -NotePropertyValue $ds -Force
            $objects += $o
        }
    }
    $wantedObjects = @(Split-ObjectPathList $ObjectPath)
    if ($wantedObjects.Count) { $objects = @($objects | Where-Object { $wantedObjects -contains $_.path }) }
    if ($objects.Count -eq 0) { Stop-Perf 'counter-not-found' 0 'No object of the perf data file(s) matches -ObjectPath.' }
    $dumpTimes = @($datasets | ForEach-Object { [DateTime]::Parse([string]$_.Data.dump.dumpTimeUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) })
    $warnings = @()
    if ($dumpTimes.Count -gt 1) {
        $spread = (($dumpTimes | Measure-Object -Maximum).Maximum - ($dumpTimes | Measure-Object -Minimum).Minimum).TotalSeconds
        if ($spread -gt 60) { $warnings += "The dumps were taken $([int]$spread) s apart; only buckets with the same UTC start are compared, so recent second/minute buckets may not overlap." }
    }
    foreach ($w in $warnings) { Write-Key 'PERF_WARNING' $w }

    $withObject = ($objects.Count -gt 1)
    $toEntries = {
        param($Selection)
        @($Selection | ForEach-Object { [pscustomobject]@{ Key = "$($_.Object.label)|$($_.Counter.code)"; Label = (Get-PerfCounterLabel ([pscustomobject]@{ path = $_.Object.label }) $_.Counter $withObject); Object = $_.Object; Counter = $_.Counter } })
    }
    $selA = Resolve-PerfSelection $objects @(Split-ListValue $Counters) $allNames
    $selB = if ($Against) { Resolve-PerfSelection $objects @(Split-ListValue $Against) $allNames } else { $selA }
    foreach ($issue in @(@($selA.Issues) + @(if ($Against) { $selB.Issues }))) { Write-Key 'PERF_COUNTER_ISSUE' "$($issue.Request)|$($issue.Kind)|$($issue.Object)|$(@($issue.Candidates) -join ', ')" }
    $entriesA = @(& $toEntries $selA.Selected)
    $entriesB = @(& $toEntries $selB.Selected)
    if ($entriesA.Count -eq 0 -or $entriesB.Count -eq 0) { Stop-Perf 'counter-not-found' 0 $null }

    $candidates = @{}
    foreach ($e in @($entriesA + $entriesB)) { if (-not $candidates.ContainsKey($e.Key)) { $candidates[$e.Key] = Get-CorrelationCandidate $e $tbList $Aggregate $MinPoints } }
    $excluded = @($candidates.Values | Where-Object { $_.Reason } | Sort-Object { $_.Entry.Label })
    foreach ($x in ($excluded | Select-Object -First 20)) { Write-Key 'PERF_EXCLUDED' "$($x.Entry.Label)|$($x.Reason)" }
    if ($excluded.Count -gt 20) { Write-Key 'PERF_EXCLUDED_MORE' "$($excluded.Count - 20) more (constant or too few buckets), listed in the report" }
    $usableA = @($entriesA | ForEach-Object { $candidates[$_.Key] } | Where-Object { -not $_.Reason })
    $usableB = @($entriesB | ForEach-Object { $candidates[$_.Key] } | Where-Object { -not $_.Reason })
    $usableAll = @($candidates.Values | Where-Object { -not $_.Reason })
    if ($usableA.Count -eq 0 -or $usableB.Count -eq 0 -or $usableAll.Count -lt 2) {
        Stop-Perf 'no-pairs' 0 "Fewer than two counters change in the selected timebases (see PERF_EXCLUDED lines); nothing to correlate."
    }

    Write-Host "Comparing $($usableAll.Count) counters ..."
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $pairs = @(Measure-PerfCorrelation $usableA $usableB $tbList $MinPoints $MaxLag)
    $anomalies = @()
    foreach ($c in ($usableAll | Sort-Object { $_.Entry.Label })) {
        foreach ($tb in $c.Timebases) { foreach ($a in @(Get-PerfAnomalies $c.Entry.Counter $tb)) { $anomalies += [pscustomobject]@{ Label = $c.Entry.Label; Anomaly = $a } } }
    }
    Write-Host "  $($pairs.Count) pairs in $([int]$sw.Elapsed.TotalSeconds) s"

    $baseDir = if ($OutDir) { $OutDir } else { Join-Path (Split-Path $files[0] -Parent) ('correlation-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
    New-Item -ItemType Directory -Force -Path $baseDir | Out-Null
    $baseDir = (Resolve-Path -LiteralPath $baseDir).Path
    # Top pairs: findings in verdict order. Counters the user named (no '*') answer a direct question: every pair
    # among them is listed, also 'none' and 'same-signal'.
    $explicit = (@(Split-ListValue $Counters) -notcontains '*') -and (-not $Against -or @(Split-ListValue $Against) -notcontains '*')
    $findings = @('strong', 'lagged', 'moderate', 'inconsistent', 'trend-only')
    # One against all (-Against): every pair contains a hinted counter, so only the other side is capped.
    $exempt = @(if ($Against) { $entriesA | ForEach-Object { $_.Key } })
    $top = if ($explicit -and $pairs.Count -le 3 * $TopPairs) { $pairs } else { @(Select-DiversePairs $pairs $findings $TopPairs 2 $exempt) }
    $top = @($top)

    # Charts: one per top pair; heat map of the timebase with the most usable counters (minute on a tie).
    $heatmap = $null
    if (-not $NoCharts) {
        $chartDir = Join-Path $baseDir 'charts'
        New-Item -ItemType Directory -Force -Path $chartDir | Out-Null
        $first = $datasets[0].Data
        for ($i = 0; $i -lt $top.Count; $i++) {
            $p = $top[$i]
            $path = Join-Path $chartDir ('pair-{0:00}.png' -f ($i + 1))
            $sub = "pre-verdict $($p.Verdict.verdict)$(if ($p.Verdict.direction) { ", $($p.Verdict.direction)" }) | aggregate $Aggregate per bucket | $($first.module.name) $($first.module.fileVersion) | dump taken $($first.dump.dumpTimeUtc) | times UTC"
            if (New-PerfPairChart $p.A.Entry.Label $p.B.Entry.Label $p.Measures $p.A.Buckets $p.B.Buckets $sub $path) { $p | Add-Member -NotePropertyName Chart -NotePropertyValue $path -Force }
        }
        $heatTb = @($tbList | Sort-Object @{ Expression = { $tb = $_; @($usableAll | Where-Object { $_.Timebases -contains $tb }).Count }; Descending = $true }, @{ Expression = { if ($_ -eq 'minute') { 0 } else { 1 } } }) | Select-Object -First 1
        $involved = @($top | Where-Object { $findings -contains $_.Verdict.verdict } | ForEach-Object { $_.A.Entry.Key; $_.B.Entry.Key } | Select-Object -Unique)
        $heatEntries = @($usableAll | Where-Object { $_.Timebases -contains $heatTb -and ($involved.Count -eq 0 -or $involved -contains $_.Entry.Key) } | Sort-Object { $_.Entry.Label } | Select-Object -First 40)
        if ($heatEntries.Count -ge 2) {
            $index = @{}
            for ($i = 0; $i -lt $heatEntries.Count; $i++) { $index[$heatEntries[$i].Entry.Key] = $i }
            $matrix = @{}
            foreach ($p in $pairs) {
                if (-not ($index.ContainsKey($p.A.Entry.Key) -and $index.ContainsKey($p.B.Entry.Key))) { continue }
                $m = $p.Measures | Where-Object { $_.timebase -eq $heatTb } | Select-Object -First 1
                if ($m -and $null -ne $m.r) { $matrix["$($index[$p.A.Entry.Key])|$($index[$p.B.Entry.Key])"] = $m.r }
            }
            $heatmap = Join-Path $chartDir "heatmap-$heatTb.png"
            New-PerfHeatmap @($heatEntries | ForEach-Object { $_.Entry.Label }) $matrix "Correlation of $Aggregate per $heatTb bucket (r)" $heatmap
        }
    }

    $result = [pscustomobject]@{
        Datasets = $datasets; Objects = $objects; Timebases = $tbList; Aggregate = $Aggregate; MinPoints = $MinPoints; MaxLag = $MaxLag
        Counters = @(Split-ListValue $Counters); Against = @(Split-ListValue $Against); Pairs = $pairs; Top = $top; Anomalies = $anomalies
        Excluded = $excluded; Usable = $usableAll; Heatmap = $heatmap; Warnings = $warnings
        ToolVersion = (Get-ToolVersion $crashScripts)
    }
    $reportPath = Join-Path $baseDir 'correlation.md'
    $summaryPath = Join-Path $baseDir 'correlation-summary.md'
    $jsonPath = Join-Path $baseDir 'correlation.json'
    [IO.File]::WriteAllText($reportPath, (New-CorrelationReportMarkdown $result $baseDir), (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($summaryPath, (New-CorrelationSummaryMarkdown $result $reportPath), (New-Object Text.UTF8Encoding($false)))
    [IO.File]::WriteAllText($jsonPath, ((ConvertTo-CorrelationData $result) | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))

    for ($i = 0; $i -lt $top.Count; $i++) {
        $p = $top[$i]; $v = $p.Verdict
        $chart = if ($p.PSObject.Properties['Chart']) { $p.Chart } else { 'no chart' }
        Write-Key 'CORRELATION_PAIR' ("{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f ($i + 1), $p.A.Entry.Label, $p.B.Entry.Label, $v.verdict, $(if ($v.direction) { $v.direction } else { '-' }), (Format-PairEvidence $v), $chart)
    }
    $found = @($pairs | Where-Object { $findings -contains $_.Verdict.verdict }).Count
    $sameSignal = @($pairs | Where-Object { $_.Verdict.verdict -eq 'same-signal' })
    Write-Key 'CORRELATION_PAIRS' "$($pairs.Count) compared, $found with a finding (strong, lagged, moderate, inconsistent, trend-only), $($sameSignal.Count) same-signal"
    foreach ($p in ($sameSignal | Select-Object -First 10)) { Write-Key 'CORRELATION_SAME_SIGNAL' "$($p.A.Entry.Label)|$($p.B.Entry.Label)|$(Format-PairEvidence $p.Verdict)" }
    foreach ($a in ($anomalies | Select-Object -First 20)) { Write-Key 'PERF_ANOMALY' "$($a.Label)|$($a.Anomaly.timebase)|$($a.Anomaly.kind)|$($a.Anomaly.detail)" }
    if ($anomalies.Count -gt 20) { Write-Key 'PERF_ANOMALY_MORE' "$($anomalies.Count - 20) more in the report" }
    if ($heatmap) { Write-Key 'HEATMAP_PNG' $heatmap }
    Write-Key 'CORRELATION_REPORT' $reportPath
    Write-Key 'CORRELATION_SUMMARY' $summaryPath
    Write-Key 'CORRELATION_JSON' $jsonPath
    Write-Key 'PERF_RESULT' 'ok'
}
catch {
    Write-Key 'PERF_ERROR' "$($_.Exception.Message) at $([IO.Path]::GetFileName($_.InvocationInfo.ScriptName)):$($_.InvocationInfo.ScriptLineNumber)"
    Write-Key 'PERF_RESULT' 'error'
    exit 1
}
