# Markdown and JSON for correlation runs (Measure-PerfCorrelation.ps1). Needs PerfData.ps1, PerfReport.ps1, PerfChart.ps1.

function Format-PerfP($P) {
    if ($null -eq $P) { return '-' }
    if ($P -lt 0.001) { return '<0.001' }
    return ([double]$P).ToString('0.000', [Globalization.CultureInfo]::InvariantCulture)
}

function Format-PerfLag($Measure) {
    if ($null -eq $Measure.lag) { return '-' }
    return ('{0:+0;-0} ({1})' -f [int]$Measure.lag, (Format-PerfR $Measure.lagR))
}

# 'minute: r 0.91, changes r 0.64, rank r 0.88, n 59, p <0.001' (+ the lag for lagged pairs, + a note on few changes)
function Format-PairEvidence($Verdict) {
    if (-not $Verdict.timebase) { return 'no timebase with enough common buckets' }
    $text = "$($Verdict.timebase): r $(Format-PerfR $Verdict.r), changes r $(Format-PerfR $Verdict.dr), rank r $(Format-PerfR $Verdict.rho), n $($Verdict.n), p $(Format-PerfP $Verdict.p)"
    if ($Verdict.verdict -eq 'lagged') { $text += ", changes of B follow A by $('{0:+0;-0}' -f [int]$Verdict.lag) bucket(s) with r $(Format-PerfR $Verdict.lagR)" }
    if ($null -ne $Verdict.changes -and $Verdict.changes -lt $script:MinChanges) { $text += ", only $($Verdict.changes) bucket-to-bucket change(s)" }
    return $text
}

function Format-MeasureCell($Measures, [string]$Timebase) {
    $m = $Measures | Where-Object { $_.timebase -eq $Timebase } | Select-Object -First 1
    if (-not $m) { return '-' }
    if ($null -eq $m.r) { return "n $($m.n)" }
    return "$(Format-PerfR $m.r) / $(Format-PerfR $m.dr) / $(Format-PerfLag $m) / $($m.n)"
}

$script:CorrelationHowTo = @'
How to read: per pair and timebase the bucket values (`{0}` per bucket, complete buckets only, same UTC bucket start) are compared.
`r` = Pearson correlation of the values; `changes r` = correlation of the bucket-to-bucket changes (high only if the counters
move together from bucket to bucket, not just drift in the same direction); `rank r` = Spearman (robust to single spikes);
`lag` = shift of the changes in buckets with the best correlation (positive: the second counter follows the first).
Pre-verdicts: `strong` (|r| >= 0.8, p < 0.01, |changes r| >= 0.5, |rank r| >= 0.6), `lagged` (changes correlate best when shifted:
|r| >= 0.6, p < 0.01), `moderate` (changes r significant at p < 0.01 and either |r| >= 0.5, p < 0.05, |changes r| >= 0.3,
or |changes r| >= 0.5: spikes and dips coincide), `inconsistent` (opposite signs in different timebases), `trend-only` (|r| and |rank r| >= 0.5 but the changes do not
correlate or are too few: both only drift or step together), `same-signal` (|r| and |changes r| >= 0.97 everywhere: one
counter is derived from the other or both from the same value), `none`. Changes count only when both counters change in
at least 5 buckets. A correlation is not a cause.
'@

function New-CorrelationReportMarkdown($Result, [string]$ReportDir) {
    $sb = New-Object Text.StringBuilder
    $first = $Result.Datasets[0].Data
    [void]$sb.AppendLine('# Performance counter correlation')
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Item | Value |')
    [void]$sb.AppendLine('|---|---|')
    foreach ($o in $Result.Objects) { [void]$sb.AppendLine("| Object | ``$(Format-PerfCell $o.label)`` (class ``$($o.className)``) |") }
    foreach ($ds in $Result.Datasets) { [void]$sb.AppendLine("| Dump | ``$($ds.Data.dump.path)``, taken $($ds.Data.dump.dumpTimeUtc), $($ds.Data.module.name) $($ds.Data.module.fileVersion) (data: ``$($ds.Path)``) |") }
    $against = if ($Result.Against.Count) { " against ``$($Result.Against -join ', ')``" } else { ' (all pairs among them)' }
    [void]$sb.AppendLine("| Requested | ``$($Result.Counters -join ', ')``$against |")
    [void]$sb.AppendLine("| Compared | $($Result.Usable.Count) counters, $($Result.Pairs.Count) pairs; timebases $($Result.Timebases -join ', '); at least $($Result.MinPoints) common complete buckets; lags up to $($Result.MaxLag) buckets |")
    [void]$sb.AppendLine("| Generated | inmation dump analyzer $($Result.ToolVersion), $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) |")
    foreach ($w in $Result.Warnings) { [void]$sb.AppendLine("| Warning | $(Format-PerfCell $w) |") }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine(($script:CorrelationHowTo -f $Result.Aggregate))
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## Pairs')
    [void]$sb.AppendLine()
    $listed = @($Result.Pairs | Where-Object { $_.Verdict.verdict -ne 'none' -and $_.Verdict.verdict -ne 'same-signal' })
    $topKeys = @{}
    foreach ($t in $Result.Top) { $topKeys["$($t.A.Entry.Key)||$($t.B.Entry.Key)"] = $true }
    # Pairs the user asked about explicitly are listed even with 'none' or 'same-signal'.
    $listed = @(@($Result.Top) + @($listed | Where-Object { -not $topKeys.ContainsKey("$($_.A.Entry.Key)||$($_.B.Entry.Key)") }))
    if ($listed.Count -eq 0) { [void]$sb.AppendLine('No pair has a pre-verdict other than `none` or `same-signal`.') }
    else {
        [void]$sb.AppendLine('| # | Counter A | Counter B | Pre-verdict | Direction | Best timebase | r | changes r | rank r | lag (r) | buckets | p | Chart |')
        [void]$sb.AppendLine('|---|---|---|---|---|---|---|---|---|---|---|---|---|')
        for ($i = 0; $i -lt $listed.Count; $i++) {
            $p = $listed[$i]; $v = $p.Verdict
            $chart = if ($p.PSObject.Properties['Chart']) { "[chart]($(Get-RelativePerfPath $ReportDir $p.Chart))" } else { '-' }
            [void]$sb.AppendLine(('| {0} | {1} | {2} | `{3}` | {4} | {5} | {6} | {7} | {8} | {9} | {10} | {11} | {12} |' -f ($i + 1), (Format-PerfCell $p.A.Entry.Label), (Format-PerfCell $p.B.Entry.Label), $v.verdict, (Get-PerfDash $v.direction), (Get-PerfDash $v.timebase), (Format-PerfR $v.r), (Format-PerfR $v.dr), (Format-PerfR $v.rho), (Format-PerfLag $v), (Get-PerfDash $v.n), (Format-PerfP $v.p), $chart))
        }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('Per timebase (r / changes r / lag (r) / buckets):')
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("| # | $($Result.Timebases -join ' | ') |")
        [void]$sb.AppendLine("|---|$(@($Result.Timebases | ForEach-Object { '---' }) -join '|')|")
        for ($i = 0; $i -lt $listed.Count; $i++) {
            $cells = @($Result.Timebases | ForEach-Object { Format-MeasureCell $listed[$i].Measures $_ })
            [void]$sb.AppendLine("| $($i + 1) | $($cells -join ' | ') |")
        }
    }
    $none = @($Result.Pairs | Where-Object { $_.Verdict.verdict -eq 'none' -and -not $topKeys.ContainsKey("$($_.A.Entry.Key)||$($_.B.Entry.Key)") }).Count
    if ($none) { [void]$sb.AppendLine(); [void]$sb.AppendLine("$none more pair(s) with pre-verdict ``none`` (data in correlation.json).") }
    $same = @($Result.Pairs | Where-Object { $_.Verdict.verdict -eq 'same-signal' -and -not $topKeys.ContainsKey("$($_.A.Entry.Key)||$($_.B.Entry.Key)") })
    if ($same.Count) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('## Same signal')
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('These pairs carry the same signal (|r| and |changes r| >= 0.97 in every compared timebase): one counter is derived from the other, or both are set from the same value. Not a finding about behavior; use one of them.')
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('| Counter A | Counter B | Evidence |')
        [void]$sb.AppendLine('|---|---|---|')
        foreach ($p in $same) { [void]$sb.AppendLine("| $(Format-PerfCell $p.A.Entry.Label) | $(Format-PerfCell $p.B.Entry.Label) | $(Format-PairEvidence $p.Verdict) |") }
    }
    if ($Result.Top.Count) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('## Charts of the top pairs')
        for ($i = 0; $i -lt $Result.Top.Count; $i++) {
            $p = $Result.Top[$i]
            if (-not $p.PSObject.Properties['Chart']) { continue }
            [void]$sb.AppendLine()
            [void]$sb.AppendLine("### $($i + 1). $($p.A.Entry.Label) vs $($p.B.Entry.Label)")
            [void]$sb.AppendLine()
            [void]$sb.AppendLine("![pair $($i + 1)]($(Get-RelativePerfPath $ReportDir $p.Chart))")
        }
    }
    if ($Result.Heatmap) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('## Correlation matrix')
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("![heat map]($(Get-RelativePerfPath $ReportDir $Result.Heatmap))")
    }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('## Anomalies')
    [void]$sb.AppendLine()
    if ($Result.Anomalies.Count -eq 0) { [void]$sb.AppendLine('None found (spike: bucket max >= 5 robust z; step: mean change >= 3 standard deviations; trend: |rank r with time| >= 0.8).') }
    else {
        [void]$sb.AppendLine('| Counter | Timebase | Kind | Detail | At (UTC) |')
        [void]$sb.AppendLine('|---|---|---|---|---|')
        foreach ($a in $Result.Anomalies) { [void]$sb.AppendLine("| $(Format-PerfCell $a.Label) | $($a.Anomaly.timebase) | $($a.Anomaly.kind) | $(Format-PerfCell $a.Anomaly.detail) | $(Get-PerfDash $a.Anomaly.atUtc) |") }
    }
    if ($Result.Excluded.Count) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('## Not compared')
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('| Counter | Reason |')
        [void]$sb.AppendLine('|---|---|')
        foreach ($x in $Result.Excluded) { [void]$sb.AppendLine("| $(Format-PerfCell $x.Entry.Label) | $($x.Reason) |") }
    }
    return $sb.ToString()
}

function New-CorrelationSummaryMarkdown($Result, [string]$ReportPath) {
    $sb = New-Object Text.StringBuilder
    [void]$sb.AppendLine("Compared $($Result.Usable.Count) counters ($($Result.Pairs.Count) pairs) of $(@($Result.Objects | ForEach-Object { '`' + $_.label + '`' }) -join ', '), ``$($Result.Aggregate)`` per bucket, timebases $($Result.Timebases -join ', ').")
    [void]$sb.AppendLine()
    if ($Result.Top.Count -eq 0) { [void]$sb.AppendLine('No pair has a pre-verdict other than `none` or `same-signal`.') }
    else {
        [void]$sb.AppendLine('| # | Counter A | Counter B | Pre-verdict | Evidence |')
        [void]$sb.AppendLine('|---|---|---|---|---|')
        for ($i = 0; $i -lt $Result.Top.Count; $i++) {
            $p = $Result.Top[$i]; $v = $p.Verdict
            $verdict = '`' + $v.verdict + '`' + $(if ($v.direction) { " ($($v.direction))" } else { '' })
            [void]$sb.AppendLine("| $($i + 1) | $(Format-PerfCell $p.A.Entry.Label) | $(Format-PerfCell $p.B.Entry.Label) | $verdict | $(Format-PairEvidence $v) |")
        }
    }
    $same = @($Result.Pairs | Where-Object { $_.Verdict.verdict -eq 'same-signal' }).Count
    if ($same) { [void]$sb.AppendLine(); [void]$sb.AppendLine("$same pair(s) carry the same signal (one counter derived from the other); listed in the report, not ranked.") }
    if ($Result.Anomalies.Count) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('Anomalies:')
        foreach ($a in ($Result.Anomalies | Select-Object -First 12)) { [void]$sb.AppendLine("- $($a.Label) ($($a.Anomaly.timebase)): $($a.Anomaly.kind) - $($a.Anomaly.detail)$(if ($a.Anomaly.kind -eq 'step') { " at $($a.Anomaly.atUtc)" })") }
        if ($Result.Anomalies.Count -gt 12) { [void]$sb.AppendLine("- ... $($Result.Anomalies.Count - 12) more in the report") }
    }
    if ($Result.Excluded.Count) { [void]$sb.AppendLine(); [void]$sb.AppendLine("Not compared (constant or too few buckets): $($Result.Excluded.Count) counter(s), listed in the report.") }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine("Report: ``$ReportPath``. Pre-verdicts are statistical; a correlation does not show which counter causes the other.")
    return $sb.ToString()
}

function ConvertTo-CorrelationData($Result) {
    $entry = { param($c) [ordered]@{ label = $c.Entry.Label; object = [string]$c.Entry.Object.path; counter = [string]$c.Entry.Counter.name; code = $c.Entry.Counter.code } }
    return [ordered]@{
        tool       = 'perf-counter-analyzer'
        toolVersion = $Result.ToolVersion
        inputs     = @($Result.Datasets | ForEach-Object { $_.Path })
        aggregate  = $Result.Aggregate
        timebases  = $Result.Timebases
        minPoints  = $Result.MinPoints
        maxLag     = $Result.MaxLag
        pairs      = @($Result.Pairs | ForEach-Object {
                [ordered]@{ a = (& $entry $_.A); b = (& $entry $_.B); verdict = $_.Verdict; measures = @($_.Measures) }
            })
        anomalies  = @($Result.Anomalies | ForEach-Object { [ordered]@{ counter = $_.Label; timebase = $_.Anomaly.timebase; kind = $_.Anomaly.kind; detail = $_.Anomaly.detail; atUtc = $_.Anomaly.atUtc } })
        excluded   = @($Result.Excluded | ForEach-Object { [ordered]@{ counter = $_.Entry.Label; reason = $_.Reason } })
    }
}
