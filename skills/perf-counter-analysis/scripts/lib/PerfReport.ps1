# Markdown for perf runs: the report (charts + statistics per counter) and the short chat summary. Needs PerfData.ps1.

function Format-PerfCell([string]$Text) { return ($Text -replace '\|', '\|' -replace "`r?`n", ' ') }

function Get-PerfDash($Value) { if ($null -eq $Value -or "$Value" -eq '') { return '-' } return "$Value" }

function Get-RelativePerfPath([string]$From, [string]$To) {
    $base = $From.TrimEnd('\') + '\'
    if ($To.StartsWith($base, [StringComparison]::OrdinalIgnoreCase)) { return ($To.Substring($base.Length) -replace '\\', '/') }
    return $To
}

function Get-PerfHeaderRows($Data) {
    $rows = @()
    foreach ($o in @($Data.objects)) { $rows += "| Object | ``$(Format-PerfCell $o.path)`` (class ``$($o.className)``, $($o.counterCount) counters) |" }
    $dumpText = '`' + $Data.dump.path + '`, taken ' + $Data.dump.dumpTimeUtc
    if ($Data.dump.processId) { $dumpText += ", PID $($Data.dump.processId)" }
    if ($Data.dump.uptime) { $dumpText += ", process uptime $($Data.dump.uptime)" }
    $rows += "| Dump | $dumpText |"
    $rows += "| Build | $($Data.module.name) $($Data.module.fileVersion) |"
    $rows += "| Symbols | $($Data.symbols.loadStatus) ($(Format-PerfCell ([string]$Data.symbols.source))) |"
    $rows += "| Generated | $($Data.tool) $($Data.toolVersion), $($Data.createdUtc) |"
    return $rows
}

$script:PerfTimebaseNote = 'Timebases: `second` buckets cover the last minute, `minute` the last hour, `hour` the last day, `day` the last 30 days. Times are bucket starts in UTC. Per bucket: `avg` = sum/num, `min`/`max` = extreme samples, `num` = number of samples (about one per second for most counters), `sum` = total. The last bucket of each timebase is still filling at dump time (hollow marker in the charts); the statistics use complete buckets only.'

function New-PerfReportMarkdown($Data, $Selected, [string]$ReportDir) {
    $sb = New-Object Text.StringBuilder
    $paths = @($Data.objects | ForEach-Object { $_.path })
    [void]$sb.AppendLine("# Performance counters of $($paths -join ', ')")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Item | Value |')
    [void]$sb.AppendLine('|---|---|')
    foreach ($r in (Get-PerfHeaderRows $Data)) { [void]$sb.AppendLine($r) }
    [void]$sb.AppendLine()
    [void]$sb.AppendLine($script:PerfTimebaseNote)
    $warnings = @($Data.warnings | Where-Object { $_ })
    if ($warnings.Count) {
        [void]$sb.AppendLine()
        [void]$sb.AppendLine('**Warnings**')
        [void]$sb.AppendLine()
        foreach ($w in $warnings) { [void]$sb.AppendLine("- $w") }
    }
    foreach ($o in @($Data.objects)) {
        $mine = @($Selected | Where-Object { $_.Object.path -eq $o.path })
        if ($mine.Count -eq 0) { continue }
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("## $($o.path)")
        [void]$sb.AppendLine()
        [void]$sb.AppendLine("Class ``$($o.className)``, object at $($o.address).")
        foreach ($sel in $mine) {
            $c = $sel.Counter
            [void]$sb.AppendLine()
            [void]$sb.AppendLine("### $($c.name)")
            [void]$sb.AppendLine()
            [void]$sb.AppendLine(('`{0}` = {1}' -f $c.enumName, $c.code))
            if ($sel.Chart) {
                [void]$sb.AppendLine()
                [void]$sb.AppendLine("![$($c.name)]($(Get-RelativePerfPath $ReportDir $sel.Chart))")
            }
            [void]$sb.AppendLine()
            [void]$sb.AppendLine('| Timebase | Complete buckets | From | To | Mean of avg | Min | Max | Max at | Last complete avg | Still filling: avg (samples) | Trend |')
            [void]$sb.AppendLine('|---|---|---|---|---|---|---|---|---|---|---|')
            foreach ($tb in $script:PerfTimebases) {
                $s = Get-PerfTimebaseStats $c $tb.Name
                $open = if ($null -ne $s.inProgress) { "$(Format-PerfValue $s.inProgress) ($(Format-PerfValue $s.inProgressSamples))" } else { '-' }
                [void]$sb.AppendLine(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} | {10} |' -f $tb.Name, $s.complete, (Get-PerfDash $s.fromUtc), (Get-PerfDash $s.toUtc), (Format-PerfValue $s.mean), (Format-PerfValue $s.min), (Format-PerfValue $s.max), (Get-PerfDash $s.maxAtUtc), (Format-PerfValue $s.lastComplete), $open, $s.trend))
            }
        }
    }
    return $sb.ToString()
}

# Chat answer: one row per counter (last minute, last hour, last day) with the trend of the minute buckets.
function New-PerfSummaryMarkdown($Data, $Selected, [string]$ReportPath) {
    $sb = New-Object Text.StringBuilder
    $objects = @($Data.objects | ForEach-Object { "**$($_.path)** (``$($_.className)``)" })
    [void]$sb.AppendLine("$($objects -join ', '); $($Data.module.name) $($Data.module.fileVersion), dump taken $($Data.dump.dumpTimeUtc).")
    [void]$sb.AppendLine()
    [void]$sb.AppendLine('| Object | Counter | Last minute (second buckets): mean / max | Last hour (minute buckets): mean / min / max | Last day (hour buckets): mean / max | Trend (minute buckets) | Chart |')
    [void]$sb.AppendLine('|---|---|---|---|---|---|---|')
    foreach ($sel in $Selected) {
        $c = $sel.Counter
        $sec = Get-PerfTimebaseStats $c 'second'
        $min = Get-PerfTimebaseStats $c 'minute'
        $hour = Get-PerfTimebaseStats $c 'hour'
        $chart = if ($sel.Chart) { '`' + $sel.Chart + '`' } else { '-' }
        [void]$sb.AppendLine(('| {0} | {1} | {2} / {3} | {4} / {5} / {6} | {7} / {8} | {9} | {10} |' -f (Format-PerfCell $sel.Object.path), $c.name, (Format-PerfValue $sec.mean), (Format-PerfValue $sec.max), (Format-PerfValue $min.mean), (Format-PerfValue $min.min), (Format-PerfValue $min.max), (Format-PerfValue $hour.mean), (Format-PerfValue $hour.max), $min.trend, $chart))
    }
    [void]$sb.AppendLine()
    foreach ($w in @($Data.warnings | Where-Object { $_ })) { [void]$sb.AppendLine("Warning: $w") }
    [void]$sb.AppendLine("Report: ``$ReportPath``. Statistics use complete buckets only; the last bucket of each timebase is still filling at dump time.")
    return $sb.ToString()
}
