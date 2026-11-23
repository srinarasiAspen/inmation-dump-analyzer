# PNG charts with the .NET Framework chart control (System.Windows.Forms.DataVisualization ships with Windows PowerShell
# 5.1; nothing to install). Needs PerfData.ps1.

$script:PerfChartReady = $false

function Initialize-PerfChart {
    if ($script:PerfChartReady) { return }
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Windows.Forms.DataVisualization
    $script:PerfChartReady = $true
}

function Get-PerfColor([string]$Name, [int]$Alpha = 255) {
    $rgb = switch ($Name) {
        'avg' { 31, 119, 180 } 'min' { 44, 160, 44 } 'max' { 214, 39, 40 } 'sum' { 148, 103, 189 } 'num' { 127, 127, 127 }
        'a' { 31, 119, 180 } 'b' { 255, 127, 14 } default { 0, 0, 0 }
    }
    return [Drawing.Color]::FromArgb($Alpha, $rgb[0], $rgb[1], $rgb[2])
}

function Get-PerfAxisFormat([string]$Timebase) {
    switch ($Timebase) { 'second' { return 'HH:mm:ss' } 'minute' { return 'HH:mm' } 'hour' { return 'MM-dd HH:mm' } default { return 'yyyy-MM-dd' } }
}

function ConvertTo-PerfDate($Ms) { return ([DateTimeOffset]::FromUnixTimeMilliseconds([int64]$Ms)).UtcDateTime }

$script:PerfChartHeaderPx = 84

# Title, subtitle and legend are placed in the top $PerfChartHeaderPx pixels; chart areas are positioned by the caller
# below that (auto docking would overlap manually positioned areas).
function New-PerfChartControl([int]$Width, [int]$Height, [string]$Title, [string]$Subtitle) {
    Initialize-PerfChart
    $pct = { param([double]$Px) [float](100.0 * $Px / $Height) }
    $chart = New-Object System.Windows.Forms.DataVisualization.Charting.Chart
    $chart.Width = $Width
    $chart.Height = $Height
    $chart.BackColor = [Drawing.Color]::White
    $chart.AntiAliasing = [System.Windows.Forms.DataVisualization.Charting.AntiAliasingStyles]::All
    $chart.TextAntiAliasingQuality = [System.Windows.Forms.DataVisualization.Charting.TextAntiAliasingQuality]::High
    $t = $chart.Titles.Add($Title)
    $t.Font = New-Object Drawing.Font('Segoe UI', 14, [Drawing.FontStyle]::Bold)
    $t.Position = New-Object System.Windows.Forms.DataVisualization.Charting.ElementPosition(0, 0, 100, (& $pct 32))
    if ($Subtitle) {
        $s = $chart.Titles.Add($Subtitle)
        $s.Font = New-Object Drawing.Font('Segoe UI', 9)
        $s.Position = New-Object System.Windows.Forms.DataVisualization.Charting.ElementPosition(0, (& $pct 32), 100, (& $pct 20))
    }
    $legend = New-Object System.Windows.Forms.DataVisualization.Charting.Legend('main')
    $legend.Alignment = [Drawing.StringAlignment]::Center
    $legend.Font = New-Object Drawing.Font('Segoe UI', 9)
    $legend.TextWrapThreshold = 0
    $legend.MaximumAutoSize = 100
    $legend.Position = New-Object System.Windows.Forms.DataVisualization.Charting.ElementPosition(0, (& $pct 54), 100, (& $pct 28))
    $chart.Legends.Add($legend)
    return $chart
}

function Add-PerfChartArea($Chart, [string]$Name, [string]$Timebase, [string]$Caption, [double]$Top, [double]$Height) {
    $area = $Chart.ChartAreas.Add($Name)
    $area.Position = New-Object System.Windows.Forms.DataVisualization.Charting.ElementPosition(0, [float]$Top, 100, [float]$Height)
    $area.AxisX.LabelStyle.Format = Get-PerfAxisFormat $Timebase
    $area.AxisX.LabelStyle.Font = New-Object Drawing.Font('Segoe UI', 8)
    $area.AxisY.LabelStyle.Font = New-Object Drawing.Font('Segoe UI', 8)
    $area.AxisX.MajorGrid.LineColor = [Drawing.Color]::Gainsboro
    $area.AxisY.MajorGrid.LineColor = [Drawing.Color]::Gainsboro
    $area.AxisY2.MajorGrid.Enabled = $false
    $area.AxisY.IsStartedFromZero = $false
    $area.AxisX.IsMarginVisible = $true
    $title = $Chart.Titles.Add($Caption)
    $title.DockedToChartArea = $Name
    $title.IsDockedInsideChartArea = $false
    $title.Alignment = [Drawing.ContentAlignment]::TopLeft
    $title.Font = New-Object Drawing.Font('Segoe UI', 10, [Drawing.FontStyle]::Bold)
    return $area
}

function New-PerfSeriesObject([string]$Name, [string]$Area, $ChartType, [Drawing.Color]$Color, [bool]$InLegend) {
    $s = New-Object System.Windows.Forms.DataVisualization.Charting.Series($Name)
    $s.ChartArea = $Area
    $s.Legend = 'main'
    $s.ChartType = $ChartType
    $s.Color = $Color
    $s.XValueType = [System.Windows.Forms.DataVisualization.Charting.ChartValueType]::DateTime
    $s.IsVisibleInLegend = $InLegend
    return $s
}

# One PNG per counter: a panel per timebase with the selected aggregates. min+max are drawn as a band; sum and num use
# the right axis. The bucket that is still filling is a hollow marker and not part of the lines.
function New-PerfCounterChart($Data, $Object, $Counter, [string[]]$Aggregates, [string]$Path, [string[]]$Timebases) {
    $tbs = @(if ($Timebases) { $Timebases } else { $script:PerfTimebases | ForEach-Object { $_.Name } })
    $aggs = @($Aggregates | ForEach-Object { $_.ToLowerInvariant() } | Where-Object { $script:PerfAggregates -contains $_ })
    if ($aggs.Count -eq 0) { $aggs = @('avg', 'min', 'max') }
    $band = ($aggs -contains 'min') -and ($aggs -contains 'max')
    $subtitle = "code $($Counter.code) | $($Data.module.name) $($Data.module.fileVersion) | dump taken $($Data.dump.dumpTimeUtc) | times UTC (bucket start)"
    $height = 330 * $tbs.Count + $script:PerfChartHeaderPx + 10
    $chart = New-PerfChartControl 1400 $height "$($Counter.name)  -  $($Object.path)" $subtitle
    try {
        $top = [double](100.0 * $script:PerfChartHeaderPx / $height)
        $h = (100 - $top - 0.5) / $tbs.Count
        for ($i = 0; $i -lt $tbs.Count; $i++) {
            $tb = $tbs[$i]
            $info = $script:PerfTimebases | Where-Object { $_.Name -eq $tb }
            $series = Get-PerfTimebaseSeries $Counter $tb
            $t = @(Get-SeriesValues $series 't')
            $caption = "$tb buckets ($($info.Retention))"
            if ($t.Count -eq 0) { $caption += ' - no data' }
            elseif ($t.Count -eq 1) { $caption += ' - only the bucket that is still filling' }
            $area = Add-PerfChartArea $chart $tb $tb $caption ($top + $i * $h) $h
            if ($t.Count -eq 0) { continue }
            if ($tb -eq 'day') {
                $area.AxisX.IntervalType = [System.Windows.Forms.DataVisualization.Charting.DateTimeIntervalType]::Days
                $area.AxisX.Interval = [Math]::Max(1, [Math]::Ceiling($t.Count / 15))
            }
            $x = @($t | ForEach-Object { ConvertTo-PerfDate $_ })
            $last = $t.Count - 1
            $legend = ($i -eq 0)
            if ($band) {
                $min = @(Get-SeriesValues $series 'min'); $max = @(Get-SeriesValues $series 'max')
                $s = New-PerfSeriesObject 'min - max' $tb ([System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Range) (Get-PerfColor 'avg' 50) $legend
                $s.Name = "range-$tb"
                $s.YValuesPerPoint = 2
                $s.LegendText = 'min - max per bucket'
                $s.BorderColor = Get-PerfColor 'avg' 110
                $s.BorderWidth = 1
                for ($k = 0; $k -lt $last; $k++) { if ($null -ne $min[$k] -and $null -ne $max[$k]) { [void]$s.Points.AddXY($x[$k], $min[$k], $max[$k]) } }
                $chart.Series.Add($s)
            }
            foreach ($a in $aggs) {
                if ($band -and ($a -eq 'min' -or $a -eq 'max')) { continue }
                $values = @(Get-SeriesValues $series $a)
                $secondary = ($a -eq 'sum' -or $a -eq 'num')
                $s = New-PerfSeriesObject "$a-$tb" $tb ([System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line) (Get-PerfColor $a) $legend
                $s.LegendText = if ($secondary) { "$a (right axis)" } else { $a }
                $s.BorderWidth = if ($a -eq 'avg') { 2 } else { 1 }
                if ($secondary) {
                    $s.YAxisType = [System.Windows.Forms.DataVisualization.Charting.AxisType]::Secondary
                    $s.BorderDashStyle = [System.Windows.Forms.DataVisualization.Charting.ChartDashStyle]::Dash
                }
                for ($k = 0; $k -lt $last; $k++) { if ($null -ne $values[$k]) { [void]$s.Points.AddXY($x[$k], $values[$k]) } }
                $chart.Series.Add($s)
                if ($null -ne $values[$last]) {
                    $p = New-PerfSeriesObject "$a-$tb-open" $tb ([System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Point) (Get-PerfColor $a) ($legend -and $a -eq $aggs[0])
                    $p.LegendText = 'last bucket, still filling'
                    $p.MarkerStyle = [System.Windows.Forms.DataVisualization.Charting.MarkerStyle]::Circle
                    $p.MarkerSize = 9
                    $p.MarkerColor = [Drawing.Color]::White
                    $p.MarkerBorderColor = Get-PerfColor $a
                    $p.MarkerBorderWidth = 2
                    if ($secondary) { $p.YAxisType = [System.Windows.Forms.DataVisualization.Charting.AxisType]::Secondary }
                    [void]$p.Points.AddXY($x[$last], $values[$last])
                    $chart.Series.Add($p)
                }
            }
            if (@($aggs | Where-Object { $_ -eq 'sum' -or $_ -eq 'num' }).Count) { $area.AxisY2.Enabled = [System.Windows.Forms.DataVisualization.Charting.AxisEnabled]::True }
        }
        $chart.SaveImage($Path, [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Png)
    }
    finally { $chart.Dispose() }
}

function Format-PerfR($Value) { if ($null -eq $Value) { return '-' } return ([double]$Value).ToString('0.00', [Globalization.CultureInfo]::InvariantCulture) }

# Two counters over time: A on the left axis, B on the right axis, one panel per compared timebase (complete buckets).
# $BucketsA/$BucketsB: timebase -> Get-CompleteBuckets result.
function New-PerfPairChart([string]$LabelA, [string]$LabelB, $Measures, [hashtable]$BucketsA, [hashtable]$BucketsB, [string]$Subtitle, [string]$Path) {
    $tbs = @($Measures | Where-Object { $_.n -gt 0 } | ForEach-Object { $_.timebase })
    if ($tbs.Count -eq 0) { return $false }
    $height = 300 * $tbs.Count + $script:PerfChartHeaderPx + 10
    $chart = New-PerfChartControl 1400 $height "$LabelA   vs   $LabelB" $Subtitle
    try {
        $top = [double](100.0 * $script:PerfChartHeaderPx / $height)
        $h = (100 - $top - 0.5) / $tbs.Count
        for ($i = 0; $i -lt $tbs.Count; $i++) {
            $tb = $tbs[$i]
            $m = $Measures | Where-Object { $_.timebase -eq $tb } | Select-Object -First 1
            $lagText = if ($null -ne $m.lag) { ", best lag of changes $('{0:+0;-0}' -f $m.lag) bucket(s): r $(Format-PerfR $m.lagR)" } else { '' }
            $caption = "$tb buckets: r $(Format-PerfR $m.r), changes r $(Format-PerfR $m.dr), rank r $(Format-PerfR $m.rho)$lagText, n $($m.n)"
            $area = Add-PerfChartArea $chart $tb $tb $caption ($top + $i * $h) $h
            $area.AxisY2.Enabled = [System.Windows.Forms.DataVisualization.Charting.AxisEnabled]::True
            $area.AxisY.LineColor = Get-PerfColor 'a'; $area.AxisY.LabelStyle.ForeColor = Get-PerfColor 'a'
            $area.AxisY2.LineColor = Get-PerfColor 'b'; $area.AxisY2.LabelStyle.ForeColor = Get-PerfColor 'b'
            $area.AxisY2.IsStartedFromZero = $false
            foreach ($side in 'a', 'b') {
                $b = if ($side -eq 'a') { $BucketsA[$tb] } else { $BucketsB[$tb] }
                $s = New-PerfSeriesObject "$side-$tb" $tb ([System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Line) (Get-PerfColor $side) ($i -eq 0)
                $s.LegendText = if ($side -eq 'a') { "$LabelA (left axis)" } else { "$LabelB (right axis)" }
                $s.BorderWidth = 2
                if ($side -eq 'b') { $s.YAxisType = [System.Windows.Forms.DataVisualization.Charting.AxisType]::Secondary }
                for ($k = 0; $k -lt $b.Count; $k++) { [void]$s.Points.AddXY((ConvertTo-PerfDate $b.T[$k]), $b.V[$k]) }
                $chart.Series.Add($s)
            }
        }
        $chart.SaveImage($Path, [System.Windows.Forms.DataVisualization.Charting.ChartImageFormat]::Png)
    }
    finally { $chart.Dispose() }
    return $true
}

function Get-HeatColor($R) {
    if ($null -eq $R) { return [Drawing.Color]::FromArgb(235, 235, 235) }
    $v = [Math]::Max(-1.0, [Math]::Min(1.0, [double]$R))
    $f = [int](255 * (1 - [Math]::Abs($v)))
    if ($v -ge 0) { return [Drawing.Color]::FromArgb(255, $f, $f) }
    return [Drawing.Color]::FromArgb($f, $f, 255)
}

# Correlation matrix as a heat map: red = move together, blue = opposite, grey = not compared. $R: "i|j" -> r.
function New-PerfHeatmap([string[]]$Labels, [hashtable]$R, [string]$Title, [string]$Path) {
    Initialize-PerfChart
    $n = $Labels.Count
    $cell = if ($n -le 20) { 34 } elseif ($n -le 40) { 22 } else { 14 }
    $font = New-Object Drawing.Font('Segoe UI', $(if ($n -le 40) { 8 } else { 7 }))
    $titleFont = New-Object Drawing.Font('Segoe UI', 12, [Drawing.FontStyle]::Bold)
    $probe = New-Object Drawing.Bitmap(1, 1)
    $g0 = [Drawing.Graphics]::FromImage($probe)
    $labelW = 40
    foreach ($l in $Labels) { $labelW = [Math]::Max($labelW, [int]$g0.MeasureString($l, $font).Width + 8) }
    $g0.Dispose(); $probe.Dispose()
    $labelW = [Math]::Min($labelW, 420)
    $left = $labelW + 10; $top = 40 + $labelW
    $width = $left + $n * $cell + 30; $height = $top + $n * $cell + 50
    $bmp = New-Object Drawing.Bitmap($width, $height)
    $g = [Drawing.Graphics]::FromImage($bmp)
    try {
        $g.Clear([Drawing.Color]::White)
        $g.TextRenderingHint = [Drawing.Text.TextRenderingHint]::ClearTypeGridFit
        $g.DrawString($Title, $titleFont, [Drawing.Brushes]::Black, 10, 8)
        $right = New-Object Drawing.StringFormat
        $right.Alignment = [Drawing.StringAlignment]::Far
        $right.LineAlignment = [Drawing.StringAlignment]::Center
        $center = New-Object Drawing.StringFormat
        $center.Alignment = [Drawing.StringAlignment]::Center
        $center.LineAlignment = [Drawing.StringAlignment]::Center
        for ($i = 0; $i -lt $n; $i++) {
            $g.DrawString($Labels[$i], $font, [Drawing.Brushes]::Black, (New-Object Drawing.RectangleF(0, ($top + $i * $cell), ($left - 6), $cell)), $right)
            $state = $g.Save()
            $g.TranslateTransform(($left + $i * $cell), ($top - 6))
            $g.RotateTransform(-90)
            $g.DrawString($Labels[$i], $font, [Drawing.Brushes]::Black, (New-Object Drawing.RectangleF(0, 0, $labelW, $cell)))
            $g.Restore($state)
            for ($j = 0; $j -lt $n; $j++) {
                $value = if ($i -eq $j) { 1.0 } elseif ($R.ContainsKey("$i|$j")) { $R["$i|$j"] } elseif ($R.ContainsKey("$j|$i")) { $R["$j|$i"] } else { $null }
                $rect = New-Object Drawing.Rectangle(($left + $j * $cell), ($top + $i * $cell), $cell, $cell)
                $brush = New-Object Drawing.SolidBrush(Get-HeatColor $value)
                $g.FillRectangle($brush, $rect); $brush.Dispose()
                $g.DrawRectangle([Drawing.Pens]::White, $rect)
                if ($null -ne $value -and $cell -ge 22 -and $i -ne $j) { $g.DrawString((Format-PerfR $value), $font, [Drawing.Brushes]::Black, [Drawing.RectangleF]$rect, $center) }
            }
        }
        $g.DrawString('red: rise and fall together, blue: opposite, grey: not compared (constant or too few buckets)', $font, [Drawing.Brushes]::DimGray, 10, ($top + $n * $cell + 12))
        $bmp.Save($Path, [Drawing.Imaging.ImageFormat]::Png)
    }
    finally { $g.Dispose(); $bmp.Dispose() }
}
