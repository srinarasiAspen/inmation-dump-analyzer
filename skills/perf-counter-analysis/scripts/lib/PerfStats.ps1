# Correlation statistics for performance counters (pure PowerShell). Needs PerfData.ps1.
# Pairs are compared per timebase on complete buckets with the same bucket start; the bucket that is still filling is
# left out. Measures: r (Pearson, levels), dr (Pearson of bucket-to-bucket changes: filters out two counters that only
# drift together), rho (Spearman, robust to outliers), best lag of the changes (which counter moves first).

$script:CorrelationVerdictOrder = @{ 'strong' = 0; 'lagged' = 1; 'moderate' = 2; 'inconsistent' = 3; 'trend-only' = 4; 'same-signal' = 5; 'none' = 6 }

# Bucket-to-bucket changes needed before 'changes r' and lags count as evidence: with fewer changes (step-like
# counters) one coincident change already gives a perfect correlation.
$script:MinChanges = 5

function Get-Pearson([double[]]$X, [double[]]$Y) {
    $n = $X.Length
    if ($n -lt 3 -or $Y.Length -ne $n) { return $null }
    $sx = 0.0; $sy = 0.0
    for ($i = 0; $i -lt $n; $i++) { $sx += $X[$i]; $sy += $Y[$i] }
    $mx = $sx / $n; $my = $sy / $n
    $sxx = 0.0; $syy = 0.0; $sxy = 0.0
    for ($i = 0; $i -lt $n; $i++) {
        $dx = $X[$i] - $mx; $dy = $Y[$i] - $my
        $sxx += $dx * $dx; $syy += $dy * $dy; $sxy += $dx * $dy
    }
    # Constant series (within floating point noise) have no correlation.
    if ($sxx -le 1e-12 * $n * ($mx * $mx + 1) -or $syy -le 1e-12 * $n * ($my * $my + 1)) { return $null }
    $r = $sxy / [Math]::Sqrt($sxx * $syy)
    return [Math]::Max(-1.0, [Math]::Min(1.0, $r))
}

# Ranks 1..n, ties get their average rank.
function Get-Ranks([double[]]$X) {
    $n = $X.Length
    $idx = [int[]](0..($n - 1))
    $keys = [double[]]$X.Clone()
    [Array]::Sort($keys, $idx)
    $ranks = New-Object double[] $n
    $i = 0
    while ($i -lt $n) {
        $j = $i
        while ($j + 1 -lt $n -and $keys[$j + 1] -eq $keys[$i]) { $j++ }
        $avg = ($i + $j) / 2.0 + 1
        for ($k = $i; $k -le $j; $k++) { $ranks[$idx[$k]] = $avg }
        $i = $j + 1
    }
    return , $ranks
}

function Get-Spearman([double[]]$X, [double[]]$Y) {
    if ($X.Length -lt 3) { return $null }
    return Get-Pearson (Get-Ranks $X) (Get-Ranks $Y)
}

function Get-Differences([double[]]$X) {
    if ($X.Length -lt 2) { return , ([double[]]@()) }
    $d = New-Object double[] ($X.Length - 1)
    for ($i = 1; $i -lt $X.Length; $i++) { $d[$i - 1] = $X[$i] - $X[$i - 1] }
    return , $d
}

# Best correlation of X[t] with Y[t + lag] for lag in -MaxLag..MaxLag (lag 0 excluded). Positive lag: Y follows X.
function Get-BestLag([double[]]$X, [double[]]$Y, [int]$MaxLag, [int]$MinPoints) {
    $best = $null
    $n = $X.Length
    for ($lag = -$MaxLag; $lag -le $MaxLag; $lag++) {
        if ($lag -eq 0) { continue }
        $m = $n - [Math]::Abs($lag)
        if ($m -lt $MinPoints) { continue }
        if ($lag -gt 0) { $a = [double[]]$X[0..($m - 1)]; $b = [double[]]$Y[$lag..($n - 1)] }
        else { $a = [double[]]$X[(-$lag)..($n - 1)]; $b = [double[]]$Y[0..($m - 1)] }
        $r = Get-Pearson $a $b
        if ($null -ne $r -and ($null -eq $best -or [Math]::Abs($r) -gt [Math]::Abs($best.R))) { $best = [pscustomobject]@{ Lag = $lag; R = $r; N = $m } }
    }
    return $best
}

# Standard normal CDF (Abramowitz-Stegun 7.1.26, error < 1.5e-7).
function Get-NormalCdf([double]$Z) {
    $x = [Math]::Abs($Z) / [Math]::Sqrt(2)
    $t = 1 / (1 + 0.3275911 * $x)
    $erf = 1 - (((((1.061405429 * $t - 1.453152027) * $t) + 1.421413741) * $t - 0.284496736) * $t + 0.254829592) * $t * [Math]::Exp(-$x * $x)
    if ($Z -ge 0) { return 0.5 * (1 + $erf) }
    return 0.5 * (1 - $erf)
}

# Two-sided p-value of a correlation (Fisher z).
function Get-CorrelationPValue([double]$R, [int]$N) {
    if ($N -lt 4) { return 1.0 }
    $a = [Math]::Min([Math]::Abs($R), 0.999999)
    $z = 0.5 * [Math]::Log((1 + $a) / (1 - $a)) * [Math]::Sqrt($N - 3)
    return [Math]::Max(0.0, 2 * (1 - (Get-NormalCdf $z)))
}

# Complete buckets of one counter and timebase (aggregate values), without the bucket that is still filling:
# T = bucket starts (sorted), V = values, Map = T -> V.
function Get-CompleteBuckets($Counter, [string]$Timebase, [string]$Aggregate) {
    $series = Get-PerfTimebaseSeries $Counter $Timebase
    $t = @(Get-SeriesValues $series 't')
    $v = @(Get-SeriesValues $series $Aggregate)
    $map = @{}
    for ($i = 0; $i -lt $t.Count - 1; $i++) { if ($null -ne $v[$i]) { $map[[int64]$t[$i]] = [double]$v[$i] } }
    $keys = [int64[]]@($map.Keys)
    [Array]::Sort($keys)
    $values = New-Object double[] $keys.Length
    for ($i = 0; $i -lt $keys.Length; $i++) { $values[$i] = $map[$keys[$i]] }
    return [pscustomobject]@{ T = $keys; V = $values; Map = $map; Count = $keys.Length }
}

function Get-AlignedValues($A, $B) {
    $same = $A.Count -eq $B.Count
    for ($i = 0; $same -and $i -lt $A.Count; $i++) { if ($A.T[$i] -ne $B.T[$i]) { $same = $false } }
    if ($same) { return [pscustomobject]@{ X = $A.V; Y = $B.V; T = $A.T } }
    $x = New-Object Collections.Generic.List[double]
    $y = New-Object Collections.Generic.List[double]
    $t = New-Object Collections.Generic.List[int64]
    for ($i = 0; $i -lt $A.Count; $i++) {
        if ($B.Map.ContainsKey($A.T[$i])) { $x.Add($A.V[$i]); $y.Add($B.Map[$A.T[$i]]); $t.Add($A.T[$i]) }
    }
    return [pscustomobject]@{ X = $x.ToArray(); Y = $y.ToArray(); T = $t.ToArray() }
}

function Get-ChangeCount([double[]]$Differences, [double[]]$Values) {
    $scale = 0.0
    foreach ($v in $Values) { $scale = [Math]::Max($scale, [Math]::Abs($v)) }
    $eps = 1e-9 * [Math]::Max($scale, 1.0)
    $n = 0
    foreach ($d in $Differences) { if ([Math]::Abs($d) -gt $eps) { $n++ } }
    return $n
}

function Measure-PairTimebase($A, $B, [string]$Timebase, [int]$MinPoints, [int]$MaxLag) {
    $al = Get-AlignedValues $A $B
    $n = $al.X.Length
    $result = [ordered]@{ timebase = $Timebase; n = $n; r = $null; p = $null; rho = $null; dr = $null; drP = $null; changes = 0; lag = $null; lagR = $null; lagP = $null }
    if ($n -lt $MinPoints) { return [pscustomobject]$result }
    $result.r = Get-Pearson $al.X $al.Y
    if ($null -ne $result.r) { $result.p = Get-CorrelationPValue $result.r $n }
    $result.rho = Get-Spearman $al.X $al.Y
    $dx = Get-Differences $al.X
    $dy = Get-Differences $al.Y
    $result.changes = [Math]::Min((Get-ChangeCount $dx $al.X), (Get-ChangeCount $dy $al.Y))
    $result.dr = Get-Pearson $dx $dy
    if ($null -ne $result.dr) { $result.drP = Get-CorrelationPValue $result.dr ($n - 1) }
    if ($MaxLag -gt 0) {
        $best = Get-BestLag $dx $dy $MaxLag ([Math]::Max(5, $MinPoints - 1))
        if ($best) { $result.lag = $best.Lag; $result.lagR = $best.R; $result.lagP = Get-CorrelationPValue $best.R $best.N }
    }
    return [pscustomobject]$result
}

function Get-Abs($Value) { if ($null -eq $Value) { return 0.0 } return [Math]::Abs([double]$Value) }

# Ranking score of a measure: mean of |r|, |changes r| and |rank r| - robust pairs rank above pairs driven by outliers.
function Get-PairScore($Measure) { return ((Get-Abs $Measure.r) + (Get-Abs $Measure.dr) + (Get-Abs $Measure.rho)) / 3 }

# Pre-verdict of a pair from its per-timebase measures (thresholds are documented in references/correlation.md).
# "Enough changes": both counters change in at least $MinChanges buckets of the timebase.
#   same-signal  |r| >= 0.97 and (|dr| >= 0.97 or too few changes) in every compared timebase, with enough changes in
#                at least one: one counter is derived from the other or both come from the same value - not a finding
#   strong       |r| >= 0.8, p < 0.01, |dr| >= 0.5, |rho| >= 0.6 (not driven by a few extreme buckets), enough changes
#   lagged       changes correlate best shifted by 1..MaxLag buckets: |lag r| >= 0.6, p < 0.01, |lag r| >= |dr| + 0.2,
#                enough changes
#   moderate     enough changes, p(dr) < 0.01 and either |r| >= 0.5, p < 0.05, |dr| >= 0.3 (levels) or |dr| >= 0.5
#                (changes alone: spikes and dips coincide while the levels drift differently)
#   inconsistent |r| >= 0.5 with opposite signs in different timebases
#   trend-only   |r| >= 0.5 and |rho| >= 0.5, but the changes do not correlate (or are too few): both only drift or
#                step together (a high r with a low rho comes from a few extreme buckets: none)
#   none         otherwise
function Get-PairVerdict($Measures) {
    $valid = @($Measures | Where-Object { $null -ne $_.r })
    $result = [ordered]@{ verdict = 'none'; direction = $null; timebase = $null; r = $null; dr = $null; rho = $null; changes = $null; lag = $null; lagR = $null; n = $null; p = $null }
    if ($valid.Count -eq 0) { return [pscustomobject]$result }
    $enough = { $_.changes -ge $script:MinChanges }
    $signs = @($valid | Where-Object { (Get-Abs $_.r) -ge 0.5 } | ForEach-Object { [Math]::Sign([double]$_.r) } | Select-Object -Unique)
    $same = @($valid | Where-Object { (Get-Abs $_.r) -ge 0.97 -and ((Get-Abs $_.dr) -ge 0.97 -or -not (& $enough)) })
    $strong = @($valid | Where-Object { (Get-Abs $_.r) -ge 0.8 -and $_.p -lt 0.01 -and (Get-Abs $_.dr) -ge 0.5 -and (Get-Abs $_.rho) -ge 0.6 -and (& $enough) })
    $moderate = @($valid | Where-Object { (& $enough) -and $_.drP -lt 0.01 -and (((Get-Abs $_.r) -ge 0.5 -and $_.p -lt 0.05 -and (Get-Abs $_.dr) -ge 0.3) -or (Get-Abs $_.dr) -ge 0.5) })
    $lagged = @($Measures | Where-Object { $null -ne $_.lagR -and (Get-Abs $_.lagR) -ge 0.6 -and $_.lagP -lt 0.01 -and (Get-Abs $_.lagR) -ge (Get-Abs $_.dr) + 0.2 -and (& $enough) })
    $trend = @($valid | Where-Object { (Get-Abs $_.r) -ge 0.5 -and (Get-Abs $_.rho) -ge 0.5 })
    $pick = $null
    if ($same.Count -eq $valid.Count -and @($same | Where-Object { & $enough }).Count -ge 1 -and $signs.Count -le 1) { $result.verdict = 'same-signal'; $pick = $same }
    elseif ($signs.Count -gt 1) { $result.verdict = 'inconsistent'; $pick = @($valid | Where-Object { (Get-Abs $_.r) -ge 0.5 }) }
    elseif ($strong.Count) { $result.verdict = 'strong'; $pick = $strong }
    elseif ($lagged.Count) { $result.verdict = 'lagged'; $pick = $lagged }
    elseif ($moderate.Count) { $result.verdict = 'moderate'; $pick = $moderate }
    elseif ($trend.Count) { $result.verdict = 'trend-only'; $pick = $trend }
    else { $pick = $valid }
    $bestKey = switch ($result.verdict) {
        'lagged' { { Get-Abs $_.lagR } }
        default { { Get-PairScore $_ } }
    }
    $best = $pick | Sort-Object $bestKey -Descending | Select-Object -First 1
    foreach ($k in 'timebase', 'r', 'dr', 'rho', 'changes', 'lag', 'lagR', 'n', 'p') { $result[$k] = $best.$k }
    # Direction from what carries the evidence: the lag, the changes (when the levels are weak) or the levels.
    $basis = if ($result.verdict -eq 'lagged') { $best.lagR } elseif ((Get-Abs $best.r) -lt 0.5 -and $null -ne $best.dr) { $best.dr } else { $best.r }
    $sign = [Math]::Sign([double]$basis)
    $result.direction = if ($result.verdict -eq 'none' -or $result.verdict -eq 'inconsistent') { $null } elseif ($sign -ge 0) { 'together' } else { 'opposite' }
    return [pscustomobject]$result
}

function Get-Median([double[]]$X) {
    $s = [double[]]$X.Clone()
    [Array]::Sort($s)
    $n = $s.Length
    if ($n -eq 0) { return $null }
    if ($n % 2) { return $s[($n - 1) / 2] }
    return ($s[$n / 2 - 1] + $s[$n / 2]) / 2
}

# Anomalies of one counter in one timebase (complete buckets of avg; bucket max for spikes). Cumulative counters
# (never falling) are skipped.
#   spike     robust z-score (median/MAD) >= 5 of the bucket maximum and >= 25% above the median, at most 10% of buckets
#   step      best split into two segments (>= 5 buckets each) with a mean change >= 3 pooled standard deviations,
#             >= 5% of the level, and a fit clearly better than a straight line (residuals < half; not a ramp)
#   trend     |Spearman(bucket index, avg)| >= 0.8 over >= 8 buckets, change >= 5% of the level
function Get-PerfAnomalies($Counter, [string]$Timebase) {
    $found = @()
    $avgB = Get-CompleteBuckets $Counter $Timebase 'avg'
    $maxB = Get-CompleteBuckets $Counter $Timebase 'max'
    $times = $avgB.T
    $avg = $avgB.V
    $n = $avg.Length
    if ($n -lt 8) { return $found }
    # Cumulative counters (never falling, e.g. *_TOTAL) rise by design; steps and trends would be noise.
    $falls = 0; $rises = 0
    for ($i = 1; $i -lt $n; $i++) { if ($avg[$i] -lt $avg[$i - 1]) { $falls++ } elseif ($avg[$i] -gt $avg[$i - 1]) { $rises++ } }
    if ($falls -eq 0 -and $rises -gt 0 -and ($Counter.name -match '_TOTAL$' -or $rises -ge ($n - 1) / 2)) { return $found }
    if ($maxB.Count -ge 8) {
        $mx = $maxB.V
        $med = Get-Median $mx
        $dev = New-Object double[] $mx.Length
        for ($i = 0; $i -lt $mx.Length; $i++) { $dev[$i] = [Math]::Abs($mx[$i] - $med) }
        $mad = Get-Median $dev
        if ($mad -gt 0) {
            # Robust z >= 5 and at least 25% above the median bucket maximum.
            $spikes = @(for ($i = 0; $i -lt $mx.Length; $i++) { $z = 0.6745 * ($mx[$i] - $med) / $mad; if ($z -ge 5 -and ($mx[$i] - $med) -ge 0.25 * [Math]::Abs($med)) { [pscustomobject]@{ T = $maxB.T[$i]; V = $mx[$i] } } })
            if ($spikes.Count -gt 0 -and $spikes.Count -le [Math]::Max(1, [Math]::Floor($mx.Length / 10))) {
                $ordered = @($spikes | Sort-Object V -Descending)
                $top = @($ordered | Select-Object -First 3 | ForEach-Object { "$(Format-PerfValue $_.V) at $(Format-PerfTime $_.T)" })
                $found += [pscustomobject]@{ timebase = $Timebase; kind = 'spike'; detail = "bucket max $($top -join ', ') (median of bucket max $(Format-PerfValue $med))"; atUtc = (Format-PerfTime $ordered[0].T) }
            }
        }
    }
    # Step: prefix sums give mean and variance of both segments for every split in O(n).
    $s = New-Object double[] ($n + 1); $q = New-Object double[] ($n + 1)
    for ($i = 0; $i -lt $n; $i++) { $s[$i + 1] = $s[$i] + $avg[$i]; $q[$i + 1] = $q[$i] + $avg[$i] * $avg[$i] }
    $bestScore = 0.0; $bestK = -1; $bestL = 0.0; $bestR = 0.0; $bestSs = 0.0
    for ($k = 5; $k -le $n - 5; $k++) {
        $ml = $s[$k] / $k; $mr = ($s[$n] - $s[$k]) / ($n - $k)
        $ss = ($q[$k] - $k * $ml * $ml) + (($q[$n] - $q[$k]) - ($n - $k) * $mr * $mr)
        $sd = [Math]::Sqrt([Math]::Max(0.0, $ss) / ($n - 2))
        $scale = [Math]::Max($sd, 1e-9 * [Math]::Max([Math]::Abs($ml), [Math]::Abs($mr)))
        if ($scale -le 0) { continue }
        $score = [Math]::Abs($mr - $ml) / $scale
        if ($score -gt $bestScore) { $bestScore = $score; $bestK = $k; $bestL = $ml; $bestR = $mr; $bestSs = [Math]::Max(0.0, $ss) }
    }
    # A ramp split in the middle also scores ~3.5: report a step only if two flat segments fit clearly better than a line.
    $mi = ($n - 1) / 2.0; $my = $s[$n] / $n; $sxx = 0.0; $sxy = 0.0
    for ($i = 0; $i -lt $n; $i++) { $sxx += ($i - $mi) * ($i - $mi); $sxy += ($i - $mi) * ($avg[$i] - $my) }
    $lineSs = [Math]::Max(0.0, ($q[$n] - $n * $my * $my) - $sxy * $sxy / $sxx)
    if ($bestK -ge 0 -and $bestScore -ge 3 -and $bestSs -lt 0.5 * $lineSs -and [Math]::Abs($bestR - $bestL) -ge 0.05 * [Math]::Max([Math]::Abs($bestL), [Math]::Abs($bestR))) {
        $dir = if ($bestR -gt $bestL) { 'up' } else { 'down' }
        $found += [pscustomobject]@{ timebase = $Timebase; kind = 'step'; detail = "avg steps $dir from $(Format-PerfValue $bestL) to $(Format-PerfValue $bestR)"; atUtc = (Format-PerfTime $times[$bestK]) }
    }
    $rho = Get-Spearman ([double[]](0..($n - 1))) $avg
    $first = ($avg[0..2] | Measure-Object -Average).Average; $last = ($avg[($n - 3)..($n - 1)] | Measure-Object -Average).Average
    if ($null -ne $rho -and [Math]::Abs($rho) -ge 0.8 -and [Math]::Abs($last - $first) -ge 0.05 * [Math]::Max([Math]::Abs($first), [Math]::Abs($last))) {
        $dir = if ($rho -gt 0) { 'rising' } else { 'falling' }
        $found += [pscustomobject]@{ timebase = $Timebase; kind = 'trend'; detail = "avg $dir over $n buckets from $(Format-PerfValue $avg[0]) to $(Format-PerfValue $avg[$n - 1]) (rank correlation with time $($rho.ToString('0.00', $script:Invariant)))"; atUtc = $null }
    }
    return $found
}

# Which counters can be correlated: enough complete buckets that are not constant in at least one timebase.
# $Entry: Key (unique), Label, Object, Counter.
function Get-CorrelationCandidate($Entry, [string[]]$Timebases, [string]$Aggregate, [int]$MinPoints) {
    $usable = @()
    $buckets = @{}
    $reason = 'no data'
    foreach ($tb in $Timebases) {
        $b = Get-CompleteBuckets $Entry.Counter $tb $Aggregate
        $buckets[$tb] = $b
        if ($b.Count -lt $MinPoints) { if ($reason -eq 'no data' -and $b.Count) { $reason = "fewer than $MinPoints complete buckets" }; continue }
        $lo = [Linq.Enumerable]::Min($b.V); $hi = [Linq.Enumerable]::Max($b.V)
        if ($lo -eq $hi) { $reason = "constant $(Format-PerfValue $lo)"; continue }
        $usable += $tb
    }
    return [pscustomobject]@{ Entry = $Entry; Timebases = $usable; Buckets = $buckets; Reason = $(if ($usable.Count) { $null } else { $reason }) }
}

# Compares every pair (CandidatesA x CandidatesB, each pair once; pass the same list twice for all pairs) in every
# timebase both can use. Pairs of the same and of different objects are treated alike: buckets start at multiples of
# the period (UTC), so buckets of different objects line up.
function Measure-PerfCorrelation($CandidatesA, $CandidatesB, [string[]]$Timebases, [int]$MinPoints, [int]$MaxLag) {
    $pairs = @()
    $done = @{}
    foreach ($a in $CandidatesA) {
        foreach ($b in $CandidatesB) {
            if ($a.Entry.Key -eq $b.Entry.Key) { continue }
            $key = if ([string]::CompareOrdinal($a.Entry.Key, $b.Entry.Key) -lt 0) { "$($a.Entry.Key)||$($b.Entry.Key)" } else { "$($b.Entry.Key)||$($a.Entry.Key)" }
            if ($done.ContainsKey($key)) { continue }
            $done[$key] = $true
            $measures = @()
            foreach ($tb in $Timebases) {
                if ($a.Timebases -notcontains $tb -or $b.Timebases -notcontains $tb) { continue }
                $measures += Measure-PairTimebase $a.Buckets[$tb] $b.Buckets[$tb] $tb $MinPoints $MaxLag
            }
            $verdict = Get-PairVerdict $measures
            $pairs += [pscustomobject]@{ A = $a; B = $b; Verdict = $verdict; Measures = $measures }
        }
    }
    return @($pairs | Sort-Object @{ Expression = { $script:CorrelationVerdictOrder[$_.Verdict.verdict] } }, @{ Expression = { if ($_.Verdict.verdict -eq 'lagged') { Get-Abs $_.Verdict.lagR } else { Get-PairScore $_.Verdict } }; Descending = $true })
}

# The first $Max findings, with each counter in at most $PerCounter of them, so a scan of every counter shows many
# different relationships instead of one family of near-identical counters. $Exempt: keys without the cap (the hinted
# counters of a one-against-all run, which are part of every pair).
function Select-DiversePairs($Pairs, [string[]]$Verdicts, [int]$Max, [int]$PerCounter = 2, [string[]]$Exempt = @()) {
    $used = @{}
    $picked = @()
    foreach ($p in $Pairs) {
        if ($picked.Count -ge $Max) { break }
        if ($Verdicts -notcontains $p.Verdict.verdict) { continue }
        $a = $p.A.Entry.Key; $b = $p.B.Entry.Key
        if ((($Exempt -notcontains $a) -and $used[$a] -ge $PerCounter) -or (($Exempt -notcontains $b) -and $used[$b] -ge $PerCounter)) { continue }
        $used[$a] = 1 + [int]$used[$a]; $used[$b] = 1 + [int]$used[$b]
        $picked += $p
    }
    return $picked
}
