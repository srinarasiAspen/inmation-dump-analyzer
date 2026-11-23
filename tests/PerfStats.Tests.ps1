. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:PerfLibRoot 'PerfData.ps1')
. (Join-Path $script:PerfLibRoot 'PerfStats.ps1')

# A counter with complete minute buckets holding $Values (avg = min = max) plus one bucket that is still filling.
function New-TestCounter([string]$Name, [double[]]$Values) {
    $t = @(for ($i = 0; $i -le $Values.Length; $i++) { [int64]1793266380000 + 60000 * $i })
    $v = @($Values) + @(999999)
    $tbs = [ordered]@{}
    foreach ($tb in 'second', 'minute', 'hour', 'day') { $tbs[$tb] = [ordered]@{ t = @(); sum = @(); num = @(); avg = @(); min = @(); max = @() } }
    $tbs['minute'] = [ordered]@{ t = $t; sum = $v; num = @($v | ForEach-Object { 60 }); avg = $v; min = $v; max = $v }
    return [ordered]@{ code = 1; name = $Name; enumName = "MODEL_PERF_$Name"; timebases = $tbs }
}

function Get-TestVerdict([double[]]$A, [double[]]$B) {
    $ma = Get-CompleteBuckets (New-TestCounter 'A' $A) 'minute' 'avg'
    $mb = Get-CompleteBuckets (New-TestCounter 'B' $B) 'minute' 'avg'
    return Get-PairVerdict @(Measure-PairTimebase $ma $mb 'minute' 8 3)
}

$rnd = New-Object Random 42
$n = 40
$x = [double[]]@(for ($i = 0; $i -lt $n; $i++) { 10 * $rnd.NextDouble() })
$y = [double[]]@(for ($i = 0; $i -lt $n; $i++) { 10 * $rnd.NextDouble() })
$e = [double[]]@(for ($i = 0; $i -lt $n; $i++) { 6 * $rnd.NextDouble() })

Describe 'correlation measures' {
    It 'computes Pearson, ignoring constant series' {
        Assert-Equal 1 (Get-Pearson @(1, 2, 3, 4) @(2, 4, 6, 8))
        Assert-Equal -1 (Get-Pearson @(1, 2, 3, 4) @(8, 6, 4, 2))
        Assert-Null (Get-Pearson @(1, 2, 3, 4) @(5, 5, 5, 5))
    }
    It 'gives tied values their average rank' {
        Assert-Equal @(1, 2.5, 2.5, 4) (Get-Ranks @(10, 20, 20, 30))
    }
    It 'finds the lag by which the second series follows the first' {
        $b = [double[]]@(@(3.3, 7.7) + @($x[0..($n - 3)]))
        $best = Get-BestLag $x $b 3 5
        Assert-Equal 2 $best.Lag
        Assert-True ($best.R -gt 0.999)
    }
    It 'turns correlations into two-sided p-values' {
        Assert-True ((Get-CorrelationPValue 0 40) -gt 0.99)
        Assert-True ((Get-CorrelationPValue 0.6 40) -lt 0.001)
        Assert-True ((Get-CorrelationPValue 0.3 40) -gt 0.05)
    }
}

Describe 'pair pre-verdicts' {
    It 'strong: levels and changes move together' {
        $v = Get-TestVerdict $x ([double[]]@(for ($i = 0; $i -lt $n; $i++) { 2 * $x[$i] + $e[$i] }))
        Assert-Equal 'strong' $v.verdict
        Assert-Equal 'together' $v.direction
    }
    It 'strong opposite: one falls when the other rises' {
        $v = Get-TestVerdict $x ([double[]]@(for ($i = 0; $i -lt $n; $i++) { 100 - 2 * $x[$i] + $e[$i] }))
        Assert-Equal 'strong' $v.verdict
        Assert-Equal 'opposite' $v.direction
    }
    It 'same-signal: one counter is a linear function of the other' {
        Assert-Equal 'same-signal' (Get-TestVerdict $x ([double[]]@($x | ForEach-Object { 3 * $_ + 5 }))).verdict
    }
    It 'lagged: the changes of the second follow the first by two buckets' {
        $v = Get-TestVerdict $x ([double[]]@(@(3.3, 7.7) + @($x[0..($n - 3)])))
        Assert-Equal 'lagged' $v.verdict
        Assert-Equal 2 $v.lag
    }
    It 'moderate: changes coincide while the levels drift apart' {
        $v = Get-TestVerdict ([double[]]@(for ($i = 0; $i -lt $n; $i++) { 0.2 * $i + $x[$i] })) ([double[]]@(for ($i = 0; $i -lt $n; $i++) { -0.2 * $i + $x[$i] }))
        Assert-Equal 'moderate' $v.verdict
        Assert-Equal 'together' $v.direction
    }
    It 'trend-only: both drift up with unrelated changes' {
        Assert-Equal 'trend-only' (Get-TestVerdict ([double[]]@(for ($i = 0; $i -lt $n; $i++) { $i + 0.3 * $x[$i] })) ([double[]]@(for ($i = 0; $i -lt $n; $i++) { 2 * $i + 0.3 * $y[$i] }))).verdict
    }
    It 'trend-only, not same-signal: two counters that step once at the same time' {
        $v = Get-TestVerdict ([double[]]@(for ($i = 0; $i -lt $n; $i++) { if ($i -lt 20) { 0 } else { 1 } })) ([double[]]@(for ($i = 0; $i -lt $n; $i++) { if ($i -lt 20) { 0 } else { 5 } }))
        Assert-Equal 'trend-only' $v.verdict
        Assert-Equal 1 $v.changes
    }
    It 'none: independent series' {
        Assert-Equal 'none' (Get-TestVerdict $x $y).verdict
    }
    It 'inconsistent: opposite signs in different timebases' {
        $up = [pscustomobject]@{ timebase = 'minute'; n = 40; r = 0.9; p = 0.0001; rho = 0.9; dr = 0.7; drP = 0.0001; changes = 30; lag = $null; lagR = $null; lagP = $null }
        $down = [pscustomobject]@{ timebase = 'hour'; n = 20; r = -0.7; p = 0.001; rho = -0.7; dr = -0.6; drP = 0.01; changes = 15; lag = $null; lagR = $null; lagP = $null }
        Assert-Equal 'inconsistent' (Get-PairVerdict @($up, $down)).verdict
    }
    It 'inconsistent also when outlier buckets carry the opposite correlations' {
        $up = [pscustomobject]@{ timebase = 'minute'; n = 40; r = 0.6; p = 0.001; rho = 0.2; dr = 0.1; drP = 0.5; changes = 30; lag = $null; lagR = $null; lagP = $null }
        $down = [pscustomobject]@{ timebase = 'hour'; n = 20; r = -0.55; p = 0.01; rho = -0.1; dr = 0.0; drP = 0.9; changes = 15; lag = $null; lagR = $null; lagP = $null }
        $v = Get-PairVerdict @($up, $down)
        Assert-Equal 'inconsistent' $v.verdict
        Assert-Equal 'minute' $v.timebase
    }
}

Describe 'counter anomalies' {
    It 'finds a single spike of the bucket maximum' {
        $v = [double[]]@(for ($i = 0; $i -lt $n; $i++) { 10 + 0.5 * $x[$i] / 10 }); $v[25] = 30
        $a = @(Get-PerfAnomalies (New-TestCounter 'S' $v) 'minute')
        Assert-Equal @('spike') @($a | ForEach-Object { $_.kind })
        Assert-Equal (Format-PerfTime (1793266380000 + 25 * 60000)) $a[0].atUtc
    }
    It 'finds a step and where it happens' {
        $v = [double[]]@(for ($i = 0; $i -lt $n; $i++) { $(if ($i -lt 20) { 10 } else { 20 }) + 0.5 * $x[$i] / 10 })
        $a = @(Get-PerfAnomalies (New-TestCounter 'S' $v) 'minute' | Where-Object { $_.kind -eq 'step' })
        Assert-Equal 1 $a.Count
        Assert-Match 'up' $a[0].detail
        Assert-Equal (Format-PerfTime (1793266380000 + 20 * 60000)) $a[0].atUtc
    }
    It 'ignores steps smaller than 5% of the level' {
        $v = [double[]]@(for ($i = 0; $i -lt $n; $i++) { $(if ($i -lt 20) { 100 } else { 100.5 }) + 0.01 * $x[$i] / 10 })
        Assert-Equal 0 @(Get-PerfAnomalies (New-TestCounter 'S' $v) 'minute').Count
    }
    It 'skips cumulative counters that only rise' {
        Assert-Equal 0 @(Get-PerfAnomalies (New-TestCounter 'REQUESTS_TOTAL' ([double[]](1..$n))) 'minute').Count
    }
    It 'finds a rising trend' {
        $v = [double[]]@(for ($i = 0; $i -lt $n; $i++) { 10 + $i + 3 * $x[$i] / 10 })
        Assert-True (@(Get-PerfAnomalies (New-TestCounter 'T' $v) 'minute' | Where-Object { $_.kind -eq 'trend' }).Count -eq 1)
    }
    It 'does not call a noisy ramp a step' {
        $v = [double[]]@(for ($i = 0; $i -lt $n; $i++) { 100 + $i + 8 * $x[$i] / 10 })
        $kinds = @(Get-PerfAnomalies (New-TestCounter 'R' $v) 'minute' | ForEach-Object { $_.kind })
        Assert-Equal @('trend') $kinds
    }
}

Describe 'top pairs' {
    It 'lists each counter in at most two findings' {
        $mk = { param($a, $b, $v) [pscustomobject]@{ A = [pscustomobject]@{ Entry = [pscustomobject]@{ Key = $a } }; B = [pscustomobject]@{ Entry = [pscustomobject]@{ Key = $b } }; Verdict = [pscustomobject]@{ verdict = $v } } }
        $pairs = @((& $mk 'a' 'b' 'strong'), (& $mk 'a' 'c' 'strong'), (& $mk 'a' 'd' 'strong'), (& $mk 'b' 'c' 'same-signal'), (& $mk 'c' 'd' 'moderate'))
        $top = @(Select-DiversePairs $pairs @('strong', 'moderate') 10)
        Assert-Equal @('a-b', 'a-c', 'c-d') @($top | ForEach-Object { "$($_.A.Entry.Key)-$($_.B.Entry.Key)" })
    }
    It 'does not cap the hinted counter of a one-against-all run' {
        $mk = { param($a, $b) [pscustomobject]@{ A = [pscustomobject]@{ Entry = [pscustomobject]@{ Key = $a } }; B = [pscustomobject]@{ Entry = [pscustomobject]@{ Key = $b } }; Verdict = [pscustomobject]@{ verdict = 'strong' } } }
        $pairs = @('b', 'c', 'd', 'e', 'f') | ForEach-Object { & $mk 'a' $_ }
        Assert-Equal 5 @(Select-DiversePairs $pairs @('strong') 10 2 @('a')).Count
    }
}
