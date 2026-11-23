. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:LibRoot 'Cdb.ps1')
. (Join-Path $script:LibRoot 'Symbols.ps1')
. (Join-Path $script:PerfLibRoot 'PerfData.ps1')
. (Join-Path $script:PerfLibRoot 'PerfChart.ps1')

$perfNames = @{ [int64]72 = 'MODEL_PERF_CPU'; [int64]145 = 'MODEL_PERF_MEMORYLOAD'; [int64]146 = 'MODEL_PERF_INMATIONMEMORYUSAGE'; [int64]111 = 'MODEL_PERF_TIMESERIESLOAD'; [int64]222 = 'MODEL_PERF_NUMBERACTIVETHREADS' }
$parsed = ConvertFrom-PerfDumpOutput (Get-Fixture 'cdb-perfdump.txt')
$counters = @(New-PerfCounterList $parsed.Objects['0x1725f89fdc0'] $perfNames)
$vqtCounters = @(New-PerfCounterList $parsed.Objects['0x1725f8b0000'] $perfNames)

Describe 'PerfDump.js output' {
    It 'reports each requested path: matches (UTF-8 paths), objects without counters, candidates, dumped object' {
        Assert-Equal 3288 $parsed.MapEntries
        Assert-Equal '/System/Core' $parsed.Requests[0].Matches[0].Path
        Assert-Equal '0x1725f89fdc0' $parsed.Requests[0].Dumped
        Assert-Equal "/System/Core/K$([char]0xFC)hler" $parsed.Requests[1].Matches[0].Path
        Assert-False $parsed.Requests[1].Matches[0].HasCounters
        Assert-Null $parsed.Requests[1].Dumped
        Assert-Equal 0 @($parsed.Requests[2].Matches).Count
        Assert-Equal '/System/Core/Stores' $parsed.Requests[2].Candidates[0].Path
        Assert-Equal '0x1725f8b0000' $parsed.Requests[3].Dumped
        Assert-True $parsed.Done
    }
    It 'assigns counters to the object they were dumped for' {
        Assert-Equal @('0x1725f89fdc0', '0x1725f8b0000') $parsed.ObjectOrder
        Assert-Equal @('CPU', 'INMATIONMEMORYUSAGE') @($counters | ForEach-Object { $_.name })
        Assert-Equal @('TIMESERIESLOAD') @($vqtCounters | ForEach-Object { $_.name })
    }
    It 'builds time-ordered columnar series per timebase with counter names from the enum' {
        $cpu = $counters[0]
        Assert-Equal @(1793266380000, 1793266440000, 1793266500000, 1793266560000) $cpu.timebases['minute'].t
        Assert-Equal @(20, 30, 40, 25) $cpu.timebases['minute'].avg
        Assert-Equal @(60, 60, 60, 20) $cpu.timebases['minute'].num
    }
    It 'keeps empty and NaN values as missing' {
        $mem = $counters[1]
        Assert-Null $mem.timebases['second'].num[0]
        Assert-Null $mem.timebases['second'].avg[0]
        Assert-Equal 700 $mem.timebases['second'].sum[0]
    }
    It 'merges per-aggregate lines of misaligned buffers by timestamp' {
        $m = $counters[1].timebases['minute']
        Assert-Equal @(1793266440000, 1793266500000) $m.t
        Assert-Equal @(42000, 21000) $m.sum
        Assert-Null $m.avg[0]
        Assert-Equal 700 $m.avg[1]
    }
    It 'parses enumerators printed by dt' {
        $map = ConvertFrom-EnumLines @('   MODEL_PERF_CPU = 0n72', '   MODEL_PERF_LAG = 0n50', '   MODEL_CLASS_NODE = 0n3813', 'junk') 'MODEL_PERF_'
        Assert-Equal 2 $map.Count
        Assert-Equal 'MODEL_PERF_CPU' $map[[int64]72]
    }
}

Describe 'perf statistics per counter' {
    It 'leaves the bucket that is still filling out of the statistics' {
        $s = Get-PerfTimebaseStats $counters[0] 'minute'
        Assert-Equal 3 $s.complete
        Assert-Equal 30 $s.mean
        Assert-Equal 5 $s.min
        Assert-Equal 88 $s.max
        Assert-Equal '2026-10-29T09:35:00Z' $s.maxAtUtc
        Assert-Equal 40 $s.lastComplete
        Assert-Equal 25 $s.inProgress
        Assert-Equal 20 $s.inProgressSamples
    }
    It 'reports a timebase with only the filling bucket as having no complete buckets' {
        $s = Get-PerfTimebaseStats $counters[0] 'day'
        Assert-Equal 0 $s.complete
        Assert-Null $s.mean
        Assert-Equal 25 $s.inProgress
    }
    It 'classifies trends of bucket averages' {
        Assert-Equal 'n/a' (Get-PerfTrend @(1, 2, 3))
        Assert-Equal 'flat' (Get-PerfTrend @(10, 10.2, 9.9, 10, 10.1, 10))
        Assert-Equal 'rising (+100%)' (Get-PerfTrend @(10, 10, 15, 15, 20, 20))
        Assert-Equal 'falling (-50%)' (Get-PerfTrend @(20, 20, 15, 15, 10, 10))
        Assert-Equal 'flat' (Get-PerfTrend @(0, 0, 0, 0, 0, 0))
    }
    It 'tells active from constant counters' {
        Assert-Equal 'active' (Get-PerfActivity $counters[0])
        $flat = [ordered]@{ code = 1; name = 'X'; timebases = [ordered]@{ second = [ordered]@{ t = @(1, 2); sum = @(0, 0); num = @(1, 1); avg = @(0, 0); min = @(0, 0); max = @(0, 0) } } }
        Assert-Equal 'constant 0' (Get-PerfActivity $flat)
    }
}

Describe 'counter and object requests' {
    $all = @{}
    foreach ($k in $perfNames.Keys) { $all[$k] = $perfNames[$k] }
    $objCounters = @(
        [pscustomobject]@{ code = 72; name = 'CPU' }
        [pscustomobject]@{ code = 74; name = 'INMATIONCPU' }
        [pscustomobject]@{ code = 145; name = 'MEMORYLOAD' }
        [pscustomobject]@{ code = 146; name = 'INMATIONMEMORYUSAGE' }
        [pscustomobject]@{ code = 222; name = 'NUMBERACTIVETHREADS' }
    )
    It 'accepts names with spaces or prefix, codes and unique name parts; drops duplicates' {
        $r = Resolve-PerfCounterRequest @('Inmation Memory Usage,MODEL_PERF_CPU;0x91', '72', 'threads') $objCounters $all
        Assert-Equal @(146, 72, 145, 222) @($r.Resolved | ForEach-Object { $_.Counter.code })
        Assert-True $r.Resolved[3].Partial
        Assert-Equal 0 @($r.Issues).Count
    }
    It 'prefers the exact name over names that contain it' {
        $r = Resolve-PerfCounterRequest @('cpu') $objCounters $all
        Assert-Equal 72 $r.Resolved[0].Counter.code
        Assert-False $r.Resolved[0].Partial
    }
    It 'reports ambiguous, not-on-object and unknown requests with candidates' {
        $r = Resolve-PerfCounterRequest @('memory', 'TimeSeriesLoad', 'cpuu') $objCounters $all
        Assert-Equal 0 @($r.Resolved).Count
        Assert-Equal @('ambiguous', 'not-on-object', 'unknown') @($r.Issues | ForEach-Object { $_.Kind })
        Assert-Equal @('MEMORYLOAD', 'INMATIONMEMORYUSAGE') $r.Issues[0].Candidates
        Assert-Equal @('TIMESERIESLOAD') $r.Issues[1].Candidates
        Assert-Equal 'CPU' $r.Issues[2].Candidates[0]
    }
    It 'selects every counter with * or all' {
        Assert-Equal 5 @((Resolve-PerfCounterRequest @('*') $objCounters $all).Resolved).Count
        Assert-Equal 5 @((Resolve-PerfCounterRequest @('ALL') $objCounters $all).Resolved).Count
    }
    It 'selects the counters that match a wildcard pattern' {
        $r = Resolve-PerfCounterRequest @('*memory*', 'inmation*') $objCounters $all
        Assert-Equal @(145, 146, 74) @($r.Resolved | ForEach-Object { $_.Counter.code })
        Assert-Equal 'unknown' (Resolve-PerfCounterRequest @('*disk*') $objCounters $all).Issues[0].Kind
    }
    It 'normalizes and splits object paths; commas inside names stay' {
        Assert-Equal '/System/Core' (Get-NormalizedObjectPath ' System/Core/ ')
        Assert-Equal '/' (Get-NormalizedObjectPath '/')
        Assert-Equal @('/a', '/b/c', '/d,e', '/f') (Split-ObjectPathList @('/a; b/c/', '/d,e, /f'))
        Assert-Equal "/System/K$([char]0xFC)hler" (ConvertFrom-Utf8Hex (ConvertTo-Utf8Hex "/System/K$([char]0xFC)hler"))
    }
}

Describe 'counter selection over several objects' {
    $objects = @(
        [pscustomobject]@{ path = '/System/Core'; counters = @($counters) }
        [pscustomobject]@{ path = '/System/Core/Stores/VQT'; counters = @($vqtCounters) }
    )
    It 'resolves an unqualified name in every object that has it, without issues for the others' {
        $s = Resolve-PerfSelection $objects @('CPU,TimeSeriesLoad') $perfNames
        Assert-Equal @('/System/Core|CPU', '/System/Core/Stores/VQT|TIMESERIESLOAD') @($s.Selected | ForEach-Object { "$($_.Object.path)|$($_.Counter.name)" })
        Assert-Equal 0 @($s.Issues).Count
    }
    It 'restricts /path:counter to that object and reports a counter it does not have' {
        $s = Resolve-PerfSelection $objects @('/System/Core/Stores/VQT:timeseriesload', 'system/core:TimeSeriesLoad') $perfNames
        Assert-Equal 1 @($s.Selected).Count
        Assert-Equal '/System/Core/Stores/VQT' $s.Selected[0].Object.path
        Assert-Equal 'not-on-object' $s.Issues[0].Kind
        Assert-Equal '/System/Core' $s.Issues[0].Object
    }
    It 'reports a qualifier that names an object not in the data' {
        $s = Resolve-PerfSelection $objects @('/Other:CPU') $perfNames
        Assert-Equal 'object-not-selected' $s.Issues[0].Kind
        Assert-Equal @('/System/Core', '/System/Core/Stores/VQT') $s.Issues[0].Candidates
    }
    It 'selects every counter of every object with *' {
        Assert-Equal 3 @((Resolve-PerfSelection $objects @('*') $perfNames).Selected).Count
    }
    It 'splits qualified requests at the last colon' {
        $q = Split-QualifiedCounter '/Plant:A/Line 1:CPU'
        Assert-Equal '/Plant:A/Line 1' $q.Path
        Assert-Equal 'CPU' $q.Counter
        Assert-Null (Split-QualifiedCounter 'CPU').Path
    }
}

Describe 'symbol gate' {
    It 'accepts only private PDB symbols' {
        $status = Get-SymbolLoadStatus @('start             end                 module name', '00007ff7`40000000 00007ff7`4a000000   inmation   (private pdb symbols)  C:\sym\inmation.pdb')
        Assert-Equal 'private pdb symbols' $status
        Assert-True (Test-PrivateSymbolStatus $status)
        Assert-False (Test-PrivateSymbolStatus 'export symbols')
        Assert-False (Test-PrivateSymbolStatus $null)
    }
}

Describe 'perf output files' {
    $core = [ordered]@{ path = '/System/Core'; counters = $counters }
    $data = [ordered]@{
        objects = @($core, [ordered]@{ path = '/System/Core/Stores/VQT'; counters = $vqtCounters })
        module  = [ordered]@{ name = 'inmation.exe'; fileVersion = '26.1.0.9038' }
        dump    = [ordered]@{ dumpTimeUtc = '2026-10-29T09:42:39Z' }
    }
    It 'writes one CSV row per object, counter and bucket and flags the bucket that is still filling' {
        $csv = Join-Path $env:TEMP "perf-test-$([Guid]::NewGuid().ToString('N')).csv"
        try {
            Write-PerfCsv $data $csv
            $rows = @(Import-Csv -LiteralPath $csv)
            Assert-Equal 18 $rows.Count
            $minute = @($rows | Where-Object { $_.counter -eq 'CPU' -and $_.timebase -eq 'minute' })
            Assert-Equal @('false', 'false', 'false', 'true') @($minute | ForEach-Object { $_.inProgress })
            Assert-Equal '2026-10-29T09:33:00Z' $minute[0].bucketStartUtc
            Assert-Equal 4 @($rows | Where-Object { $_.object -eq '/System/Core/Stores/VQT' }).Count
        }
        finally { Remove-Item -LiteralPath $csv -Force -ErrorAction SilentlyContinue }
    }
    It 'renders a PNG chart per counter' {
        $png = Join-Path $env:TEMP "perf-test-$([Guid]::NewGuid().ToString('N')).png"
        try {
            New-PerfCounterChart $data $core $counters[0] @('avg', 'min', 'max', 'num') $png
            $bytes = [IO.File]::ReadAllBytes($png)
            Assert-True ($bytes.Length -gt 1000)
            Assert-Equal 'PNG' ([Text.Encoding]::ASCII.GetString($bytes, 1, 3))
        }
        finally { Remove-Item -LiteralPath $png -Force -ErrorAction SilentlyContinue }
    }
}
