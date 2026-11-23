# Performance counter data: debugger output parsing, counter name matching, data file, statistics.
# A counter (CObjectPerformance item) keeps buckets per timebase; each bucket has the aggregates sum, num (samples),
# avg (sum/num), min and max. The last bucket of every timebase is still filling at dump time.

$script:PerfTimebases = @(
    [pscustomobject]@{ Index = 0; Name = 'second'; PeriodMs = [int64]1000; Retention = 'last minute' }
    [pscustomobject]@{ Index = 1; Name = 'minute'; PeriodMs = [int64]60000; Retention = 'last hour' }
    [pscustomobject]@{ Index = 2; Name = 'hour'; PeriodMs = [int64]3600000; Retention = 'last day' }
    [pscustomobject]@{ Index = 3; Name = 'day'; PeriodMs = [int64]86400000; Retention = 'last 30 days' }
)
$script:PerfAggregates = @('sum', 'num', 'avg', 'min', 'max')
$script:Invariant = [Globalization.CultureInfo]::InvariantCulture

function ConvertTo-Utf8Hex([string]$Text) {
    return (@([Text.Encoding]::UTF8.GetBytes($Text) | ForEach-Object { $_.ToString('x2') }) -join '')
}

function ConvertFrom-Utf8Hex([string]$Hex) {
    $bytes = New-Object byte[] ([int]($Hex.Length / 2))
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($Hex.Substring(2 * $i, 2), 16) }
    return [Text.Encoding]::UTF8.GetString($bytes)
}

# Object paths are canonical ('/System/Core/...'); the user may omit the leading slash or add a trailing one.
function Get-NormalizedObjectPath([string]$Path) {
    $p = $Path.Trim().Trim('"').Trim("'").Trim()
    if (-not $p.StartsWith('/')) { $p = '/' + $p }
    while ($p.Length -gt 1 -and $p.EndsWith('/')) { $p = $p.Substring(0, $p.Length - 1) }
    return $p
}

# Comma- or semicolon-separated values (scripts started with -File receive one string per [string[]] parameter).
function Split-ListValue([string[]]$Values) {
    return @($Values | ForEach-Object { $_ -split '[,;]' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# Object paths: separated by ';', or by ',' directly before the next '/' (object names may contain commas).
function Split-ObjectPathList([string[]]$Values) {
    return @($Values | ForEach-Object { $_ -split ';|,\s*(?=/)' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object { Get-NormalizedObjectPath $_ } | Select-Object -Unique)
}

function ConvertTo-PerfNumber([string]$Text) {
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $value = [double]::Parse($Text, $script:Invariant)
    if ([double]::IsNaN($value) -or [double]::IsInfinity($value)) { return $null }
    return $value
}

# Values of a ROW line (fields 4..8); inline parsing, called for every bucket.
function ConvertFrom-PerfRowValues([string[]]$Fields) {
    $values = New-Object object[] 5
    for ($a = 0; $a -lt 5; $a++) {
        $text = $Fields[4 + $a]
        if (-not $text) { continue }
        $d = [double]::Parse($text, $script:Invariant)
        if (-not ([double]::IsNaN($d) -or [double]::IsInfinity($d))) { $values[$a] = $d }
    }
    return , $values
}

# Enumerators printed by 'dt <enum type>', e.g. '   MODEL_PERF_CPU = 0n72' -> @{ 72 = 'MODEL_PERF_CPU' }.
function ConvertFrom-EnumLines([string[]]$Lines, [string]$Prefix) {
    $map = @{}
    foreach ($line in $Lines) {
        if ($line -match ('^\s+(' + [regex]::Escape($Prefix) + '\w+)\s*=\s*0n(\d+)\s*$')) {
            $code = [int64]$Matches[2]
            if (-not $map.ContainsKey($code)) { $map[$code] = $Matches[1] }
        }
    }
    return $map
}

# 'MODEL_PERF_TIMESERIESLOAD' -> 'TIMESERIESLOAD'
function Get-PerfCounterName([string]$EnumName) { return ($EnumName -replace '^MODEL_PERF_', '') }

# Matching key: upper case, no MODEL_PERF_ prefix, letters and digits only ('Time Series Load' = 'TIMESERIESLOAD').
function Get-PerfNameKey([string]$Name) { return (($Name.ToUpperInvariant() -replace '^MODEL_PERF_', '') -replace '[^A-Z0-9]', '') }

function ConvertFrom-PerfDumpOutput([string[]]$Lines) {
    $result = [ordered]@{
        MapEntries = $null; Walked = $null; ScanMs = $null; Requests = @{}; Objects = @{}; ObjectOrder = @(); Listed = @()
        ListedShown = $null; WithCounters = $null; Warnings = @(); Errors = @(); Done = $false
    }
    $request = {
        param([int]$Index)
        if (-not $result.Requests.ContainsKey($Index)) { $result.Requests[$Index] = [pscustomobject]@{ Matches = @(); Candidates = @(); Dumped = $null } }
        $result.Requests[$Index]
    }
    $current = $null
    foreach ($line in $Lines) {
        if ($line -notmatch '^@@PERF\|(.*)$') { continue }
        $f = $Matches[1].Split('|')
        switch ($f[0]) {
            'MAPS' { $result.MapEntries = [int64]$f[1]; $result.Walked = [int64]$f[2]; if ($null -eq $result.ScanMs) { $result.ScanMs = [int64]$f[3] } }
            'MATCH' { $r = & $request ([int]$f[1]); $r.Matches += [pscustomobject]@{ Address = '0x' + $f[2]; Path = ConvertFrom-Utf8Hex $f[3]; ClassCode = [int64]$f[4]; HasCounters = $f[5] -eq '1'; CounterCount = [int64]$f[6] } }
            'CAND' { $r = & $request ([int]$f[1]); $r.Candidates += [pscustomobject]@{ Path = ConvertFrom-Utf8Hex $f[2]; ClassCode = [int64]$f[3]; HasCounters = $f[4] -eq '1'; CounterCount = [int64]$f[5] } }
            'LIST' { $result.Listed += [pscustomobject]@{ Path = ConvertFrom-Utf8Hex $f[1]; ClassCode = [int64]$f[2]; CounterCount = [int64]$f[3] } }
            'LISTED' { $result.ListedShown = [int64]$f[1]; $result.WithCounters = [int64]$f[2] }
            'DUMPED' {
                $address = '0x' + $f[2]
                (& $request ([int]$f[1])).Dumped = $address
                if (-not $result.Objects.ContainsKey($address)) {
                    $result.Objects[$address] = [pscustomobject]@{ Address = $address; ItemOrder = New-Object Collections.Generic.List[int64]; Rows = @{} }
                    $result.ObjectOrder += $address
                }
                $current = $result.Objects[$address]
            }
            'ITEM' { if ($current -and -not $current.ItemOrder.Contains([int64]$f[1])) { $current.ItemOrder.Add([int64]$f[1]) } }
            'ROW' {
                if (-not $current) { continue }
                $key = "$($f[1])|$($f[2])"
                if (-not $current.Rows.ContainsKey($key)) { $current.Rows[$key] = @{} }
                $current.Rows[$key][[int64]$f[3]] = ConvertFrom-PerfRowValues $f
            }
            'AGG' {
                if (-not $current) { continue }
                $key = "$($f[1])|$($f[2])"
                if (-not $current.Rows.ContainsKey($key)) { $current.Rows[$key] = @{} }
                $t = [int64]$f[4]
                if (-not $current.Rows[$key].ContainsKey($t)) { $current.Rows[$key][$t] = @($null, $null, $null, $null, $null) }
                $current.Rows[$key][$t][[int]$f[3]] = ConvertTo-PerfNumber $f[5]
            }
            'WARN' { $result.Warnings += ($f[1..($f.Count - 1)] -join '|') }
            'ERR' { $result.Errors += ($f[1..($f.Count - 1)] -join '|') }
            'DONE' { $result.Done = $true }
        }
    }
    return [pscustomobject]$result
}

# Columnar series of one counter and timebase: t (ms since 1970, UTC, bucket start) and one array per aggregate.
function New-PerfSeries([hashtable]$Rows) {
    $series = [ordered]@{ t = @(); sum = @(); num = @(); avg = @(); min = @(); max = @() }
    if (-not $Rows) { return $series }
    foreach ($t in @($Rows.Keys | Sort-Object)) {
        $v = $Rows[$t]
        $series.t += [int64]$t
        for ($a = 0; $a -lt 5; $a++) { $series[$script:PerfAggregates[$a]] += $v[$a] }
    }
    return $series
}

function New-PerfCounterList($ParsedObject, [hashtable]$PerfNames) {
    $counters = @()
    foreach ($code in $ParsedObject.ItemOrder) {
        $enumName = if ($PerfNames.ContainsKey($code)) { $PerfNames[$code] } else { "MODEL_PERF_CODE$code" }
        $timebases = [ordered]@{}
        foreach ($tb in $script:PerfTimebases) {
            $key = "$code|$($tb.Index)"
            $timebases[$tb.Name] = New-PerfSeries $(if ($ParsedObject.Rows.ContainsKey($key)) { $ParsedObject.Rows[$key] } else { $null })
        }
        $counters += [ordered]@{ code = $code; name = (Get-PerfCounterName $enumName); enumName = $enumName; timebases = $timebases }
    }
    return $counters
}

function Get-PerfCounter($Object, $Code) { return @($Object.counters | Where-Object { [int64]$_.code -eq [int64]$Code }) | Select-Object -First 1 }

function Get-PerfTimebaseSeries($Counter, [string]$Timebase) {
    $p = $Counter.timebases.PSObject.Properties[$Timebase]
    if ($p) { return $p.Value }
    if ($Counter.timebases -is [Collections.IDictionary] -and $Counter.timebases.Contains($Timebase)) { return $Counter.timebases[$Timebase] }
    return $null
}

function Get-SeriesValues($Series, [string]$Name) {
    if ($null -eq $Series) { return @() }
    $v = if ($Series -is [Collections.IDictionary]) { $Series[$Name] } else { $Series.$Name }
    if ($null -eq $v) { return @() }
    $in = @($v)
    $out = New-Object object[] $in.Count
    for ($i = 0; $i -lt $in.Count; $i++) { if ($null -ne $in[$i]) { $out[$i] = [double]$in[$i] } }
    return $out
}

# Statistics of the complete buckets (the last bucket is still filling and is left out).
function Get-PerfTimebaseStats($Counter, [string]$Timebase) {
    $series = Get-PerfTimebaseSeries $Counter $Timebase
    $times = @(Get-SeriesValues $series 't')
    $result = [ordered]@{ timebase = $Timebase; buckets = $times.Count; complete = 0; fromUtc = $null; toUtc = $null; mean = $null; min = $null; max = $null; maxAtUtc = $null; lastComplete = $null; inProgress = $null; inProgressSamples = $null; trend = 'n/a'; flat = $false }
    if ($times.Count -eq 0) { return [pscustomobject]$result }
    $avg = @(Get-SeriesValues $series 'avg'); $min = @(Get-SeriesValues $series 'min'); $max = @(Get-SeriesValues $series 'max'); $numv = @(Get-SeriesValues $series 'num')
    $result.inProgress = $avg[$times.Count - 1]
    $result.inProgressSamples = $numv[$times.Count - 1]
    $n = $times.Count - 1
    $result.complete = $n
    if ($n -lt 1) { return [pscustomobject]$result }
    $result.fromUtc = Format-PerfTime $times[0]
    $result.toUtc = Format-PerfTime $times[$n - 1]
    $vals = @(for ($i = 0; $i -lt $n; $i++) { if ($null -ne $avg[$i]) { $avg[$i] } })
    $mins = @(for ($i = 0; $i -lt $n; $i++) { if ($null -ne $min[$i]) { $min[$i] } })
    $maxs = @(for ($i = 0; $i -lt $n; $i++) { if ($null -ne $max[$i]) { $max[$i] } })
    if ($vals.Count -eq 0) { return [pscustomobject]$result }
    $result.mean = ($vals | Measure-Object -Average).Average
    $result.min = if ($mins.Count) { ($mins | Measure-Object -Minimum).Minimum } else { $null }
    $result.max = if ($maxs.Count) { ($maxs | Measure-Object -Maximum).Maximum } else { $null }
    if ($null -ne $result.max) {
        for ($i = 0; $i -lt $n; $i++) { if ($max[$i] -eq $result.max) { $result.maxAtUtc = Format-PerfTime $times[$i]; break } }
    }
    $result.lastComplete = $avg[$n - 1]
    $result.flat = (($vals | Measure-Object -Minimum).Minimum -eq ($vals | Measure-Object -Maximum).Maximum)
    $result.trend = Get-PerfTrend $vals
    return [pscustomobject]$result
}

# First third vs. last third of the bucket averages: 'rising (+35%)', 'falling (-20%)', 'flat', 'n/a' (< 6 buckets).
function Get-PerfTrend([double[]]$Values) {
    if ($Values.Count -lt 6) { return 'n/a' }
    $k = [int][Math]::Floor($Values.Count / 3)
    $first = ($Values[0..($k - 1)] | Measure-Object -Average).Average
    $last = ($Values[($Values.Count - $k)..($Values.Count - 1)] | Measure-Object -Average).Average
    $scale = [Math]::Max([Math]::Abs($first), [Math]::Abs($last))
    if ($scale -eq 0) { return 'flat' }
    $change = ($last - $first) / $scale
    if ([Math]::Abs($change) -lt 0.1) { return 'flat' }
    $pct = if ($first -ne 0) { ' ({0:+0;-0}%)' -f (100 * ($last - $first) / [Math]::Abs($first)) } else { '' }
    if ($change -gt 0) { return "rising$pct" }
    return "falling$pct"
}

function Format-PerfTime($Ms) {
    if ($null -eq $Ms) { return $null }
    return ([DateTimeOffset]::FromUnixTimeMilliseconds([int64]$Ms)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Format-PerfValue($Value) {
    if ($null -eq $Value) { return '-' }
    $d = [double]$Value
    if ($d -ne 0 -and ([Math]::Abs($d) -ge 1e7 -or [Math]::Abs($d) -lt 1e-3)) { return $d.ToString('0.###e+0', $script:Invariant) }
    return $d.ToString('0.###', $script:Invariant)
}

# Activity of a counter for listing: 'active' (changes), 'constant <v>' or 'no data'.
function Get-PerfActivity($Counter) {
    $values = @()
    foreach ($tb in $script:PerfTimebases) {
        $series = Get-PerfTimebaseSeries $Counter $tb.Name
        foreach ($a in 'min', 'max') { $values += @(Get-SeriesValues $series $a | Where-Object { $null -ne $_ }) }
    }
    if ($values.Count -eq 0) { return 'no data' }
    $lo = ($values | Measure-Object -Minimum).Minimum
    $hi = ($values | Measure-Object -Maximum).Maximum
    if ($lo -eq $hi) { return "constant $(Format-PerfValue $lo)" }
    return 'active'
}

function Get-EditDistance([string]$A, [string]$B) {
    $prev = [int[]](0..$B.Length)
    for ($i = 1; $i -le $A.Length; $i++) {
        $cur = New-Object int[] ($B.Length + 1)
        $cur[0] = $i
        for ($j = 1; $j -le $B.Length; $j++) {
            $cost = if ($A[$i - 1] -ceq $B[$j - 1]) { 0 } else { 1 }
            $cur[$j] = [Math]::Min([Math]::Min($prev[$j] + 1, $cur[$j - 1] + 1), $prev[$j - 1] + $cost)
        }
        $prev = $cur
    }
    return $prev[$B.Length]
}

# Resolves the counters the user asked for against the counters of the object.
# Accepted: '*' or 'all', the enum name (MODEL_PERF_CPU), the name (CPU, 'Time Series Load'), the code (72, 0x48),
# a unique part of a name, or a wildcard pattern ('*buffer*'). Issues: ambiguous (several names contain it),
# not-on-object (the counter exists but this object's class does not have it), unknown (with the closest names).
function Resolve-PerfCounterRequest([string[]]$Requested, $Counters, [hashtable]$AllNames) {
    $resolved = New-Object Collections.Generic.List[object]
    $issues = @()
    $seen = @{}
    $add = { param($c, [string]$Request, [bool]$Partial) if (-not $seen.ContainsKey([int64]$c.code)) { $seen[[int64]$c.code] = $true; $resolved.Add([pscustomobject]@{ Counter = $c; Request = $Request; Partial = $Partial }) } }
    foreach ($request in @(Split-ListValue $Requested)) {
        if ($request -eq '*' -or $request -ieq 'all') { foreach ($c in $Counters) { & $add $c $request $false }; continue }
        if ($request -match '[*?]') {
            # Wildcards on the name key: '*buffer*', 'SAF*MEMORY'.
            $pattern = ($request.ToUpperInvariant() -replace '^MODEL_PERF_', '') -replace '[^A-Z0-9*?]', ''
            $hits = @($Counters | Where-Object { (Get-PerfNameKey $_.name) -like $pattern })
            if ($hits.Count) { foreach ($c in $hits) { & $add $c $request $true } }
            else { $issues += [pscustomobject]@{ Request = $request; Kind = 'unknown'; Candidates = @() } }
            continue
        }
        $code = $null
        if ($request -match '^0x([0-9a-fA-F]+)$') { $code = [Convert]::ToInt64($Matches[1], 16) }
        elseif ($request -match '^\d+$') { $code = [int64]$request }
        if ($null -ne $code) {
            $hit = @($Counters | Where-Object { [int64]$_.code -eq $code })
            if ($hit.Count) { & $add $hit[0] $request $false }
            elseif ($AllNames.ContainsKey($code)) { $issues += [pscustomobject]@{ Request = $request; Kind = 'not-on-object'; Candidates = @(Get-PerfCounterName $AllNames[$code]) } }
            else { $issues += [pscustomobject]@{ Request = $request; Kind = 'unknown'; Candidates = @() } }
            continue
        }
        $key = Get-PerfNameKey $request
        if (-not $key) { continue }
        $exact = @($Counters | Where-Object { (Get-PerfNameKey $_.name) -eq $key })
        if ($exact.Count) { & $add $exact[0] $request $false; continue }
        $partial = @($Counters | Where-Object { (Get-PerfNameKey $_.name).Contains($key) })
        if ($partial.Count -eq 1) { & $add $partial[0] $request $true; continue }
        if ($partial.Count -gt 1) { $issues += [pscustomobject]@{ Request = $request; Kind = 'ambiguous'; Candidates = @($partial | Select-Object -First 15 | ForEach-Object { $_.name }) }; continue }
        $global = @($AllNames.Values | Where-Object { (Get-PerfNameKey $_) -eq $key -or (Get-PerfNameKey $_).Contains($key) } | Sort-Object | ForEach-Object { Get-PerfCounterName $_ })
        if ($global.Count) { $issues += [pscustomobject]@{ Request = $request; Kind = 'not-on-object'; Candidates = @($global | Select-Object -First 10) }; continue }
        $closest = @($Counters | Sort-Object { Get-EditDistance (Get-PerfNameKey $_.name) $key } | Select-Object -First 3 | ForEach-Object { $_.name })
        $issues += [pscustomobject]@{ Request = $request; Kind = 'unknown'; Candidates = $closest }
    }
    return [pscustomobject]@{ Resolved = $resolved.ToArray(); Issues = $issues }
}

function Read-PerfData([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "Perf data file not found: $Path" }
    return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

# '/System/Core:CPU' -> Path '/System/Core', Counter 'CPU'. Unqualified requests have no Path. Counter names have no
# '/' or ':', so a request with both is qualified and the last colon separates (object names may contain one).
function Split-QualifiedCounter([string]$Request) {
    $i = $Request.LastIndexOf(':')
    if ($Request.Contains('/') -and $i -gt 0) { return [pscustomobject]@{ Path = $Request.Substring(0, $i).Trim(); Counter = $Request.Substring($i + 1).Trim() } }
    return [pscustomobject]@{ Path = $null; Counter = $Request }
}

# Counter requests over one or more objects. An unqualified request (name, code, unique part, * or all) applies to
# every object and is an issue only when no object has a match; '/path:counter' applies to that object only.
# Returns Selected (Object, Counter, Request, Partial; each object/counter once) and Issues (Request, Kind, Object,
# Candidates) with Kind ambiguous, not-on-object, unknown or object-not-selected.
function Resolve-PerfSelection($Objects, [string[]]$Requested, [hashtable]$AllNames) {
    $selected = New-Object Collections.Generic.List[object]
    $seen = @{}
    $issues = @()
    $objects = @($Objects)
    foreach ($request in @(Split-ListValue $Requested)) {
        $q = Split-QualifiedCounter $request
        $targets = $objects
        if ($q.Path) {
            $wanted = Get-NormalizedObjectPath $q.Path
            $targets = @($objects | Where-Object { $_.path -ieq $wanted })
            if ($targets.Count -eq 0) { $issues += [pscustomobject]@{ Request = $request; Kind = 'object-not-selected'; Object = $wanted; Candidates = @($objects | ForEach-Object { $_.path }) }; continue }
        }
        $hits = @()
        $objectIssues = @()
        foreach ($o in $targets) {
            $r = Resolve-PerfCounterRequest @($q.Counter) @($o.counters) $AllNames
            foreach ($x in $r.Resolved) { $hits += [pscustomobject]@{ Object = $o; Counter = $x.Counter; Request = $request; Partial = $x.Partial } }
            foreach ($i in $r.Issues) { $objectIssues += [pscustomobject]@{ Request = $request; Kind = $i.Kind; Object = $o.path; Candidates = @($i.Candidates) } }
        }
        if ($hits.Count -eq 0) { $issues += $objectIssues; continue }
        foreach ($h in $hits) {
            $objectKey = if ($h.Object.PSObject.Properties['label']) { $h.Object.label } else { $h.Object.path }
            $key = "$objectKey|$($h.Counter.code)"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $selected.Add($h)
        }
    }
    return [pscustomobject]@{ Selected = $selected.ToArray(); Issues = $issues }
}

# Label of a selected counter: the name, with the object path when several objects are involved.
function Get-PerfCounterLabel($Object, $Counter, [bool]$WithObject) {
    if ($WithObject) { return "$($Counter.name) @ $($Object.path)" }
    return [string]$Counter.name
}

function Write-PerfCsv($Data, [string]$Path) {
    $sb = New-Object Text.StringBuilder
    [void]$sb.AppendLine('object,counter,code,timebase,bucketStartUtc,tMs,sum,num,avg,min,max,inProgress')
    foreach ($o in @($Data.objects)) {
        $objectCell = '"' + ([string]$o.path).Replace('"', '""') + '"'
        foreach ($c in @($o.counters)) {
            foreach ($tb in $script:PerfTimebases) {
                $s = Get-PerfTimebaseSeries $c $tb.Name
                $t = @(Get-SeriesValues $s 't')
                $cols = @(foreach ($a in $script:PerfAggregates) { , @(Get-SeriesValues $s $a) })
                $prefix = "$objectCell,$($c.name),$($c.code),$($tb.Name),"
                for ($i = 0; $i -lt $t.Count; $i++) {
                    [void]$sb.Append($prefix).Append((Format-PerfTime $t[$i])).Append(',').Append(([int64]$t[$i]).ToString($script:Invariant))
                    for ($a = 0; $a -lt 5; $a++) {
                        [void]$sb.Append(',')
                        $v = $cols[$a][$i]
                        if ($null -ne $v) { [void]$sb.Append(([double]$v).ToString('R', $script:Invariant)) }
                    }
                    [void]$sb.AppendLine($(if ($i -eq $t.Count - 1) { ',true' } else { ',false' }))
                }
            }
        }
    }
    [IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object Text.UTF8Encoding($false)))
}

# File-name-safe label.
function Get-PerfFileName([string]$Name) {
    $s = ($Name.Trim('/') -replace '[^A-Za-z0-9_.-]', '_')
    if (-not $s) { $s = 'root' }
    if ($s.Length -gt 80) { $s = $s.Substring($s.Length - 80) }
    return $s
}
