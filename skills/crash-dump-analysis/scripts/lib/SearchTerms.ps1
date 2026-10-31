# Search terms for TFS from a crash: identifiers of the asserted expression and distinctive frame function names.

$script:luaVmRegex = '^(luaV_\w+|luaD_\w+|luaG_\w+|luaT_\w+|luaH_\w+|luaC_\w+|luaE_\w+|luaF_\w+|luaO_\w+|lua_pcallk|lua_callk|lua_resume|lua_error|luaL_error|luaB_pcall|luaB_xpcall|f_call|resume)$'
$script:osModuleRegex = '^(ntdll|KERNELBASE|kernel32|ucrtbase|vcruntime\d*|msvcp\d*|wow64\w*|combase|rpcrt4|ws2_32|mswsock)$'
$script:keywordRegex = '^(const|static_cast|reinterpret_cast|nullptr|NULL|sizeof|return|true|false|unsigned|signed|struct|class|this)$'

# Short but distinctive name of a frame function: the method name if it is long or has an underscore, else Class::method.
function Get-SearchTermName([string]$Function) {
    $name = $Function
    while ($name -match '<[^<>]*>') { $name = $name -replace '<[^<>]*>', '' }
    $parts = @($name -split '::' | Where-Object { $_ })
    if ($parts.Count -eq 0) { return $null }
    $method = $parts[-1]
    if (-not $method -or $method -match '^operator' -or $method -match 'lambda|`|\$|<|>|\s') { return $null }
    $core = $method.TrimStart('_')
    if ($core.Length -ge 10 -or $core.Contains('_')) { return $method }
    if ($parts.Count -ge 2 -and $parts[-2] -notmatch '`|\s|anonymous') { return "$($parts[-2])::$method" }
    if ($core.Length -ge 6) { return $method }
    return $null
}

function Get-CrashTerms($Dump, [int]$MaxFrameTerms = 6) {
    $terms = New-Object Collections.Generic.List[object]
    $seen = @{}
    $assertion = Get-Cfg $Dump 'assertion' $null
    $expression = Get-Cfg $assertion 'expression' $null
    if ($expression) {
        foreach ($m in [regex]::Matches($expression, '[A-Za-z_][A-Za-z0-9_]{5,}')) {
            $t = $m.Value
            if ($t -match $script:keywordRegex -or $seen.ContainsKey($t.ToLowerInvariant())) { continue }
            $seen[$t.ToLowerInvariant()] = $true
            $terms.Add([pscustomobject]@{ Text = $t; Kind = 'asserted expression'; Weight = 3.0; Frame = $null })
        }
    }
    $rank = 0
    foreach ($frame in @(Get-Cfg $Dump 'crashStack' @() | Sort-Object { [int]$_.index })) {
        if ($rank -ge $MaxFrameTerms) { break }
        $function = [string](Get-Cfg $frame 'function' '')
        $module = [string](Get-Cfg $frame 'module' '')
        if (-not $function -or $function -match '^0x[0-9a-f`]+$' -or $function -ieq $module -or $function -match '\+0x[0-9a-f]+$') { continue }
        if ($function -match $script:noiseFunctionRegex -or $function -match $script:ehRuntimeRegex -or $function -match $script:luaVmRegex -or $module -match $script:osModuleRegex) { continue }
        if ($function -match '^(std|Concurrency|boost)::') { continue }
        $t = Get-SearchTermName $function
        if (-not $t -or $seen.ContainsKey($t.ToLowerInvariant())) { continue }
        $seen[$t.ToLowerInvariant()] = $true
        $weight = if ($rank -eq 0) { 3.0 } elseif ($rank -le 2) { 2.0 } else { 1.0 }
        $terms.Add([pscustomobject]@{ Text = $t; Kind = "frame $([int]$frame.index) ($module)"; Weight = $weight; Frame = [int]$frame.index })
        $rank++
    }
    return $terms.ToArray()
}
