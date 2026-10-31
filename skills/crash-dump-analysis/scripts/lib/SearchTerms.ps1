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
    # Constructor / destructor: the class name is what people write in bug reports (cdb shows {ctor}, VS shows Class::Class).
    if ($method -match '^\{[cd]tor\}$') { if ($parts.Count -ge 2 -and $parts[-2].Length -ge 6) { return $parts[-2] } else { return $null } }
    if ($method.StartsWith('~')) { $method = $method.Substring(1); if ($method.Length -ge 6) { return $method } else { return $null } }
    $core = $method.TrimStart('_')
    if ($core.Length -ge 10 -or $core.Contains('_')) { return $method }
    if ($parts.Count -ge 2 -and $parts[-2] -notmatch '`|\s|anonymous') { return "$($parts[-2])::$method" }
    if ($core.Length -ge 6) { return $method }
    return $null
}

# Regex (case-insensitive) that finds a term in a work item text. Constructor and destructor terms (searched by class name)
# must appear as a constructor / destructor, because the bare class name also shows up as a parameter type in other stacks.
function Get-TermMatchPattern([string]$Function, [string]$Term) {
    if ($Function) {
        $name = $Function
        while ($name -match '<[^<>]*>') { $name = $name -replace '<[^<>]*>', '' }
        $parts = @($name -split '::' | Where-Object { $_ })
        $method = if ($parts.Count) { $parts[-1] } else { '' }
        $class = if ($parts.Count -ge 2) { [regex]::Escape($parts[-2]) } else { $null }
        if ($class -and ($method -eq '{dtor}' -or $method.StartsWith('~'))) { return "~$class\b|$class::\{dtor\}" }
        if ($class -and $method -eq '{ctor}') { return "\b$class::$class\b|$class::\{ctor\}" }
    }
    $plain = ($Term -split '::')[-1]
    if ($plain.Length -ge 6 -and $plain -ne $Term) { return "$([regex]::Escape($Term))|$([regex]::Escape($plain))" }
    return [regex]::Escape($Term)
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
            $terms.Add([pscustomobject]@{ Text = $t; Kind = 'asserted expression'; Weight = 3.0; Frame = $null; Pattern = (Get-TermMatchPattern $null $t) })
        }
    }
    $rank = 0
    # Unhandled C++ exception: the throw site and its callers (recovered from the stack) and the thrown type.
    $cpp = Get-Cfg $Dump 'cppException' $null
    if ($cpp) {
        foreach ($f in @(Get-Cfg $cpp 'frames' @() | Where-Object { Get-Cfg $_ 'application' $false } | Select-Object -First 3)) {
            $t = Get-SearchTermName ([string](Get-Cfg $f 'function' ''))
            if (-not $t -or $seen.ContainsKey($t.ToLowerInvariant())) { continue }
            $seen[$t.ToLowerInvariant()] = $true
            $terms.Add([pscustomobject]@{ Text = $t; Kind = $(if ($rank -eq 0) { 'throw site (stack scan)' } else { 'caller of throw site (stack scan)' }); Weight = $(if ($rank -eq 0) { 3.0 } else { 2.0 }); Frame = $null; Pattern = (Get-TermMatchPattern ([string](Get-Cfg $f 'function' '')) $t) })
            $rank++
        }
        $type = (([string](Get-Cfg $cpp 'thrownType' '')) -split '::')[-1]
        if ($type -and $type.Length -ge 6 -and $type -ne 'exception' -and -not $seen.ContainsKey($type.ToLowerInvariant())) {
            $seen[$type.ToLowerInvariant()] = $true
            $terms.Add([pscustomobject]@{ Text = $type; Kind = 'thrown C++ type'; Weight = 1.0; Frame = $null; Pattern = (Get-TermMatchPattern $null $type) })
        }
    }
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
        $terms.Add([pscustomobject]@{ Text = $t; Kind = "frame $([int]$frame.index) ($module)"; Weight = $weight; Frame = [int]$frame.index; Pattern = (Get-TermMatchPattern $function $t) })
        $rank++
    }
    return $terms.ToArray()
}
