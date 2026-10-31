# Frame classification (reporting / exception-dispatch frames) and assertion / abort detection.

# Frames that only report a failure (CRT abort/assert/terminate, fail-fast helpers, exception dispatch). They are
# skipped for the crash signature and searched for the assertion text.
$script:noiseFunctionRegex = '^(abort|raise|_?wassert|_assert|_bson_assert_failed_on_line|bson_abort|std::terminate|terminate|__std_terminate|_invalid_parameter(_noinfo)?(_noreturn)?|_invoke_watson|_purecall|_CxxThrowException|RaiseException|RtlRaiseException|__report_gsfailure|__report_securityfailure|__fastfail|_?_?acrt_call_reportfault|_call_reportfault|__scrt_unhandled_exception_filter|KiUserExceptionDispatcher|RtlDispatchException|RtlUserThreadStart|BaseThreadInitThunk)$'
# MSVC C++ exception dispatch/unwind frames: on the stack of every unhandled exception, never evidence of a bug.
$script:ehRuntimeRegex = '^(__CxxFrameHandler\d*|__InternalCxxFrameHandler(Wrapper)?(<.*>)?|FindHandler(<.*>)?|CatchIt(<.*>)?|__FrameHandler\d*::\w+|_CallSettingFrame\w*|_CallCatchBlock\d*|__C_specific_handler|__GSHandlerCheck\w*|__FrameUnwindFilter|__ExceptionPtrRethrow|std::_Throw_Cpp_error|std::_Throw_C_error|std::rethrow_exception|RtlpExecuteHandlerFor(Exception|Unwind)|RtlUnwindEx)$'

# Own product code: a frame of a product binary that is not a vcpkg port, the CRT/STL, std/boost or a reporting frame.
function Test-ApplicationFrame($Frame, [string[]]$OwnModules) {
    if ($OwnModules -notcontains $Frame.module -or $Frame.thirdParty) { return $false }
    if ($Frame.sourceFile -match '[\\/](vcpkg|vcpkg_installed|minkernel|vctools)[\\/]|[\\/]MSVC[\\/][^\\/]+[\\/]include[\\/]') { return $false }
    if ($Frame.function -match '^(std|boost|Concurrency|stdext)::|^0x') { return $false }
    return -not (Test-NoiseFrame $Frame)
}

# Function name with template argument lists collapsed (std::_Hash<...>::_Find_last); lambda names are kept.
function Get-CompactFunctionName([string]$Function) {
    if (-not $Function -or $Function -match 'operator\s*(<|>|->)') { return $Function }
    $sb = New-Object Text.StringBuilder
    $depth = 0
    for ($i = 0; $i -lt $Function.Length; $i++) {
        $ch = $Function[$i]
        if ($ch -eq '<') {
            if ($depth -eq 0 -and $Function.Substring($i).StartsWith('<lambda_')) {
                $end = $Function.IndexOf('>', $i)
                if ($end -gt $i) { [void]$sb.Append($Function.Substring($i, $end - $i + 1)); $i = $end; continue }
            }
            if ($depth -eq 0) { [void]$sb.Append('<...>') }
            $depth++
            continue
        }
        if ($ch -eq '>' -and $depth -gt 0) { $depth--; continue }
        if ($depth -eq 0) { [void]$sb.Append($ch) }
    }
    return $sb.ToString()
}

function Test-NoiseFrame($Frame) {
    # A bare address below frame 0 is a wrong unwind (e.g. minidump without KERNELBASE/ntdll), not a caller. Frame 0
    # as a bare address is kept: the crash executed outside known code.
    $bogusUnwind = ($Frame.index -gt 0) -and (-not $Frame.module) -and ($Frame.function -match '^0x[0-9a-f`]+$')
    return [bool](($Frame.function -match $script:noiseFunctionRegex) -or ($Frame.function -match $script:ehRuntimeRegex) -or $bogusUnwind -or (($Frame.module -match '^(ntdll|KERNELBASE|kernel32|ucrtbase|vcruntime\d*|msvcp\d*)$') -and ($Frame.function -match 'Raise|Exception|Fail|abort|terminate')))
}

# Splits 'dv /t /v' output of several '.frame N' commands into a map frame index -> local lines.
function Split-LocalsByFrame([string[]]$Lines) {
    $map = @{}
    $current = $null
    foreach ($line in $Lines) {
        if ($line -match '^(?<num>[0-9a-f]{2,})\s+(?:[0-9a-f]{8}(?:`[0-9a-f]{8})?\s+[0-9a-f]{8}(?:`[0-9a-f]{8})?|\(Inline Function\))') {
            $current = [Convert]::ToInt32($Matches['num'], 16)
            if (-not $map.ContainsKey($current)) { $map[$current] = New-Object Collections.Generic.List[string] }
            continue
        }
        if ($null -ne $current) { $map[$current].Add($line) }
    }
    return $map
}

function Get-LocalValue([string[]]$Lines, [string[]]$Names) {
    foreach ($name in $Names) {
        foreach ($line in $Lines) {
            if ($line -match ('\b' + [regex]::Escape($name) + ' = (?:0x[0-9a-f`]+ )?(?:(?<str>"(?:[^"\\]|\\.)*")|0n(?<dec>-?\d+)|(?<num>-?\d+|0x[0-9a-f`]+))')) {
                if ($Matches['str']) { return $Matches['str'].Trim('"') }
                if ($Matches['dec']) { return $Matches['dec'] }
                return $Matches['num']
            }
        }
    }
    return $null
}

function Get-AssertionInfo($Frames, [hashtable]$LocalsByFrame, $Exception) {
    $kinds = [ordered]@{
        '_bson_assert_failed_on_line' = 'BSON_ASSERT (libbson/libmongoc)'
        'bson_abort'                  = 'bson_abort'
        '_wassert'                    = 'CRT assert()'
        '_assert'                     = 'CRT assert()'
        '_invalid_parameter'          = 'CRT invalid parameter'
        '_invalid_parameter_noinfo'   = 'CRT invalid parameter'
        '_invalid_parameter_noinfo_noreturn' = 'CRT invalid parameter'
        '_purecall'                   = 'pure virtual call'
        'std::terminate'              = 'std::terminate (unhandled C++ exception or noexcept violation)'
        'terminate'                   = 'std::terminate (unhandled C++ exception or noexcept violation)'
        '__std_terminate'             = 'std::terminate (unhandled C++ exception or noexcept violation)'
        'abort'                       = 'abort()'
    }
    $hit = $null
    foreach ($key in $kinds.Keys) {
        $hit = $Frames | Where-Object { $_.index -lt 12 -and $_.function -eq $key } | Select-Object -First 1
        if ($hit) { break }
    }
    if (-not $hit) { return $null }
    $lines = if ($LocalsByFrame.ContainsKey($hit.index)) { @($LocalsByFrame[$hit.index]) } else { @() }
    $reporter = $Frames | Where-Object { $_.index -gt $hit.index -and -not (Test-NoiseFrame $_) } | Select-Object -First 1
    $info = [ordered]@{
        kind          = $kinds[$hit.function]
        frame         = $hit.index
        function      = $hit.function
        expression    = Get-LocalValue $lines @('test', 'expression', '_Message', 'message', 'expr')
        file          = Get-LocalValue $lines @('file', '_File')
        line          = Get-LocalValue $lines @('line', '_Line')
        inFunction    = Get-LocalValue $lines @('func', 'function', '_Function')
        reportedBy    = if ($reporter) { $reporter.callSite } else { $null }
        deliberate    = $true
        note          = $null
        unwindNote    = $null
    }
    if ($Exception -and $Exception.failFastCode -eq 7) { $info.note = 'Exception 0xC0000409 subcode 7 (FAST_FAIL_FATAL_APP_EXIT) is how abort() terminates the process; this is not a stack buffer overrun.' }
    if (-not $reporter -and $info.kind -like 'std::terminate*') {
        $info.unwindNote = 'No application frame on the unwound stack: the unwind stopped in the C++ exception dispatch (typical for a minidump without KERNELBASE/ntdll). The thrown exception and its throw site are still on the stack; decode them with the agent recipe "Unhandled C++ exception (std::terminate)".'
    }
    return [pscustomobject]$info
}

# Crash signature: the first frame that does not only report the failure, plus the first own (non third-party) frame when
# that is a different one, prefixed with the asserted expression. Family is the same without code offsets, so the same
# crash in two builds (different offsets) lands in one group.
function Get-CrashSignature($Frames, $Assertion, [string[]]$OwnModules) {
    $top = $Frames | Where-Object { -not (Test-NoiseFrame $_) } | Select-Object -First 1
    $noApplicationFrame = -not $top
    if (-not $top) { $top = $Frames | Select-Object -First 1 }
    $firstOwn = if (-not $top) { $null } else { $Frames | Where-Object { $_.index -ge $top.index -and (Test-ApplicationFrame $_ $OwnModules) } | Select-Object -First 1 }
    $parts = @()
    if ($top) { $parts += $top }
    if ($firstOwn -and $firstOwn -ne $top) { $parts += $firstOwn }
    $exact = (@($parts | ForEach-Object { $_.callSite }) -join ' <- ')
    $family = (@($parts | ForEach-Object { if ($_.module -and $_.function -notmatch '^0x') { "$($_.module)!$(Get-CompactFunctionName $_.function)" } else { $_.callSite } }) -join ' <- ')
    $prefix = ''
    $suffix = ''
    if ($noApplicationFrame -and $exact) { $suffix = ' [no application frame unwound]' }
    if ($Assertion -and $Assertion.expression) { $prefix = "assert '$($Assertion.expression)' in " }
    elseif ($Assertion) { $prefix = "$($Assertion.function) in " }
    return [pscustomobject]@{
        Signature          = if ($exact) { "$prefix$exact$suffix" } else { $null }
        Family             = if ($family) { "$prefix$family$suffix" } else { $null }
        NoApplicationFrame = [bool]$noApplicationFrame
        TopFrame           = $top
        FirstOwnFrame      = $firstOwn
    }
}
