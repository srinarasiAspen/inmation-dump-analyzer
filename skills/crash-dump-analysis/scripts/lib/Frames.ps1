# Frame classification (reporting / exception-dispatch frames) and assertion / abort detection.

# Frames that only report a failure (CRT abort/assert/terminate, fail-fast helpers, exception dispatch). They are
# skipped for the crash signature and searched for the assertion text.
$script:noiseFunctionRegex = '^(abort|raise|_?wassert|_assert|_bson_assert_failed_on_line|bson_abort|std::terminate|terminate|__std_terminate|_invalid_parameter(_noinfo)?(_noreturn)?|_invoke_watson|_purecall|_CxxThrowException|RaiseException|RtlRaiseException|__report_gsfailure|__report_securityfailure|__fastfail|_?_?acrt_call_reportfault|_call_reportfault|__scrt_unhandled_exception_filter|KiUserExceptionDispatcher|RtlDispatchException|RtlUserThreadStart|BaseThreadInitThunk)$'
# MSVC C++ exception dispatch/unwind frames: on the stack of every unhandled exception, never evidence of a bug.
$script:ehRuntimeRegex = '^(__CxxFrameHandler\d*|__InternalCxxFrameHandler(Wrapper)?(<.*>)?|FindHandler(<.*>)?|CatchIt(<.*>)?|__FrameHandler\d*::\w+|_CallSettingFrame\w*|_CallCatchBlock\d*|__C_specific_handler|__GSHandlerCheck\w*|__FrameUnwindFilter|__ExceptionPtrRethrow|std::_Throw_Cpp_error|std::_Throw_C_error|std::rethrow_exception|RtlpExecuteHandlerFor(Exception|Unwind)|RtlUnwindEx)$'

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
