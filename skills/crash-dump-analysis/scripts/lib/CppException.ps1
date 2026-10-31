# Unhandled C++ exceptions (std::terminate, 0xE06D7363): finds MSVC C++ exception records on the crashing thread's stack,
# reads the thrown type (vftable of the exception object), the error code of std::system_error-like types, and the throw
# site plus callers from a raw scan of the stack above the record. Works when the unwind stopped in the exception dispatch
# (minidump without KERNELBASE/ntdll).

$script:cppThrowHelperRegex = '^(_CxxThrowException|std::_Throw_Cpp_error|std::_Throw_C_error|std::_Throw_system_error|std::_Throw_future_error|std::_Throw_range_error|std::_Xbad_alloc|std::_Xbad_function_call|std::_Xinvalid_argument|std::_Xlength_error|std::_Xout_of_range|std::_Xoverflow_error|std::_Xruntime_error|std::_Xregex_error|std::_Throw_bad_array_new_length|std::_Throw_bad_optional_access|std::_Throw_bad_variant_access|std::_Throw_tzdb_error|boost::throw_exception(<.*>)?|boost::detail::throw_exception(<.*>)?|RaiseException)$'

$script:errnoNames = @{
    1 = 'operation_not_permitted (EPERM)'; 2 = 'no_such_file_or_directory (ENOENT)'; 4 = 'interrupted (EINTR)'; 5 = 'io_error (EIO)'
    9 = 'bad_file_descriptor (EBADF)'; 11 = 'resource_unavailable_try_again (EAGAIN)'; 12 = 'not_enough_memory (ENOMEM)'
    13 = 'permission_denied (EACCES)'; 16 = 'device_or_resource_busy (EBUSY)'; 17 = 'file_exists (EEXIST)'; 22 = 'invalid_argument (EINVAL)'
    24 = 'too_many_files_open (EMFILE)'; 28 = 'no_space_on_device (ENOSPC)'; 34 = 'result_out_of_range (ERANGE)'
    36 = 'resource_deadlock_would_occur (EDEADLK)'; 39 = 'no_lock_available (ENOLCK)'; 105 = 'operation_canceled (ECANCELED)'
    107 = 'connection_refused (ECONNREFUSED)'; 108 = 'connection_reset (ECONNRESET)'; 129 = 'not_supported (ENOTSUP)'
    133 = 'owner_dead (EOWNERDEAD)'; 138 = 'timed_out (ETIMEDOUT)'
}
$script:futureErrorNames = @{ 1 = 'broken_promise'; 2 = 'future_already_retrieved'; 3 = 'promise_already_satisfied'; 4 = 'no_state' }

# cdb commands: scan the stack for EXCEPTION_RECORDs with code 0xE06D7363 and the MSVC magic 0x19930520 in
# ExceptionInformation[0]; print the record, the first pointer-size slots of the thrown object and the stack above it.
function New-CppExceptionCommands([bool]$Is32Bit, [bool]$Wow64) {
    $cmds = New-Object Collections.Generic.List[string]
    if ($Wow64) { $cmds.Add('.load wow64exts'); $cmds.Add('!sw') }
    $cmds.Add('.ecxr')
    if ($Is32Bit) { $sp = '@esp'; $magic = '0x14'; $object = '0x18' } else { $sp = '@rsp'; $magic = '0x20'; $object = '0x28' }
    $cmds.Add(".foreach (rec {s -[1]d $sp L?0x6000 e06d7363}) { .if (dwo(`${rec}+$magic) == 0x19930520) { .echo <<<CXX_RECORD `${rec}>>>; .exr `${rec}; .echo <<<CXX_OBJECT>>>; dps poi(`${rec}+$object) L6; .echo <<<THROW_STACK>>>; dps `${rec} L400; .echo <<<CXX_END>>> } }")
    $cmds.Add('q')
    return $cmds
}

function ConvertFrom-DpsLine([string]$Line) {
    $m = [regex]::Match($Line, '^(?<sa>[0-9a-f]{8}(?:`[0-9a-f]{8})?)\s+(?<val>[0-9a-f?]{8}(?:`[0-9a-f?]{8})?)(?:\s+(?<sym>[^\[]+?))?(?:\s+\[(?<file>[^\]]+?) @ (?<line>\d+)\])?\s*$')
    if (-not $m.Success) { return $null }
    $sym = if ($m.Groups['sym'].Success) { $m.Groups['sym'].Value.Trim() } else { $null }
    $module = $null; $function = $null; $isCode = $false
    if ($sym -and $sym -match '^(?<mod>[^!\s]+)!(?<fn>.+)\+0x[0-9a-f]+$' -and $sym -notmatch '<PERF>') {
        $module = $Matches['mod']; $function = $Matches['fn']
        $isCode = $function -notmatch "vftable'|^TI\d|^__ImageBase|_Static$|^__scrt_|_tls_|^``string'"
    }
    elseif ($sym -and $sym -match '^(?<mod>[^!\s]+)!(?<fn>.+)$') { $module = $Matches['mod']; $function = $Matches['fn'] }
    return [pscustomobject]@{
        stackAddress = '0x' + ($m.Groups['sa'].Value -replace '`', '')
        value        = $m.Groups['val'].Value -replace '`', ''
        symbol       = $sym
        module       = $module
        function     = $function
        isCode       = [bool]$isCode
        sourceFile   = if ($m.Groups['file'].Success) { $m.Groups['file'].Value } else { $null }
        sourceLine   = if ($m.Groups['line'].Success) { [int]$m.Groups['line'].Value } else { $null }
    }
}

function Get-CppErrorCodeText([string]$Category, [int64]$Value) {
    switch -regex ($Category) {
        'Generic' { if ($script:errnoNames.ContainsKey([int]$Value)) { return "generic_category $Value = $($script:errnoNames[[int]$Value])" }; return "generic_category (errno) $Value" }
        'System' { return "system_category (Win32 error) $Value" }
        'Future' { if ($script:futureErrorNames.ContainsKey([int]$Value)) { return "future_category $Value = $($script:futureErrorNames[[int]$Value])" }; return "future_category $Value" }
        'Iostream' { return "iostream_category $Value" }
        default { return "$Category $Value" }
    }
}

# Parses the output of New-CppExceptionCommands. Returns one entry per record that has a readable thrown object.
function ConvertFrom-CppExceptionScan([string[]]$Lines, [string[]]$OwnModules) {
    $records = @()
    $current = $null
    $part = $null
    foreach ($line in $Lines) {
        if ($line -match '^<<<CXX_RECORD (?<a>\S+)>>>$') {
            $current = [pscustomobject]@{ record = ($Matches['a'] -replace '`', ''); object = New-Object Collections.ArrayList; stack = New-Object Collections.ArrayList }
            $records += $current; $part = 'record'; continue
        }
        if ($line -eq '<<<CXX_OBJECT>>>') { $part = 'object'; continue }
        if ($line -eq '<<<THROW_STACK>>>') { $part = 'stack'; continue }
        if ($line -eq '<<<CXX_END>>>') { $part = $null; continue }
        if (-not $current -or $part -notin 'object', 'stack') { continue }
        $entry = ConvertFrom-DpsLine $line
        if ($entry) { [void]$current.$part.Add($entry) }
    }

    $results = @()
    $seenTypes = @{}
    foreach ($r in $records) {
        $slots = $r.object.ToArray()
        if ($slots.Count -eq 0 -or -not $slots[0].function -or $slots[0].function -notmatch "^(?<t>.+)::``vftable'$") { continue }
        $type = $Matches['t']
        $errorValue = $null; $errorCategory = $null; $errorText = $null
        if ($slots.Count -ge 5 -and $slots[4].function -match '_(?<c>\w+?)_error_category') {
            $errorCategory = $Matches['c']
            $raw = $slots[3].value
            if ($raw -match '^[0-9a-f]+$') {
                $low = [Convert]::ToUInt32($raw.Substring([Math]::Max(0, $raw.Length - 8)), 16)
                $errorValue = [int64][BitConverter]::ToInt32([BitConverter]::GetBytes($low), 0)
                $errorText = Get-CppErrorCodeText $errorCategory $errorValue
            }
        }
        $code = @($r.stack.ToArray() | Where-Object { $_.isCode })
        $throwIndex = -1
        for ($i = 0; $i -lt $code.Count; $i++) { if ($code[$i].function -eq '_CxxThrowException') { $throwIndex = $i; break } }
        $after = if ($throwIndex -ge 0) { @($code | Select-Object -Skip ($throwIndex + 1)) } else { $code }
        $frames = @()
        $previous = $null
        foreach ($c in $after) {
            $callSite = "$($c.module)!$($c.function)"
            if ($callSite -eq $previous) { continue }
            $previous = $callSite
            $frame = [pscustomobject][ordered]@{ index = $frames.Count; module = $c.module; function = $c.function; callSite = $c.symbol; sourceFile = $c.sourceFile; sourceLine = $c.sourceLine; stackAddress = $c.stackAddress; thirdParty = $null; helper = $false; application = $false }
            $frame.helper = $frame.function -match $script:cppThrowHelperRegex
            $frame.application = (-not $frame.helper) -and (Test-ApplicationFrame $frame $OwnModules)
            $frames += $frame
        }
        $throwSite = $frames | Where-Object { $_.application } | Select-Object -First 1
        $key = "$type|$errorValue|$(if ($throwSite) { $throwSite.callSite })"
        if ($seenTypes.ContainsKey($key)) { continue }
        $seenTypes[$key] = $true
        $results += [pscustomobject][ordered]@{
            record        = $r.record
            thrownType    = $type
            errorCategory = $errorCategory
            errorValue    = $errorValue
            errorText     = $errorText
            throwSite     = $throwSite
            thrownVia     = @($frames | Where-Object { $_.helper } | ForEach-Object { $_.function } | Select-Object -Unique)
            frames        = @($frames | Select-Object -First 40)
            source        = 'raw stack scan (frames were on the stack; not an exact call chain)'
        }
    }
    return , $results
}
