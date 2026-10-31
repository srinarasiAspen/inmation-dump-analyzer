# Deterministic crash classification from the exception record, assertion, C++ exception and stack. The result is a
# category with a one-line explanation: a classification of the crash kind, not a root cause.

# Short, readable function name for titles: template arguments collapsed, at most the last two scopes.
function Get-DisplayFunctionName([string]$Function) {
    if (-not $Function) { return $Function }
    $compact = Get-CompactFunctionName $Function
    $parts = @($compact -split '::')
    if ($parts.Count -gt 2) { return ($parts[-2..-1] -join '::') }
    return $compact
}

function Get-StackRecursion($Frames) {
    $counts = @{}
    foreach ($f in @($Frames | Where-Object { $_.function -and $_.function -notmatch '^0x' })) {
        $key = "$($f.module)!$($f.function)"
        if ($counts.ContainsKey($key)) { $counts[$key]++ } else { $counts[$key] = 1 }
    }
    $top = $counts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1
    if ($top -and $top.Value -ge 3) { return [pscustomobject]@{ Function = $top.Key; Count = $top.Value } }
    return $null
}

function Get-CrashClassification($Exception, $Assertion, $Frames, $Signature, $CppException, [string[]]$OwnModules, [bool]$Is32Bit) {
    $top = if ($Signature) { $Signature.TopFrame } else { $null }
    $own = if ($Signature) { $Signature.FirstOwnFrame } else { $null }
    $where = ''
    $location = $null
    if ($top -and $top.module -and $top.function -notmatch '^0x') {
        $location = Get-DisplayFunctionName $top.function
        if ($top.thirdParty -and $top.thirdParty.port) { $where = " in third-party code ($($top.thirdParty.port) $($top.thirdParty.version))" }
        elseif ($OwnModules -notcontains $top.module) { $where = " in external module $($top.module)" }
    }
    $caller = if ($own -and $own -ne $top) { Get-DisplayFunctionName $own.function } else { $null }
    $inText = if ($location) { " in $location$(if ($caller) { " (called from $caller)" })" } else { '' }

    $result = [ordered]@{ category = 'other'; title = $null; text = $null; stackRole = 'culprit'; hints = @() }
    $code = if ($Exception) { [string]$Exception.code } else { $null }

    if (-not $Exception) {
        $result.category = 'no-exception'
        $result.title = 'Dump without exception record (manual or hang dump)'
        $result.text = 'The dump has no exception record: it was written manually or by a hang detector. The stack is the current thread, not necessarily a crash.'
        $result.stackRole = 'unknown'
        $result.hints = @('Look for threads blocked in waits or locks in threads.txt (deadlock / hang analysis).')
        return [pscustomobject]$result
    }

    # Linux signals use the same paths as the matching Windows exceptions.
    $failFast = $Exception.failFastCode
    if ($code -like 'SIG*') {
        if ($Exception.external) {
            $result.category = 'killed-by-signal'
            $result.title = "$code sent to the process from outside (no fault)"
            $senderPid = $null; try { $senderPid = $Exception.senderPid } catch { }
            $sender = if ($senderPid) { ", sender PID $senderPid$(if ($senderPid -eq 1) { ' = the container init process, which forwards signals from docker stop / docker kill' })" } else { '' }
            $result.text = "The process received $code from another process (si_code $($Exception.siCode): kill / tgkill$sender), for example docker kill, an orchestrator or a watchdog. It did not fault; the stack shows where the main thread was when the signal arrived."
            $result.stackRole = 'unknown'
            $result.hints = @('Find who sent the signal (container runtime, health check, watchdog, operator) and why; check the logs around the crash time.')
            return [pscustomobject]$result
        }
        $glibcCheck = @($Frames | Where-Object { $_.function -match '^(malloc_printerr|__libc_message|__libc_message_impl|__fortify_fail|__stack_chk_fail|__chk_fail)$' } | Select-Object -First 1)
        $glibcMessage = if ($Assertion -and $Assertion.kind -eq 'glibc fatal error') { [string]$Assertion.expression } else { $null }
        switch ($code) {
            'SIGSEGV' { $code = '0xC0000005' }
            'SIGBUS' { $code = '0xC0000005'; $result.hints += 'SIGBUS: access to a page of a mapped file that no longer exists (file truncated or on a lost volume) or a misaligned access.' }
            'SIGFPE' { $code = '0xC0000094' }
            'SIGILL' { $code = '0xC000001D' }
            'SIGTRAP' { $code = '0x80000003' }
            'SIGABRT' {
                $code = '0xC0000409'; $failFast = 7
                if (($glibcCheck.Count -and $glibcCheck[0].function -match 'stack_chk') -or $glibcMessage -match 'stack smashing') { $failFast = 2 }
                elseif ($glibcCheck.Count -or $glibcMessage) { $failFast = 50 }
            }
        }
        if ($glibcMessage) { $result.hints += "glibc message: $glibcMessage"; $Assertion = $null }
    }

    $terminate = ($Assertion -and $Assertion.kind -like 'std::terminate*') -or $code -eq '0xE06D7363'
    if ($terminate) {
        $result.category = 'unhandled-cpp-exception'
        if ($CppException) {
            $site = if ($CppException.throwSite) { Get-DisplayFunctionName $CppException.throwSite.function } else { $null }
            $err = if ($CppException.errorText) { " ($($CppException.errorText))" } else { '' }
            $result.title = "Unhandled $($CppException.thrownType)$(if ($site) { " thrown in $site" })"
            $result.text = "Unhandled C++ exception $($CppException.thrownType)$err$(if ($site) { " thrown in $site" }); std::terminate ended the process (deliberate abort, not memory corruption)."
            if ($site -and $CppException.throwSite.function -match '::~') {
                $result.hints += 'The throw site is a destructor: destructors are implicitly noexcept, so any exception escaping it calls std::terminate.'
            }
            $result.hints += 'Thrown type and throw site come from a raw stack scan: reliable as "was on the stack", not as an exact call chain.'
        }
        else {
            $result.title = "Unhandled C++ exception$inText"
            $result.text = "Unhandled C++ exception$inText; std::terminate ended the process. The thrown object was not found on the stack."
        }
        $result.hints += 'Find why the throw site throws and why no handler caught it (destructor, noexcept function, thread entry without try/catch).'
        return [pscustomobject]$result
    }

    if ($Assertion) {
        $expr = if ($Assertion.expression) { " '$($Assertion.expression)'" } else { '' }
        switch -wildcard ($Assertion.kind) {
            'BSON_ASSERT*' { $result.category = 'failed-assertion'; $result.title = "Failed BSON_ASSERT$expr$inText" }
            'CRT assert*' { $result.category = 'failed-assertion'; $result.title = "Failed assert()$expr$inText" }
            'assert()*' { $result.category = 'failed-assertion'; $result.title = "Failed assert()$expr$inText" }
            'CRT invalid parameter' { $result.category = 'invalid-parameter'; $result.title = "CRT invalid parameter$inText" }
            'pure virtual call' { $result.category = 'pure-virtual-call'; $result.title = "Pure virtual function call$inText" }
            default { $result.category = 'deliberate-abort'; $result.title = "$($Assertion.kind)$inText" }
        }
        $result.text = switch ($result.category) {
            'failed-assertion' { "Deliberate abort: assertion$expr failed$inText$where. The asserted condition was false; the stack shows where the bad value was used (culprit, not a victim of memory corruption)." }
            'invalid-parameter' { "A CRT/STL function was called with an invalid argument (for example an out-of-range index, an invalid iterator or a null string)$inText$where." }
            'pure-virtual-call' { "A pure virtual function was called${inText}: the object was used during its construction or destruction, or after it was destroyed (use-after-free)." }
            default { "Deliberate abort ($($Assertion.kind))$inText$where." }
        }
        if ($result.category -eq 'pure-virtual-call') { $result.stackRole = 'culprit-or-victim' }
        $result.hints += 'Explain why the condition was false and where the bad value came from along the call chain.'
        return [pscustomobject]$result
    }

    switch ($code) {
        '0xC0000005' {
            $kind = $null; $address = $null
            if (@($Exception.parameters).Count -ge 2) {
                $kind = [Convert]::ToUInt64(([string]$Exception.parameters[0] -replace '^0x', ''), 16)
                $address = [Convert]::ToUInt64(([string]$Exception.parameters[1] -replace '^0x', ''), 16)
            }
            $verb = switch ($kind) { 0 { 'read' } 1 { 'write' } 8 { 'execute' } default { 'access' } }
            $addrText = if ($null -ne $address) { '0x{0:X}' -f $address } else { 'an unknown address' }
            $highNull = if ($Is32Bit) { [uint64]0xFFFF0000L } else { [Convert]::ToUInt64('FFFFFFFFFFFF0000', 16) }
            if ($kind -eq 8 -or ($null -ne $address -and ('0x{0:X16}' -f $address) -eq $Exception.address)) {
                $result.category = 'bad-code-pointer'
                $result.title = "Execution at an invalid address$(if ($caller) { " (called from $caller)" } elseif ($location) { " in $location" })"
                $result.text = "Access violation: the CPU tried to execute code at $addrText. Typical causes: a corrupted function pointer or vtable, or a call through a destroyed object."
                $result.stackRole = 'culprit-or-victim'
            }
            elseif ($null -ne $address -and $address -lt 0x10000) {
                $result.category = 'null-pointer'
                $result.title = "Null-pointer $verb$inText"
                $offset = if ($address -gt 0) { " (member at offset 0x$('{0:X}' -f $address) of a null pointer)" } else { '' }
                $result.text = "Access violation: $verb at $addrText$offset$inText$where - a null or near-null pointer was dereferenced."
                $result.hints += 'Find the pointer that is null in the faulting instruction (register in the disassembly, FAULTING_LOCAL_VARIABLE_NAME) and where it should have been set.'
            }
            elseif ($null -ne $address -and $address -eq [uint64]::MaxValue -and -not $Is32Bit) {
                $result.category = 'wild-pointer'
                $result.title = "Access violation through a garbage pointer$inText"
                $result.text = "Access violation$inText$where with address 0xFFFFFFFFFFFFFFFF: Windows reports this for a non-canonical x64 address, so the pointer held garbage (use-after-free, race, or memory corruption)."
                $result.stackRole = 'culprit-or-victim'
            }
            elseif ($null -ne $address -and $address -ge $highNull) {
                $result.category = 'null-pointer'
                $result.title = "Null-pointer $verb (negative offset)$inText"
                $result.text = "Access violation: $verb at $addrText, just below address 0 - a null pointer with a negative offset was dereferenced$inText$where."
            }
            else {
                $result.category = 'wild-pointer'
                $result.title = "Access violation ($verb at invalid non-null address)$inText"
                $result.text = "Access violation: $verb at $addrText$inText$where. The address is not null, so the pointer was invalid: typically use-after-free, a data race on the object, an index or length out of range (base register valid, offset too large), or memory corruption."
                $result.stackRole = 'culprit-or-victim'
                $result.hints += 'Check threads.txt for other threads using the same object, and the object lifetime (who frees it).'
            }
        }
        '0xC0000409' {
            $sub = $failFast
            $isSignal = ([string]$Exception.code) -like 'SIG*'
            $checkName = if ($isSignal) { 'glibc runtime check (malloc_printerr / __libc_message)' } else { $Exception.failFastName }
            switch ($sub) {
                7 { $result.category = 'deliberate-abort'; $result.title = "abort()$inText"; $result.text = $(if ($isSignal) { "Deliberate abort (SIGABRT raised by abort())$inText." } else { "Deliberate abort (fail-fast subcode 7, FAST_FAIL_FATAL_APP_EXIT)$inText - not a buffer overrun." }) }
                { $_ -eq 0 -or $_ -eq 2 } { $result.category = 'stack-buffer-overrun'; $result.title = "Stack buffer overrun ($(if ($isSignal) { 'stack protector' } else { '/GS' }))$inText"; $result.text = "The stack cookie check failed$inText${where}: a fixed-size local buffer of that function was overwritten."; $result.hints += 'Look for fixed-size local arrays written without bounds checks in the function that owns the cookie.' }
                5 { $result.category = 'invalid-parameter'; $result.title = "CRT invalid parameter$inText"; $result.text = "Fail-fast invalid argument (subcode 5)$inText${where}: a CRT/STL function was called with an invalid argument." }
                10 { $result.category = 'bad-code-pointer'; $result.title = "Control Flow Guard violation$inText"; $result.text = "Control Flow Guard stopped an indirect call to an invalid target${inText}: a corrupted function pointer or vtable."; $result.stackRole = 'culprit-or-victim' }
                default { $result.category = 'memory-corruption-detected'; $result.title = "Memory corruption detected ($checkName)$inText"; $result.text = "A runtime check detected corrupted memory ($checkName)$inText. The crashing stack may be a victim; the corrupting write happened earlier."; $result.stackRole = 'victim-possible'; $result.hints += $(if ($isSignal) { 'Reproduce with ASan or MALLOC_CHECK_=3 / valgrind to catch the corrupting write.' } else { 'Reproduce with PageHeap (gflags /p /enable inmation.exe /full) or ASan to catch the corrupting write.' }) }
            }
        }
        '0xC0000374' {
            $result.category = 'heap-corruption'
            $result.title = "Heap corruption detected$inText"
            $result.text = "The heap manager detected corrupted heap metadata$inText. The crashing stack is often a victim; the corrupting write happened earlier, possibly in another thread."
            $result.stackRole = 'victim-possible'
            $result.hints += 'Do not treat the stack as the culprit. Reproduce with PageHeap (gflags /p /enable inmation.exe /full) or ASan.'
        }
        '0xC00000FD' {
            $result.category = 'stack-overflow'
            $rec = Get-StackRecursion $Frames
            $result.title = if ($rec) { "Stack overflow (recursion in $(Get-DisplayFunctionName ($rec.Function -replace '^[^!]+!', '')))" } else { "Stack overflow$inText" }
            $result.text = if ($rec) { "Stack overflow: $($rec.Function) appears $($rec.Count) times in the first frames - unbounded recursion." } else { "Stack overflow${inText}: deep recursion or very large stack allocations." }
        }
        '0xC0000094' { $result.category = 'divide-by-zero'; $result.title = "Integer division by zero$inText"; $result.text = "Integer division by zero$inText$where." }
        '0xC000001D' { $result.category = 'bad-code-pointer'; $result.title = "Illegal instruction$inText"; $result.text = "Illegal instruction${inText}: execution reached bytes that are not valid code (corrupted function pointer) or an unsupported CPU instruction."; $result.stackRole = 'culprit-or-victim' }
        '0xC0000006' { $result.category = 'in-page-error'; $result.title = "In-page I/O error$inText"; $result.text = "In-page error${inText}: a page of a mapped file or the image could not be read (disk, network share or storage failure). Often an environment problem, not a code defect."; $result.stackRole = 'unknown' }
        '0xC0000017' { $result.category = 'out-of-memory'; $result.title = "Out of memory$inText"; $result.text = "Out of memory${inText}: an allocation failed."; $result.stackRole = 'victim-possible'; $result.hints += 'Check process memory size and growth (uptime, handle/thread counts); the stack shows the allocation that failed, not necessarily the leak.' }
        '0x80000003' { $result.category = 'breakpoint'; $result.title = "Breakpoint$inText"; $result.text = "A breakpoint instruction (__debugbreak / DebugBreak / int 3) was hit${inText}: a deliberate stop."; }
        default { $result.title = "$($Exception.name)$inText"; $result.text = "Exception $code $($Exception.name)$inText$where." }
    }
    if ($top -and $top.module -and $OwnModules -notcontains $top.module -and $top.module -notmatch '^(ntdll|KERNELBASE|kernel32|ucrtbase|vcruntime\d*|msvcp\d*)$') {
        $result.hints += "The faulting frame is in $($top.module), which is not an inmation binary. Check the arguments inmation passed to it$(if ($caller) { " (from $caller)" }) and the version of that DLL."
    }
    return [pscustomobject]$result
}
