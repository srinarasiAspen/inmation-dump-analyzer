. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:LibRoot 'Frames.ps1')
. (Join-Path $script:LibRoot 'Classification.ps1')
. (Join-Path $script:LibRoot 'LinuxCore.ps1')

function New-LinuxException([string]$Code, [int]$SiCode, [string]$Address = $null) {
    return [pscustomobject][ordered]@{
        threadId = 7; code = $Code; name = $Code; signal = 0; siCode = $SiCode; external = (($SiCode -le 0) -and ($Code -ne 'SIGABRT')); failFastCode = $null; failFastName = $null; flags = $null
        address = $Address; access = $null; parameters = @($(if ($Address) { '0x0'; $Address }))
    }
}

$script:linuxObjects = @([pscustomobject]@{ Name = 'inmation'; Path = '/inmation/bin/inmation'; Base = [uint64]0x5ff6c3400000; End = [uint64]0x5ff6c4000000; BuildId = 'aa' })

Describe 'gdb backtrace parsing' {
    $frames = ConvertFrom-GdbBacktrace (Get-Fixture 'gdb-kill-backtrace.txt') $script:linuxObjects @('inmation')

    It 'parses every frame' {
        Assert-Equal 9 $frames.Count
        Assert-Equal (0..8) @($frames | ForEach-Object { $_.index })
    }
    It 'takes the module from "from <lib>" or from the mapped files' {
        Assert-Equal 'libc.so.6' $frames[0].module
        Assert-Equal 'libstdc++.so.6' $frames[2].module
        Assert-Equal 'inmation' $frames[5].module
    }
    It 'normalizes names: no parameter signature, no symbol version' {
        Assert-Equal 'pthread_cond_wait' $frames[1].function
        Assert-Equal 'std::condition_variable::wait' $frames[2].function
        Assert-Equal 'std::condition_variable::wait<inmation::svc::wait_for_exit_signal()::<lambda()> >' $frames[3].function
        Assert-Equal 'inmation::svc::wait_for_exit_signal' $frames[4].function
        $f = ConvertFrom-GdbBacktrace @('#0  0x00007f3a1b4343d1 in __assert_fail_base.cold () from /sysroot/lib64/libc.so.6', '#1  0x00007f3a1b6a1a3d in __gnu_cxx::__verbose_terminate_handler() [clone .cold] () from /sysroot/lib64/libstdc++.so.6') @() @('inmation')
        Assert-Equal '__assert_fail_base' $f[0].function
        Assert-Equal '__gnu_cxx::__verbose_terminate_handler' $f[1].function
    }
    It 'marks frames without an address as inline frames of the next physical frame' {
        Assert-True $frames[4].inline
        Assert-Equal 'inmation' $frames[4].module
        Assert-False $frames[5].inline
    }
    It 'keeps source file and line' {
        Assert-Equal '/root/inmation/server/inmation/src/inInit.cpp' $frames[7].sourceFile
        Assert-Equal 470 $frames[7].sourceLine
        Assert-Match '^\(argc=' $frames[7].arguments
    }
    It 'builds module!function call sites' {
        Assert-Equal 'inmation!inmation::svc::run_console' $frames[5].callSite
    }
    It 'gives a signature through the first own frame' {
        $sig = Get-CrashSignature $frames $null @('inmation')
        Assert-Match 'inmation::svc::wait_for_exit_signal' $sig.Signature
    }
    It 'keeps operator() intact' {
        $f = ConvertFrom-GdbBacktrace @('#0  0x00005ff6c3a1b2c4 in inmation::Foo::operator() (this=0x1) at /root/inmation/server/inmation/src/Foo.cpp:12') $script:linuxObjects @('inmation')
        Assert-Equal 'inmation::Foo::operator()' $f[0].function
    }
    It 'shows module+offset for frames without a symbol' {
        $f = ConvertFrom-GdbBacktrace @('#0  0x00005ff6c3400010 in ?? ()') $script:linuxObjects @('inmation')
        Assert-Equal 'inmation+0x10' $f[0].callSite
    }
}

Describe 'Linux unhandled C++ exception' {
    $frames = ConvertFrom-GdbBacktrace (Get-Fixture 'gdb-terminate-backtrace.txt') $script:linuxObjects @('inmation')
    $assertion = Get-LinuxAssertionInfo $frames $null
    $cpp = Get-LinuxCppException $frames @('inmation')

    It 'recognizes std::terminate' {
        Assert-Match '^std::terminate' $assertion.kind
        Assert-Equal 'inmation!std::mutex::lock' $assertion.reportedBy 'the first frame after the C++ runtime frames'
    }
    It 'names the thrown type from the libstdc++ throw helper' {
        Assert-Equal 'std::system_error' $cpp.thrownType
        Assert-Equal 'inmation::core::Cache::get' $cpp.throwSite.function
    }
    It 'classifies as an unhandled C++ exception' {
        $sig = Get-CrashSignature $frames $assertion @('inmation')
        $c = Get-CrashClassification (New-LinuxException 'SIGABRT' -6) $assertion $frames $sig $cpp @('inmation') $false
        Assert-Equal 'unhandled-cpp-exception' $c.category
        Assert-Match 'std::system_error thrown in Cache::get' $c.title
    }
}

Describe 'glibc abort message' {
    It 'reads the x/s output of __abort_msg' {
        $msg = ConvertFrom-GdbAbortMessage @('0x7f1234560014:	"inmation: /root/inmation/server/inmation/src/core/Vector.h:55: T& Vector<T>::at(size_t): Assertion `index < size()'' failed.\n"')
        Assert-Equal 'inmation: /root/inmation/server/inmation/src/core/Vector.h:55: T& Vector<T>::at(size_t): Assertion `index < size()'' failed.' $msg
    }
    It 'returns null when __abort_msg is not set' {
        Assert-Null (ConvertFrom-GdbAbortMessage @('Cannot access memory at address 0x4'))
        Assert-Null (ConvertFrom-GdbAbortMessage @())
    }
    It 'turns an assert message into a failed assertion' {
        $frames = ConvertFrom-GdbBacktrace @(
            '#0  0x00007f3a1b4979dc in __pthread_kill_implementation () from /sysroot/lib64/libc.so.6',
            '#1  0x00007f3a1b4344b3 in abort () from /sysroot/lib64/libc.so.6',
            '#2  0x00007f3a1b4343d1 in __assert_fail_base.cold () from /sysroot/lib64/libc.so.6',
            '#3  0x00005ff6c3a1b2c4 in inmation::core::Vector<int>::at (this=0x1, index=9) at /root/inmation/server/inmation/src/core/Vector.h:55'
        ) $script:linuxObjects @('inmation')
        $a = Get-LinuxAssertionInfo $frames 'inmation: /root/inmation/server/inmation/src/core/Vector.h:55: T& Vector<T>::at(size_t): Assertion `index < size()'' failed.'
        Assert-Equal 'index < size()' $a.expression
        Assert-Equal '55' $a.line
        Assert-Equal 'inmation!inmation::core::Vector<int>::at' $a.reportedBy
        $c = Get-CrashClassification (New-LinuxException 'SIGABRT' -6) $a $frames (Get-CrashSignature $frames $a @('inmation')) $null @('inmation') $false
        Assert-Equal 'failed-assertion' $c.category
        Assert-Match "index < size\(\)" $c.title
    }
    It 'classifies glibc heap check messages as detected memory corruption' {
        $frames = ConvertFrom-GdbBacktrace @(
            '#0  0x00007f3a1b4979dc in __pthread_kill_implementation () from /sysroot/lib64/libc.so.6',
            '#1  0x00007f3a1b4344b3 in abort () from /sysroot/lib64/libc.so.6',
            '#2  0x00007f3a1b4a1fd7 in __libc_message.cold () from /sysroot/lib64/libc.so.6',
            '#3  0x00007f3a1b4a3a2c in free () from /sysroot/lib64/libc.so.6',
            '#4  0x00005ff6c3a1b2c4 in inmation::core::Buffer::~Buffer (this=0x1) at /root/inmation/server/inmation/src/core/Buffer.cpp:20'
        ) $script:linuxObjects @('inmation')
        $a = Get-LinuxAssertionInfo $frames 'free(): invalid pointer'
        Assert-Equal 'glibc fatal error' $a.kind
        $c = Get-CrashClassification (New-LinuxException 'SIGABRT' -6) $a $frames (Get-CrashSignature $frames $a @('inmation')) $null @('inmation') $false
        Assert-Equal 'memory-corruption-detected' $c.category
        Assert-True (@($c.hints) -contains 'glibc message: free(): invalid pointer')
    }
    It 'classifies stack smashing as a stack buffer overrun' {
        $a = Get-LinuxAssertionInfo @() '*** stack smashing detected ***: terminated'
        $c = Get-CrashClassification (New-LinuxException 'SIGABRT' -6) $a @() $null $null @('inmation') $false
        Assert-Equal 'stack-buffer-overrun' $c.category
    }
}

Describe 'Linux signal classification' {
    It 'reports a signal sent by another process as killed-by-signal' {
        $c = Get-CrashClassification (New-LinuxException 'SIGSEGV' 0) $null @() $null $null @('inmation') $false
        Assert-Equal 'killed-by-signal' $c.category
        $e = New-LinuxException 'SIGTERM' 0
        $e | Add-Member -NotePropertyName senderPid -NotePropertyValue 1
        Assert-Match 'sender PID 1 = the container init process' (Get-CrashClassification $e $null @() $null $null @('inmation') $false).text
    }
    It 'treats a SIGSEGV fault like an access violation' {
        $frames = ConvertFrom-GdbBacktrace @('#0  0x00005ff6c3a1b2c4 in inmation::core::Cache::get (this=0x0, key=42) at /root/inmation/server/inmation/src/core/Cache.cpp:118') $script:linuxObjects @('inmation')
        $c = Get-CrashClassification (New-LinuxException 'SIGSEGV' 1 '0x10') $null $frames (Get-CrashSignature $frames $null @('inmation')) $null @('inmation') $false
        Assert-NotMatch 'killed-by-signal' $c.category
        Assert-Match 'null|access' $c.category
    }
}

Describe 'Linux core files' {
    $dir = Join-Path ([IO.Path]::GetTempPath()) "cda-tests-$PID"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    try {
        It 'recognizes an ELF core by its header' {
            $core = Join-Path $dir 'core.1'
            $exe = Join-Path $dir 'exe'
            $header = New-Object byte[] 64
            $header[0] = 0x7f; $header[1] = 0x45; $header[2] = 0x4c; $header[3] = 0x46; $header[4] = 2; $header[16] = 4
            [IO.File]::WriteAllBytes($core, $header)
            $header[16] = 2
            [IO.File]::WriteAllBytes($exe, $header)
            Assert-True (Test-ElfCoreFile $core)
            Assert-False (Test-ElfCoreFile $exe)
        }
        It 'finds the product version string in the memory of the core' {
            $file = Join-Path $dir 'memory.bin'
            $text = "junk 1.108.1.123 x`0 26.1.0.7608.dev`0 more 26.1.0.7608.dev`0 26.0.3.7391 once`0" + (' ' * 100)
            [IO.File]::WriteAllBytes($file, [Text.Encoding]::ASCII.GetBytes($text))
            $v = Find-CoreVersionString $file
            Assert-Equal '26.1.0.7608' $v.Version
            Assert-True $v.Dev
            Assert-Equal 2 $v.Count
        }
        It 'needs at least two occurrences' {
            $file = Join-Path $dir 'memory2.bin'
            [IO.File]::WriteAllBytes($file, [Text.Encoding]::ASCII.GetBytes("26.0.3.7391`0" + (' ' * 100)))
            Assert-Null (Find-CoreVersionString $file)
        }
        It 'takes the crash time from the WSL dump name' {
            Assert-Equal '2026-07-10T09:36:32Z' (Get-CoreCrashTime 'C:\x\wsl-crash-1783676192-7-_inmation_bin_inmation-11.dmp')
        }
    }
    finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
}
