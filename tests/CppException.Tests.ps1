. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:LibRoot 'Frames.ps1')
. (Join-Path $script:LibRoot 'CppException.ps1')

Describe 'C++ exception scan' {
    $records = ConvertFrom-CppExceptionScan (Get-Fixture 'cdb-cxx-scan-system-error.txt') @('inmation')

    It 'finds one record and the thrown type from the vftable' {
        Assert-Equal 1 $records.Count
        Assert-Equal 'std::system_error' $records[0].thrownType
    }
    It 'decodes the error code of std::system_error' {
        Assert-Equal 'Generic' $records[0].errorCategory
        Assert-Equal 36 $records[0].errorValue
        Assert-Match 'resource_deadlock_would_occur' $records[0].errorText
    }
    It 'finds the throw site after the throw helpers' {
        Assert-Equal 'OpcUa::Server::RequestContext::~RequestContext' $records[0].throwSite.function
        Assert-Equal 120 $records[0].throwSite.sourceLine
        Assert-True (@($records[0].thrownVia) -contains 'std::_Throw_Cpp_error')
    }
    It 'lists the recovered callers and drops data symbols' {
        $fns = @($records[0].frames | ForEach-Object { $_.function })
        Assert-True ($fns -contains 'OpcUa::Server::UaSession::Close')
        Assert-True ($fns -contains 'OpcUa::Server::UaSessions::Close')
        Assert-False ($fns -contains '__ImageBase')
        Assert-False (@($fns | Where-Object { $_ -match 'vftable' }).Count -gt 0)
        Assert-False ($fns -contains 'std::system_error::system_error') 'frames before _CxxThrowException belong to the throw itself'
    }
    It 'builds 32-bit and 64-bit scan commands' {
        Assert-Match '@rsp.*\+0x20\) == 0x19930520' ((New-CppExceptionCommands $false $false) -join "`n")
        Assert-Match '!sw' ((New-CppExceptionCommands $true $true) -join "`n")
        Assert-Match '@esp.*\+0x14\) == 0x19930520' ((New-CppExceptionCommands $true $true) -join "`n")
    }
}

Describe 'dps line parsing' {
    It 'keeps function names with spaces' {
        $e = ConvertFrom-DpsLine '00000052`e9dff7b8  00007ff6`e77e41a2 inmation!thread_start<unsigned int (__cdecl*)(void *),1>+0x5a [minkernel\crts\ucrt\src\appcrt\startup\thread.cpp @ 97]'
        Assert-Equal 'thread_start<unsigned int (__cdecl*)(void *),1>' $e.function
        Assert-True $e.isCode
        Assert-Equal 97 $e.sourceLine
    }
    It 'treats PERF and data symbols as data' {
        Assert-False (ConvertFrom-DpsLine '00000052`e9dfedb0  00007ff6`e8d23000 inmation!__scrt_ucrt_dll_is_in_use <PERF> (inmation+0x31b3000)').isCode
        Assert-False (ConvertFrom-DpsLine '00000052`e9dfee60  00007ff6`e7b29190 inmation!std::system_error::`vftable''').isCode
    }
}
