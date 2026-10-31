. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:LibRoot 'Cdb.ps1')
. (Join-Path $script:LibRoot 'Frames.ps1')
. (Join-Path $script:LibRoot 'SearchTerms.ps1')

Describe 'cdb stack parsing' {
    $sections = Split-CdbSections (Get-Fixture 'cdb-terminate-minidump.txt')
    $frames = @(ConvertFrom-CdbStack (Get-Section $sections 'stack'))

    It 'splits marker sections' {
        Assert-True ($sections.ContainsKey('stack') -and $sections.ContainsKey('locals') -and $sections.ContainsKey('modules'))
    }
    It 'parses every frame with a hex index' {
        Assert-Equal 17 $frames.Count
        Assert-Equal 16 $frames[-1].index
    }
    It 'reads module, function, offset and source line' {
        Assert-Equal 'inmation' $frames[0].module
        Assert-Equal 'abort' $frames[0].function
        Assert-Equal 'inmation!abort+0x35' $frames[0].callSite
        Assert-Equal 'minkernel\crts\ucrt\src\appcrt\startup\abort.cpp' $frames[0].sourceFile
        Assert-Equal 77 $frames[0].sourceLine
    }
    It 'keeps template arguments in the function name' {
        Assert-Equal 'FindHandler<__FrameHandler4>' $frames[12].function
    }
    It 'treats bare addresses as frames without module' {
        Assert-Null $frames[1].module
        Assert-Equal '0x00007ff6`00000000' $frames[1].function
    }
    It 'parses inline frames' {
        $inline = @(ConvertFrom-CdbStack @('00 (Inline Function) --------`--------     inmation!mongo::BSONObjIterator::{ctor}+0xc [E:\ws\vcpkg\buildtrees\mongo-cxx-driver-legacy10\src\1.0.7-0123456789.clean\src\mongo\bson\bsonobjiterator.h @ 42]'))
        Assert-Equal 1 $inline.Count
        Assert-True $inline[0].inline
        Assert-Equal 'mongo::BSONObjIterator::{ctor}' $inline[0].function
        Assert-Equal 42 $inline[0].sourceLine
    }
}

Describe 'raw stack (unverified symbols)' {
    It 'converts return addresses to module+RVA' {
        $frames = @(
            [pscustomobject]@{ index = 0; inline = $false; retAddr = '0x00007ff600001234' },
            [pscustomobject]@{ index = 1; inline = $false; retAddr = '0x0000000000000010' })
        $modules = @([pscustomobject]@{ Name = 'inmation.exe'; Base = '0x00007FF600000000'; Size = 0x100000 })
        $raw = @(Get-RawStack $frames '0x00007FF600000100' $modules)
        Assert-Equal 'inmation.exe+0x100' $raw[0].address
        Assert-Equal 'inmation.exe+0x1234' $raw[1].address
    }
}

Describe 'frame classification and signature' {
    $sections = Split-CdbSections (Get-Fixture 'cdb-terminate-minidump.txt')
    $frames = @(ConvertFrom-CdbStack (Get-Section $sections 'stack'))
    $locals = Split-LocalsByFrame (Get-Section $sections 'locals')

    It 'marks CRT reporting and C++ exception dispatch frames as noise' {
        Assert-True (Test-NoiseFrame $frames[0])
        Assert-True (Test-NoiseFrame $frames[6])
        Assert-True (Test-NoiseFrame $frames[10])
        Assert-True (Test-NoiseFrame $frames[12])
    }
    It 'marks bare addresses below frame 0 as wrong unwinds' {
        Assert-True (Test-NoiseFrame $frames[1])
    }
    It 'keeps application frames' {
        $f = [pscustomobject]@{ index = 3; module = 'inmation'; function = 'inmation::server::cache::get' }
        Assert-False (Test-NoiseFrame $f)
    }
    It 'detects std::terminate without an application frame' {
        $a = Get-AssertionInfo $frames $locals $null
        Assert-Match '^std::terminate' $a.kind
        Assert-Equal 'terminate' $a.function
        Assert-Null $a.reportedBy
        Assert-NotNull $a.unwindNote
    }
    It 'builds the terminate signature and its offset-free family' {
        $a = Get-AssertionInfo $frames $locals $null
        $sig = Get-CrashSignature $frames $a @('inmation')
        Assert-Equal 'terminate in inmation!abort+0x35 [no application frame unwound]' $sig.Signature
        Assert-Equal 'terminate in inmation!abort [no application frame unwound]' $sig.Family
        Assert-True $sig.NoApplicationFrame
    }
    It 'uses the first meaningful frame and the first own frame' {
        $stack = @(
            [pscustomobject]@{ index = 0; inline = $true; module = 'inmation'; function = 'mongo::BSONElement::{ctor}'; callSite = 'inmation!mongo::BSONElement::{ctor}+0xe'; sourceFile = 'E:\ws\vcpkg\buildtrees\mongo\src\x.clean\bsonelement.h'; thirdParty = [pscustomobject]@{ port = 'mongo' } },
            [pscustomobject]@{ index = 1; inline = $false; module = 'inmation'; function = 'inmation::server::cache::get'; callSite = 'inmation!inmation::server::cache::get+0x101'; sourceFile = 'E:\ws\server\inmation\inServer.cpp'; thirdParty = $null })
        $sig = Get-CrashSignature $stack $null @('inmation')
        Assert-Equal 'inmation!mongo::BSONElement::{ctor}+0xe <- inmation!inmation::server::cache::get+0x101' $sig.Signature
        Assert-Equal 'inmation!mongo::BSONElement::{ctor} <- inmation!inmation::server::cache::get' $sig.Family
    }
    It 'prefixes the asserted expression' {
        $stack = @([pscustomobject]@{ index = 3; inline = $false; module = 'inmation'; function = '_mongoc_cursor_collection'; callSite = 'inmation!_mongoc_cursor_collection+0x84'; sourceFile = 'x.c'; thirdParty = $null })
        $sig = Get-CrashSignature $stack ([pscustomobject]@{ expression = '*collection_len > 0'; function = '_bson_assert_failed_on_line' }) @('inmation')
        Assert-Equal "assert '*collection_len > 0' in inmation!_mongoc_cursor_collection+0x84" $sig.Signature
    }
    It 'skips STL frames when looking for the first own frame' {
        $stack = @(
            [pscustomobject]@{ index = 0; inline = $true; module = 'inmation'; function = 'std::_Hash<std::_Umap_traits<long,std::basic_string<char> > >::_Find_last'; callSite = 'inmation!std::_Hash<std::_Umap_traits<long,std::basic_string<char> > >::_Find_last+0x11'; sourceFile = 'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.40.33807\include\xhash'; thirdParty = $null },
            [pscustomobject]@{ index = 1; inline = $false; module = 'inmation'; function = 'inmation::Errors::find'; callSite = 'inmation!inmation::Errors::find+0x20'; sourceFile = 'E:\ws\server\inmation\Errors.cpp'; thirdParty = $null })
        $sig = Get-CrashSignature $stack $null @('inmation')
        Assert-Equal 'inmation!std::_Hash<...>::_Find_last <- inmation!inmation::Errors::find' $sig.Family
    }
}

Describe 'function name compaction' {
    It 'collapses template arguments but keeps lambda names' {
        Assert-Equal 'std::_Func_impl_no_alloc<...>::_Do_call' (Get-CompactFunctionName 'std::_Func_impl_no_alloc<<lambda_1>,void,std::shared_ptr<int> >::_Do_call')
        Assert-Equal 'UaServer::BeginAsyncService::<lambda_1>::operator()' (Get-CompactFunctionName 'UaServer::BeginAsyncService::<lambda_1>::operator()')
        Assert-Equal 'std::operator<<<char>' (Get-CompactFunctionName 'std::operator<<<char>')
    }
}

Describe 'locals' {
    It 'reads string and number locals' {
        $lines = @('0x000000ab`cdef0000 char * test = 0x00007ff6`12345678 "*collection_len > 0"', '0x000000ab`cdef0008 int line = 0n1234')
        Assert-Equal '*collection_len > 0' (Get-LocalValue $lines @('test'))
        Assert-Equal '1234' (Get-LocalValue $lines @('line'))
        Assert-Null (Get-LocalValue $lines @('missing'))
    }
}

Describe 'TFS search terms' {
    It 'shortens long method names and qualifies short ones' {
        Assert-Equal 'process_vqt_writes' (Get-SearchTermName 'inmation::net::prot::ox::COxProtocol::process_vqt_writes')
        Assert-Equal 'cache::get' (Get-SearchTermName 'inmation::server::cache::get')
        Assert-Equal 'FindHandler' (Get-SearchTermName 'FindHandler<__FrameHandler4>')
        Assert-Null (Get-SearchTermName 'operator()')
    }
    It 'skips reporting, dispatch, Lua VM, std and bare-address frames' {
        $dump = [pscustomobject]@{
            assertion  = [pscustomobject]@{ expression = '*collection_len > 0' }
            crashStack = @(
                [pscustomobject]@{ index = 0; module = 'inmation'; function = 'abort' },
                [pscustomobject]@{ index = 1; module = $null; function = '0x00007ff6`00000000' },
                [pscustomobject]@{ index = 2; module = 'inmation'; function = '__CxxFrameHandler4' },
                [pscustomobject]@{ index = 3; module = 'inmation'; function = '_mongoc_cursor_collection' },
                [pscustomobject]@{ index = 4; module = 'inmation'; function = 'luaD_precall' },
                [pscustomobject]@{ index = 5; module = 'inmation'; function = 'std::_Func_impl_no_alloc<x>::_Do_call' },
                [pscustomobject]@{ index = 6; module = 'inmation'; function = 'inmation::model::scripting::lua::l_opt_safecall' })
        }
        $terms = @(Get-CrashTerms $dump)
        Assert-Equal @('collection_len', '_mongoc_cursor_collection', 'l_opt_safecall') @($terms | ForEach-Object { $_.Text })
    }
}
