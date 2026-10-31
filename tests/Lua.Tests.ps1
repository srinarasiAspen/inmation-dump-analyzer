. (Join-Path $script:LibRoot 'Common.ps1')
. (Join-Path $script:LibRoot 'Lua.ps1')

Describe 'Lua layout' {
    It 'picks the struct layout from the lua port version' {
        Assert-Equal '5.3' (Get-LuaFlavor '5.3.6')
        Assert-Equal '5.4' (Get-LuaFlavor '5.4.4')
        Assert-Equal '5.5' (Get-LuaFlavor '5.4.6')
        Assert-Equal '5.5' (Get-LuaFlavor '5.5.0')
        Assert-Equal '5.3' (Get-LuaFlavor $null)
    }
    It 'computes 5.4 line numbers from abslineinfo and relative lineinfo' {
        # Function defined at line 10; pc 0..3 advance by +1, 0, +2, -1.
        Assert-Equal 12 (Get-Lua54Line 3 10 @() ([byte[]](1, 0, 2, 255)))
        # An absolute entry (pc 2 -> line 50) overrides the deltas before it.
        Assert-Equal 49 (Get-Lua54Line 3 10 @(2, 50) ([byte[]](1, 0, 2, 255)))
        Assert-Null (Get-Lua54Line 9 10 @() ([byte[]](1, 0)))
    }
}

Describe 'cdb value parsing' {
    It 'reads db output into bytes, including ?? as gaps' {
        $bytes = ConvertFrom-DbLines @('00000000`10000000  41 42 43-44 00 01                                ABCD..')
        Assert-Equal @(65, 66, 67, 68, 0, 1) $bytes
        $win = ConvertFrom-DbWindow @('00000000`10000004  41 ?? 43 44                                      A.CD') ([uint64]0x10000000) 10
        Assert-Equal @(0, 0, 0, 0, 65, 0, 67, 68, 0, 0) $win
    }
    It 'reads dd output as signed ints' {
        Assert-Equal @(1, -1) (ConvertFrom-DdLines @('00000000`10000000  00000001 ffffffff'))
    }
    It 'reads the value after a marker, skipping echoed prompts' {
        $block = @('LF_DEF', '0:087> dx -r0 ((Proto*)0x1)->linedefined', '((Proto*)0x1)->linedefined : 120 [Type: int]', 'LF_SRC', '((char*)0x2) : 0x2 : "@/System/Core#Lib" [Type: char *]', 'LF_TT', 'Evaluate expression: 6 = 00000000`00000006')
        Assert-Equal '120' (Get-MarkedValue $block 'LF_DEF')
        Assert-Equal '@/System/Core#Lib' (Get-MarkedValue $block 'LF_SRC')
        Assert-Equal '6' (Get-MarkedValue $block 'LF_TT')
    }
}

Describe 'script masking' {
    It 'masks credential assignments in recovered text' {
        $masked = Protect-ScriptText "local password = 'secret1'`nlocal api_key=`"abc`"`nlocal user = 'bob'"
        Assert-Match "password = '\*\*\*masked\*\*\*'" $masked
        Assert-Match 'api_key="\*\*\*masked\*\*\*"' $masked
        Assert-Match "user = 'bob'" $masked
    }
    It 'parses an SCI request and masks authorization headers and tokens' {
        $req = '{"method":"POST","url":{"pathname":"/api/v2/execfunction","search":"?x=1"},"remote_ip_address":"10.0.0.1","headers":{"Authorization":"Bearer abc","User-Agent":"ua","Referer":"https://host/app"},"access_token":"tok"}'
        $payload = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('{"lib":"my-lib","func":"run"}'))
        $text = "package.loaded['inmation.api'] = function() end`nlocal msg = { topic = [[execfunction]], req = [[$req]], payload = [[$payload]], [`"content-type`"] = [[application/json]] }"
        $info = ConvertFrom-SciScript $text
        Assert-Equal @('inmation.api') $info.modules
        Assert-Equal 'POST' $info.method
        Assert-Equal '/api/v2/execfunction?x=1' $info.endpoint
        Assert-Equal '10.0.0.1' $info.remoteIp
        Assert-Equal 'base64-decoded' $info.payloadEncoding
        Assert-Equal '{"lib":"my-lib","func":"run"}' $info.payload
        Assert-NotMatch 'Bearer abc' $info.maskedText
        Assert-NotMatch '"tok"' $info.maskedText
    }
}

Describe 'model library validation' {
    It 'accepts text whose function lines match the prototype' {
        $text = "local M = {}`nfunction M.run(x)`n  return x.findOne`nend`nreturn M"
        $frames = @([pscustomobject]@{ lineDefined = 2; lastLineDefined = 4; stringConstants = @('findOne') })
        Assert-Equal @('2-4') (Test-LuaLibraryText $text $frames)
    }
    It 'rejects text whose lines do not match' {
        $frames = @([pscustomobject]@{ lineDefined = 1; lastLineDefined = 2; stringConstants = @('findOne') })
        Assert-Equal 0 (Test-LuaLibraryText "x = 1`ny = 2" $frames).Count
    }
}
