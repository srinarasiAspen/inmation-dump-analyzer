# Lua call chain, SCI script context and model library recovery (second and third cdb pass).

function Get-LuaFlavor([string]$Version) {
    if (-not $Version) { return '5.3' }
    if ($Version -match '^5\.3') { return '5.3' }
    if ($Version -match '^5\.4\.([0-5])$') { return '5.4' }
    if ($Version -match '^5\.(4|5)') { return '5.5' }
    return '5.3'
}

# Builds a cdb command file that walks the Lua CallInfo chain and dumps the configured script strings.
# cdb pitfalls handled here: '.if' conditions must not contain @@c++(), so values go through pseudo-registers first;
# every 'r' resets the register context set by .ecxr, so each 'r' that reads a local is preceded by '.ecxr; .frame'.
function New-ContextCommands($Frames, [string]$LuaFlavor, $ScriptFrames, [int]$MaxScriptBytes, [bool]$Wow64) {
    $cmds = New-Object Collections.Generic.List[string]
    if ($Wow64) { $cmds.Add('.load wow64exts'); $cmds.Add('!sw') }
    $cmds.Add('.ecxr')
    $luaCore = '^(luaD_precall|luaD_call|luaD_callnoyield|luaV_execute|luaD_rawrunprotected|luaD_pcall|lua_pcallk|lua_callk|luaT_callTM|luaD_throw|luaG_.*|luaH_.*|luaV_.*|precallC|ccall)$'
    $firstCore = $Frames | Where-Object { $_.function -match $luaCore } | Select-Object -First 1
    if ($firstCore) {
        $tries = @($Frames | Where-Object { $_.index -le $firstCore.index + 1 -and $_.index -ge [Math]::Max(0, $firstCore.index - 4) } | Sort-Object { if ($_.index -lt $firstCore.index) { $firstCore.index - $_.index } else { 10 + $_.index } })
        $cmds.Add('.echo <<<CTX:lua>>>')
        $cmds.Add('r $t0 = 0')
        foreach ($f in $tries) { $cmds.Add(".if (@`$t0 == 0) { .ecxr; .frame 0n$($f.index); r `$t0 = @@c++(L->ci) }") }
        $cmds.Add('.echo LUA_START'); $cmds.Add('? @$t0')
        $ci = '((CallInfo*)@$t0)'
        switch ($LuaFlavor) {
            '5.3' { $tv = "(*$ci->func)" }
            '5.4' { $tv = "$ci->func->val" }
            default { $tv = "$ci->func.p->val" }
        }
        $p = "((LClosure*)$tv.value_.gc)->p"
        $pc = "(($ci->u.l.savedpc - $p->code) - 1)"
        $luaBody = @('.echo <<<LUAFRAME>>>', "r `$t2 = @@c++($tv.tt_)", '.echo LF_TT', '? @$t2')
        $luaInner = @()
        switch ($LuaFlavor) {
            '5.3' { $luaInner += '.echo LF_SRC', "dx -r0 (char*)($p->source+1)" }
            '5.4' { $luaInner += '.echo LF_SRC', "dx -r0 (char*)$p->source->contents" }
            default {
                $luaInner += "r `$t3 = @@c++($p->source->shrlen)", '.echo LF_SRC'
                $luaInner += ".if ((@`$t3 & 0x80) == 0) { dx -r0 (char*)&$p->source->contents } .else { dx -r0 $p->source->contents }"
            }
        }
        $luaInner += '.echo LF_DEF', "dx -r0 $p->linedefined", '.echo LF_LAST', "dx -r0 $p->lastlinedefined", '.echo LF_PROTO', "? @@c++($p)"
        if ($LuaFlavor -eq '5.3') {
            $luaInner += '.echo LF_LINE', "dx -r0 $p->lineinfo[$pc]"
        }
        else {
            $luaInner += '.echo LF_PC', "dx -r0 (int)$pc"
            $luaInner += "r `$t4 = @@c++($p->sizeabslineinfo)", '.if (@$t4 > 0n4096) { r $t4 = 0n4096 }', '.echo LF_ABS'
            $luaInner += ".if (@`$t4 > 0) { dd @@c++($p->abslineinfo) L?(@`$t4 * 2) }"
            $luaInner += "r `$t5 = @@c++($ci->u.l.savedpc - $p->code)", '.if (@$t5 > 0n65536) { r $t5 = 0n65536 }', '.echo LF_LI'
            $luaInner += ".if (@`$t5 > 0) { db @@c++($p->lineinfo) L?@`$t5 }"
        }
        $cInner = @('.echo LF_CFN', "dx -r0 $tv.value_.f")
        $ccInner = @('.echo LF_CFN', "dx -r0 ((CClosure*)$tv.value_.gc)->f")
        $luaBody += ".if ((@`$t2 & 0x3f) == 6) { $($luaInner -join '; ') } .else { .if (@`$t2 == 0x16) { $($cInner -join '; ') } .else { .if ((@`$t2 & 0x3f) == 0x26) { $($ccInner -join '; ') } } }"
        $luaBody += "r `$t0 = @@c++($ci->previous)"
        $cmds.Add(".for (r `$t1 = 0; (@`$t0 != 0) & (@`$t1 < 0n80); r `$t1 = @`$t1 + 1) { $($luaBody -join '; ') }")
        $cmds.Add('.echo <<<CTX:luaend>>>')
    }
    foreach ($sf in @($ScriptFrames)) {
        $v = $sf.Variable
        $cmds.Add(".echo <<<CTX:script:$($sf.Frame)>>>")
        $at = ".ecxr; .frame 0n$($sf.Frame)"
        $cmds.Add('r $t2 = 0'); $cmds.Add('r $t3 = 0'); $cmds.Add('r $t4 = 0')
        $cmds.Add("$at; r `$t3 = @@c++($v._Mypair._Myval2._Mysize)")
        $cmds.Add("$at; r `$t4 = @@c++($v._Mypair._Myval2._Myres)")
        $cmds.Add(".if (@`$t4 >= 0n16) { $at; r `$t2 = @@c++($v._Mypair._Myval2._Bx._Ptr) } .else { $at; r `$t2 = @@c++(&$v._Mypair._Myval2._Bx._Buf[0]) }")
        $cmds.Add('.echo SCRIPT_SIZE'); $cmds.Add('? @$t3')
        $cmds.Add(".if (@`$t3 > 0n$MaxScriptBytes) { r `$t3 = 0n$MaxScriptBytes }")
        $cmds.Add('.echo SCRIPT_BYTES')
        $cmds.Add('.if ((@$t2 != 0) & (@$t3 != 0)) { db @$t2 L?@$t3 }')
        $cmds.Add('.echo SCRIPT_END')
    }
    $cmds.Add('.echo <<<CTX:end>>>')
    $cmds.Add('q')
    return $cmds
}

function ConvertFrom-DbLines([string[]]$Lines) {
    $bytes = New-Object Collections.Generic.List[byte]
    foreach ($l in $Lines) {
        if ($l -match '^(?:[0-9a-f]{8}`)?[0-9a-f]{8}  ((?:[0-9a-f]{2}[ -]){1,16})') {
            foreach ($h in ($Matches[1].Trim() -split '[ -]+')) { if ($h) { $bytes.Add([Convert]::ToByte($h, 16)) } }
        }
    }
    return , $bytes.ToArray()
}

function ConvertFrom-DdLines([string[]]$Lines) {
    $values = New-Object Collections.Generic.List[int]
    foreach ($l in $Lines) {
        if ($l -match '^(?:[0-9a-f]{8}`)?[0-9a-f]{8}  ((?:[0-9a-f]{8} ?){1,4})') {
            foreach ($h in ($Matches[1].Trim() -split ' +')) { if ($h) { $values.Add([BitConverter]::ToInt32([BitConverter]::GetBytes([Convert]::ToUInt32($h, 16)), 0)) } }
        }
    }
    return , $values.ToArray()
}

# Value of the 'dx' / '?' output line that follows a marker line.
function Get-MarkedValue([string[]]$Block, [string]$Marker) {
    for ($i = 0; $i -lt $Block.Count; $i++) {
        if ($Block[$i] -ne $Marker) { continue }
        # Commands from a -cf file are echoed with the prompt (e.g. '0:087> ? @$t3'); skip those lines.
        $j = $i + 1
        while ($j -lt $Block.Count -and $Block[$j] -match '^\d+:\d+(:x86)?> ') { $j++ }
        $next = if ($j -lt $Block.Count) { $Block[$j] } else { '' }
        if ($next -match '^Error|Unable to|memory read error') { return $null }
        if ($next -match ': (?:0x[0-9a-f`]+ : )?"(?<s>.*)" \[Type:') { return $Matches['s'] }
        if ($next -match 'Evaluate expression: (?<n>-?\d+) =') { return $Matches['n'] }
        if ($next -match ': 0x[0-9a-f`]+ : (?<sym>[^\s\[]+) \[Type:') { return $Matches['sym'] }
        if ($next -match ': (?<n>-?\d+) \[Type:') { return $Matches['n'] }
        return $null
    }
    return $null
}

function Get-MarkedRange([string[]]$Block, [string]$Marker) {
    $start = [Array]::IndexOf($Block, $Marker)
    if ($start -lt 0) { return @() }
    $out = @()
    for ($i = $start + 1; $i -lt $Block.Count; $i++) {
        if ($Block[$i] -match '^LF_[A-Z]+$') { break }
        $out += $Block[$i]
    }
    return $out
}

# luaG_getfuncline of Lua 5.4/5.5: absolute base line from abslineinfo plus the relative deltas in lineinfo.
function Get-Lua54Line([int]$Pc, [int]$LineDefined, [int[]]$AbsPairs, [byte[]]$LineInfo) {
    if (-not $LineInfo -or $LineInfo.Count -eq 0) { return $null }
    $basePc = -1; $line = $LineDefined
    for ($i = 0; $i + 1 -lt $AbsPairs.Count; $i += 2) {
        if ($AbsPairs[$i] -le $Pc) { $basePc = $AbsPairs[$i]; $line = $AbsPairs[$i + 1] } else { break }
    }
    while ($basePc -lt $Pc) {
        $basePc++
        if ($basePc -ge $LineInfo.Count) { return $null }
        $delta = [int]$LineInfo[$basePc]; if ($delta -gt 127) { $delta -= 256 }
        $line += $delta
    }
    return $line
}

function ConvertFrom-LuaContext([string[]]$Lines, [string]$LuaFlavor) {
    $frames = @()
    $blocks = @()
    $current = $null
    foreach ($l in $Lines) {
        if ($l -eq '<<<LUAFRAME>>>') { if ($null -ne $current) { $blocks += , $current.ToArray() }; $current = New-Object Collections.Generic.List[string]; continue }
        if ($null -ne $current) { $current.Add($l) }
    }
    if ($null -ne $current) { $blocks += , $current.ToArray() }
    $level = 0
    foreach ($b in $blocks) {
        $level++
        $tt = Get-MarkedValue $b 'LF_TT'
        $ttValue = if ($tt) { [int64]$tt } else { -1 }
        if (($ttValue -band 0x3f) -eq 6) {
            $source = Get-MarkedValue $b 'LF_SRC'
            $def = Get-MarkedValue $b 'LF_DEF'
            $line = $null
            if ($LuaFlavor -eq '5.3') { $line = Get-MarkedValue $b 'LF_LINE' }
            else {
                $pcText = Get-MarkedValue $b 'LF_PC'
                if ($pcText -and $def) { $line = Get-Lua54Line ([int]$pcText) ([int]$def) (ConvertFrom-DdLines (Get-MarkedRange $b 'LF_ABS')) (ConvertFrom-DbLines (Get-MarkedRange $b 'LF_LI')) }
            }
            $protoText = Get-MarkedValue $b 'LF_PROTO'
            $frames += [pscustomobject][ordered]@{ level = $level; kind = 'Lua'; source = $source; lineDefined = $def; lastLineDefined = (Get-MarkedValue $b 'LF_LAST'); line = $line; cFunction = $null; text = $null; proto = $(if ($protoText) { '0x{0:x}' -f [uint64]$protoText } else { $null }); upvalueNames = @(); localNames = @(); stringConstants = @() }
        }
        elseif ($ttValue -eq 0x16 -or ($ttValue -band 0x3f) -eq 0x26) {
            $frames += [pscustomobject][ordered]@{ level = $level; kind = 'C'; source = $null; lineDefined = $null; lastLineDefined = $null; line = $null; cFunction = (Get-MarkedValue $b 'LF_CFN'); text = $null; proto = $null; upvalueNames = @(); localNames = @(); stringConstants = @() }
        }
        else {
            $kindText = if ($ttValue -eq 0) { 'base (entered from C++)' } else { "other (tt=$tt)" }
            $frames += [pscustomobject][ordered]@{ level = $level; kind = $kindText; source = $null; lineDefined = $null; lastLineDefined = $null; line = $null; cFunction = $null; text = $null; proto = $null; upvalueNames = @(); localNames = @(); stringConstants = @() }
        }
    }
    return $frames
}

# Parses the Lua text that the Web API sends through SCI (bundled libraries, request message). Credentials and the
# access token payload are masked in the returned text.
function ConvertFrom-SciScript([string]$Text) {
    $info = [ordered]@{ sizeBytes = $Text.Length; modules = @(); topic = $null; contentType = $null; endpoint = $null; method = $null; remoteIp = $null; referer = $null; userAgent = $null; payload = $null; payloadEncoding = $null; maskedText = $Text; notes = @() }
    $info.modules = @([regex]::Matches($Text, "package\.loaded\[\s*['""]([^'""]+)['""]\s*\]\s*=") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $topic = [regex]::Match($Text, '(?s)\btopic\s*=\s*\[\[(.*?)\]\]'); if ($topic.Success) { $info.topic = $topic.Groups[1].Value }
    $ct = [regex]::Match($Text, '(?s)\["content-type"\]\s*=\s*\[\[(.*?)\]\]'); if ($ct.Success) { $info.contentType = $ct.Groups[1].Value }
    $payload = [regex]::Match($Text, '(?s)\bpayload\s*=\s*\[\[(.*?)\]\]')
    if ($payload.Success) {
        $raw = $payload.Groups[1].Value
        $info.payload = $raw; $info.payloadEncoding = 'raw'
        if ($raw -match '^[A-Za-z0-9+/=\s]+$' -and $raw.Trim().Length % 4 -eq 0 -and $raw.Trim().Length -gt 0) {
            try {
                $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw.Trim()))
                $printable = @($decoded.ToCharArray() | Where-Object { [int]$_ -ge 32 -or $_ -match '\s' }).Count
                if ($decoded.Length -gt 0 -and $printable / $decoded.Length -gt 0.95) { $info.payload = $decoded; $info.payloadEncoding = 'base64-decoded' }
            }
            catch { }
        }
    }
    $req = [regex]::Match($Text, '(?s)\breq\s*=\s*\[\[(.*?)\]\]')
    if ($req.Success) {
        $masked = $null
        try {
            $json = $req.Groups[1].Value | ConvertFrom-Json
            $info.method = Get-Cfg $json 'method' $null
            $url = Get-Cfg $json 'url' $null
            if ($url) { $info.endpoint = "$(Get-Cfg $url 'pathname' '')$([Uri]::UnescapeDataString([string](Get-Cfg $url 'search' '')))" }
            $info.remoteIp = Get-Cfg $json 'remote_ip_address' $null
            $headers = Get-Cfg $json 'headers' $null
            if ($headers) {
                $info.referer = Get-Cfg $headers 'Referer' $null
                $info.userAgent = Get-Cfg $headers 'User-Agent' $null
                foreach ($h in @($headers.PSObject.Properties | Where-Object { $_.Name -match '^(Authorization|Cookie|Set-Cookie|X-Api-Key|Proxy-Authorization)$' })) { $h.Value = '***masked***' }
            }
            foreach ($prop in @($json.PSObject.Properties | Where-Object { $_.Name -match 'token|password|secret|credential' })) { $prop.Value = '***masked***' }
            $masked = $json | ConvertTo-Json -Depth 20 -Compress
        }
        catch { $info.notes += "Request JSON could not be parsed ($($_.Exception.Message)); it was removed from the saved script." }
        if (-not $masked) { $masked = '<removed: request could not be parsed for masking>' }
        $info.maskedText = $Text.Substring(0, $req.Groups[1].Index) + $masked + $Text.Substring($req.Groups[1].Index + $req.Groups[1].Length)
    }
    return [pscustomobject]$info
}

# cdb fragment that prints the contents of the TString* in pseudo-register $t8 (layout per Lua version).
function Get-LuaStringCommand([string]$LuaFlavor) {
    switch ($LuaFlavor) {
        '5.3' { return 'dx -r0 (char*)((TString*)@$t8 + 1)' }
        '5.4' { return 'dx -r0 (char*)((TString*)@$t8)->contents' }
        default { return 'r $t7 = @@c++(((TString*)@$t8)->shrlen); .if ((@$t7 & 0x80) == 0) { dx -r0 (char*)&((TString*)@$t8)->contents } .else { dx -r0 ((TString*)@$t8)->contents }' }
    }
}

# Third cdb pass: string constants, upvalue names and local variable names of the given Lua function prototypes.
function New-ProtoCommands([string[]]$Protos, [string]$LuaFlavor, [bool]$Wow64) {
    $str = Get-LuaStringCommand $LuaFlavor
    $cmds = New-Object Collections.Generic.List[string]
    if ($Wow64) { $cmds.Add('.load wow64exts'); $cmds.Add('!sw') }
    foreach ($proto in $Protos) {
        $p = '((Proto*)@$t5)'
        $cmds.Add(".echo <<<PROTO:$proto>>>")
        $cmds.Add("r `$t5 = $proto")
        foreach ($part in @(
                @('sizek', 'PK', "r `$t2 = @@c++($p->k[@`$t1].tt_); .if (((@`$t2 & 0x3f) == 4) | ((@`$t2 & 0x3f) == 0x14)) { r `$t8 = @@c++($p->k[@`$t1].value_.gc); .echo PK; $str }"),
                @('sizeupvalues', 'PU', "r `$t8 = @@c++($p->upvalues[@`$t1].name); .if (@`$t8 != 0) { .echo PU; $str }"),
                @('sizelocvars', 'PL', "r `$t8 = @@c++($p->locvars[@`$t1].varname); .if (@`$t8 != 0) { .echo PL; $str }"))) {
            $cmds.Add("r `$t6 = @@c++($p->$($part[0]))")
            $cmds.Add('.if (@$t6 > 0n256) { r $t6 = 0n256 }')
            $cmds.Add(".for (r `$t1 = 0; @`$t1 < @`$t6; r `$t1 = @`$t1 + 1) { $($part[2]) }")
        }
    }
    $cmds.Add('.echo <<<PROTO:end>>>')
    $cmds.Add('q')
    return $cmds
}

function Get-MarkedValues([string[]]$Block, [string]$Marker) {
    $values = @()
    for ($i = 0; $i -lt $Block.Count; $i++) {
        if ($Block[$i] -eq $Marker) {
            $v = Get-MarkedValue $Block[$i..([Math]::Min($Block.Count - 1, $i + 3))] $Marker
            if ($null -ne $v) { $values += $v }
        }
    }
    return $values
}

# Parses 'db' output into a byte array that starts at $Start; unreadable bytes ('??') and gaps stay 0 (a string boundary).
function ConvertFrom-DbWindow([string[]]$Lines, [uint64]$Start, [int]$Length) {
    $bytes = New-Object byte[] $Length
    $regex = [regex]'^(?<a>[0-9a-f]{8}(?:`[0-9a-f]{8})?)  (?<h>(?:(?:[0-9a-f]{2}|\?\?)[ -]){1,16})'
    foreach ($l in $Lines) {
        $m = $regex.Match($l)
        if (-not $m.Success) { continue }
        $offset = [int64]([Convert]::ToUInt64(($m.Groups['a'].Value -replace '`', ''), 16) - $Start)
        foreach ($h in ($m.Groups['h'].Value.Trim() -split '[ -]+')) {
            if ($offset -ge 0 -and $offset -lt $Length -and $h -ne '??') { $bytes[$offset] = [Convert]::ToByte($h, 16) }
            $offset++
        }
    }
    return , $bytes
}

# Checks recovered text against the Lua prototypes of the chunk: the line of 'linedefined' must start a function, the
# line of 'lastlinedefined' must contain its 'end', and most string constants of the prototype must occur in between.
function Test-LuaLibraryText([string]$Text, $LuaFrames) {
    $lines = $Text -split "\r?\n"
    $validated = @()
    foreach ($lf in $LuaFrames) {
        if (-not $lf.lineDefined -or -not $lf.lastLineDefined) { continue }
        $def = [int]$lf.lineDefined; $last = [int]$lf.lastLineDefined
        if ($def -lt 1 -or $last -lt $def -or $last -gt $lines.Count) { continue }
        if ($lines[$def - 1] -notmatch '\bfunction\b' -or $lines[$last - 1] -notmatch '\bend\b') { continue }
        $body = $lines[($def - 1)..($last - 1)] -join "`n"
        $consts = @($lf.stringConstants | Where-Object { $_.Length -ge 3 })
        $found = @($consts | Where-Object { $body.Contains($_) }).Count
        if ($consts.Count -eq 0 -or $found / $consts.Count -ge 0.5) { $validated += "$def-$last" }
    }
    return , @($validated | Select-Object -Unique)
}

# Recovers the text of Lua libraries stored in the model (chunk names '@<object path>#<library>'), which are not in the
# repository and not part of the SCI entry script: reads the prototypes of their frames, searches process memory for
# distinctive names from them, and keeps the NUL-terminated text around a hit only if it matches the prototypes' lines.
function Invoke-LuaLibraryRecovery($Ctx, $LuaFrames, [string]$LuaFlavor, $Settings) {
    $libFrames = @($LuaFrames | Where-Object { $_.kind -eq 'Lua' -and $_.source -and $_.source.StartsWith('@') -and $_.proto })
    if ($libFrames.Count -eq 0) { return @() }
    $protos = @($libFrames | ForEach-Object { $_.proto } | Select-Object -Unique | Select-Object -First 16)
    $protoCmdFile = Join-Path $Ctx.OutDir 'lua-proto.cdb.txt'
    $protoLog = Join-Path $Ctx.OutDir 'lua-proto.log'
    Set-Content -LiteralPath $protoCmdFile -Value (New-ProtoCommands $protos $LuaFlavor $Ctx.Wow64) -Encoding ASCII
    Invoke-CdbScript $Ctx.Cdb $Ctx.Dump $Ctx.SymbolPath $Ctx.ImagePath $protoLog $protoCmdFile $Ctx.Timeout
    $protoBlocks = @{}
    $current = $null
    foreach ($l in (Get-Content -LiteralPath $protoLog)) {
        if ($l -match '^<<<PROTO:(?<p>[^>]+)>>>$') { $current = $Matches['p']; $protoBlocks[$current] = New-Object Collections.Generic.List[string]; continue }
        if ($current) { $protoBlocks[$current].Add($l) }
    }
    foreach ($lf in $libFrames) {
        if (-not $protoBlocks.ContainsKey($lf.proto)) { continue }
        $block = @($protoBlocks[$lf.proto])
        $lf.stringConstants = @(Get-MarkedValues $block 'PK')
        $lf.upvalueNames = @(Get-MarkedValues $block 'PU')
        $lf.localNames = @(Get-MarkedValues $block 'PL')
    }

    $stop = '^(syslib|string|table|require|pairs|ipairs|tostring|tonumber|setmetatable|getmetatable|rawget|rawset|format|insert|remove|concat|unpack|select|assert|error|pcall|xpcall|result|results|options|params|value|values|message|payload|response|request|object|objects|config|settings|default|findOne|collection|database|filter|projection|ObjectID|length|string_format|_ENV)$'
    $results = @()
    $maxAddress = if ($Ctx.Is32Bit) { '0xffffffff' } else { '0x7fffffffffff' }
    $window = [int](Get-Cfg $Settings 'windowBytes' 131072)
    foreach ($chunk in @($libFrames | ForEach-Object { $_.source } | Select-Object -Unique)) {
        $chunkFrames = @($libFrames | Where-Object { $_.source -eq $chunk })
        $names = @($chunkFrames | ForEach-Object { $_.upvalueNames }) + @($chunkFrames | ForEach-Object { $_.stringConstants } | Sort-Object Length -Descending) + @($chunkFrames | ForEach-Object { $_.localNames } | Sort-Object Length -Descending)
        $tokens = @($names | Where-Object { $_ -cmatch '^[A-Za-z_][A-Za-z0-9_]{5,63}$' -and $_ -notmatch $stop } | Select-Object -Unique | Select-Object -First ([int](Get-Cfg $Settings 'maxTokens' 3)))
        $lib = [ordered]@{ chunk = $chunk; recovered = $false; savedPath = $null; sizeBytes = $null; address = $null; validatedFunctions = @(); tokens = $tokens; candidatesChecked = 0; note = $null }
        $results += $lib
        if ($tokens.Count -eq 0) { $lib.note = 'No distinctive names in the prototypes (stripped bytecode?); search memory manually.'; continue }

        $searchFile = Join-Path $Ctx.OutDir 'lua-search.cdb.txt'
        $searchLog = Join-Path $Ctx.OutDir 'lua-search.log'
        $cmds = @(); foreach ($t in $tokens) { $cmds += ".echo <<<SEARCH:$t>>>", "s -[1]a 0 L?$maxAddress `"$t`"" }; $cmds += '.echo <<<SEARCH:end>>>', 'q'
        Set-Content -LiteralPath $searchFile -Value $cmds -Encoding ASCII
        Invoke-CdbScript $Ctx.Cdb $Ctx.Dump $Ctx.SymbolPath $Ctx.ImagePath $searchLog $searchFile $Ctx.Timeout
        $hitsByToken = [ordered]@{}
        $currentToken = $null
        foreach ($l in [IO.File]::ReadLines($searchLog)) {
            if ($l -match '^<<<SEARCH:(?<t>[^>]+)>>>$') { $currentToken = $Matches['t']; $hitsByToken[$currentToken] = New-Object Collections.Generic.List[uint64]; continue }
            if ($currentToken -and $l -match '^0x(?<a>[0-9a-f]{8}(?:`[0-9a-f]{8})?)\s*$') { $hitsByToken[$currentToken].Add([Convert]::ToUInt64(($Matches['a'] -replace '`', ''), 16)) }
        }
        # A name that occurs everywhere (e.g. 'Property') is not distinctive; rarest names first.
        $maxTokenHits = [int](Get-Cfg $Settings 'maxTokenHits' 500)
        $usable = @($hitsByToken.Keys | Where-Object { $_ -ne 'end' -and $hitsByToken[$_].Count -gt 0 -and $hitsByToken[$_].Count -le $maxTokenHits } | Sort-Object { $hitsByToken[$_].Count })
        $selected = New-Object Collections.Generic.List[uint64]
        $maxHits = [int](Get-Cfg $Settings 'maxHits' 6)
        foreach ($t in $usable) {
            foreach ($h in $hitsByToken[$t]) {
                if ($selected.Count -ge $maxHits) { break }
                $near = $false
                foreach ($s in $selected) { if ([Math]::Abs([double]$s - [double]$h) -lt $window) { $near = $true; break } }
                if (-not $near) { $selected.Add($h) }
            }
        }
        if ($selected.Count -eq 0) {
            $lib.note = "None of the names ($(@($hitsByToken.Keys | Where-Object { $_ -ne 'end' } | ForEach-Object { "$_ x$($hitsByToken[$_].Count)" }) -join ', ')) found in process memory with at most $maxTokenHits hits."
            continue
        }

        $winFile = Join-Path $Ctx.OutDir 'lua-window.cdb.txt'
        $winLog = Join-Path $Ctx.OutDir 'lua-window.log'
        $cmds = @(); foreach ($h in $selected) { $cmds += ('.echo <<<WIN:0x{0:x}>>>' -f $h), ('db 0x{0:x} L?0x{1:x}' -f ($h - [uint64]$window), (2 * $window)) }; $cmds += '.echo <<<WIN:end>>>', 'q'
        Set-Content -LiteralPath $winFile -Value $cmds -Encoding ASCII
        Invoke-CdbScript $Ctx.Cdb $Ctx.Dump $Ctx.SymbolPath $Ctx.ImagePath $winLog $winFile $Ctx.Timeout
        $winBlocks = @{}
        $current = $null
        foreach ($l in [IO.File]::ReadLines($winLog)) {
            if ($l -match '^<<<WIN:0x(?<a>[0-9a-f]+)>>>$') { $current = $Matches['a']; $winBlocks[$current] = New-Object Collections.Generic.List[string]; continue }
            if ($current) { $winBlocks[$current].Add($l) }
        }
        $best = $null
        $seen = @{}
        foreach ($h in $selected) {
            $key = '{0:x}' -f $h
            if (-not $winBlocks.ContainsKey($key)) { continue }
            $bytes = ConvertFrom-DbWindow @($winBlocks[$key]) ($h - [uint64]$window) (2 * $window)
            $s = $window; while ($s -gt 0 -and $bytes[$s - 1] -ne 0) { $s-- }
            $e = $window; while ($e -lt $bytes.Length -and $bytes[$e] -ne 0) { $e++ }
            if ($s -eq 0 -or $e -ge $bytes.Length) { continue }
            $text = [Text.Encoding]::UTF8.GetString($bytes, $s, $e - $s)
            if ($seen.ContainsKey($text)) { continue }
            $seen[$text] = $true
            $lib.candidatesChecked++
            $valid = Test-LuaLibraryText $text $chunkFrames
            if ($valid.Count -gt 0 -and (-not $best -or $valid.Count -gt $best.Valid.Count)) { $best = @{ Text = $text; Valid = $valid; Address = ($h - [uint64]$window + [uint64]$s) } }
        }
        if (-not $best) {
            $lib.note = "Text around $($selected.Count) memory hit(s) did not match the line ranges of the prototypes (library larger than 2 x windowBytes, or a different copy); search manually."
            continue
        }
        $fileName = 'library-' + (($chunk -replace '^.*[#/\\]', '') -replace '[^A-Za-z0-9_.-]', '_') + '.lua'
        $saved = Join-Path $Ctx.OutDir $fileName
        [IO.File]::WriteAllText($saved, (Protect-ScriptText $best.Text), [Text.UTF8Encoding]::new($false))
        $lines = $best.Text -split "\r?\n"
        foreach ($lf in @($LuaFrames | Where-Object { $_.source -eq $chunk })) {
            if ($lf.line -and [int]$lf.line -ge 1 -and [int]$lf.line -le $lines.Count) { $lf.text = $lines[[int]$lf.line - 1].Trim() }
        }
        $lib.recovered = $true; $lib.savedPath = $saved; $lib.sizeBytes = [Text.Encoding]::UTF8.GetByteCount($best.Text); $lib.address = '0x{0:x}' -f $best.Address; $lib.validatedFunctions = $best.Valid
    }
    return $results
}
