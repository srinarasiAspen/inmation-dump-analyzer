# Crash report (Markdown) generated from summary.json: header, section 1 (crash summary) and placeholders for the
# later stages, plus the short chat summary. Stages 2 and 3 replace their sections with Set-ReportSection.

$script:ReportSections = @{
    1 = '1. Crashing call stack'
    2 = '2. Existing TFS work items'
    3 = '3. Does the problem still exist?'
    4 = '4. Fixing commit'
    5 = '5. Root cause'
}

function Get-Prop($Object, [string]$Path) {
    $v = $Object
    foreach ($part in $Path.Split('.')) {
        if ($null -eq $v) { return $null }
        if ($v -is [Collections.IDictionary]) { if ($v.Contains($part)) { $v = $v[$part] } else { return $null }; continue }
        if (-not $v.PSObject.Properties[$part]) { return $null }
        $v = $v.PSObject.Properties[$part].Value
    }
    return $v
}

function Format-Code([string]$Text) { return '`' + ($Text -replace '`', "'") + '`' }

# Identity of the symbol file a blocked dump needs: PDB GUID/age (Windows) or GNU build-id (Linux).
function Get-BlockedIdentity($Blocked) {
    if (Get-Prop $Blocked 'identity') { return [string](Get-Prop $Blocked 'identity') }
    return "GUID $(Get-Prop $Blocked 'pdbGuid') age $(Get-Prop $Blocked 'pdbAge')"
}

# 'v1.2.3.4' or 'version unknown'.
function Get-VersionLabel($Dump) {
    $v = Get-Prop $Dump 'module.fileVersion'
    if ($v) { return "v$v" }
    return 'version unknown'
}

function Format-MdCell([string]$Text) { return ($Text -replace '\|', '\|' -replace "`r?`n", '<br>') }

function Format-ReportFrame($Frame, [int]$NameWidth = 0) {
    $index = '{0,2}' -f [int](Get-Prop $Frame 'index')
    $site = [string](Get-Prop $Frame 'callSite')
    if ($site.Length -gt 140) {
        $module = Get-Prop $Frame 'module'
        $site = "$(if ($module) { "$module!" })$(Get-CompactFunctionName ([string](Get-Prop $Frame 'function')))$(if ($site -match '(\+0x[0-9a-f]+)$') { $Matches[1] })"
    }
    $parts = @("$index  $site")
    $file = Get-Prop $Frame 'sourceFile'
    if ($file) { $parts += "($([IO.Path]::GetFileName($file)):$(Get-Prop $Frame 'sourceLine'))" }
    if (Get-Prop $Frame 'inline') { $parts += '[inline]' }
    $tp = Get-Prop $Frame 'thirdParty'
    if ($tp -and (Get-Prop $tp 'port')) { $parts += "[vcpkg $(Get-Prop $tp 'port') $(Get-Prop $tp 'version')]" }
    elseif ($tp) { $parts += '[vcpkg header]' }
    return ($parts -join '  ')
}

# First lines of the crashing stack: from the first meaningful frame, about 8 frames, extended to the first own frame.
function Get-ReportStack($Dump, [int]$Max = 8) {
    $frames = @(Get-Prop $Dump 'crashStack')
    $info = Get-Prop $Dump 'signatureInfo'
    $start = if ($info -and $null -ne (Get-Prop $info 'topFrame')) { [int](Get-Prop $info 'topFrame') } else { 0 }
    $ownIndex = if ($info -and $null -ne (Get-Prop $info 'firstOwnFrame')) { [int](Get-Prop $info 'firstOwnFrame') } else { -1 }
    $end = [Math]::Max($start + $Max - 1, [Math]::Min($ownIndex + 1, $start + 14))
    $shown = @($frames | Where-Object { [int]$_.index -ge $start -and [int]$_.index -le $end -and -not ([string]$_.function -match '^0x' -and [int]$_.index -gt 0) })
    $skipped = @($frames | Where-Object { [int]$_.index -lt $start -and [string]$_.function -notmatch '^0x' } | ForEach-Object { $_.function } | Select-Object -Unique)
    return [pscustomobject]@{ Lines = @($shown | ForEach-Object { Format-ReportFrame $_ }); Skipped = $skipped }
}

function Get-RecoveredThrowLines($Cpp, [int]$Max = 12) {
    $lines = @()
    $n = 0
    foreach ($f in @(Get-Prop $Cpp 'frames')) {
        $file = [string](Get-Prop $f 'sourceFile')
        $runtime = $file -match '[\\/](minkernel|vctools)[\\/]|[\\/]MSVC[\\/][^\\/]+[\\/]include[\\/]'
        if ($runtime -and -not (Get-Prop $f 'helper')) { continue }
        $tag = if (Get-Prop $f 'helper') { '  [throw helper]' } elseif ($file -match '[\\/]vcpkg[\\/]buildtrees[\\/](?<p>[^\\/]+)[\\/]') { "  [vcpkg $($Matches['p'])]" } else { '' }
        $site = [string](Get-Prop $f 'callSite')
        if ($site.Length -gt 140) { $site = "$(Get-Prop $f 'module')!$(Get-CompactFunctionName ([string](Get-Prop $f 'function')))" }
        $lines += "$site$(if ($file) { "  ($([IO.Path]::GetFileName($file)):$(Get-Prop $f 'sourceLine'))" })$tag"
        $n++
        if ($n -ge $Max) { break }
    }
    return $lines
}

function Get-DumpLabel($Dump) {
    $name = [IO.Path]::GetFileName([string](Get-Prop $Dump 'dump.path'))
    $archive = Get-Prop $Dump 'dump.archive'
    if ($archive) { return "$name (in $([IO.Path]::GetFileName([string]$archive)))" }
    return $name
}

function Get-BuildText($Dump) {
    $b = Get-Prop $Dump 'build'
    $parts = @()
    $parts += "$(Get-Prop $Dump 'module.name') file version v$(Get-Prop $Dump 'module.fileVersion')"
    $detail = @()
    if (Get-Prop $b 'productLine') { $detail += Get-Prop $b 'productLine' }
    if (Get-Prop $b 'channel') { $detail += "$(Get-Prop $b 'channel') build" }
    if (Get-Prop $b 'brand') { $detail += "brand $(Get-Prop $b 'brand')" }
    if ($detail) { $parts += "($($detail -join ', '))" }
    if (Get-Prop $b 'buildTimeUtc') { $parts += "built $(Get-Prop $b 'buildTimeUtc')" }
    return ($parts -join ' ')
}

# Letter (A, B, ...) per signature group with verified symbols, in the order of summary.groups. All stages use it.
function Get-ReportGroupLetters($Summary) {
    $letters = @{}
    $n = 0
    $dumps = @(Get-Prop $Summary 'dumps')
    foreach ($g in @(Get-Prop $Summary 'groups')) {
        $first = $dumps | Where-Object { (Get-Prop $_ 'dump.path') -eq @(Get-Prop $g 'dumps')[0] } | Select-Object -First 1
        if (-not $first -or (Get-Prop $first 'blocked') -or -not (Get-Prop $first 'module')) { continue }
        $letters[[string](Get-Prop $g 'signature')] = [string][char](65 + $n)
        $n++
    }
    return $letters
}

function Get-ReportTitle($Summary) {
    $groups = @(Get-Prop $Summary 'groups')
    $titles = @()
    foreach ($g in $groups) {
        $rep = @(Get-Prop $Summary 'dumps') | Where-Object { (Get-Prop $_ 'dump.path') -eq @(Get-Prop $g 'dumps')[0] } | Select-Object -First 1
        $t = if (Get-Prop $rep 'blocked') { "unverified $(Get-Prop $rep 'exception.code') in $(Get-VersionLabel $rep)" } else { Get-Prop $rep 'classification.title' }
        if ($t) { $titles += $t }
    }
    $titles = @($titles | Select-Object -Unique)
    if ($titles.Count -eq 0) { return 'crash dump(s)' }
    if ($titles.Count -eq 1) { return $titles[0] }
    $text = "$($titles.Count) crash signatures - $($titles[0..([Math]::Min(1, $titles.Count - 1))] -join '; ')"
    if ($titles.Count -gt 2) { $text += '; ...' }
    return $text
}

function New-CrashReportMarkdown($Summary, [string]$Generator = 'crash-dump-analyzer') {
    $dumps = @(Get-Prop $Summary 'dumps' | Where-Object { Get-Prop $_ 'module' })
    $failed = @(Get-Prop $Summary 'dumps' | Where-Object { -not (Get-Prop $_ 'module') })
    $groups = @(Get-Prop $Summary 'groups')
    $fence = '```'
    $sb = New-Object Text.StringBuilder
    $add = { param([string]$Line = '') [void]$sb.AppendLine($Line) }

    & $add "# Crash analysis: $(Get-ReportTitle $Summary)"
    & $add ''
    & $add "> Generated by $Generator (stage 1) on $(Get-Prop $Summary 'generatedUtc'). Facts come from the dump and verified symbols; later stages fill sections 2-5."
    & $add ''
    & $add '| | |'
    & $add '|---|---|'
    $dumpLines = @($dumps | ForEach-Object { $copyCount = @(Get-Prop $_ 'dump.copies' | Where-Object { $_ }).Count; "$(Get-DumpLabel $_): crash $(Get-Prop $_ 'dump.crashTimeUtc')$(if (Get-Prop $_ 'dump.uptime') { ", uptime $(Get-Prop $_ 'dump.uptime')" }), PID $(Get-Prop $_ 'dump.processId')$(if ($copyCount) { ", $copyCount identical cop$(if ($copyCount -eq 1) { 'y' } else { 'ies' })" })" })
    $dumpLines += @($failed | ForEach-Object { "$(Get-DumpLabel $_): not analyzed - $(@(Get-Prop $_ 'errors') -join '; ')" })
    & $add "| Dumps | $(Get-Prop $Summary 'uniqueDumps') unique dump(s) from $(Get-Prop $Summary 'inputDumpFiles') file(s) / archive entries<br>$(Format-MdCell ($dumpLines -join "`n")) |"
    & $add "| Binary | $(Format-MdCell ((@($dumps | ForEach-Object { Get-BuildText $_ }) | Select-Object -Unique) -join "`n")) |"
    $symLines = @($dumps | ForEach-Object {
            if (Get-Prop $_ 'blocked') { "$(Get-VersionLabel $_): not verified - see Blocked dumps" }
            else { "$(Get-Prop $_ 'symbols.pdbName') $(if ([string](Get-Prop $_ 'module.pdbGuid') -like 'build-id*') { Get-Prop $_ 'module.pdbGuid' } else { "GUID $(Get-Prop $_ 'module.pdbGuid')" }) verified ($(Get-Prop $_ 'symbols.loadStatus')), from $(Get-Prop $_ 'symbols.source')" }
        } | Select-Object -Unique)
    & $add "| Symbols | $(Format-MdCell ($symLines -join "`n")) |"
    & $add '| Stages done | 1 crash summary |'
    & $add '| Existing work item | not searched yet (stage 2) |'
    $commitLines = @($dumps | Where-Object { -not (Get-Prop $_ 'blocked') } | ForEach-Object {
            $b = Get-Prop $_ 'build'
            if (Get-Prop $b 'commit') { "v$(Get-Prop $_ 'module.fileVersion'): $(Get-Prop $b 'commit') ($(Get-Prop $b 'confidence'), $(Get-Prop $b 'method')) - not verified before stage 3" }
            else { "v$(Get-Prop $_ 'module.fileVersion'): unknown" }
        } | Select-Object -Unique)
    & $add "| Build commit | $(Format-MdCell ($commitLines -join "`n")) |"
    $refs = @($dumps | ForEach-Object { Get-Prop $_ 'compare.ref' } | Where-Object { $_ } | Select-Object -Unique)
    & $add "| Compared against | not yet (stage 3$(if ($refs) { ": $($refs -join ', ')" })) |"
    & $add "| Verdict | not analyzed$(if (@($dumps | Where-Object { Get-Prop $_ 'blocked' }).Count) { '; blocked dumps: pending PDB' }) |"
    & $add ''
    & $add "## $($script:ReportSections[1])"

    $letter = 0
    $letters = Get-ReportGroupLetters $Summary
    foreach ($g in $groups) {
        $members = @($dumps | Where-Object { @(Get-Prop $g 'dumps') -contains (Get-Prop $_ 'dump.path') })
        if ($members.Count -eq 0 -or (Get-Prop $members[0] 'blocked')) { continue }
        $rep = $members[0]
        $name = $letters[[string](Get-Prop $g 'signature')]; $letter++
        $cls = Get-Prop $rep 'classification'
        & $add ''
        & $add "### Signature $name - $(Get-Prop $cls 'title') ($($members.Count) dump$(if ($members.Count -ne 1) { 's' }))"
        & $add ''
        & $add "Signature: ``$(Get-Prop $g 'signature')``"
        & $add ''
        & $add "- Classification: **$(Get-Prop $cls 'category')** - $(Get-Prop $cls 'text')"
        $e = Get-Prop $rep 'exception'
        if ($e) {
            $access = if (Get-Prop $e 'access') { ", $(Get-Prop $e 'access')" } else { '' }
            & $add "- Exception: ``$(Get-Prop $e 'code')`` $(Get-Prop $e 'name')$(if (Get-Prop $e 'address') { " at $(Get-Prop $e 'address')" })$access, thread $(Get-Prop $e 'threadId')"
        }
        $a = Get-Prop $rep 'assertion'
        if ($a -and (Get-Prop $a 'expression')) { & $add "- Assertion: ``$(Get-Prop $a 'expression')`` ($(Get-Prop $a 'kind'))$(if (Get-Prop $a 'file') { " at $(Get-Prop $a 'file'):$(Get-Prop $a 'line')" })" }
        $cpp = Get-Prop $rep 'cppException'
        if ($cpp) {
            & $add "- Thrown C++ exception: ``$(Get-Prop $cpp 'thrownType')``$(if (Get-Prop $cpp 'errorText') { ", $(Get-Prop $cpp 'errorText')" })$(if (Get-Prop $cpp 'throwSite') { ", thrown in ``$(Get-Prop $cpp 'throwSite.function')`` ($([IO.Path]::GetFileName([string](Get-Prop $cpp 'throwSite.sourceFile'))):$(Get-Prop $cpp 'throwSite.sourceLine'))" }) - recovered from a raw stack scan"
        }
        foreach ($h in @(Get-Prop $cls 'hints')) { if ($h) { & $add "- Note: $h" } }
        $versions = @($members | ForEach-Object { "v$(Get-Prop $_ 'module.fileVersion') ($(Get-Prop $_ 'build.channel'))" } | Select-Object -Unique)
        & $add "- Dumps: $($members.Count), $($versions -join ', '); crash times $(@($members | ForEach-Object { Get-Prop $_ 'dump.crashTimeUtc' }) -join ', ')$(if (@($members | Where-Object { Get-Prop $_ 'dump.uptime' }).Count) { "; uptimes $(@($members | ForEach-Object { Get-Prop $_ 'dump.uptime' }) -join ', ')" })"
        $exact = @(Get-Prop $g 'exactSignatures')
        if ($exact.Count -gt 1) { & $add "- Exact signatures per build: $(@($exact | ForEach-Object { '`' + $_ + '`' }) -join '; ')" }
        & $add ''
        $stack = Get-ReportStack $rep
        if (Get-Prop $rep 'signatureInfo.noApplicationFrame') {
            & $add 'The debugger could not unwind past the C++ exception dispatch (the minidump lacks KERNELBASE/ntdll).'
            if ($cpp) {
                & $add 'Frames recovered from a raw stack scan (innermost first; reliable as "was on the stack", not as an exact call chain):'
                & $add ''
                & $add $fence
                foreach ($l in (Get-RecoveredThrowLines $cpp)) { & $add $l }
                & $add $fence
            }
        }
        else {
            & $add 'First lines of the crashing stack (frame number, module!function+offset, source file:line):'
            & $add ''
            & $add $fence
            foreach ($l in $stack.Lines) { & $add $l }
            & $add $fence
        }
        if ($stack.Skipped.Count -gt 0) { & $add ''; & $add "Reporting frames above them (skipped): $(@($stack.Skipped | ForEach-Object { Format-Code (Get-CompactFunctionName $_) }) -join ', ')." }
        $lua = @(Get-Prop $rep 'luaStack' | Where-Object { (Get-Prop $_ 'kind') -eq 'Lua' } | Select-Object -First 5)
        if ($lua.Count -gt 0) {
            & $add ''
            & $add 'Innermost Lua frames:'
            & $add ''
            foreach ($lf in $lua) { & $add "- level $(Get-Prop $lf 'level'): ``$(Get-Prop $lf 'source')`` line $(Get-Prop $lf 'line')$(if (Get-Prop $lf 'text') { ' - ' + (Format-Code (Get-Prop $lf 'text')) })" }
        }
        foreach ($sc in @(Get-Prop $rep 'scriptContext' | Where-Object { Get-Prop $_ 'request.endpoint' })) {
            & $add ''
            & $add "Request: $(Get-Prop $sc 'request.method') ``$(Get-Prop $sc 'request.endpoint')`` ($(Get-Prop $sc 'kind'))"
        }
    }
    if ($letter -eq 0) { & $add ''; & $add 'No dump with verified symbols - see Blocked dumps.' }

    foreach ($n in 2..5) {
        & $add ''
        & $add "## $($script:ReportSections[$n])"
        & $add ''
        if ($n -eq 2) { & $add '_Not done yet - stage 2._' }
        elseif (Get-Prop $Summary 'sourceAvailable') { & $add '_Not done yet - stage 3._' }
        else { & $add '_Stage 3 needs the source repository; not available on this machine._' }
    }

    $blocked = @($dumps | Where-Object { Get-Prop $_ 'blocked' })
    if ($blocked.Count -gt 0) {
        & $add ''
        & $add '## Blocked dumps'
        & $add ''
        & $add 'No verified symbols: only raw facts. No function names, grouping, build commit or root cause until the matching PDB is supplied (-PdbPath, or next to the dump).'
        & $add ''
        & $add '| Dump | File version | Exception | Faulting address | Required PDB | Binary linked | Install path |'
        & $add '|---|---|---|---|---|---|---|'
        foreach ($b in $blocked) {
            $raw = @(Get-Prop $b 'rawStack' | Where-Object { Get-Prop $_ 'address' }) | Select-Object -First 1
            & $add "| $(Format-MdCell (Get-DumpLabel $b)) | $(Get-VersionLabel $b) ($(Get-Prop $b 'build.channel')) | ``$(Get-Prop $b 'exception.code')`` $(Get-Prop $b 'exception.name')$(if (Get-Prop $b 'exception.access') { ", $(Get-Prop $b 'exception.access')" }) | $(if ($raw) { Get-Prop $raw 'address' }) | $(Get-Prop $b 'blocked.requiredPdb') $(Get-BlockedIdentity (Get-Prop $b 'blocked')) | $(Get-Prop $b 'blocked.binaryLinkedUtc') | $(Format-MdCell ([string](Get-Prop $b 'blocked.installPath'))) |"
        }
        $hints = @($blocked | Where-Object { Get-Prop $_ 'blocked.hint' } | ForEach-Object { "$(Get-DumpLabel $_): $(Get-Prop $_ 'blocked.hint')" } | Select-Object -Unique)
        if ($hints.Count -gt 0) {
            & $add ''
            foreach ($h in $hints) { & $add "- $h" }
        }
    }

    & $add ''
    & $add '## Artifacts'
    & $add ''
    & $add "- Run folder: $(Get-Prop $Summary 'runDir') (``summary.json``, ``digest.md``, one folder per dump with ``cdb.log`` or ``gdb.log``, ``locals.txt``, ``threads.txt``, ``analyze.txt``)"
    foreach ($d in @(Get-Prop $Summary 'dumps')) {
        foreach ($f in @(Get-Prop $d 'files.scripts') + @(Get-Prop $d 'files.libraries')) { if ($f) { & $add "- $f" } }
    }
    $extracted = @(Get-Prop $Summary 'extractedDumps' | ForEach-Object { Split-Path ([string](Get-Prop $_ 'dump')) -Parent } | Select-Object -Unique)
    if ($extracted.Count -gt 0) { & $add "- Dumps extracted from zip archives (delete when done): $($extracted -join ', ')" }
    return $sb.ToString()
}

# Short answer for the chat after stage 1.
function New-ChatSummaryMarkdown($Summary, [string]$ReportPath) {
    $dumps = @(Get-Prop $Summary 'dumps' | Where-Object { Get-Prop $_ 'module' })
    $fence = '```'
    $sb = New-Object Text.StringBuilder
    $add = { param([string]$Line = '') [void]$sb.AppendLine($Line) }
    $copies = [int](Get-Prop $Summary 'inputDumpFiles') - [int](Get-Prop $Summary 'uniqueDumps')
    & $add "**Crash summary (stage 1)** - $(Get-Prop $Summary 'uniqueDumps') unique dump(s)$(if ($copies -gt 0) { " ($copies identical copies folded)" }). Report: $ReportPath"
    & $add ''
    $letter = 0
    $letters = Get-ReportGroupLetters $Summary
    foreach ($g in @(Get-Prop $Summary 'groups')) {
        $members = @($dumps | Where-Object { @(Get-Prop $g 'dumps') -contains (Get-Prop $_ 'dump.path') })
        if ($members.Count -eq 0 -or (Get-Prop $members[0] 'blocked')) { continue }
        $rep = $members[0]
        $name = $letters[[string](Get-Prop $g 'signature')]; $letter++
        $versions = @($members | ForEach-Object { "v$(Get-Prop $_ 'module.fileVersion') $(Get-Prop $_ 'build.channel')$(if (Get-Prop $_ 'build.brand') { " ($(Get-Prop $_ 'build.brand'))" })" } | Select-Object -Unique)
        & $add "**$name. $(Get-Prop $rep 'classification.title')** (``$(Get-Prop $rep 'classification.category')``) - $($members.Count) dump(s), $($versions -join ', ')"
        & $add ''
        & $add "$(Get-Prop $rep 'classification.text')"
        & $add ''
        $lines = @(if ((Get-Prop $rep 'signatureInfo.noApplicationFrame') -and (Get-Prop $rep 'cppException')) { Get-RecoveredThrowLines (Get-Prop $rep 'cppException') 6 } else { (Get-ReportStack $rep 6).Lines })
        if ($lines.Count -gt 0) { & $add $fence; foreach ($l in $lines) { & $add $l }; & $add $fence }
        $lua = @(Get-Prop $rep 'luaStack' | Where-Object { (Get-Prop $_ 'kind') -eq 'Lua' } | Select-Object -First 2)
        foreach ($lf in $lua) { & $add "- Lua: ``$(Get-Prop $lf 'source')`` line $(Get-Prop $lf 'line')" }
        foreach ($sc in @(Get-Prop $rep 'scriptContext' | Where-Object { Get-Prop $_ 'request.endpoint' } | Select-Object -First 1)) { & $add "- Request: $(Get-Prop $sc 'request.method') ``$(Get-Prop $sc 'request.endpoint')``" }
        $hint = @(Get-Prop $rep 'classification.hints' | Where-Object { $_ }) | Select-Object -First 1
        if ($hint) { & $add "- Next: $hint" }
        if ((Get-Prop $rep 'classification.category') -eq 'killed-by-signal') { & $add '- Stages 2-3: not useful - nothing faulted, there is no code defect to search for (unless the stop itself was unexpected).' }
        & $add ''
    }
    foreach ($b in @($dumps | Where-Object { Get-Prop $_ 'blocked' })) {
        & $add "**Blocked:** $(Get-DumpLabel $b) $(Get-VersionLabel $b) - $(Get-Prop $b 'exception.code') $(Get-Prop $b 'exception.name'). Needs $(Get-Prop $b 'blocked.requiredPdb') $(Get-BlockedIdentity (Get-Prop $b 'blocked')).$(if (Get-Prop $b 'blocked.hint') { ' ' + (Get-Prop $b 'blocked.hint') })"
    }
    foreach ($f in @(Get-Prop $Summary 'dumps' | Where-Object { -not (Get-Prop $_ 'module') })) {
        & $add "**Not analyzed:** $(Get-DumpLabel $f) - $(@(Get-Prop $f 'errors') -join '; ')"
    }
    & $add ''
    & $add "Source code: $(if (Get-Prop $Summary 'sourceAvailable') { 'available (stage 3 possible)' } else { "not available ($(Get-Prop $Summary 'sourceNote')) - stage 3 needs a machine with the repository" })"
    return $sb.ToString()
}

# Replaces the body of a numbered report section (up to the next '## ' heading) and optionally header table rows.
function Set-ReportSection([string]$Path, [int]$Number, [string]$Body, [hashtable]$HeaderRows = @{}) {
    $text = [IO.File]::ReadAllText($Path)
    $heading = "## $($script:ReportSections[$Number])"
    $start = $text.IndexOf($heading)
    if ($start -lt 0) { throw "Section '$heading' not found in $Path" }
    $bodyStart = $start + $heading.Length
    $next = $text.IndexOf("`n## ", $bodyStart)
    $end = if ($next -ge 0) { $next + 1 } else { $text.Length }
    $text = $text.Substring(0, $bodyStart) + "`r`n`r`n" + $Body.Trim() + "`r`n`r`n" + $text.Substring($end)
    foreach ($row in $HeaderRows.Keys) {
        $text = [regex]::Replace($text, "(?m)^\| $([regex]::Escape($row)) \|.*\|\r?$", "| $row | $(Format-MdCell $HeaderRows[$row]) |")
    }
    [IO.File]::WriteAllText($Path, $text, [Text.UTF8Encoding]::new($false))
}

function Get-ReportHeaderValue([string]$Path, [string]$Row) {
    $m = [regex]::Match([IO.File]::ReadAllText($Path), "(?m)^\| $([regex]::Escape($Row)) \| (.*) \|\r?$")
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}
