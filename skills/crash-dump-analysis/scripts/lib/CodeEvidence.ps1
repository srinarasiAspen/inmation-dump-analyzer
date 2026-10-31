# Source-level evidence for stage 3: locating the faulting function in a C++ file at two commits, comparing it, and
# checking candidate fixing commits. Heuristic C++ parsing: good enough to quote code, never a substitute for reading it.

# Class and method of a frame function: 'inmation::server::cache::get' -> class 'cache', method 'get'.
function Split-FunctionName([string]$Function) {
    $name = Get-CompactFunctionName $Function
    $name = $name -replace '<\.\.\.>', ''
    $parts = @($name -split '::' | Where-Object { $_ })
    $method = if ($parts.Count) { $parts[-1] } else { '' }
    $class = if ($parts.Count -ge 2) { $parts[-2] } else { $null }
    if ($method -eq '{ctor}' -and $class) { $method = $class }
    if ($method -eq '{dtor}' -and $class) { $method = "~$class" }
    return [pscustomobject]@{ Class = $class; Method = $method; Usable = [bool]($method -match '^~?[A-Za-z_]\w*$') }
}

# Removes string/char literals and comments from one line so braces inside them are not counted.
function Get-CodeOnly([string]$Line, [ref]$InBlockComment) {
    $sb = New-Object Text.StringBuilder
    $i = 0
    while ($i -lt $Line.Length) {
        if ($InBlockComment.Value) {
            $end = $Line.IndexOf('*/', $i)
            if ($end -lt 0) { return $sb.ToString() }
            $InBlockComment.Value = $false; $i = $end + 2; continue
        }
        $ch = $Line[$i]
        if ($ch -eq '/' -and $i + 1 -lt $Line.Length) {
            if ($Line[$i + 1] -eq '/') { break }
            if ($Line[$i + 1] -eq '*') { $InBlockComment.Value = $true; $i += 2; continue }
        }
        if ($ch -eq '"' -or $ch -eq "'") {
            $q = $ch; $i++
            while ($i -lt $Line.Length -and $Line[$i] -ne $q) { if ($Line[$i] -eq '\') { $i++ }; $i++ }
            $i++; continue
        }
        [void]$sb.Append($ch); $i++
    }
    return $sb.ToString()
}

# End line (1-based) of the brace block that opens at or after StartLine, or $null.
function Get-BlockEnd([string[]]$Lines, [int]$StartLine, [int]$MaxOpenSearch = 12) {
    $inComment = $false
    $depth = 0; $opened = $false
    for ($i = $StartLine; $i -le $Lines.Count; $i++) {
        $code = Get-CodeOnly $Lines[$i - 1] ([ref]$inComment)
        if (-not $opened -and $i -gt $StartLine + $MaxOpenSearch) { return $null }
        if (-not $opened -and $code -match ';\s*$' -and $code -notmatch '[{}]') { return $null }
        foreach ($ch in $code.ToCharArray()) {
            if ($ch -eq '{') { $depth++; $opened = $true }
            elseif ($ch -eq '}') { $depth--; if ($opened -and $depth -eq 0) { return $i } }
        }
    }
    return $null
}

# Definitions of Class::Method (or Method inside a class body): start line, end line. Calls and declarations are skipped.
function Find-FunctionDefinitions([string[]]$Lines, [string]$Class, [string]$Method) {
    $m = [regex]::Escape($Method)
    $qualified = if ($Class) { "\b$([regex]::Escape($Class))\s*::\s*$m\s*\(" } else { $null }
    $plain = "(^|[\s\*&:~])$m\s*\("
    $results = @()
    for ($i = 1; $i -le $Lines.Count; $i++) {
        $line = $Lines[$i - 1]
        $isQualified = $qualified -and $line -match $qualified
        $isPlain = -not $isQualified -and $line -match $plain -and $line -match "^\s*(?:[\w:<>,\*&~\s]+\s)?~?$m\s*\(" -and $line -notmatch '^\s*(return|if|while|for|switch|else|case|throw|co_return)\b' -and $line -notmatch '(=|\.|->)\s*~?\w*\s*\(' 
        if (-not ($isQualified -or $isPlain)) { continue }
        if ($line -match '^\s*(//|\*)') { continue }
        $end = Get-BlockEnd $Lines $i
        if ($end) { $results += [pscustomobject]@{ Start = $i; End = $end; Qualified = [bool]$isQualified } }
    }
    return , $results
}

# The definition that contains Line (build commit), or the best match on another commit (prefer qualified, then the one
# containing the given text).
function Select-FunctionDefinition($Definitions, [int]$Line, [string[]]$Lines, [string]$MustContain) {
    $defs = @($Definitions)
    if ($Line -gt 0) {
        $containing = @($defs | Where-Object { $_.Start -le $Line -and $_.End -ge $Line } | Sort-Object { $_.End - $_.Start })
        if ($containing.Count) { return $containing[0] }
        return $null
    }
    if ($MustContain) {
        $needle = $MustContain.Trim()
        $hit = @($defs | Where-Object { @(@($Lines[($_.Start - 1)..($_.End - 1)]) | Where-Object { $_.Trim() -eq $needle }).Count -gt 0 })
        if ($hit.Count) { return $hit[0] }
    }
    $q = @($defs | Where-Object { $_.Qualified })
    if ($q.Count) { return $q[0] }
    if ($defs.Count) { return $defs[0] }
    return $null
}

function Format-NumberedLines([string[]]$Lines, [int]$From, [int]$To, [int]$Mark = 0, [int]$Max = 160) {
    $out = @()
    $to = [Math]::Min($To, $Lines.Count)
    if ($to - $From + 1 -gt $Max) {
        # Keep the head of the function and the area around the marked line.
        $keep = @($From..[Math]::Min($From + 19, $to))
        if ($Mark -gt 0) { $keep += @([Math]::Max($From, $Mark - 40)..[Math]::Min($to, $Mark + 40)) }
        $keep = @($keep | Sort-Object -Unique)
    }
    else { $keep = @($From..$to) }
    $prev = $null
    foreach ($n in $keep) {
        if ($null -ne $prev -and $n -gt $prev + 1) { $out += '        ...' }
        $out += ('{0}{1,6}: {2}' -f $(if ($n -eq $Mark) { '>' } else { ' ' }), $n, $Lines[$n - 1])
        $prev = $n
    }
    return $out
}

# Line-based diff of two text blocks with git (no repository needed); returns the unified diff lines without headers.
function Get-TextDiff([string[]]$Old, [string[]]$New, [int]$Context = 3) {
    $a = [IO.Path]::GetTempFileName(); $b = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllLines($a, $Old); [IO.File]::WriteAllLines($b, $New)
        $eap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $out = & git diff --no-index --no-color "-U$Context" -- $a $b 2>$null } finally { $ErrorActionPreference = $eap }
        return @($out | Where-Object { $_ -notmatch '^(diff --git|index |--- |\+\+\+ )' })
    }
    finally { Remove-Item -LiteralPath $a, $b -Force -ErrorAction SilentlyContinue }
}
