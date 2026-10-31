# Deterministic matching of TFS work items against a crash: candidate selection after the search and a pre-verdict per
# fetched work item (same / likely same / related / different) from the crash facts found in its text. The pre-verdict is
# a pointer for the agent, who confirms it by reading the work item.

$script:exceptionKeywords = @{
    'null-pointer'               = 'access violation|c0000005|null ?pointer|nullptr|segfault|segmentation'
    'wild-pointer'               = 'access violation|c0000005|use.after.free|dangling|segfault|segmentation'
    'bad-code-pointer'           = 'access violation|c0000005|vtable|function pointer|illegal instruction|c000001d'
    'failed-assertion'           = 'assert'
    'deliberate-abort'           = '\babort'
    'unhandled-cpp-exception'    = 'terminate|e06d7363|c\+\+ exception'
    'heap-corruption'            = 'heap corruption|c0000374|corrupt'
    'memory-corruption-detected' = 'corrupt|c0000409'
    'stack-buffer-overrun'       = 'buffer overrun|stack cookie|/gs|c0000409'
    'stack-overflow'             = 'stack overflow|c00000fd'
    'invalid-parameter'          = 'invalid parameter|c0000409'
    'pure-virtual-call'          = 'pure virtual|purecall'
    'divide-by-zero'             = 'divi(de|sion) by zero|c0000094'
    'out-of-memory'              = 'out of memory|bad_alloc|c0000017'
}

# 'yes' if the text mentions the crash's exception kind, 'different' if it names only other exception codes, else 'no-info'.
function Get-ExceptionKindMatch($Dump, [string]$Text) {
    $lower = $Text.ToLowerInvariant()
    $category = [string](Get-Cfg (Get-Cfg $Dump 'classification' $null) 'category' '')
    $pattern = if ($script:exceptionKeywords.ContainsKey($category)) { $script:exceptionKeywords[$category] } else { $null }
    $extra = @()
    $expr = [string](Get-Cfg (Get-Cfg $Dump 'assertion' $null) 'expression' '')
    if ($expr) { $extra += [regex]::Escape($expr.ToLowerInvariant()) }
    $type = [string](Get-Cfg (Get-Cfg $Dump 'cppException' $null) 'thrownType' '')
    if ($type) { $extra += [regex]::Escape(($type -split '::')[-1].ToLowerInvariant()) }
    $all = @(@($pattern) + $extra | Where-Object { $_ })
    if ($all.Count -gt 0 -and $lower -match ('(' + ($all -join '|') + ')')) { return [pscustomobject]@{ Match = 'yes'; Evidence = $Matches[1] } }
    $code = ([string](Get-Cfg (Get-Cfg $Dump 'exception' $null) 'code' '')).ToLowerInvariant() -replace '^0x', ''
    $codes = @([regex]::Matches($lower, '\b(?:0x)?(c0000[0-9a-f]{3}|e06d7363)\b') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    if ($codes.Count -gt 0 -and $codes -notcontains $code) { return [pscustomobject]@{ Match = 'different'; Evidence = ($codes -join ', ') } }
    return [pscustomobject]@{ Match = 'no-info'; Evidence = $null }
}

function Test-TermFound($Term, [string]$Text) {
    $pattern = if ($Term.PSObject.Properties['Pattern'] -and $Term.Pattern) { $Term.Pattern } else { [regex]::Escape([string]$Term.Text) }
    return [regex]::IsMatch($Text, $pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

function Get-WorkItemPreVerdict($Dump, [string]$Text, [int]$MaxFrameTerms = 6) {
    $terms = @(Get-CrashTerms $Dump $MaxFrameTerms)
    $frameTerms = @($terms | Where-Object { $_.Kind -match '^(frame|throw site|caller of throw site)' })
    $exprTerms = @($terms | Where-Object { $_.Kind -eq 'asserted expression' })
    $first = @($frameTerms | Select-Object -First 3)
    $foundFirst = @($first | Where-Object { Test-TermFound $_ $Text })
    $foundAll = @($frameTerms | Where-Object { Test-TermFound $_ $Text })
    $exprFound = @($exprTerms | Where-Object { Test-TermFound $_ $Text })
    $topFound = ($first.Count -gt 0) -and (Test-TermFound $first[0] $Text)
    # The signature is 'faulting frame <- first own frame': a third-party/STL faulting frame reached from a different own
    # caller is another crash path, so 'same' needs the own frame too.
    $ownIndex = Get-Cfg (Get-Cfg $Dump 'signatureInfo' $null) 'firstOwnFrame' $null
    $ownTerm = if ($null -ne $ownIndex) { $frameTerms | Where-Object { $_.Frame -eq $ownIndex } | Select-Object -First 1 } else { $null }
    $ownFound = (-not $ownTerm) -or ($ownTerm -eq $first[0]) -or (Test-TermFound $ownTerm $Text)
    $kind = Get-ExceptionKindMatch $Dump $Text
    $needed = [Math]::Min(2, $first.Count)
    $verdict = if ($topFound -and $ownFound -and $foundFirst.Count -ge $needed -and $kind.Match -ne 'different') { 'same (to confirm)' }
    elseif ((($topFound -and ($kind.Match -eq 'yes' -or $first.Count -eq 1)) -or ($exprTerms.Count -gt 0 -and $exprFound.Count -eq $exprTerms.Count)) -and $kind.Match -ne 'different') { 'likely same' }
    # Same own caller and path with the same exception kind, but another innermost (inlined library) frame.
    elseif ($ownTerm -and $ownTerm -ne $first[0] -and (Test-TermFound $ownTerm $Text) -and $kind.Match -eq 'yes' -and $foundAll.Count -ge 2) { 'likely same' }
    elseif ($foundAll.Count -gt 0 -or $exprFound.Count -gt 0) { 'related' }
    else { 'different' }
    $reasons = @()
    if ($first.Count -gt 0) { $reasons += "first frame ``$($first[0].Text)`` $(if ($topFound) { 'found' } else { 'not found' })" }
    if ($ownTerm -and $ownTerm -ne $first[0]) { $reasons += "own caller ``$($ownTerm.Text)`` $(if ($ownFound) { 'found' } else { 'not found' })" }
    if ($first.Count -gt 1) { $reasons += "$($foundFirst.Count) of the first $($first.Count) frame terms found" }
    if ($exprTerms.Count -gt 0) { $reasons += "$($exprFound.Count) of $($exprTerms.Count) asserted identifiers found" }
    $reasons += switch ($kind.Match) { 'yes' { "exception kind mentioned ('$($kind.Evidence)')" } 'different' { "names other exception codes ($($kind.Evidence))" } default { 'exception kind not mentioned' } }
    $hasStack = $Text -match '![\w:~<>]+(\+0x[0-9a-f]+|\()|\.(cpp|cxx|hpp|h|c)\s*(@|:|\()\s*\d+|\)\s+Line\s+\d+'
    if (-not $hasStack) { $reasons += 'no call stack in the text (attachments may hold it)' }
    return [pscustomobject]@{ Verdict = $verdict; Reason = ($reasons -join '; '); TopFound = $topFound; FirstFound = $foundFirst.Count; FirstCount = $first.Count; ExceptionKind = $kind.Match; HasStack = [bool]$hasStack }
}

function Get-WorkItemStateMeaning([string]$State, [string]$Reason) {
    if ($Reason -match '^(Duplicate)$') { return 'duplicate' }
    if ($Reason -match '^(Obsolete|Cut|Not fixed|Won''t fix|Wont fix|As Designed|Cannot Reproduce|Copied to Backlog|Deferred|Removed)$' -or $State -eq 'Removed') { return 'closed without fix' }
    if ($State -match '^(Resolved|Closed|Done|Verified)$') { return 'fixed' }
    if ($State -match '^(New|Active|Approved|Committed|In Progress|Proposed|Open|Reopened)$') { return 'open' }
    return 'unknown'
}

# Which candidates to fetch: the strongest one (all or all but one scored terms matched) plus candidates that match the
# same first frame terms; otherwise the best five that match at least one non-broad term.
function Select-CandidatesToVerify($SearchEntry, [int]$BroadHits = 50, [int]$Max = 5) {
    $scored = @($SearchEntry.terms | Where-Object { -not $_.tooGeneric -and [int]$_.hits -gt 0 })
    $candidates = @($SearchEntry.candidates)
    if ($candidates.Count -eq 0 -or $scored.Count -eq 0) { return @() }
    $first3 = @($scored | Where-Object { $_.kind -ne 'user term' } | Select-Object -First 3 | ForEach-Object { $_.term })
    $strong = @($candidates | Where-Object { @($_.matchedTerms).Count -ge [Math]::Max(1, $scored.Count - 1) })
    if ($strong.Count -gt 0) {
        $pick = @($strong | Select-Object -First 3)
        if ($first3.Count -gt 0) {
            foreach ($c in $candidates) {
                if ($pick.Count -ge 4) { break }
                if (@($pick | Where-Object { $_.id -eq $c.id }).Count) { continue }
                $matched = @($c.matchedTerms)
                if (@($first3 | Where-Object { $matched -notcontains $_ }).Count -eq 0) { $pick += $c }
            }
        }
        return @($pick | ForEach-Object { [int]$_.id } | Select-Object -Unique)
    }
    $broad = @($SearchEntry.terms | Where-Object { [int]$_.hits -gt $BroadHits } | ForEach-Object { $_.term })
    $result = @()
    foreach ($c in $candidates) {
        if ($result.Count -ge $Max) { break }
        if (@(@($c.matchedTerms) | Where-Object { $broad -notcontains $_ }).Count -gt 0) { $result += [int]$c.id }
    }
    return $result
}
