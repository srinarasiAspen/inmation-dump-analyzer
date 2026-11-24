<#
.SYNOPSIS
Stage 3 evidence pack: compares the crashing code at the build commit with the latest code and checks candidate fixing
commits. Writes code-evidence.md next to summary.json and fills the evidence part of report sections 3-5.

.DESCRIPTION
Read-only on the repository (git show / log / grep / merge-base / branch --contains). For every crash signature with
verified symbols it:
  1. States the build commit (and how it was found) and the analysis ref (latest code of the product line, or the source
     branch of a dev build).
  2. For the faulting own frames (and the throw site of an unhandled C++ exception) extracts the whole function at the
     build commit with the faulting line marked, finds the same function on the analysis ref, and reports whether the
     faulting line is unchanged, changed or gone, with the diff of the function.
  3. Lists the commits on the analysis ref that touched the function since the build (git log -L).
  4. Checks the commits and pull requests (Azure Repos 'Merged PR <n>' and GitHub '#<n>') linked to matching work items
     of the old TFS and the new ADO (tfs-verification.json / ado-verification.json from stage 2):
     present locally, on the analysis ref, contained in the crashed build, touching the crashing files, release branches
     and tags containing them.
  5. Release builds only: whether the version branch and newer release branches contain the fix (also by subject, for
     cherry-picks).
The verdict and the root cause stay with the analyst: the report gets placeholders '_analyst: ..._' to replace.

.EXAMPLE
.\Get-CodeEvidence.ps1 -SummaryJson C:\Users\me\AppData\Local\inmation-crash-analysis\runs\20261031-101500\summary.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SummaryJson,
    [string]$RepoPath,
    [string]$Signature,
    [string]$ConfigPath,
    [switch]$NoReportUpdate
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
foreach ($lib in 'Common', 'Frames', 'Source', 'Report', 'CodeEvidence') { . (Join-Path $PSScriptRoot "lib\$lib.ps1") }

$config = (Read-AnalyzerConfig $ConfigPath $PSScriptRoot).Config
$summary = Get-Content -LiteralPath $SummaryJson -Raw -Encoding UTF8 | ConvertFrom-Json
$runDir = Split-Path (Resolve-Path -LiteralPath $SummaryJson).Path -Parent
$repo = if ($RepoPath) { (Resolve-SourceRepo $RepoPath $false $config).Repo } elseif (Get-Prop $summary 'repo') { [string](Get-Prop $summary 'repo') } else { (Resolve-SourceRepo $null $false $config).Repo }
if (-not $repo) {
    Write-Host 'STAGE3_BLOCKED=no source repository (run the collector from a clone of the inmation server repository, or pass -RepoPath)'
    exit 2
}
$ownModules = @((Get-Cfg $config 'binaries' $null).PSObject.Properties | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_.Name) })

$tfsData = @()
foreach ($name in 'tfs-verification.json', 'ado-verification.json') {
    $p = Join-Path $runDir $name
    if (Test-Path -LiteralPath $p) { $tfsData += @((Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json) | ForEach-Object { $_ } | Where-Object { $_ }) }
}

function Get-Short([string]$Sha) { if ($Sha) { return $Sha.Substring(0, [Math]::Min(10, $Sha.Length)) } return '' }

function Test-Ancestor([string]$Ancestor, [string]$Descendant) {
    if (-not $Ancestor -or -not $Descendant) { return $null }
    return (Invoke-Git $repo @('merge-base', '--is-ancestor', $Ancestor, $Descendant)).ExitCode -eq 0
}

function Get-FileAt([string]$Commit, [string]$Path) {
    if (-not $Commit -or -not $Path) { return $null }
    return Get-GitFileLines $repo $Commit $Path
}

function Format-YesNo($Value) { if ($null -eq $Value) { return 'unknown' } elseif ($Value) { return 'yes' } else { return 'no' } }

# Function at the build commit (containing the faulting line) and on the analysis ref, compared.
function Get-FunctionEvidence($Frame, [string]$BuildCommit, [string]$RefCommit, [string]$RefName) {
    $path = Get-Prop $Frame 'repoPath'
    $line = [int](Get-Prop $Frame 'sourceLine')
    $fn = Split-FunctionName ([string](Get-Prop $Frame 'function'))
    $ev = [ordered]@{ function = [string](Get-Prop $Frame 'function'); path = $path; line = $line; faultingLine = $null; buildRange = $null; buildText = @(); refPath = $null; refRange = $null; status = 'not analyzed'; diff = @(); commits = @(); note = $null }
    if (-not $path -or $line -le 0) { $ev.note = 'frame has no repository path or line'; return [pscustomobject]$ev }
    $buildLines = Get-FileAt $BuildCommit $path
    if (-not $buildLines) { $ev.note = "file not readable at build commit $(Get-Short $BuildCommit)"; return [pscustomobject]$ev }
    if ($line -le $buildLines.Count) { $ev.faultingLine = $buildLines[$line - 1].Trim() }
    $def = if ($fn.Usable) { Select-FunctionDefinition (Find-FunctionDefinitions $buildLines $fn.Class $fn.Method) $line $buildLines $null } else { $null }
    if ($def) { $ev.buildRange = "$($def.Start)-$($def.End)"; $ev.buildText = @(Format-NumberedLines $buildLines $def.Start $def.End $line) }
    else { $ev.buildText = @(Format-NumberedLines $buildLines ([Math]::Max(1, $line - 25)) ([Math]::Min($buildLines.Count, $line + 15)) $line); $ev.note = 'function boundaries not found; showing the lines around the faulting line' }
    if (-not $RefCommit) { $ev.status = 'no analysis ref'; return [pscustomobject]$ev }

    $refPath = $path
    $refLines = Get-FileAt $RefCommit $path
    if (-not $refLines -and $fn.Usable) {
        # The file moved or was renamed: find the definition by name.
        $pattern = if ($fn.Class) { "$($fn.Class)::$($fn.Method)(" } else { "$($fn.Method)(" }
        $grep = Invoke-Git $repo @('grep', '-l', '-F', $pattern, $RefCommit, '--', '*.cpp', '*.cxx', '*.cc', '*.h', '*.hpp', '*.c')
        $candidate = @($grep.Lines | ForEach-Object { ($_ -split ':', 2)[1] } | Where-Object { $_ }) | Select-Object -First 1
        if ($candidate) { $refPath = $candidate; $refLines = Get-FileAt $RefCommit $refPath }
    }
    $ev.refPath = $refPath
    if (-not $refLines) { $ev.status = 'file not found'; return [pscustomobject]$ev }
    $refDef = if ($fn.Usable) { Select-FunctionDefinition (Find-FunctionDefinitions $refLines $fn.Class $fn.Method) 0 $refLines $ev.faultingLine } else { $null }
    if (-not $refDef) {
        $ev.status = 'function not found (removed, renamed or not parsable)'
        return [pscustomobject]$ev
    }
    $ev.refRange = "$($refDef.Start)-$($refDef.End)"
    $refBody = @($refLines[($refDef.Start - 1)..($refDef.End - 1)])
    if ($def) {
        $buildBody = @($buildLines[($def.Start - 1)..($def.End - 1)])
        $ev.diff = @(Get-TextDiff $buildBody $refBody 3 | Select-Object -First 150)
        $lineKept = [bool](@($refBody | Where-Object { $_.Trim() -eq $ev.faultingLine }).Count)
        $ev.status = if ($ev.diff.Count -eq 0) { 'function unchanged' } elseif ($lineKept) { 'function changed, faulting line unchanged' } else { 'function changed, faulting line changed or removed' }
    }
    else {
        $ev.status = if (@($refBody | Where-Object { $_.Trim() -eq $ev.faultingLine }).Count) { 'faulting line still present (function boundaries at build not found)' } else { 'faulting line not found in the function (function boundaries at build not found)' }
    }
    if ($def -and $refPath -eq $path) {
        $log = Invoke-Git $repo @('log', '-L', "$($def.Start),$($def.End):$path", '--format=%h %ad %an | %s', '--date=short', '-s', "$BuildCommit..$RefCommit")
        $ev.commits = @($log.Lines | Where-Object { $_ -match '^[0-9a-f]{7,} ' } | Select-Object -First 25)
    }
    return [pscustomobject]$ev
}

# Where a candidate fixing commit is: on the analysis ref, in the crashed build, which files, branches and tags.
function Get-CommitEvidence([string]$Sha, [string]$BuildCommit, [string]$RefCommit, [string[]]$CrashFiles, [string]$VersionBranch) {
    $ev = [ordered]@{ sha = $Sha; known = $false; subject = $null; date = $null; author = $null; onRef = $null; inBuild = $null; touchesCrashFiles = $null; files = @(); releaseBranches = @(); tags = @(); versionBranch = $VersionBranch; onVersionBranch = $null; cherryPicks = @() }
    $show = Invoke-Git $repo @('show', '-s', '--format=%H%x09%ad%x09%an%x09%s', '--date=short', $Sha)
    if ($show.ExitCode -ne 0 -or -not $show.Lines) { return [pscustomobject]$ev }
    $p = $show.Lines[0] -split "`t", 4
    $ev.known = $true; $ev.sha = $p[0]; $ev.date = $p[1]; $ev.author = $p[2]; $ev.subject = $p[3]
    $ev.onRef = Test-Ancestor $ev.sha $RefCommit
    $ev.inBuild = Test-Ancestor $ev.sha $BuildCommit
    $ev.files = @((Invoke-Git $repo @('show', '--format=', '--name-only', $ev.sha)).Lines | Where-Object { $_ } | Select-Object -First 40)
    $ev.touchesCrashFiles = [bool](@($ev.files | Where-Object { $CrashFiles -contains $_ }).Count)
    $ev.releaseBranches = @((Invoke-Git $repo @('branch', '-r', '--contains', $ev.sha, '--list', '*/release/*')).Lines | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -First 15)
    $ev.tags = @((Invoke-Git $repo @('tag', '--contains', $ev.sha, '--list', 'v*', '--sort=version:refname')).Lines | Where-Object { $_ } | Select-Object -First 5)
    if ($VersionBranch) {
        $ev.onVersionBranch = Test-Ancestor $ev.sha $VersionBranch
        if (-not $ev.onVersionBranch -and $ev.subject) {
            $needle = ($ev.subject -replace '^Merged PR \d+:\s*', '')
            if ($needle.Length -gt 60) { $needle = $needle.Substring(0, 60) }
            $ev.cherryPicks = @((Invoke-Git $repo @('log', $VersionBranch, '-F', "--grep=$needle", '--format=%h %ad %s', '--date=short', '-n', '3')).Lines | Where-Object { $_ })
        }
    }
    return [pscustomobject]$ev
}

$letters = Get-ReportGroupLetters $summary
$dumps = @(Get-Prop $summary 'dumps')
$md = New-Object Text.StringBuilder
$add = { param([string]$Line = '') [void]$md.AppendLine($Line) }
$fence = '```'
$sec3 = New-Object Text.StringBuilder
$sec4 = New-Object Text.StringBuilder
$sec5 = New-Object Text.StringBuilder
$verdictRows = @()
& $add '# Code evidence (stage 3)'
& $add ''
& $add "Repository: $repo. Generated $([DateTime]::UtcNow.ToString('yyyy-MM-dd HH:mm'))Z. Facts from git; the verdict and root cause are for the analyst."

foreach ($g in @(Get-Prop $summary 'groups')) {
    $sig = [string](Get-Prop $g 'signature')
    if (-not $letters.ContainsKey($sig)) { continue }
    if ($Signature -and -not $sig.Contains($Signature)) { continue }
    $letter = $letters[$sig]
    $members = @($dumps | Where-Object { @(Get-Prop $g 'dumps') -contains (Get-Prop $_ 'dump.path') })
    $rep = $members[0]
    $build = Get-Prop $rep 'build'
    $buildCommit = [string](Get-Prop $build 'commit')
    $channel = [string](Get-Prop $build 'channel')
    $refName = [string](Get-Prop $rep 'compare.ref')
    $refCommit = [string](Get-Prop $rep 'compare.commit')
    $title = [string](Get-Prop $rep 'classification.title')
    & $add ''
    & $add "## Signature $letter - $title"
    & $add ''
    & $add "Signature: ``$sig``"
    & $add ''
    & $add "- Build: v$(Get-Prop $rep 'module.fileVersion') ($channel build$(if (Get-Prop $build 'brand') { ", brand $(Get-Prop $build 'brand')" })); build commit ``$buildCommit`` - confidence **$(Get-Prop $build 'confidence')** via $(Get-Prop $build 'method')$(if (Get-Prop $build 'sourceBranch') { "; source branch $(Get-Prop $build 'sourceBranch')" })"
    & $add "- Analysis ref: ``$refName`` @ ``$(Get-Short $refCommit)`` ($(Get-Prop $rep 'compare.reason')); build commit contained in it: $(Format-YesNo (Get-Prop $rep 'compare.buildCommitIsAncestor'))"
    foreach ($n in @(Get-Prop $build 'notes')) { if ($n) { & $add "- Note: $n" } }
    if (-not $buildCommit) {
        & $add ''
        & $add '**No build commit** - source-level comparison is not possible. Determine the commit first (see the build commit notes), then rerun.'
        [void]$sec3.AppendLine("### Signature $letter - $title`r`n`r`nNo build commit known; code comparison not possible.`r`n`r`n**Verdict:** _analyst: Inconclusive unless the build commit can be determined_`r`n")
        continue
    }

    # Frames to analyze: the faulting frame if it is own code, the first own frame, the next own caller; for an unhandled
    # C++ exception without unwound frames, the throw site and its callers from the stack scan.
    $stack = @(Get-Prop $rep 'crashStack')
    $targets = @()
    $info = Get-Prop $rep 'signatureInfo'
    $cpp = Get-Prop $rep 'cppException'
    if ((Get-Prop $info 'noApplicationFrame') -and $cpp) {
        foreach ($f in @(Get-Prop $cpp 'frames' | Where-Object { Get-Prop $_ 'application' } | Select-Object -First 2)) {
            $copy = [pscustomobject]@{ index = $null; module = (Get-Prop $f 'module'); function = (Get-Prop $f 'function'); sourceFile = (Get-Prop $f 'sourceFile'); sourceLine = (Get-Prop $f 'sourceLine'); repoPath = $null; role = 'throw site / caller (stack scan)' }
            $copy.repoPath = Convert-ToRepoPath $repo $buildCommit ([string]$copy.sourceFile) $config
            $targets += $copy
        }
    }
    else {
        $own = @($stack | Where-Object { (Get-Prop $_ 'repoPath') -and (Test-ApplicationFrame $_ $ownModules) })
        foreach ($f in @($own | Select-Object -First 2)) { $targets += [pscustomobject]@{ index = (Get-Prop $f 'index'); module = (Get-Prop $f 'module'); function = (Get-Prop $f 'function'); sourceFile = (Get-Prop $f 'sourceFile'); sourceLine = (Get-Prop $f 'sourceLine'); repoPath = (Get-Prop $f 'repoPath'); role = $(if ((Get-Prop $f 'index') -eq (Get-Prop $info 'topFrame')) { 'faulting frame' } else { 'first own frame / caller' }) } }
    }
    $crashFiles = @($targets | ForEach-Object { $_.repoPath } | Where-Object { $_ } | Select-Object -Unique)
    $functionFacts = @()
    foreach ($t in $targets) {
        $ev = Get-FunctionEvidence $t $buildCommit $refCommit $refName
        $functionFacts += [pscustomobject]@{ Target = $t; Evidence = $ev }
        & $add ''
        & $add "### $(if ($null -ne $t.index) { "Frame $($t.index)" } else { 'Frame' }) ($($t.role)): ``$(Get-CompactFunctionName $t.function)`` - $($ev.path):$($ev.line)"
        & $add ''
        if ($ev.note) { & $add "_$($ev.note)_"; & $add '' }
        if ($ev.faultingLine) { & $add "Faulting line at the build commit: ``$($ev.faultingLine -replace '`', "'")``"; & $add '' }
        & $add "**On ${refName}: $($ev.status)**$(if ($ev.refPath -and $ev.refPath -ne $ev.path) { " (moved to $($ev.refPath))" })$(if ($ev.refRange) { ", lines $($ev.refRange)" })"
        if (@($ev.buildText).Count) {
            & $add ''
            & $add "Function at the build commit ($(Get-Short $buildCommit), lines $($ev.buildRange); '>' marks the faulting line):"
            & $add ''
            & $add "${fence}cpp"
            foreach ($l in $ev.buildText) { & $add $l }
            & $add $fence
        }
        if (@($ev.diff).Count) {
            & $add ''
            & $add "Diff of the function, build commit -> ${refName}:"
            & $add ''
            & $add "${fence}diff"
            foreach ($l in $ev.diff) { & $add $l }
            & $add $fence
        }
        if (@($ev.commits).Count) {
            & $add ''
            & $add "Commits on $refName that changed this function since the build (newest first):"
            & $add ''
            foreach ($c in $ev.commits) { & $add "- $c" }
        }
    }
    if ($targets.Count -eq 0) { & $add ''; & $add '_No own frame with a repository path: the crash is entirely in third-party or runtime code. Compare the port versions below and look at the first own caller in the digest._' }

    $ports = @(Get-Prop $rep 'thirdParty')
    if ($ports.Count) {
        & $add ''
        & $add '### Third-party ports on the stack'
        & $add ''
        foreach ($p in $ports) {
            $b = Get-Prop $p 'atBuildCommit'; $r = Get-Prop $p 'atCompareRef'
            $fmt = { param($x) if (-not $x) { 'n/a' } elseif (-not (Get-Prop $x 'dir')) { [string](Get-Prop $x 'note') } else { "$(Get-Prop $x 'version')$(if ($null -ne (Get-Prop $x 'portVersion')) { "#$(Get-Prop $x 'portVersion')" }), patches: $(if (@(Get-Prop $x 'patches').Count) { @(Get-Prop $x 'patches') -join ', ' } else { 'none' })" } }
            & $add "- $(Get-Prop $p 'port'): build $(& $fmt $b); $refName $(& $fmt $r)"
        }
    }

    # Linked fixes from stage 2.
    $commitFacts = @()
    $matchedItems = @($tfsData | Where-Object { (Get-Prop $_ 'signature') -eq $sig } | ForEach-Object { @(Get-Prop $_ 'items') } | Where-Object { $_ -and (Get-Prop $_ 'verdict') -match '^(same|likely same)' })
    $versionBranch = [string](Get-Prop $build 'branch')
    if ($matchedItems.Count) {
        & $add ''
        & $add '### Fixes linked to matching TFS / ADO work items'
        foreach ($it in $matchedItems) {
            $ref = [string](Get-Prop $it 'ref'); if (-not $ref) { $ref = "#$(Get-Prop $it 'id')" }
            & $add ''
            & $add "$ref $(Get-Prop $it 'title') - $(Get-Prop $it 'verdict'), $(Get-Prop $it 'state') ($(Get-Prop $it 'reason'))"
            $shas = @(Get-Prop $it 'commits' | Where-Object { $_ })
            foreach ($pr in @(Get-Prop $it 'pullRequests' | Where-Object { $_ })) {
                $merge = (Invoke-Git $repo @('log', '--all', '-F', "--grep=Merged PR $($pr):", '--format=%H', '-n', '1')).Lines | Select-Object -First 1
                if ($merge) { $shas += $merge } else { & $add "- Pull request ${pr}: no 'Merged PR $pr' commit in this repository (other repository, or not fetched)" }
            }
            # GitHub: squash merges end with '(#<n>)', merge commits start with 'Merge pull request #<n> '.
            foreach ($pr in @(Get-Prop $it 'githubPullRequests' | Where-Object { $_ })) {
                $merge = (Invoke-Git $repo @('log', '--all', '-F', "--grep=(#$pr)", "--grep=Merge pull request #$pr ", '--format=%H', '-n', '1')).Lines | Select-Object -First 1
                if ($merge) { $shas += $merge } else { & $add "- GitHub pull request #${pr}: no '(#$pr)' / 'Merge pull request #$pr' commit in this repository (other repository, or not fetched)" }
            }
            foreach ($sha in @($shas | Select-Object -Unique)) {
                $ce = Get-CommitEvidence $sha $buildCommit $refCommit $crashFiles $versionBranch
                $commitFacts += [pscustomobject]@{ Item = $ref; Evidence = $ce }
                if (-not $ce.known) { & $add "- Commit ``$(Get-Short $sha)``: not in this repository (fetch, or it belongs to another repository)"; continue }
                & $add "- Commit ``$(Get-Short $ce.sha)`` $($ce.date) $($ce.author): $($ce.subject)"
                & $add "  - on ${refName}: $(Format-YesNo $ce.onRef); contained in the crashed build: $(Format-YesNo $ce.inBuild); touches the crashing files: $(Format-YesNo $ce.touchesCrashFiles)"
                if ($channel -ne 'dev') {
                    & $add "  - release branches: $(if ($ce.releaseBranches.Count) { $ce.releaseBranches -join ', ' } else { 'none' }); first tags: $(if ($ce.tags.Count) { $ce.tags -join ', ' } else { 'none' })"
                    if ($versionBranch) { & $add "  - version branch ${versionBranch}: $(Format-YesNo $ce.onVersionBranch)$(if ($ce.cherryPicks.Count) { "; cherry-pick candidates by subject: $($ce.cherryPicks -join ' / ')" })" }
                }
                & $add "  - files: $(@($ce.files | Select-Object -First 12) -join ', ')"
                if ($ce.touchesCrashFiles) {
                    $patch = @((Invoke-Git $repo @('show', '--format=', '-U3', $ce.sha, '--') + @($crashFiles)).Lines | Select-Object -First 120)
                    if ($patch.Count) {
                        & $add ''
                        & $add "  Change to the crashing files$(if ($patch.Count -ge 120) { ' (first 120 lines)' }):"
                        & $add ''
                        & $add "${fence}diff"
                        foreach ($l in $patch) { & $add $l }
                        & $add $fence
                    }
                }
            }
        }
    }
    elseif ($tfsData.Count) { & $add ''; & $add '_Stage 2 found no matching work item with a linked fix for this signature._' }
    else { & $add ''; & $add '_Stage 2 results (tfs-verification.json / ado-verification.json) not found: linked fixes were not checked._' }

    # Report section drafts: facts filled, decisions as placeholders.
    $lines3 = @("### Signature $letter - $title", '', '_Evidence generated by Get-CodeEvidence.ps1 - details, function text and diffs in code-evidence.md._', '')
    $lines3 += "- Build: v$(Get-Prop $rep 'module.fileVersion') ($channel build), build commit ``$(Get-Short $buildCommit)`` ($(Get-Prop $build 'confidence'), $(Get-Prop $build 'method')); analysis ref ``$refName`` @ ``$(Get-Short $refCommit)``"
    foreach ($ff in $functionFacts) {
        $lines3 += "- ``$(Get-CompactFunctionName $ff.Target.function)`` ($($ff.Evidence.path):$($ff.Evidence.line)): **$($ff.Evidence.status)** on $refName$(if (@($ff.Evidence.commits).Count) { "; $(@($ff.Evidence.commits).Count) commit(s) changed it since the build, newest: $(@($ff.Evidence.commits)[0])" })"
    }
    foreach ($cf in @($commitFacts | Where-Object { $_.Evidence.known })) {
        $lines3 += "- Linked fix of $($cf.Item): ``$(Get-Short $cf.Evidence.sha)`` - on $refName $(Format-YesNo $cf.Evidence.onRef), in the crashed build $(Format-YesNo $cf.Evidence.inBuild), touches the crashing files $(Format-YesNo $cf.Evidence.touchesCrashFiles)"
    }
    $lines3 += ''
    if ($channel -eq 'dev') {
        $lines3 += "Dev build - analyzed on ``$refName``."
        $lines3 += ''
        $lines3 += '**Still failing on the latest code?** _analyst: yes / no / unclear - one sentence why, citing the function status above_'
    }
    else {
        $lines3 += '**Verdict:** _analyst: one of Fixed / Fixed - related risk remains / Still present / Inconclusive - and one sentence of evidence_'
    }
    [void]$sec3.AppendLine(($lines3 -join "`r`n")); [void]$sec3.AppendLine('')

    $lines4 = @("### Signature $letter")
    if ($channel -eq 'dev') { $lines4 += '', 'n/a - dev build (root cause on the latest code instead).' }
    else {
        $cands = @($commitFacts | Where-Object { $_.Evidence.known -and $_.Evidence.onRef } | ForEach-Object { "``$(Get-Short $_.Evidence.sha)`` $($_.Evidence.subject) (linked from $($_.Item))" })
        $cands += @($functionFacts | ForEach-Object { @($_.Evidence.commits | Select-Object -First 5) } | ForEach-Object { "``$(($_ -split ' ')[0])`` $((($_ -split '\| ', 2)[1]))" })
        $cands = @($cands | Select-Object -Unique)
        $lines4 += '', "Candidates (verify each with ``git show <sha> -- <file>``): $(if ($cands.Count) { '' } else { 'none found' })"
        foreach ($c in $cands) { $lines4 += "- $c" }
        $lines4 += '', '**Fixing commit:** _analyst: sha, date, author, subject and the hunk that fixes the defect, or "n/a - still present"_'
        $lines4 += '**Available in:** _analyst: releases / release branches containing it (incl. cherry-picks), or the version to upgrade to_'
    }
    [void]$sec4.AppendLine(($lines4 -join "`r`n")); [void]$sec4.AppendLine('')

    $hints = @(Get-Prop $rep 'classification.hints' | Where-Object { $_ })
    $lines5 = @("### Signature $letter", '', "Classification: $(Get-Prop $rep 'classification.text')")
    foreach ($h in $hints) { $lines5 += "- Hint: $h" }
    $lines5 += '', '**Mechanism:** _analyst: what the faulting instruction did and which value was bad (register, local, pointer) - cite the dump facts_'
    $lines5 += '**Where the bad value came from:** _analyst: along the call chain; trigger (input, timing, configuration)_'
    $lines5 += '**Fix proposal:** _analyst: short diff against the latest code (not applied), or the fixing commit_'
    $lines5 += '**Confidence:** _analyst: high / medium / low, and what extra data would decide_'
    [void]$sec5.AppendLine(($lines5 -join "`r`n")); [void]$sec5.AppendLine('')
    $verdictRows += $letter
}

$evidencePath = Join-Path $runDir 'code-evidence.md'
[IO.File]::WriteAllText($evidencePath, $md.ToString(), [Text.UTF8Encoding]::new($false))
Write-Host "CODE_EVIDENCE_MD=$evidencePath"
$reportPath = [string](Get-Prop $summary 'reportPath')
if (-not $NoReportUpdate -and $reportPath -and (Test-Path -LiteralPath $reportPath)) {
    $stages = [string](Get-ReportHeaderValue $reportPath 'Stages done')
    if ($stages -notmatch '\b3\b') { $stages = "$stages, 3 code analysis (evidence generated; verdict pending)" }
    $refs = @($dumps | Where-Object { Get-Prop $_ 'compare.ref' } | ForEach-Object { "$(Get-Prop $_ 'compare.ref') @ $(Get-Short ([string](Get-Prop $_ 'compare.commit')))" } | Select-Object -Unique)
    $headerRows = @{ 'Stages done' = $stages; 'Compared against' = ($refs -join "`n") }
    # Exact / high confidence build commits need no check; estimated ones stay open for the analyst (Complete-CrashReport).
    $buildRow = [string](Get-ReportHeaderValue $reportPath 'Build commit')
    if ($buildRow -match 'not verified before stage 3') {
        $headerRows['Build commit'] = (@($buildRow -split '<br>' | ForEach-Object { if ($_ -match '\((exact|high),') { $_ -replace ' - not verified before stage 3$', '' } else { $_ } }) -join "`n")
    }
    Set-ReportSection $reportPath 3 $sec3.ToString() $headerRows
    Set-ReportSection $reportPath 4 $sec4.ToString()
    Set-ReportSection $reportPath 5 $sec5.ToString()
    Write-Host "REPORT_UPDATED=$reportPath"
    Write-Host "NEXT_STEP=Read $evidencePath, then list the open items and fill the answers file: powershell -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $PSScriptRoot 'Complete-CrashReport.ps1')`" -ReportPath `"$reportPath`""
}
