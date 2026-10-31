# Product line / channel routing, build folder candidates, PDB resolution, build commit estimation.

function Get-BuildChannel($Config, [hashtable]$Vars) {
    if (-not $Vars.minor) { return 'release' }
    $rule = Get-Cfg $Config 'devBuildRule' 'oddMinor'
    if ($rule -eq 'oddMinor' -and ([int]$Vars.minor % 2) -eq 1) { return 'dev' }
    return 'release'
}

function Get-ProductLine($Config, [hashtable]$Vars) {
    $gitCfg = Get-Cfg $Config 'git' $null
    $defaultRef = Get-Cfg $gitCfg 'compareRef' 'origin/main-legacy'
    $major = 0
    $hasMajor = $Vars.major -and [int]::TryParse([string]$Vars.major, [ref]$major)
    $lines = @(Get-Cfg $Config 'productLines' @())
    if ($lines.Count -eq 0) {
        # Legacy flat configuration
        $lines = @([pscustomobject]@{ name = 'default'; releaseRoots = @(Get-Cfg $Config 'releaseRoots' @()); devRoots = @(Get-Cfg $Config 'devRoots' @()); compareRef = $defaultRef })
    }
    $chosen = $null
    foreach ($line in $lines) {
        $min = [int](Get-Cfg $line 'minMajor' 0)
        $max = [int](Get-Cfg $line 'maxMajor' ([int]::MaxValue))
        if (($hasMajor -and $major -ge $min -and $major -le $max) -or (-not $hasMajor -and $min -eq 0)) { $chosen = $line; break }
    }
    if (-not $chosen) { $chosen = $lines[-1] }
    return [pscustomobject]@{
        Name         = Get-Cfg $chosen 'name' 'default'
        ReleaseRoots = @(Get-Cfg $chosen 'releaseRoots' @() | ForEach-Object { Expand-PathValue $_ })
        DevRoots     = @(Get-Cfg $chosen 'devRoots' @() | ForEach-Object { Expand-PathValue $_ })
        BrandedReleaseRoots = @(Get-Cfg $chosen 'brandedReleaseRoots' @() | ForEach-Object { Expand-PathValue $_ })
        BrandedDevRoots     = @(Get-Cfg $chosen 'brandedDevRoots' @() | ForEach-Object { Expand-PathValue $_ })
        CompareRef   = Get-Cfg $chosen 'compareRef' $defaultRef
    }
}

# Roots of the expected channel come first; the other channel is a fallback because a few builds do not follow the rule.
function Get-SearchRoots($Line, [string]$Channel) {
    $release = @($Line.ReleaseRoots | ForEach-Object { [pscustomobject]@{ Channel = 'release'; Root = $_ } })
    $dev = @($Line.DevRoots | ForEach-Object { [pscustomobject]@{ Channel = 'dev'; Root = $_ } })
    if ($Channel -eq 'dev') { return @($dev + $release) }
    return @($release + $dev)
}

function Find-VersionDirectory($Config, $Line, [hashtable]$Vars, [string]$Channel) {
    return Find-VersionFolderInRoots $Config $Vars (Get-SearchRoots $Line $Channel)
}

function Find-VersionFolderInRoots($Config, [hashtable]$Vars, $Roots) {
    $folder = Expand-Template (Get-Cfg $Config 'versionFolderPattern' 'v{version}') $Vars
    $roots = @($Roots)
    foreach ($entry in $roots) {
        $candidate = Join-Path $entry.Root $folder
        if (Test-Path -LiteralPath $candidate) { return [pscustomobject]@{ Path = $candidate; Channel = $entry.Channel } }
    }
    # Folders can carry a suffix, e.g. v2.0.0.3061_keep_for_qa
    foreach ($entry in $roots) {
        if (-not (Test-Path -LiteralPath $entry.Root)) { continue }
        $match = Get-ChildItem -LiteralPath $entry.Root -Directory -Filter "$folder*" -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $folder -or $_.Name.StartsWith("${folder}_") } | Select-Object -First 1
        if ($match) { return [pscustomobject]@{ Path = $match.FullName; Channel = $entry.Channel } }
    }
    return $null
}

# Brands whose path hints occur in the binary's install path come first (e.g. D:\AspenTech\inmation.root -> aspen).
function Get-OrderedBrands($Config, [string]$ModulePath) {
    $hinted = @(); $others = @()
    foreach ($brand in @(Get-Cfg $Config 'brands' @())) {
        $name = Get-Cfg $brand 'name' $null
        if (-not $name) { continue }
        $hit = @(Get-Cfg $brand 'pathHints' @()) | Where-Object { $_ -and $ModulePath -and $ModulePath.IndexOf($_, [StringComparison]::OrdinalIgnoreCase) -ge 0 } | Select-Object -First 1
        if ($hit) { $hinted += [pscustomobject]@{ Name = $name; Hint = $hit } } else { $others += [pscustomobject]@{ Name = $name; Hint = $null } }
    }
    return @($hinted + $others)
}

# All build folders that may hold the crashed binary: the unbranded folder of the product line and the same version in
# every branded root. Each candidate carries the PDB identity of its binary, so the matching folder is known before any
# symbol archive is extracted.
function Get-BuildFolderCandidates($Config, $Line, [hashtable]$Vars, [string]$Channel, $Module) {
    $list = New-Object Collections.Generic.List[object]
    $seen = @{}
    $binaryFolder = Get-Cfg $Config 'binaryFolder' 'inmation.root\bin'
    $add = {
        param($Hit, $Brand, $Hint)
        if (-not $Hit -or $seen.ContainsKey($Hit.Path.ToLowerInvariant())) { return }
        $seen[$Hit.Path.ToLowerInvariant()] = $true
        $exe = Join-Path (Join-Path $Hit.Path $binaryFolder) $Module.Name
        $state = 'unknown'; $exeGuid = $null; $exeTime = $null
        if (Test-Path -LiteralPath $exe) {
            try {
                $pe = Read-PeIdentity $exe
                $exeGuid = $pe.Guid
                $exeTime = ([DateTimeOffset]::FromUnixTimeSeconds($pe.TimeStamp)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
                if ($pe.Guid) { $state = if ($pe.Guid -eq $Module.PdbGuid) { 'match' } else { 'mismatch' } }
                elseif ($pe.TimeStamp -eq $Module.TimeStamp) { $state = 'match' }
            }
            catch { $state = 'unknown' }
        }
        $list.Add([pscustomobject]@{ Path = $Hit.Path; Channel = $Hit.Channel; Brand = $Brand; BrandHint = $Hint; ExePath = $exe; ExeGuid = $exeGuid; ExeTimeUtc = $exeTime; State = $state })
    }
    $brands = Get-OrderedBrands $Config $Module.Path
    $brandedHits = @()
    foreach ($brand in $brands) {
        $roots = @()
        $release = @($Line.BrandedReleaseRoots | ForEach-Object { [pscustomobject]@{ Channel = 'release'; Root = $_.Replace('{brand}', $brand.Name) } })
        $dev = @($Line.BrandedDevRoots | ForEach-Object { [pscustomobject]@{ Channel = 'dev'; Root = $_.Replace('{brand}', $brand.Name) } })
        $roots = if ($Channel -eq 'dev') { @($dev + $release) } else { @($release + $dev) }
        $hit = Find-VersionFolderInRoots $Config $Vars $roots
        if ($hit) { $brandedHits += [pscustomobject]@{ Hit = $hit; Brand = $brand } }
    }
    $primary = Find-VersionDirectory $Config $Line $Vars $Channel
    foreach ($b in @($brandedHits | Where-Object { $_.Brand.Hint })) { & $add $b.Hit $b.Brand.Name $b.Brand.Hint }
    if ($primary) { & $add $primary $null $null }
    foreach ($b in @($brandedHits | Where-Object { -not $_.Brand.Hint })) { & $add $b.Hit $b.Brand.Name $null }
    $candidates = $list.ToArray()
    # Folders whose binary matches the dump first, then folders without a readable binary; mismatches last.
    return @(@($candidates | Where-Object { $_.State -eq 'match' }) + @($candidates | Where-Object { $_.State -eq 'unknown' }) + @($candidates | Where-Object { $_.State -eq 'mismatch' }))
}

function Format-CandidateList($Candidates, $Module) {
    $dumpTime = ([DateTimeOffset]::FromUnixTimeSeconds($Module.TimeStamp)).UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $items = @($Candidates | ForEach-Object {
            $brandText = if ($_.Brand) { "brand $($_.Brand)" } else { 'unbranded' }
            "$($_.Path) [$brandText, $($_.Channel)]: binary GUID $($_.ExeGuid), linked $($_.ExeTimeUtc) -> $($_.State)"
        })
    return "dump binary GUID $($Module.PdbGuid), linked $dumpTime, path $($Module.Path). Build folders checked: $(if ($items) { $items -join '; ' } else { 'none' })"
}

function Get-NearbyVersions($Line, [hashtable]$Vars, [string]$Channel) {
    $found = @()
    foreach ($entry in (Get-SearchRoots $Line $Channel)) {
        if (Test-Path -LiteralPath $entry.Root) {
            $found += @(Get-ChildItem -LiteralPath $entry.Root -Directory -Filter ('v{0}.{1}.*' -f $Vars.major, $Vars.minor) -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 10 | ForEach-Object { $_.FullName })
        }
    }
    return $found
}

function Read-BuildInfo($Config, [string]$VersionDir) {
    if (-not $VersionDir) { return $null }
    $path = Join-Path $VersionDir (Get-Cfg $Config 'buildInfoFile' 'build_info.txt')
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $info = [ordered]@{ path = $path; sourceBranch = $null; commit = $null }
    foreach ($line in (Get-Content -LiteralPath $path)) {
        if ($line -match '^\s*Source Branch:\s*(\S+)') { $info.sourceBranch = $Matches[1] }
        elseif ($line -match '^\s*Commit ID:\s*([0-9a-fA-F]{7,40})') { $info.commit = $Matches[1].ToLowerInvariant() }
    }
    return [pscustomobject]$info
}

function Resolve-Pdb($Config, $Module, [string]$PdbName, $Candidates, [string]$PdbOverride, [string[]]$DumpDirs, $BundledPdbs) {
    $cacheRoot = Expand-PathValue (Get-Cfg $Config 'localSymbolCache' "$env:LOCALAPPDATA\inmation-crash-analysis\symbols")
    $key = ($Module.PdbGuid -replace '-', '').ToUpperInvariant() + $Module.PdbAge
    $targetDir = Join-Path (Join-Path $cacheRoot $PdbName) $key
    $target = Join-Path $targetDir $PdbName

    if (Test-Path -LiteralPath $target) {
        $cached = Read-PdbIdentity $target
        if ($cached.Guid -eq $Module.PdbGuid) {
            return [pscustomobject]@{ PdbPath = $target; SymbolDir = $targetDir; Source = 'local cache'; Guid = $cached.Guid; Age = $cached.Age; Candidate = $null }
        }
        Remove-Item -LiteralPath $target -Force
    }

    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    $partial = "$target.partial"

    if ($PdbOverride) {
        $identity = Read-PdbIdentity $PdbOverride
        if ($identity.Guid -ne $Module.PdbGuid) {
            throw "PDB mismatch: dump expects $PdbName GUID $($Module.PdbGuid) age $($Module.PdbAge), but '$PdbOverride' has GUID $($identity.Guid)."
        }
        Copy-Item -LiteralPath $PdbOverride -Destination $target -Force
        return [pscustomobject]@{ PdbPath = $target; SymbolDir = $targetDir; Source = $PdbOverride; Guid = $identity.Guid; Age = $identity.Age; Candidate = $null }
    }

    foreach ($dumpDir in @($DumpDirs | Where-Object { $_ } | Select-Object -Unique)) {
        $adjacent = Join-Path $dumpDir $PdbName
        if (Test-Path -LiteralPath $adjacent) {
            $identity = Read-PdbIdentity $adjacent
            if ($identity.Guid -eq $Module.PdbGuid) {
                return [pscustomobject]@{ PdbPath = $adjacent; SymbolDir = $dumpDir; Source = "$adjacent (next to dump)"; Guid = $identity.Guid; Age = $identity.Age; Candidate = $null }
            }
        }
    }

    # Symbols shipped inside the dump's zip (or another zip of the input) take precedence over the build shares.
    $mismatches = @()
    foreach ($bundled in @($BundledPdbs | Where-Object { $_ -and $_.Name -ieq $PdbName })) {
        $zip = [IO.Compression.ZipFile]::OpenRead($bundled.Archive)
        try {
            $entry = $zip.GetEntry($bundled.Entry)
            if (-not $entry) { continue }
            Write-Host "  Extracting $($bundled.Entry) from $($bundled.Archive) ($([Math]::Round($entry.Length / 1MB)) MB, bundled with the dump) ..."
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $partial, $true)
        }
        finally { $zip.Dispose() }
        try { $identity = Read-PdbIdentity $partial }
        catch { $mismatches += "$($bundled.Archive)!$($bundled.Entry) is not a readable PDB ($($_.Exception.Message))"; Remove-Item -LiteralPath $partial -Force; continue }
        if ($identity.Guid -eq $Module.PdbGuid) {
            Move-Item -LiteralPath $partial -Destination $target -Force
            return [pscustomobject]@{ PdbPath = $target; SymbolDir = $targetDir; Source = "$($bundled.Archive)!$($bundled.Entry) (bundled with dump)"; Guid = $identity.Guid; Age = $identity.Age; Candidate = $null }
        }
        $mismatches += "$($bundled.Archive)!$($bundled.Entry) (bundled) has GUID $($identity.Guid)"
        Remove-Item -LiteralPath $partial -Force
    }

    $candidates = @($Candidates | Where-Object { $_ })
    if ($candidates.Count -eq 0) {
        $bundledNote = if ($mismatches.Count -gt 0) { " Bundled symbols do not match: $($mismatches -join '; ')." } else { '' }
        if (-not (Get-ChildItem -LiteralPath $targetDir -Force -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $targetDir -Force -ErrorAction SilentlyContinue }
        throw "No build folder found for this version on the release, dev or branded shares; pass -PdbPath with the matching $PdbName.$bundledNote"
    }

    $searched = @()
    foreach ($candidate in $candidates) {
        if ($candidate.State -eq 'mismatch') {
            $mismatches += "$($candidate.ExePath) is a different build (binary GUID $($candidate.ExeGuid), linked $($candidate.ExeTimeUtc)); its symbols were not extracted"
            continue
        }
        $archive = Join-Path $candidate.Path (Get-Cfg $Config 'symbolArchive' 'symbols\symbols.zip')
        $searched += $archive
        $found = { param($Identity, $Source) [pscustomobject]@{ PdbPath = $target; SymbolDir = $targetDir; Source = $Source; Guid = $Identity.Guid; Age = $Identity.Age; Candidate = $candidate } }
        if (Test-Path -LiteralPath $archive) {
            $zip = [IO.Compression.ZipFile]::OpenRead($archive)
            try {
                foreach ($entry in @($zip.Entries | Where-Object { $_.Name -ieq $PdbName })) {
                    $entryName = $entry.FullName
                    Write-Host "  Extracting $entryName from $archive ($([Math]::Round($entry.Length / 1MB)) MB) ..."
                    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $partial, $true)
                    $identity = Read-PdbIdentity $partial
                    if ($identity.Guid -eq $Module.PdbGuid) {
                        Move-Item -LiteralPath $partial -Destination $target -Force
                        return (& $found $identity "$archive!$entryName")
                    }
                    $mismatches += "$archive!$entryName has GUID $($identity.Guid)"
                    Remove-Item -LiteralPath $partial -Force
                }
            }
            finally { $zip.Dispose() }
        }
        else {
            $loose = Join-Path (Split-Path $archive -Parent) $PdbName
            if (Test-Path -LiteralPath $loose) {
                $identity = Read-PdbIdentity $loose
                if ($identity.Guid -eq $Module.PdbGuid) {
                    Copy-Item -LiteralPath $loose -Destination $target -Force
                    return (& $found $identity $loose)
                }
                $mismatches += "$loose has GUID $($identity.Guid)"
            }
        }
    }

    $context = Format-CandidateList $candidates $Module
    if (-not (Get-ChildItem -LiteralPath $targetDir -Force -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $targetDir -Force -ErrorAction SilentlyContinue }
    if ($mismatches.Count -gt 0) {
        throw "PDB mismatch: dump expects $PdbName GUID $($Module.PdbGuid) age $($Module.PdbAge). Candidates: $($mismatches -join '; '). $context. No build folder holds this binary (private/hotfix build, or a brand or share not in the config); pass -PdbPath."
    }
    throw "$PdbName not found in $($searched -join ', ') (or next to it). $context. Pass -PdbPath."
}

function Get-BuildTime($Config, [string]$VersionDir, $Module) {
    if ($VersionDir) {
        $manifest = Get-ChildItem -LiteralPath $VersionDir -Filter (Get-Cfg $Config 'manifestPattern' 'manifest_*.txt') -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($manifest) {
            $match = Select-String -LiteralPath $manifest.FullName -Pattern 'Build time \(UTC\):\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})' | Select-Object -First 1
            if ($match) {
                $time = [DateTime]::ParseExact($match.Matches[0].Groups[1].Value, 'yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal')
                return [pscustomobject]@{ TimeUtc = $time; Source = $manifest.FullName }
            }
        }
    }
    $peTime = ([DateTimeOffset]::FromUnixTimeSeconds($Module.TimeStamp)).UtcDateTime
    if ($peTime.Year -ge 2015 -and $peTime -le [DateTime]::UtcNow.AddDays(1)) {
        return [pscustomobject]@{ TimeUtc = $peTime; Source = 'PE header timestamp' }
    }
    return $null
}

function Find-BuildCommit($Config, [string]$Repo, [hashtable]$Vars, $BuildTime, $BuildInfo, [string]$CompareRef) {
    $gitCfg = Get-Cfg $Config 'git' $null
    $compareRef = if ($CompareRef) { $CompareRef } else { Get-Cfg $gitCfg 'compareRef' 'origin/main-legacy' }
    $result = [ordered]@{ branch = $null; sourceBranch = $null; commit = $null; commitDateUtc = $null; subject = $null; method = $null; confidence = 'none'; notes = @() }

    if (-not $Repo) {
        if ($BuildInfo -and $BuildInfo.commit) {
            $result.sourceBranch = $BuildInfo.sourceBranch
            $result.commit = $BuildInfo.commit; $result.method = "build_info.txt ($($BuildInfo.path)); not verified - no source repository"; $result.confidence = 'exact'
        }
        else { $result.notes += 'No source repository available; the build commit is only known when the build folder has build_info.txt.' }
        return $result
    }

    foreach ($pattern in @(Get-Cfg $gitCfg 'branchPatterns' @('origin/release/v{major}.{minor}'))) {
        $ref = Expand-Template $pattern $Vars
        if ((Invoke-Git $Repo @('rev-parse', '--verify', '--quiet', "$ref^{commit}")).ExitCode -eq 0) { $result.branch = $ref; break }
    }

    $buildIso = if ($BuildTime) { $BuildTime.TimeUtc.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
    $commit = $null

    if ($BuildInfo -and $BuildInfo.commit) {
        $result.sourceBranch = $BuildInfo.sourceBranch
        $known = Invoke-Git $Repo @('rev-parse', '--verify', '--quiet', "$($BuildInfo.commit)^{commit}")
        if ($known.ExitCode -eq 0 -and $known.Lines.Count -gt 0) {
            $commit = $known.Lines[0]; $result.method = "build_info.txt ($($BuildInfo.path))"; $result.confidence = 'exact'
        }
        else {
            $result.notes += "build_info.txt names commit $($BuildInfo.commit) (source $($BuildInfo.sourceBranch)), but it is not in this repository. Fetch the source branch or use a clone that has it; falling back to estimation."
        }
    }

    foreach ($tagPattern in @(Get-Cfg $gitCfg 'tagPatterns' @('v{version}'))) {
        if ($commit) { break }
        $tag = Expand-Template $tagPattern $Vars
        $tagCommit = Invoke-Git $Repo @('rev-parse', '--verify', '--quiet', "refs/tags/$tag^{commit}")
        if ($tagCommit.ExitCode -eq 0 -and $tagCommit.Lines.Count -gt 0) {
            $commit = $tagCommit.Lines[0]; $result.method = "release tag $tag"; $result.confidence = 'high'
            break
        }
    }

    if (-not $commit -and $result.branch) {
        $messageTemplate = Get-Cfg $gitCfg 'versionCommitMessage' 'make v{major}.{minor}.{revision}'
        $messageRegex = ((Expand-Template $messageTemplate $Vars) -replace '([.\[\]()*+?{}|^$\\])', '\$1') + '([^0-9]|$)'
        $bump = Invoke-Git $Repo @('log', $result.branch, '-1', '--format=%H', '-E', "--grep=$messageRegex")
        if ($bump.ExitCode -eq 0 -and $bump.Lines.Count -gt 0 -and $bump.Lines[0]) {
            $commit = $bump.Lines[0]; $result.method = 'version bump commit on version branch'; $result.confidence = 'high'
        }
        elseif ($buildIso) {
            $atTime = Invoke-Git $Repo @('rev-list', '-1', "--before=$buildIso", $result.branch)
            if ($atTime.Lines.Count -gt 0 -and $atTime.Lines[0]) {
                $commit = $atTime.Lines[0]; $result.method = 'last commit on version branch before build time'; $result.confidence = 'medium'
                $result.notes += "No '$(Expand-Template $messageTemplate $Vars)' commit exists on $($result.branch); the build may contain changes that were never pushed to this repository. Validate with the PDB source lines."
            }
        }
    }
    elseif (-not $commit) {
        $result.notes += "No version branch found (patterns: $((@(Get-Cfg $gitCfg 'branchPatterns' @())) -join ', '))."
        if ($buildIso) {
            $atTime = Invoke-Git $Repo @('rev-list', '-1', "--before=$buildIso", $compareRef)
            if ($atTime.Lines.Count -gt 0 -and $atTime.Lines[0]) {
                $commit = $atTime.Lines[0]; $result.method = "last commit on $compareRef before build time"; $result.confidence = 'low'
            }
        }
    }

    if ($commit) {
        $info = Invoke-Git $Repo @('show', '-s', '--format=%cI%x09%s', $commit)
        $parts = $info.Lines[0] -split "`t", 2
        $result.commit = $commit; $result.commitDateUtc = $parts[0]; $result.subject = $parts[1]
    }
    else {
        $result.notes += 'Could not determine the build commit.'
    }
    return $result
}
