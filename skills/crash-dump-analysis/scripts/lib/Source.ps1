# Mapping PDB source paths to repository files at a commit.

$script:repoPathCache = @{}
$script:fileCache = @{}

function Convert-ToRepoPath([string]$Repo, [string]$Commit, [string]$SourceFile, $Config) {
    if (-not $SourceFile -or -not $Commit) { return $null }
    $cacheKey = "$Commit|$SourceFile"
    if ($script:repoPathCache.ContainsKey($cacheKey)) { return $script:repoPathCache[$cacheKey] }
    $candidates = @()
    foreach ($root in @(Get-Cfg $Config 'buildSourceRoots' @())) {
        if ($SourceFile.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { $candidates += $SourceFile.Substring($root.Length) }
    }
    $segments = $SourceFile -split '[\\/]' | Where-Object { $_ -and $_ -notmatch ':$' }
    for ($i = 0; $i -lt [Math]::Min($segments.Count - 1, 8); $i++) { $candidates += ($segments[$i..($segments.Count - 1)] -join '/') }
    $resolved = $null
    foreach ($candidate in $candidates) {
        $rel = $candidate -replace '\\', '/'
        if ((Invoke-Git $Repo @('cat-file', '-e', ('{0}:{1}' -f $Commit, $rel))).ExitCode -eq 0) { $resolved = $rel; break }
    }
    $script:repoPathCache[$cacheKey] = $resolved
    return $resolved
}

function Get-GitFileLines([string]$Repo, [string]$Commit, [string]$RelPath) {
    $key = "$Commit|$RelPath"
    if (-not $script:fileCache.ContainsKey($key)) {
        $show = Invoke-Git $Repo @('show', ('{0}:{1}' -f $Commit, $RelPath))
        $script:fileCache[$key] = if ($show.ExitCode -eq 0) { $show.Lines } else { $null }
    }
    return $script:fileCache[$key]
}

function Get-ShortFunctionName([string]$Function) {
    $name = $Function
    while ($name -match '<[^<>]*>') { $name = $name -replace '<[^<>]*>', '' }
    $name = ($name -split '::')[-1]
    if (-not $name -or $name -match '^operator' -or $name -match 'lambda') { return $null }
    return $name
}

# Repository path and source lines at the build commit for every own frame with a source file.
function Add-SourceSnippets($Frames, [string]$Repo, [string]$Commit, $Config, [string[]]$OwnModules) {
    if (-not $Repo -or -not $Commit) { return }
    foreach ($frame in $Frames) {
        if (-not $frame.sourceFile -or $OwnModules -notcontains $frame.module) { continue }
        $frame.repoPath = Convert-ToRepoPath $Repo $Commit $frame.sourceFile $Config
        if (-not $frame.repoPath -or -not $frame.sourceLine) { continue }
        $fileLines = Get-GitFileLines $Repo $Commit $frame.repoPath
        if (-not $fileLines) { continue }
        $start = [Math]::Max(1, $frame.sourceLine - 4); $end = [Math]::Min($fileLines.Count, $frame.sourceLine + 4)
        $frame.buildSnippet = (@($start..$end | ForEach-Object { '{0}{1,6}: {2}' -f $(if ($_ -eq $frame.sourceLine) { '>' } else { ' ' }), $_, $fileLines[$_ - 1] })) -join "`n"
        $short = Get-ShortFunctionName $frame.function
        if ($short) {
            $window = $fileLines[0..([Math]::Min($fileLines.Count, $frame.sourceLine) - 1)]
            $frame.functionFoundAtBuildCommit = [bool](@($window | Where-Object { $_.Contains("$short(") }).Count)
        }
    }
}

# Commits on the analysis ref that are not in the build commit and touch the files of the top frames.
function Get-SourceHistory($Frames, [string]$Repo, [string]$BuildCommit, [string]$CompareCommit, $Config) {
    if (-not $Repo -or -not $BuildCommit -or -not $CompareCommit) { return @() }
    $result = @()
    $histFiles = @($Frames | Where-Object { $_ -and $_.repoPath } | Select-Object -First ([int](Get-Cfg $Config 'topFramesForHistory' 6)) | ForEach-Object { $_.repoPath } | Select-Object -Unique)
    foreach ($rel in $histFiles) {
        $log = Invoke-Git $Repo @('log', '--format=%h%x09%ad%x09%an%x09%s', '--date=short', '-n', '60', "$BuildCommit..$CompareCommit", '--', $rel)
        $existsNow = (Invoke-Git $Repo @('cat-file', '-e', ('{0}:{1}' -f $CompareCommit, $rel))).ExitCode -eq 0
        $result += [ordered]@{ file = $rel; existsInCompareRef = $existsNow; commitsNotInBuild = @($log.Lines | Where-Object { $_ }) }
    }
    return $result
}
