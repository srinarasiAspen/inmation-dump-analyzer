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
