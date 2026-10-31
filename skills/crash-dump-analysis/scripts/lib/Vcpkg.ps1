# Third-party (vcpkg port) frames: port, version and patches at a commit.

function ConvertFrom-VcpkgSourcePath([string]$SourceFile) {
    if (-not $SourceFile) { return $null }
    if ($SourceFile -match '[\\/]buildtrees[\\/](?<port>[^\\/]+)[\\/]src[\\/](?<dir>[^\\/]+?)\.clean[\\/](?<rel>.+)$') {
        $dir = $Matches['dir']; $port = $Matches['port']; $rel = $Matches['rel'] -replace '\\', '/'
        $version = if ($dir -match '^(?<v>.+)-(?<h>[0-9a-f]{10})$') { $Matches['v'] } else { $dir }
        return [pscustomobject]@{ port = $port; sourceDir = $dir; version = $version; relPath = $rel }
    }
    if ($SourceFile -match '[\\/]vcpkg_installed[\\/][^\\/]+[\\/](?:[^\\/]+[\\/])?include[\\/](?<rel>.+)$') {
        return [pscustomobject]@{ port = $null; sourceDir = $null; version = $null; relPath = 'include/' + ($Matches['rel'] -replace '\\', '/') }
    }
    return $null
}

function Read-PortDirectory([string]$Repo, [string]$Commit, [string]$Dir) {
    $files = Invoke-Git $Repo @('ls-tree', '--name-only', "${Commit}:$Dir")
    if ($files.ExitCode -ne 0 -or $files.Lines.Count -eq 0) { return $null }
    $version = $null; $portVersion = $null
    $manifest = Invoke-Git $Repo @('show', "${Commit}:$Dir/vcpkg.json")
    if ($manifest.ExitCode -eq 0) {
        try {
            $json = ($manifest.Lines -join "`n") | ConvertFrom-Json
            foreach ($field in 'version', 'version-string', 'version-semver', 'version-date') { if (-not $version) { $version = Get-Cfg $json $field $null } }
            $portVersion = Get-Cfg $json 'port-version' $null
        }
        catch { $version = '(vcpkg.json unreadable)' }
    }
    $portfile = (Invoke-Git $Repo @('show', "${Commit}:$Dir/portfile.cmake")).Lines
    $active = @($portfile | Where-Object { $_ -notmatch '^\s*#' } | ForEach-Object { ($_ -split '#', 2)[0] }) -join "`n"
    $patches = @($files.Lines | Where-Object { $_ -match '\.(patch|diff)$' -and $active.Contains($_) })
    return [pscustomobject]@{ dir = $Dir; version = $version; portVersion = $portVersion; patches = $patches; note = $null }
}

# Port definition used by a commit: an overlay port of this repository, else the port of the vcpkg submodule commit
# pinned by that commit (needs the submodule checked out locally).
function Get-PortInfo($Config, [string]$Repo, [string]$Commit, [string]$Port) {
    if (-not $Repo -or -not $Commit -or -not $Port) { return $null }
    foreach ($root in @(Get-Cfg $Config 'vcpkgPortRoots' @('vcpkg-ports-inmation', 'vcpkg-ports', 'vcpkg-ports-ci'))) {
        $info = Read-PortDirectory $Repo $Commit "$root/$Port"
        if ($info) { return $info }
    }
    $submodule = Get-Cfg $Config 'vcpkgSubmodule' 'vcpkg'
    $link = (Invoke-Git $Repo @('ls-tree', $Commit, '--', $submodule)).Lines | Select-Object -First 1
    if ($link -match '^160000 commit ([0-9a-f]{40})\s') {
        $subCommit = $Matches[1]
        $subRepo = Join-Path $Repo $submodule
        if ((Test-Path -LiteralPath $subRepo) -and (Invoke-Git $subRepo @('cat-file', '-e', "$subCommit^{commit}")).ExitCode -eq 0) {
            $info = Read-PortDirectory $subRepo $subCommit "ports/$Port"
            if ($info) { $info.dir = "$submodule@$($subCommit.Substring(0, 10)):ports/$Port"; return $info }
        }
        return [pscustomobject]@{ dir = $null; version = $null; portVersion = $null; patches = @(); note = "upstream port from vcpkg submodule commit $($subCommit.Substring(0, 10)) (not available locally)" }
    }
    return [pscustomobject]@{ dir = $null; version = $null; portVersion = $null; patches = @(); note = 'port not found in overlay roots or vcpkg submodule' }
}

function Find-LocalPortSource($Config, [string]$Repo, $ThirdParty) {
    if (-not $ThirdParty.port) { return $null }
    $root = Expand-PathValue (Get-Cfg $Config 'localBuildtrees' '')
    if (-not $root -and $Repo) { $root = Join-Path $Repo 'vcpkg\buildtrees' }
    if (-not $root) { return $null }
    $srcRoot = Join-Path (Join-Path $root $ThirdParty.port) 'src'
    if (-not (Test-Path -LiteralPath $srcRoot)) { return $null }
    $rel = $ThirdParty.relPath -replace '/', '\'
    $exact = Join-Path (Join-Path $srcRoot "$($ThirdParty.sourceDir).clean") $rel
    if (Test-Path -LiteralPath $exact) { return [pscustomobject]@{ path = $exact; exact = $true } }
    $same = Get-ChildItem -LiteralPath $srcRoot -Directory -Filter "$($ThirdParty.version)-*.clean" -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName $rel } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($same) { return [pscustomobject]@{ path = $same; exact = $false } }
    return $null
}
