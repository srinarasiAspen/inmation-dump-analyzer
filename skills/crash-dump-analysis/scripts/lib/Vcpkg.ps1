# Third-party (vcpkg port) frames: port, version and patches at a commit.

function ConvertFrom-VcpkgSourcePath([string]$SourceFile) {
    if (-not $SourceFile) { return $null }
    if ($SourceFile -match '[\\/]buildtrees[\\/](?<port>[^\\/]+)[\\/]src[\\/](?<dir>[^\\/]+?)\.clean[\\/](?<rel>.+)$') {
        $dir = $Matches['dir']; $port = $Matches['port']; $rel = $Matches['rel'] -replace '\\', '/'
        $prefix = if ($dir -match '^(?<v>.+)-(?<h>[0-9a-f]{10})$') { $Matches['v'] } else { $dir }
        # vcpkg shortens the source folder name ('gacy-1.0.7' for legacy-1.0.7, 'ost-1.90.0' for boost-1.90.0).
        $version = if ($prefix -match '(?<v>v?\d+(?:\.\d+)+(?:[-.][0-9A-Za-z]+)*)$') { $Matches['v'] } else { $prefix }
        return [pscustomobject]@{ port = $port; sourceDir = $dir; dirPrefix = $prefix; version = $version; relPath = $rel }
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
    $same = Get-ChildItem -LiteralPath $srcRoot -Directory -Filter "$($ThirdParty.dirPrefix)-*.clean" -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName $rel } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($same) { return [pscustomobject]@{ path = $same; exact = $false } }
    return $null
}

# Third-party frames (vcpkg buildtrees / vcpkg_installed headers): marks frame.thirdParty and returns per port the version
# in the build path, the port definition at the build commit and on the compare ref, and local sources.
function Get-ThirdPartyPorts($Frames, $Config, [string]$Repo, [string]$BuildCommit, [string]$CompareCommit) {
    $portMap = [ordered]@{}
    foreach ($frame in @($Frames | Where-Object { $_ })) {
        $tp = ConvertFrom-VcpkgSourcePath $frame.sourceFile
        if (-not $tp) { continue }
        $frame.thirdParty = $tp
        if (-not $tp.port) { continue }
        if (-not $portMap.Contains($tp.port)) {
            $portMap[$tp.port] = [ordered]@{
                port = $tp.port; versionInBuildPath = $tp.version; sourceDirInBuild = $tp.sourceDir; frames = @()
                atBuildCommit = Get-PortInfo $Config $Repo $BuildCommit $tp.port
                atCompareRef = Get-PortInfo $Config $Repo $CompareCommit $tp.port
                localSource = @()
            }
        }
        $portMap[$tp.port].frames += $frame.index
        $local = Find-LocalPortSource $Config $Repo $tp
        if ($local -and $portMap[$tp.port].localSource.Count -lt 5) { $portMap[$tp.port].localSource += [ordered]@{ frame = $frame.index; path = $local.path; exactBuildTree = $local.exact } }
    }
    return @($portMap.Values)
}
