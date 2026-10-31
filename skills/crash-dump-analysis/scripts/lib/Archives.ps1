# Zipped dump input: extraction, de-duplication by SHA-256, bundled PDB discovery.

# Expands *.zip inputs that contain .dmp files into the extract root (reused on later runs) and returns the dump paths
# together with the original archive. An entry whose SHA-256 equals a dump that is already part of the input (same
# size first, then hash of the entry stream) is not extracted; it is returned as a copy of that dump (Extracted = $false).
# PDB entries of every archive (dump zips that bundle their symbols, or symbol-only zips) are listed as Symbols; they are
# extracted later by Resolve-Pdb, only after their name matches, and used only if their GUID matches the dump.
function Expand-DumpArchives([string[]]$ZipPaths, [string]$ExtractRoot, [string[]]$ExistingDumps) {
    $result = @()
    $empty = @()
    $symbols = @()
    $pool = New-Object Collections.Generic.List[string]
    foreach ($d in @($ExistingDumps)) { if ($d) { $pool.Add($d) } }
    foreach ($zipPath in $ZipPaths) {
        $zipItem = Get-Item -LiteralPath $zipPath
        $zip = [IO.Compression.ZipFile]::OpenRead($zipPath)
        try {
            foreach ($pdbEntry in @($zip.Entries | Where-Object { $_.Name -match '\.pdb$' })) {
                $symbols += [pscustomobject]@{ Archive = $zipPath; Entry = $pdbEntry.FullName; Name = $pdbEntry.Name; SizeBytes = $pdbEntry.Length }
            }
            $entries = @($zip.Entries | Where-Object { $_.Name -match '\.dmp$' })
            if ($entries.Count -eq 0) {
                if (-not ($symbols | Where-Object { $_.Archive -eq $zipPath })) { $empty += $zipPath }
                continue
            }
            $target = Join-Path $ExtractRoot ('{0}_{1}' -f [IO.Path]::GetFileNameWithoutExtension($zipItem.Name), $zipItem.Length)
            foreach ($entry in $entries) {
                $sameSize = @($pool | Where-Object { (Get-Item -LiteralPath $_).Length -eq $entry.Length })
                if ($sameSize.Count -gt 0) {
                    Write-Host "Hashing $zipPath!$($entry.FullName) to compare with $($sameSize.Count) dump(s) of the same size ..."
                    $stream = $entry.Open()
                    try { $entryHash = Get-StreamSha256 $stream } finally { $stream.Dispose() }
                    $same = $sameSize | Where-Object { (Get-FileSha256 $_) -eq $entryHash } | Select-Object -First 1
                    if ($same) {
                        Write-Host "Not extracting $zipPath!$($entry.FullName): identical (SHA-256) to $same."
                        $result += [pscustomobject]@{ DumpPath = $same; Archive = $zipPath; Entry = $entry.FullName; SizeBytes = $entry.Length; Extracted = $false }
                        continue
                    }
                }
                $dest = Join-Path $target $entry.Name
                if ((Test-Path -LiteralPath $dest) -and (Get-Item -LiteralPath $dest).Length -eq $entry.Length) {
                    Write-Host "Reusing extracted $dest"
                }
                else {
                    New-Item -ItemType Directory -Force -Path $target | Out-Null
                    $drive = [IO.Path]::GetPathRoot($target)
                    $free = (New-Object IO.DriveInfo($drive)).AvailableFreeSpace
                    if ($free -lt $entry.Length + 1GB) { throw "Not enough disk space to extract $($entry.Name) ($([Math]::Round($entry.Length / 1GB, 2)) GB) to $target (free: $([Math]::Round($free / 1GB, 2)) GB). Set extractRoot in the config." }
                    Write-Host "Extracting $zipPath!$($entry.FullName) ($([Math]::Round($entry.Length / 1GB, 2)) GB) to $target ..."
                    [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, "$dest.partial", $true)
                    Move-Item -LiteralPath "$dest.partial" -Destination $dest -Force
                }
                $pool.Add($dest)
                $result += [pscustomobject]@{ DumpPath = $dest; Archive = $zipPath; Entry = $entry.FullName; SizeBytes = $entry.Length; Extracted = $true }
            }
        }
        finally { $zip.Dispose() }
    }
    return [pscustomobject]@{ Dumps = $result; EmptyArchives = $empty; Symbols = $symbols }
}
