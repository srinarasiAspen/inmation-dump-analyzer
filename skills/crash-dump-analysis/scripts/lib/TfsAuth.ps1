# TFS authentication: a PAT from SOURCE_ADO_PAT / TFS_PAT or ~/.config/inmation-ado/.env (same as the inmation-ado-*
# skills), otherwise Windows integrated authentication. The token is never printed.

function Read-EnvFileValue([string]$Path, [string[]]$Names) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        if ($line -match '^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$' -and $Names -contains $Matches[1]) {
            $value = $Matches[2].Trim('"', "'")
            if ($value) { return $value }
        }
    }
    return $null
}

function Get-TfsAuth {
    $pat = if ($env:SOURCE_ADO_PAT) { $env:SOURCE_ADO_PAT } elseif ($env:TFS_PAT) { $env:TFS_PAT } else { $null }
    if (-not $pat) {
        $configHome = if ($env:XDG_CONFIG_HOME) { $env:XDG_CONFIG_HOME } else { Join-Path $HOME '.config' }
        $pat = Read-EnvFileValue (Join-Path (Join-Path $configHome 'inmation-ado') '.env') @('SOURCE_ADO_PAT', 'TFS_PAT')
    }
    if ($pat) {
        return [pscustomobject]@{ Mode = 'PAT'; Headers = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$pat")) }; UseDefaultCredentials = $false }
    }
    return [pscustomobject]@{ Mode = 'Windows integrated'; Headers = @{}; UseDefaultCredentials = $true }
}
