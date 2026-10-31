# Minimal, dependency-free test helpers (Windows PowerShell 5.1 has only Pester 3.4; tests must run anywhere).

$script:TestResults = New-Object Collections.Generic.List[object]
$script:CurrentSuite = ''

function Describe([string]$Name, [scriptblock]$Body) {
    $previous = $script:CurrentSuite
    $script:CurrentSuite = if ($previous) { "$previous > $Name" } else { $Name }
    try { & $Body } finally { $script:CurrentSuite = $previous }
}

function It([string]$Name, [scriptblock]$Body) {
    $full = "$script:CurrentSuite > $Name"
    try {
        & $Body
        $script:TestResults.Add([pscustomobject]@{ Name = $full; Passed = $true; Message = $null })
    }
    catch {
        $where = if ($_.InvocationInfo) { " ($([IO.Path]::GetFileName($_.InvocationInfo.ScriptName)):$($_.InvocationInfo.ScriptLineNumber))" } else { '' }
        $script:TestResults.Add([pscustomobject]@{ Name = $full; Passed = $false; Message = "$($_.Exception.Message)$where" })
    }
}

function Format-TestValue($Value) {
    if ($null -eq $Value) { return '<null>' }
    if ($Value -is [array]) { return '@(' + (@($Value | ForEach-Object { Format-TestValue $_ }) -join ', ') + ')' }
    return "'$Value'"
}

function Assert-Equal($Expected, $Actual, [string]$Because = '') {
    $ok = if ($Expected -is [array] -or $Actual -is [array]) {
        $e = @($Expected); $a = @($Actual)
        ($e.Count -eq $a.Count) -and -not (@(for ($i = 0; $i -lt $e.Count; $i++) { if ("$($e[$i])" -cne "$($a[$i])") { $i } }).Count)
    }
    else { "$Expected" -ceq "$Actual" -and (($null -eq $Expected) -eq ($null -eq $Actual)) }
    if (-not $ok) { throw "Expected $(Format-TestValue $Expected), got $(Format-TestValue $Actual). $Because" }
}

function Assert-True($Condition, [string]$Because = '') { if (-not $Condition) { throw "Expected true. $Because" } }
function Assert-False($Condition, [string]$Because = '') { if ($Condition) { throw "Expected false. $Because" } }
function Assert-Null($Value, [string]$Because = '') { if ($null -ne $Value) { throw "Expected null, got $(Format-TestValue $Value). $Because" } }
function Assert-NotNull($Value, [string]$Because = '') { if ($null -eq $Value) { throw "Expected a value, got null. $Because" } }

function Assert-Match([string]$Pattern, $Actual, [string]$Because = '') {
    if ("$Actual" -notmatch $Pattern) { throw "Expected '$Actual' to match /$Pattern/. $Because" }
}

function Assert-NotMatch([string]$Pattern, $Actual, [string]$Because = '') {
    if ("$Actual" -match $Pattern) { throw "Expected '$Actual' not to match /$Pattern/. $Because" }
}

function Assert-Throws([scriptblock]$Body, [string]$MessagePattern = '.') {
    try { & $Body } catch { if ($_.Exception.Message -notmatch $MessagePattern) { throw "Threw '$($_.Exception.Message)', expected /$MessagePattern/." }; return }
    throw 'Expected an exception.'
}

function Get-Fixture([string]$Name) { return Get-Content -LiteralPath (Join-Path $PSScriptRoot "fixtures\$Name") -Encoding UTF8 }
