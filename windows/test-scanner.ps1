param([Parameter(Mandatory)][string]$Scanner)
$ErrorActionPreference = 'Stop'
$Scanner = (Resolve-Path $Scanner).Path
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('strazh-test-' + [guid]::NewGuid())
New-Item -ItemType Directory $fixture | Out-Null
try {
  $file = Join-Path $fixture 'Проверка файла.txt'
  [IO.File]::WriteAllText($file, 'ordinary test content')
  $result = & $Scanner --mode hashes -- $file
  if ($LASTEXITCODE -ne 0) { throw 'Ordinary file scan failed' }
  $summary = $result[-1] | ConvertFrom-Json
  if ($summary.files -ne 1 -or $summary.errors -ne 0 -or !$summary.done) { throw 'Incomplete ordinary scan' }
  $hash = (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()
  $database = Join-Path $fixture 'hashes.txt'
  [IO.File]::WriteAllText($database, "$hash CustomTestIndicator`n")
  $result = & $Scanner --mode hashes --signatures $database -- $file
  if ($LASTEXITCODE -ne 1) { throw 'Imported hash was not detected' }
  $summary = $result[-1] | ConvertFrom-Json
  if ($summary.matches -ne 1 -or $summary.errors -ne 0) { throw 'Incorrect matching result' }
  & $Scanner --mode hashes -- (Join-Path $fixture 'missing.txt') | Out-Null
  if ($LASTEXITCODE -ne 2) { throw 'Missing file did not report failure' }
} finally {
  Remove-Item -LiteralPath $fixture -Recurse -Force
}
Write-Host 'Windows scanner integration tests passed.'

$global:LASTEXITCODE = 0
