param(
  [string]$MainClass = "app.Main"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$bin = Join-Path $root "bin"
if (-not (Test-Path $bin)) {
  Write-Host "bin/ not found; building once..."
  & powershell -ExecutionPolicy Bypass -File (Join-Path $root "build.ps1") -MainClass $MainClass
  exit $LASTEXITCODE
}

$jars = Get-ChildItem -Path $root -Filter "*.jar" | Sort-Object Name
$cp = ($jars | ForEach-Object { $_.FullName }) -join ";"

& java -cp ("$bin;$cp") $MainClass
