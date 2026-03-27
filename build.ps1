param(
  [string]$MainClass = "ui.MainDashboard"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$bin = Join-Path $root "bin"
if (-not (Test-Path $bin)) { New-Item -ItemType Directory -Path $bin | Out-Null }

# Build classpath from bundled jars
$jars = Get-ChildItem -Path $root -Filter "*.jar" | Sort-Object Name
$cp = ($jars | ForEach-Object { $_.FullName }) -join ";"

# Compile all sources so packages like monitoring1/ui resolve
$srcFiles = Get-ChildItem -Path (Join-Path $root "src") -Recurse -Filter "*.java" |
  ForEach-Object { $_.FullName }

Write-Host "Compiling" $srcFiles.Count "Java files..."
& javac -encoding UTF-8 -d $bin -cp $cp $srcFiles

Write-Host "Running $MainClass ..."
& java -cp ("$bin;$cp") $MainClass
