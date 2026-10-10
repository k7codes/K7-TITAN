#!/usr/bin/env pwsh
# K7 TITAN - full build script
# Builds: C++ engine, C helper lib, Rust core, minifilter driver, .NET solution.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$cmake = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"

function Step($name) { Write-Host "`n=== $name ===" -ForegroundColor Cyan }

Step "C++ scan engine (CMake)"
& $cmake -S "$root\src\K7Titan.Engine" -B "$root\src\K7Titan.Engine\build" -G "Visual Studio 17 2022" -A x64
& $cmake --build "$root\src\K7Titan.Engine\build" --config Debug

Step "C helper library (CMake)"
& $cmake -S "$root\src\K7Titan.CLib" -B "$root\src\K7Titan.CLib\build" -G "Visual Studio 17 2022" -A x64
& $cmake --build "$root\src\K7Titan.CLib\build" --config Debug

Step "Rust crypto core (Cargo)"
Push-Location "$root\src\K7Titan.Rust"
cargo build --release
cargo test --release
Pop-Location

Step "Minifilter driver (WDK toolchain)"
& cmd /c "$root\src\K7Titan.Driver\build-driver.bat"

Step "Java analyzer (Maven)"
$mvn = Get-Command mvn.cmd -ErrorAction SilentlyContinue
if (-not $mvn) {
  $mvn = Get-ChildItem "$env:USERPROFILE\.m2\wrapper\dists" -Recurse -Filter mvn.cmd -ErrorAction SilentlyContinue |
    Select-Object -First 1
}
if ($mvn) {
  $mvnPath = if ($mvn.Path) { $mvn.Path } else { $mvn.FullName }
  if (-not $env:JAVA_HOME) {
    $jdk = Get-ChildItem "C:\Program Files\Java" -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -like "jdk-21*" } | Select-Object -First 1
    if ($jdk) { $env:JAVA_HOME = $jdk.FullName }
  }
  & $mvnPath -q -f "$root\src\K7Titan.Java\pom.xml" package
} else {
  Write-Host "Maven not found - skipping Java build" -ForegroundColor Yellow
}

Step ".NET solution"
dotnet build "$root\K7Titan.sln" --configuration Debug

Step "Tests"
dotnet test "$root\K7Titan.sln" --configuration Debug --no-build

Write-Host "`nK7 TITAN build complete." -ForegroundColor Green
