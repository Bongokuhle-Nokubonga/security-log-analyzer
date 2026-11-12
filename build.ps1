# Compile, test and run the Security Log Analyzer on Windows.
# Usage:  .\build.ps1          -> compile + run tests
#         .\build.ps1 demo     -> compile + analyse the sample logs (writes report.html)
$ErrorActionPreference = "Stop"
if (Test-Path out) { Remove-Item -Recurse -Force out }
$sources = Get-ChildItem -Recurse src -Filter *.java | ForEach-Object { $_.FullName }
javac --release 17 -d out $sources
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($args[0] -eq "demo") {
    java -cp out seclog.Main --year 2026 --html report.html samples\auth.log samples\ufw.log
} else {
    java -cp out seclog.AnalyzerTest
    exit $LASTEXITCODE
}
