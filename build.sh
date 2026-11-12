#!/usr/bin/env bash
# Compile, test and run the Security Log Analyzer on Linux/macOS.
# Usage:  ./build.sh        -> compile + run tests
#         ./build.sh demo   -> compile + analyse the sample logs (writes report.html)
set -euo pipefail
rm -rf out
javac --release 17 -d out $(find src -name "*.java")
if [ "${1:-}" = "demo" ]; then
  java -cp out seclog.Main --year 2026 --html report.html samples/auth.log samples/ufw.log
else
  java -cp out seclog.AnalyzerTest
fi
