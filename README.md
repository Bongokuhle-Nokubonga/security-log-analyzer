# Security Log Analyzer (Java)

A command-line tool that reads **Linux SSH authentication logs** and **UFW firewall logs**
and detects common attacks, the way a junior SOC (Security Operations Centre) analyst
would during log triage. Every alert is mapped to a **MITRE ATT&CK** technique and ranked
by severity, and the tool suggests what to do next.

Plain Java 17, no external libraries.

## What it detects

| Rule | What it means | Severity | MITRE ATT&CK |
|---|---|---|---|
| Login after repeated failures | Password guessing worked: account may be compromised | **CRITICAL** | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts |
| SSH brute force | 5+ failed logins from one IP within 5 minutes | **HIGH** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing |
| Password spraying | 5+ different usernames tried from one IP within 30 minutes | **HIGH** | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying |
| Port scan | 10+ different ports blocked for one IP within 1 minute | **MEDIUM** | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery |

Design choices that keep the alerts useful:

- **One attack, one alert.** A 200-attempt brute force produces a single alert covering all 200 attempts, not 40 duplicates.
- **Few false positives.** A user who mistypes their password twice, or old failures from hours earlier, do not trigger alerts. There are tests for both.
- **Slow attacks are still caught.** Password spraying is spread out to dodge brute-force limits, so it has its own longer window and counts *distinct usernames*.
- **Safe reports.** Attackers control fields like usernames. The HTML report escapes everything taken from the logs, so a username such as `<script>` can't inject code (XSS). There is a test for this.

## Run it

Requires Java 17 or newer.

```powershell
.\build.ps1          # compile and run the 18 tests
.\build.ps1 demo     # analyse the sample attack logs and write report.html
```

On Linux/macOS use `./build.sh` and `./build.sh demo`.

To analyse your own logs:

```bash
java -cp out seclog.Main --html report.html /var/log/auth.log /var/log/ufw.log
```

## Example output

The `samples/` folder contains a simulated night on a web server: a brute-force attack that succeeds,
a slow password-spraying attempt, a port scan, and normal staff logins mixed in.

```
Failed logins: 20   Successful logins: 4   Invalid users: 7   Firewall blocks: 17
Alerts: 1 critical, 2 high, 1 medium, 0 low

[1] CRITICAL Login after repeated failures  (MITRE T1078 Valid Accounts)
    Source: 203.0.113.45   10 Nov 02:14:01 -> 10 Nov 02:16:52   (13 events)
    Successful login as 'root' after 12 failed attempts. Account may be compromised: ...

[2] HIGH     SSH brute force  (MITRE T1110.001 Brute Force: Password Guessing)
    Source: 203.0.113.45   10 Nov 02:14:01 -> 10 Nov 02:16:17   (12 events)
    12 failed SSH logins in 2m 16s targeting root, admin

[3] HIGH     Password spraying  (MITRE T1110.003 Brute Force: Password Spraying)
    Source: 198.51.100.23   10 Nov 09:00:03 -> 10 Nov 09:25:39   (6 events)
    6 different usernames tried in 25m 36s: admin, test, oracle, ubuntu, guest, postgres

[4] MEDIUM   Port scan  (MITRE T1046 Network Service Discovery)
    Source: 198.51.100.77   10 Nov 03:30:01 -> 10 Nov 03:30:19   (14 events)
    14 different ports probed in 18s: 21 (FTP), 23 (Telnet), 25 (SMTP), 53 (DNS), ...

Recommended actions:
  1. Block these IPs at the firewall: 203.0.113.45, 198.51.100.23
  2. Treat CRITICAL alerts as a possible breach: reset the affected passwords,
     review what those sessions did, and escalate to the security team.
  - Disable SSH password login (use keys) and root login over SSH.
  - Consider fail2ban to block brute-force attempts automatically.
```

The sample logs use IP addresses from the ranges reserved for documentation
(RFC 5737), so they don't point at any real system.

## Project structure

```
src/main/java/seclog/
  Main.java                 command-line entry point
  Analyzer.java             parses all files, runs all rules
  parse/                    SSH auth.log and UFW firewall parsers (classic and ISO timestamps)
  rules/                    the four detection rules + shared time-window logic
  report/                   text report and HTML report
src/test/java/seclog/
  AnalyzerTest.java         18 tests: parsers, each rule, false positives, end-to-end, XSS
samples/                    example auth.log and ufw.log with simulated attacks
```

## What I practised

- Reading real Linux log formats and turning them into structured events
- Writing detection rules with time windows and thresholds, and tuning them to avoid false positives
- Mapping findings to MITRE ATT&CK and writing analyst-friendly recommendations
- Secure coding: treating log content as untrusted input
- Testing and continuous integration with GitHub Actions
