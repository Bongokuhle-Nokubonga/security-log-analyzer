package seclog;

import seclog.parse.FirewallLogParser;
import seclog.parse.SshAuthLogParser;
import seclog.report.HtmlReport;
import seclog.rules.BruteForceRule;
import seclog.rules.PasswordSprayRule;
import seclog.rules.PortScanRule;
import seclog.rules.SuccessAfterFailuresRule;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Self-contained test suite (no external libraries needed).
 * Run from the project folder with: java -cp out seclog.AnalyzerTest
 */
public class AnalyzerTest {
    private static int passed = 0;
    private static int failed = 0;
    private static final int YEAR = 2026;

    public static void main(String[] args) {
        // ---------- Parsers ----------
        test("parses a failed SSH password", () -> {
            LogEvent e = ssh("Nov 10 02:14:01 web01 sshd[2211]: Failed password for root from 203.0.113.45 port 52211 ssh2");
            check(e.type() == EventType.LOGIN_FAILED, "type");
            check(e.user().equals("root") && e.sourceIp().equals("203.0.113.45"), "user and IP");
            check(e.time().equals(LocalDateTime.of(2026, 11, 10, 2, 14, 1)), "time");
        });

        test("parses failed login for an invalid user", () -> {
            LogEvent e = ssh("Nov 10 09:00:03 web01 sshd[3520]: Failed password for invalid user admin from 198.51.100.23 port 40100 ssh2");
            check(e.type() == EventType.LOGIN_FAILED && e.user().equals("admin"), "user should be admin");
        });

        test("parses accepted login and invalid-user lines", () -> {
            check(ssh("Nov 10 02:16:52 web01 sshd[2240]: Accepted password for root from 203.0.113.45 port 52290 ssh2")
                    .type() == EventType.LOGIN_SUCCESS, "accepted");
            check(ssh("Nov 10 02:14:38 web01 sshd[2214]: Invalid user admin from 203.0.113.45 port 52214")
                    .type() == EventType.INVALID_USER, "invalid user");
        });

        test("handles single-digit days padded with a space", () -> {
            LogEvent e = ssh("Nov  3 08:00:00 web01 sshd[1]: Failed password for bob from 10.0.0.9 port 1 ssh2");
            check(e.time().getDayOfMonth() == 3, "day should be 3");
        });

        test("handles ISO 8601 timestamps", () -> {
            LogEvent e = ssh("2026-11-10T02:14:01.123456+02:00 web01 sshd[2211]: Failed password for root from 203.0.113.45 port 52211 ssh2");
            check(e.time().equals(LocalDateTime.of(2026, 11, 10, 2, 14, 1, 123456000)), "ISO time");
        });

        test("ignores unrelated and malformed lines", () -> {
            SshAuthLogParser p = new SshAuthLogParser();
            check(p.parse("Nov 10 02:05:40 web01 CRON[2050]: session opened for user root", YEAR, "t").isEmpty(), "cron");
            check(p.parse("garbage line", YEAR, "t").isEmpty(), "garbage");
            check(p.parse("Feb 30 01:00:00 web01 sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2", YEAR, "t").isEmpty(),
                    "impossible date");
        });

        test("parses UFW block with destination port", () -> {
            Optional<LogEvent> e = new FirewallLogParser().parse(
                    "Nov 10 03:30:01 web01 kernel: [86400.1] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e SRC=198.51.100.77 DST=10.0.0.5 PROTO=TCP SPT=40001 DPT=21",
                    YEAR, "t");
            check(e.isPresent() && e.get().type() == EventType.FIREWALL_BLOCK, "block");
            check(e.get().sourceIp().equals("198.51.100.77") && e.get().destPort() == 21, "IP and port");
        });

        // ---------- Rules ----------
        test("brute force fires at the threshold, not below", () -> {
            BruteForceRule rule = new BruteForceRule(5, Duration.ofMinutes(5));
            check(rule.detect(failures("1.1.1.1", 4, 10)).isEmpty(), "4 failures should not alert");
            List<Alert> alerts = rule.detect(failures("1.1.1.1", 5, 10));
            check(alerts.size() == 1 && alerts.get(0).severity() == Severity.HIGH, "5 failures should alert");
        });

        test("slow failures spread out over time do not count as brute force", () -> {
            check(new BruteForceRule(5, Duration.ofMinutes(5)).detect(failures("1.1.1.1", 10, 120)).isEmpty(),
                    "one failure every 2 minutes should not alert");
        });

        test("one long attack gives one alert, not many", () -> {
            List<Alert> alerts = new BruteForceRule(5, Duration.ofMinutes(5)).detect(failures("1.1.1.1", 200, 5));
            check(alerts.size() == 1, "expected 1 alert, got " + alerts.size());
            check(alerts.get(0).eventCount() == 200, "alert should cover all 200 attempts");
        });

        test("attacks from different IPs are reported separately", () -> {
            List<LogEvent> events = new ArrayList<>(failures("1.1.1.1", 6, 5));
            events.addAll(failures("2.2.2.2", 6, 5));
            events.sort((a, b) -> a.time().compareTo(b.time()));
            check(new BruteForceRule(5, Duration.ofMinutes(5)).detect(events).size() == 2, "two IPs, two alerts");
        });

        test("password spraying counts distinct usernames", () -> {
            List<LogEvent> events = new ArrayList<>();
            String[] users = {"admin", "test", "oracle", "guest", "ubuntu"};
            for (int i = 0; i < users.length; i++) {
                events.add(new LogEvent(T0.plusMinutes(5L * i), EventType.LOGIN_FAILED, "9.9.9.9", users[i], 0, "t"));
            }
            PasswordSprayRule rule = new PasswordSprayRule(5, Duration.ofMinutes(30));
            check(rule.detect(events).size() == 1, "5 users should alert");
            check(rule.detect(failures("9.9.9.9", 20, 5)).isEmpty(), "same user many times is not spraying");
        });

        test("successful login after many failures is CRITICAL", () -> {
            List<LogEvent> events = new ArrayList<>(failures("6.6.6.6", 6, 10));
            events.add(new LogEvent(T0.plusMinutes(2), EventType.LOGIN_SUCCESS, "6.6.6.6", "root", 0, "t"));
            List<Alert> alerts = new SuccessAfterFailuresRule(5, Duration.ofMinutes(30)).detect(events);
            check(alerts.size() == 1 && alerts.get(0).severity() == Severity.CRITICAL, "should be critical");
            check(alerts.get(0).detail().contains("'root'"), "should name the account");
        });

        test("a user mistyping their password twice is not an alert", () -> {
            List<LogEvent> events = new ArrayList<>(failures("192.168.1.35", 2, 10));
            events.add(new LogEvent(T0.plusSeconds(30), EventType.LOGIN_SUCCESS, "192.168.1.35", "user", 0, "t"));
            check(new SuccessAfterFailuresRule(5, Duration.ofMinutes(30)).detect(events).isEmpty(), "no alert");
        });

        test("old failures outside the lookback window are ignored", () -> {
            List<LogEvent> events = new ArrayList<>(failures("6.6.6.6", 10, 10));
            events.add(new LogEvent(T0.plusHours(3), EventType.LOGIN_SUCCESS, "6.6.6.6", "root", 0, "t"));
            check(new SuccessAfterFailuresRule(5, Duration.ofMinutes(30)).detect(events).isEmpty(), "no alert");
        });

        test("port scan needs many distinct ports", () -> {
            PortScanRule rule = new PortScanRule(10, Duration.ofMinutes(1));
            List<LogEvent> scan = new ArrayList<>();
            List<LogEvent> samePort = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                scan.add(new LogEvent(T0.plusSeconds(i), EventType.FIREWALL_BLOCK, "7.7.7.7", "", 1000 + i, "t"));
                samePort.add(new LogEvent(T0.plusSeconds(i), EventType.FIREWALL_BLOCK, "7.7.7.7", "", 23, "t"));
            }
            check(rule.detect(scan).size() == 1, "12 ports should alert");
            check(rule.detect(samePort).isEmpty(), "12 hits on one port is not a scan");
        });

        // ---------- End to end ----------
        test("sample logs produce the expected alerts", () -> {
            Map<String, List<String>> files = new LinkedHashMap<>();
            files.put("auth.log", Files.readAllLines(Path.of("samples", "auth.log")));
            files.put("ufw.log", Files.readAllLines(Path.of("samples", "ufw.log")));
            AnalysisResult r = Analyzer.withDefaultRules().analyze(files, YEAR);

            check(r.alerts().size() == 4, "expected 4 alerts, got " + r.alerts().size());
            Alert top = r.alerts().get(0);
            check(top.severity() == Severity.CRITICAL && top.sourceIp().equals("203.0.113.45"), "critical first");
            check(has(r, "SSH brute force", "203.0.113.45"), "brute force");
            check(has(r, "Password spraying", "198.51.100.23"), "spray");
            check(has(r, "Port scan", "198.51.100.77"), "port scan");
            check(r.alerts().stream().noneMatch(a -> a.sourceIp().startsWith("192.168.1.")), "no false positives on LAN users");
            check(r.ipsToBlock().equals(List.of("203.0.113.45", "198.51.100.23")), "block list " + r.ipsToBlock());
        });

        // ---------- Report safety ----------
        test("HTML report escapes attacker-controlled usernames (no XSS)", () -> {
            String evil = "Nov 10 02:14:0%d web01 sshd[1]: Failed password for invalid user <script>alert(1)</script> from 5.5.5.5 port 1 ssh2";
            List<String> lines = new ArrayList<>();
            for (int i = 0; i < 6; i++) lines.add(String.format(evil, i));
            Map<String, List<String>> files = Map.of("evil.log", lines);
            String html = HtmlReport.render(Analyzer.withDefaultRules().analyze(files, YEAR));
            check(!html.contains("<script>"), "raw script tag must not appear");
            check(html.contains("&lt;script&gt;"), "escaped tag should appear");
        });

        System.out.printf("%n%d passed, %d failed%n", passed, failed);
        if (failed > 0) System.exit(1);
    }

    // ---------- helpers ----------

    private static final LocalDateTime T0 = LocalDateTime.of(2026, 11, 10, 2, 0, 0);

    private static LogEvent ssh(String line) {
        return new SshAuthLogParser().parse(line, YEAR, "test").orElseThrow(() -> new AssertionError("did not parse: " + line));
    }

    /** {@code count} failed logins for root from {@code ip}, {@code gapSeconds} apart. */
    private static List<LogEvent> failures(String ip, int count, int gapSeconds) {
        List<LogEvent> list = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            list.add(new LogEvent(T0.plusSeconds((long) i * gapSeconds), EventType.LOGIN_FAILED, ip, "root", 0, "t" + i));
        }
        return list;
    }

    private static boolean has(AnalysisResult r, String rule, String ip) {
        return r.alerts().stream().anyMatch(a -> a.rule().equals(rule) && a.sourceIp().equals(ip));
    }

    interface Body { void run() throws Exception; }

    private static void test(String name, Body body) {
        try {
            body.run();
            passed++;
            System.out.println("PASS  " + name);
        } catch (Throwable e) {
            failed++;
            System.out.println("FAIL  " + name + " -> " + e);
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
