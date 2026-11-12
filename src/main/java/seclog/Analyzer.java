package seclog;

import seclog.parse.FirewallLogParser;
import seclog.parse.LogParser;
import seclog.parse.SshAuthLogParser;
import seclog.rules.BruteForceRule;
import seclog.rules.DetectionRule;
import seclog.rules.PasswordSprayRule;
import seclog.rules.PortScanRule;
import seclog.rules.SuccessAfterFailuresRule;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Parses log lines into events, then runs every detection rule over them. */
public final class Analyzer {
    private final List<LogParser> parsers;
    private final List<DetectionRule> rules;

    public Analyzer(List<LogParser> parsers, List<DetectionRule> rules) {
        this.parsers = List.copyOf(parsers);
        this.rules = List.copyOf(rules);
    }

    /** Thresholds tuned for a small internet-facing Linux server. */
    public static Analyzer withDefaultRules() {
        return new Analyzer(
                List.of(new SshAuthLogParser(), new FirewallLogParser()),
                List.of(
                        new SuccessAfterFailuresRule(5, Duration.ofMinutes(30)),
                        new BruteForceRule(5, Duration.ofMinutes(5)),
                        new PasswordSprayRule(5, Duration.ofMinutes(30)),
                        new PortScanRule(10, Duration.ofMinutes(1))));
    }

    public List<DetectionRule> rules() {
        return rules;
    }

    /**
     * @param files file name to its lines, in the order to read them
     * @param year  year to assume for classic syslog timestamps
     */
    public AnalysisResult analyze(Map<String, List<String>> files, int year) {
        List<LogEvent> events = new ArrayList<>();
        int read = 0;
        int skipped = 0;
        for (Map.Entry<String, List<String>> file : files.entrySet()) {
            List<String> lines = file.getValue();
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                if (line.isBlank()) continue;
                read++;
                Optional<LogEvent> event = parseLine(line, year, file.getKey() + ":" + (i + 1));
                if (event.isPresent()) {
                    events.add(event.get());
                } else {
                    skipped++;
                }
            }
        }
        events.sort(Comparator.comparing(LogEvent::time)); // stable: keeps file order for equal times

        List<Alert> alerts = new ArrayList<>();
        for (DetectionRule rule : rules) {
            alerts.addAll(rule.detect(events));
        }
        alerts.sort(Alert.BY_PRIORITY);
        return new AnalysisResult(List.copyOf(events), List.copyOf(alerts), read, skipped);
    }

    private Optional<LogEvent> parseLine(String line, int year, String origin) {
        for (LogParser p : parsers) {
            Optional<LogEvent> e = p.parse(line, year, origin);
            if (e.isPresent()) return e;
        }
        return Optional.empty();
    }
}
