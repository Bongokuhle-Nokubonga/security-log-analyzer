package seclog;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Everything one analysis run produced.
 *
 * @param events       parsed events, oldest first
 * @param alerts       alerts, most severe first
 * @param linesRead    non-empty lines read from all files
 * @param linesSkipped lines that were not SSH or firewall events (normal for real logs)
 */
public record AnalysisResult(List<LogEvent> events, List<Alert> alerts, int linesRead, int linesSkipped) {

    public long count(EventType type) {
        return events.stream().filter(e -> e.type() == type).count();
    }

    public long count(Severity severity) {
        return alerts.stream().filter(a -> a.severity() == severity).count();
    }

    /** The IPs with the most events of a type, most first. */
    public Map<String, Long> topSources(EventType type, int limit) {
        return events.stream()
                .filter(e -> e.type() == type)
                .collect(Collectors.groupingBy(LogEvent::sourceIp, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed()
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(limit)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                        (a, b) -> a, LinkedHashMap::new));
    }

    /** IPs with at least one HIGH or CRITICAL alert, in alert order: candidates for blocking. */
    public List<String> ipsToBlock() {
        return alerts.stream()
                .filter(a -> a.severity().compareTo(Severity.HIGH) >= 0)
                .map(Alert::sourceIp)
                .distinct()
                .collect(Collectors.toList());
    }
}
