package seclog.report;

import seclog.Alert;
import seclog.AnalysisResult;
import seclog.EventType;
import seclog.Severity;

import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Plain-text report for the terminal. */
public final class TextReport {
    static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("dd MMM HH:mm:ss", Locale.ENGLISH);

    private TextReport() { }

    public static String format(AnalysisResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("==============================================\n");
        sb.append(" SECURITY LOG ANALYSIS\n");
        sb.append("==============================================\n");
        sb.append(String.format("Lines read: %d   Events parsed: %d   Other lines: %d%n",
                r.linesRead(), r.events().size(), r.linesSkipped()));
        sb.append(String.format("Failed logins: %d   Successful logins: %d   Invalid users: %d   Firewall blocks: %d%n",
                r.count(EventType.LOGIN_FAILED), r.count(EventType.LOGIN_SUCCESS),
                r.count(EventType.INVALID_USER), r.count(EventType.FIREWALL_BLOCK)));
        sb.append(String.format("Alerts: %d critical, %d high, %d medium, %d low%n%n",
                r.count(Severity.CRITICAL), r.count(Severity.HIGH),
                r.count(Severity.MEDIUM), r.count(Severity.LOW)));

        if (r.alerts().isEmpty()) {
            sb.append("No suspicious activity found.\n");
        }
        int n = 1;
        for (Alert a : r.alerts()) {
            sb.append(String.format("[%d] %-8s %s  (MITRE %s %s)%n",
                    n++, a.severity(), a.rule(), a.mitreId(), a.mitreName()));
            sb.append(String.format("    Source: %s   %s -> %s   (%d events)%n",
                    a.sourceIp(), a.first().format(TIME), a.last().format(TIME), a.eventCount()));
            sb.append("    ").append(a.detail()).append("\n\n");
        }

        Map<String, Long> top = r.topSources(EventType.LOGIN_FAILED, 5);
        if (!top.isEmpty()) {
            sb.append("Top sources of failed logins:\n");
            top.forEach((ip, c) -> sb.append(String.format("  %-18s %d%n", ip, c)));
            sb.append('\n');
        }

        List<String> block = r.ipsToBlock();
        if (!block.isEmpty()) {
            sb.append("Recommended actions:\n");
            sb.append("  1. Block these IPs at the firewall: ").append(String.join(", ", block)).append('\n');
            if (r.count(Severity.CRITICAL) > 0) {
                sb.append("  2. Treat CRITICAL alerts as a possible breach: reset the affected passwords,\n");
                sb.append("     review what those sessions did, and escalate to the security team.\n");
            }
            sb.append("  - Disable SSH password login (use keys) and root login over SSH.\n");
            sb.append("  - Consider fail2ban to block brute-force attempts automatically.\n");
        }
        return sb.toString();
    }
}
