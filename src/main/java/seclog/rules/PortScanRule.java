package seclog.rules;

import seclog.Alert;
import seclog.EventType;
import seclog.LogEvent;
import seclog.Severity;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * One IP hitting many different ports and being blocked by the firewall: someone
 * scanning for open services, often the first step before an attack.
 * MITRE ATT&amp;CK T1046 (Network Service Discovery).
 */
public class PortScanRule implements DetectionRule {
    private final int distinctPorts;
    private final Duration window;

    public PortScanRule(int distinctPorts, Duration window) {
        this.distinctPorts = distinctPorts;
        this.window = window;
    }

    @Override
    public String name() {
        return "Port scan";
    }

    @Override
    public List<Alert> detect(List<LogEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, List<LogEvent>> e : Windows.byIp(events, EventType.FIREWALL_BLOCK).entrySet()) {
            for (List<LogEvent> burst : Windows.bursts(e.getValue(), distinctPorts, window, LogEvent::destPort)) {
                TreeSet<Integer> ports = new TreeSet<>();
                burst.forEach(ev -> ports.add(ev.destPort()));
                alerts.add(new Alert(Severity.MEDIUM, name(), "T1046", "Network Service Discovery",
                        e.getKey(), burst.get(0).time(), burst.get(burst.size() - 1).time(), burst.size(),
                        ports.size() + " different ports probed in " + BruteForceRule.minutes(burst)
                                + ": " + describe(ports)));
            }
        }
        return alerts;
    }

    private static String describe(TreeSet<Integer> ports) {
        List<String> parts = new ArrayList<>();
        for (int p : ports) parts.add(p + serviceName(p));
        return String.join(", ", parts);
    }

    private static String serviceName(int port) {
        return switch (port) {
            case 21 -> " (FTP)";
            case 22 -> " (SSH)";
            case 23 -> " (Telnet)";
            case 25 -> " (SMTP)";
            case 53 -> " (DNS)";
            case 80 -> " (HTTP)";
            case 110 -> " (POP3)";
            case 135 -> " (MS-RPC)";
            case 139 -> " (NetBIOS)";
            case 143 -> " (IMAP)";
            case 443 -> " (HTTPS)";
            case 445 -> " (SMB)";
            case 1433 -> " (MS SQL)";
            case 3306 -> " (MySQL)";
            case 3389 -> " (RDP)";
            case 5432 -> " (PostgreSQL)";
            case 8080 -> " (HTTP-alt)";
            default -> "";
        };
    }
}
