package seclog.rules;

import seclog.Alert;
import seclog.EventType;
import seclog.LogEvent;
import seclog.Severity;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * One IP failing to log in as many different usernames. Attackers do this slowly with
 * a few common passwords to stay under brute-force limits.
 * MITRE ATT&amp;CK T1110.003 (Brute Force: Password Spraying).
 */
public class PasswordSprayRule implements DetectionRule {
    private final int distinctUsers;
    private final Duration window;

    public PasswordSprayRule(int distinctUsers, Duration window) {
        this.distinctUsers = distinctUsers;
        this.window = window;
    }

    @Override
    public String name() {
        return "Password spraying";
    }

    @Override
    public List<Alert> detect(List<LogEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, List<LogEvent>> e : Windows.byIp(events, EventType.LOGIN_FAILED).entrySet()) {
            for (List<LogEvent> burst : Windows.bursts(e.getValue(), distinctUsers, window, LogEvent::user)) {
                LinkedHashSet<String> users = new LinkedHashSet<>();
                burst.forEach(ev -> users.add(ev.user()));
                alerts.add(new Alert(Severity.HIGH, name(), "T1110.003", "Brute Force: Password Spraying",
                        e.getKey(), burst.get(0).time(), burst.get(burst.size() - 1).time(), burst.size(),
                        users.size() + " different usernames tried in " + BruteForceRule.minutes(burst)
                                + ": " + String.join(", ", users)));
            }
        }
        return alerts;
    }
}
