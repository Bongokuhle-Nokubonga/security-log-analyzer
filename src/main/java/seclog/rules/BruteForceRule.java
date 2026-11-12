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
 * Many failed logins from one IP in a short time: someone guessing passwords.
 * MITRE ATT&amp;CK T1110.001 (Brute Force: Password Guessing).
 */
public class BruteForceRule implements DetectionRule {
    private final int threshold;
    private final Duration window;

    public BruteForceRule(int threshold, Duration window) {
        this.threshold = threshold;
        this.window = window;
    }

    @Override
    public String name() {
        return "SSH brute force";
    }

    @Override
    public List<Alert> detect(List<LogEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, List<LogEvent>> e : Windows.byIp(events, EventType.LOGIN_FAILED).entrySet()) {
            // count every attempt (each event is distinct), not distinct usernames
            for (List<LogEvent> burst : Windows.bursts(e.getValue(), threshold, window, ev -> ev)) {
                LinkedHashSet<String> users = new LinkedHashSet<>();
                burst.forEach(ev -> users.add(ev.user()));
                alerts.add(new Alert(Severity.HIGH, name(), "T1110.001", "Brute Force: Password Guessing",
                        e.getKey(), burst.get(0).time(), burst.get(burst.size() - 1).time(), burst.size(),
                        burst.size() + " failed SSH logins in " + minutes(burst)
                                + " targeting " + String.join(", ", users)));
            }
        }
        return alerts;
    }

    static String minutes(List<LogEvent> burst) {
        long secs = Duration.between(burst.get(0).time(), burst.get(burst.size() - 1).time()).getSeconds();
        return secs < 60 ? secs + "s" : (secs / 60) + "m " + (secs % 60) + "s";
    }
}
