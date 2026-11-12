package seclog.rules;

import seclog.Alert;
import seclog.EventType;
import seclog.LogEvent;
import seclog.Severity;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A successful login from an IP that just failed many times. This is the most
 * important alert: the password guessing probably worked and the account may be compromised.
 * MITRE ATT&amp;CK T1078 (Valid Accounts).
 */
public class SuccessAfterFailuresRule implements DetectionRule {
    private final int minFailures;
    private final Duration lookback;

    public SuccessAfterFailuresRule(int minFailures, Duration lookback) {
        this.minFailures = minFailures;
        this.lookback = lookback;
    }

    @Override
    public String name() {
        return "Login after repeated failures";
    }

    @Override
    public List<Alert> detect(List<LogEvent> events) {
        List<Alert> alerts = new ArrayList<>();
        Map<String, Deque<LogEvent>> recentFailures = new HashMap<>();
        for (LogEvent e : events) {
            if (e.type() == EventType.LOGIN_FAILED) {
                recentFailures.computeIfAbsent(e.sourceIp(), k -> new ArrayDeque<>()).addLast(e);
            } else if (e.type() == EventType.LOGIN_SUCCESS) {
                Deque<LogEvent> failures = recentFailures.getOrDefault(e.sourceIp(), new ArrayDeque<>());
                while (!failures.isEmpty()
                        && Duration.between(failures.peekFirst().time(), e.time()).compareTo(lookback) > 0) {
                    failures.removeFirst(); // too old to be related
                }
                if (failures.size() >= minFailures) {
                    LogEvent first = failures.peekFirst();
                    alerts.add(new Alert(Severity.CRITICAL, name(), "T1078", "Valid Accounts",
                            e.sourceIp(), first.time(), e.time(), failures.size() + 1,
                            "Successful login as '" + e.user() + "' after " + failures.size()
                                    + " failed attempts. Account may be compromised: reset the password,"
                                    + " check what this session did, and block the IP"));
                }
                failures.clear();
            }
        }
        return alerts;
    }
}
