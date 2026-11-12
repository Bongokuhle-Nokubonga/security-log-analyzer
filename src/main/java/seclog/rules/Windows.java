package seclog.rules;

import seclog.EventType;
import seclog.LogEvent;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/** Shared helpers for time-window detection rules. */
final class Windows {
    private Windows() { }

    /** Events of one type, grouped by source IP, keeping time order. */
    static Map<String, List<LogEvent>> byIp(List<LogEvent> events, EventType type) {
        Map<String, List<LogEvent>> map = new LinkedHashMap<>();
        for (LogEvent e : events) {
            if (e.type() == type) {
                map.computeIfAbsent(e.sourceIp(), k -> new ArrayList<>()).add(e);
            }
        }
        return map;
    }

    /**
     * Finds bursts of activity: places where at least {@code threshold} distinct values
     * of {@code key} occur within {@code window}. Once a burst starts it keeps growing while
     * each next event is within {@code window} of the previous one, so one long attack
     * produces one alert, not dozens.
     *
     * @param sorted events, oldest first
     * @param key    what to count distinct values of (e.g. username, port, or the event itself)
     */
    static List<List<LogEvent>> bursts(List<LogEvent> sorted, int threshold, Duration window,
                                       Function<LogEvent, Object> key) {
        List<List<LogEvent>> result = new ArrayList<>();
        int n = sorted.size();
        int i = 0;
        while (i < n) {
            int j = i;
            while (j + 1 < n && within(sorted.get(i), sorted.get(j + 1), window)) {
                j++;
            }
            if (distinct(sorted.subList(i, j + 1), key) >= threshold) {
                int end = j;
                while (end + 1 < n && within(sorted.get(end), sorted.get(end + 1), window)) {
                    end++;
                }
                result.add(sorted.subList(i, end + 1));
                i = end + 1;
            } else {
                i++;
            }
        }
        return result;
    }

    static int distinct(List<LogEvent> events, Function<LogEvent, Object> key) {
        Set<Object> seen = new HashSet<>();
        for (LogEvent e : events) seen.add(key.apply(e));
        return seen.size();
    }

    /** True if b happened no more than {@code window} after a. */
    private static boolean within(LogEvent a, LogEvent b, Duration window) {
        return Duration.between(a.time(), b.time()).compareTo(window) <= 0;
    }
}
