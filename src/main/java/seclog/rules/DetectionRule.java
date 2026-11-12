package seclog.rules;

import seclog.Alert;
import seclog.LogEvent;

import java.util.List;

/** Looks through events (sorted by time) and reports suspicious patterns. */
public interface DetectionRule {

    /** Short name shown in reports. */
    String name();

    /** @param events all parsed events, sorted oldest first */
    List<Alert> detect(List<LogEvent> events);
}
