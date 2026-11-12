package seclog;

import java.time.LocalDateTime;
import java.util.Comparator;

/**
 * A suspicious pattern found in the logs.
 *
 * @param severity   how serious it is
 * @param rule       the name of the rule that fired
 * @param mitreId    MITRE ATT&amp;CK technique ID, e.g. T1110.001
 * @param mitreName  MITRE ATT&amp;CK technique name
 * @param sourceIp   the IP address responsible
 * @param first      time of the first event in the pattern
 * @param last       time of the last event in the pattern
 * @param eventCount how many log events make up the pattern
 * @param detail     a plain-language explanation for the analyst
 */
public record Alert(Severity severity, String rule, String mitreId, String mitreName,
                    String sourceIp, LocalDateTime first, LocalDateTime last,
                    int eventCount, String detail) {

    /** Most severe first, then oldest first. */
    public static final Comparator<Alert> BY_PRIORITY =
            Comparator.comparing(Alert::severity).reversed()
                    .thenComparing(Alert::first);
}
