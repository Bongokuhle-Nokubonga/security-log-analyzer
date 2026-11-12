package seclog;

import java.time.LocalDateTime;

/**
 * One parsed log line.
 *
 * @param time     when it happened
 * @param type     what happened
 * @param sourceIp the IP address the activity came from
 * @param user     the username tried (SSH events), or "" if not applicable
 * @param destPort the destination port (firewall events), or 0 if not applicable
 * @param origin   where the line came from, e.g. "auth.log:42"
 */
public record LogEvent(LocalDateTime time, EventType type, String sourceIp,
                       String user, int destPort, String origin) {
}
