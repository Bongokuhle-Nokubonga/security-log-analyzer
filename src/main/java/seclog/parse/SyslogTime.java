package seclog.parse;

import java.time.DateTimeException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads the timestamp at the start of a syslog line. Supports both formats Linux uses:
 * <ul>
 *   <li>classic: {@code Nov 10 02:14:01 server ...} (no year, day may be padded with a space)</li>
 *   <li>ISO 8601: {@code 2026-11-10T02:14:01+02:00 server ...}</li>
 * </ul>
 */
final class SyslogTime {
    private static final List<String> MONTHS = List.of(
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec");
    private static final Pattern CLASSIC =
            Pattern.compile("^([A-Z][a-z]{2})\\s+(\\d{1,2})\\s+(\\d{2}):(\\d{2}):(\\d{2})\\s+(.*)$");
    private static final Pattern ISO =
            Pattern.compile("^(\\d{4}-\\d{2}-\\d{2}T\\S+)\\s+(.*)$");

    /** A timestamp and the rest of the line after it. */
    record Parsed(LocalDateTime time, String rest) { }

    private SyslogTime() { }

    static Optional<Parsed> parse(String line, int year) {
        Matcher m = CLASSIC.matcher(line);
        if (m.matches()) {
            int month = MONTHS.indexOf(m.group(1)) + 1;
            if (month == 0) {
                return Optional.empty();
            }
            try {
                LocalDateTime t = LocalDateTime.of(year, month, Integer.parseInt(m.group(2)),
                        Integer.parseInt(m.group(3)), Integer.parseInt(m.group(4)),
                        Integer.parseInt(m.group(5)));
                return Optional.of(new Parsed(t, m.group(6)));
            } catch (DateTimeException e) {
                return Optional.empty(); // e.g. "Feb 30"
            }
        }
        m = ISO.matcher(line);
        if (m.matches()) {
            String ts = m.group(1);
            try {
                return Optional.of(new Parsed(OffsetDateTime.parse(ts).toLocalDateTime(), m.group(2)));
            } catch (DateTimeParseException withoutOffset) {
                try {
                    return Optional.of(new Parsed(LocalDateTime.parse(ts), m.group(2)));
                } catch (DateTimeParseException e) {
                    return Optional.empty();
                }
            }
        }
        return Optional.empty();
    }
}
