package seclog.parse;

import seclog.LogEvent;

import java.util.Optional;

/** Turns one log line into an event, if the line is one this parser understands. */
public interface LogParser {

    /**
     * @param line   the raw log line
     * @param year   the year to assume for classic syslog timestamps, which have no year
     * @param origin a label for error messages and reports, e.g. "auth.log:12"
     * @return the event, or empty if this parser does not recognise the line
     */
    Optional<LogEvent> parse(String line, int year, String origin);
}
