package seclog.parse;

import seclog.EventType;
import seclog.LogEvent;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses OpenSSH lines from a Linux authentication log ({@code /var/log/auth.log}
 * on Debian/Ubuntu, {@code /var/log/secure} on Red Hat). Examples:
 * <pre>
 * Nov 10 02:14:01 web01 sshd[2211]: Failed password for root from 203.0.113.45 port 52211 ssh2
 * Nov 10 02:14:05 web01 sshd[2213]: Failed password for invalid user admin from 203.0.113.45 port 52213 ssh2
 * Nov 10 02:16:52 web01 sshd[2240]: Accepted password for root from 203.0.113.45 port 52290 ssh2
 * Nov 10 02:14:04 web01 sshd[2213]: Invalid user admin from 203.0.113.45 port 52213
 * </pre>
 */
public class SshAuthLogParser implements LogParser {
    private static final Pattern FAILED = Pattern.compile(
            "Failed (?:password|publickey|keyboard-interactive/pam) for (invalid user )?(\\S*) from (\\S+) port \\d+");
    private static final Pattern ACCEPTED = Pattern.compile(
            "Accepted (?:password|publickey|keyboard-interactive/pam) for (\\S+) from (\\S+) port \\d+");
    private static final Pattern INVALID = Pattern.compile(
            "Invalid user (\\S*) from (\\S+)");

    @Override
    public Optional<LogEvent> parse(String line, int year, String origin) {
        Optional<SyslogTime.Parsed> ts = SyslogTime.parse(line, year);
        if (ts.isEmpty() || !ts.get().rest().contains("sshd")) {
            return Optional.empty();
        }
        String rest = ts.get().rest();

        Matcher m = FAILED.matcher(rest);
        if (m.find()) {
            return Optional.of(new LogEvent(ts.get().time(), EventType.LOGIN_FAILED,
                    m.group(3), m.group(2), 0, origin));
        }
        m = ACCEPTED.matcher(rest);
        if (m.find()) {
            return Optional.of(new LogEvent(ts.get().time(), EventType.LOGIN_SUCCESS,
                    m.group(2), m.group(1), 0, origin));
        }
        m = INVALID.matcher(rest);
        if (m.find()) {
            return Optional.of(new LogEvent(ts.get().time(), EventType.INVALID_USER,
                    m.group(2), m.group(1), 0, origin));
        }
        return Optional.empty();
    }
}
