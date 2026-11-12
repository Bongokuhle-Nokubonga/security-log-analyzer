package seclog.parse;

import seclog.EventType;
import seclog.LogEvent;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses UFW (Uncomplicated Firewall) lines from {@code /var/log/ufw.log}. Example:
 * <pre>
 * Nov 10 03:30:01 web01 kernel: [1234.5] [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.77 DST=10.0.0.5 PROTO=TCP SPT=40001 DPT=22
 * </pre>
 */
public class FirewallLogParser implements LogParser {
    private static final Pattern ACTION = Pattern.compile("\\[UFW (BLOCK|ALLOW|AUDIT)]");
    private static final Pattern SRC = Pattern.compile("\\bSRC=(\\S+)");
    private static final Pattern DPT = Pattern.compile("\\bDPT=(\\d+)");

    @Override
    public Optional<LogEvent> parse(String line, int year, String origin) {
        Optional<SyslogTime.Parsed> ts = SyslogTime.parse(line, year);
        if (ts.isEmpty()) {
            return Optional.empty();
        }
        String rest = ts.get().rest();
        Matcher action = ACTION.matcher(rest);
        Matcher src = SRC.matcher(rest);
        if (!action.find() || !src.find() || action.group(1).equals("AUDIT")) {
            return Optional.empty();
        }
        Matcher dpt = DPT.matcher(rest);
        int port = dpt.find() ? Integer.parseInt(dpt.group(1)) : 0; // ICMP has no port
        EventType type = action.group(1).equals("BLOCK") ? EventType.FIREWALL_BLOCK : EventType.FIREWALL_ALLOW;
        return Optional.of(new LogEvent(ts.get().time(), type, src.group(1), "", port, origin));
    }
}
