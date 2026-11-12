package seclog.report;

import seclog.Alert;
import seclog.AnalysisResult;
import seclog.EventType;
import seclog.Severity;

import java.util.Locale;
import java.util.Map;

/**
 * A single self-contained HTML page to share with a team lead.
 * Everything taken from the logs is HTML-escaped: attackers control fields such as
 * usernames, so writing them into a page unescaped would let a log line inject script (XSS).
 */
public final class HtmlReport {
    private HtmlReport() { }

    public static String render(AnalysisResult r) {
        StringBuilder sb = new StringBuilder();
        sb.append("""
                <!doctype html>
                <html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Security Log Analysis</title>
                <style>
                :root{--bg:#f6f7fb;--card:#fff;--text:#1a1d29;--muted:#5d6475;--border:#e3e6ee;
                --critical:#b42318;--high:#c4320a;--medium:#b54708;--low:#475467}
                @media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--text:#e8eaf0;
                --muted:#9aa1b2;--border:#262c38;--critical:#f97066;--high:#fd853a;--medium:#fdb022;--low:#98a2b3}}
                body{margin:0;background:var(--bg);color:var(--text);font:15px/1.6 system-ui,sans-serif}
                main{max-width:960px;margin:0 auto;padding:32px 16px}
                h1{margin:0 0 4px}.muted{color:var(--muted)}
                .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}
                .stat,.alert{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
                .stat b{display:block;font-size:1.6rem}
                .alert{margin:12px 0;border-left:5px solid var(--sev)}
                .sev{font-weight:700;color:var(--sev);font-size:.8rem;letter-spacing:.05em}
                .critical{--sev:var(--critical)}.high{--sev:var(--high)}.medium{--sev:var(--medium)}.low{--sev:var(--low)}
                code{font-family:ui-monospace,monospace;font-size:.9em}
                table{border-collapse:collapse;width:100%;background:var(--card)}
                td,th{border:1px solid var(--border);padding:6px 10px;text-align:left}
                </style></head><body><main>
                <h1>Security Log Analysis</h1>
                """);
        sb.append("<p class=\"muted\">").append(r.linesRead()).append(" lines read, ")
                .append(r.events().size()).append(" security events parsed</p>\n");

        sb.append("<div class=\"stats\">");
        stat(sb, "Critical alerts", r.count(Severity.CRITICAL));
        stat(sb, "High alerts", r.count(Severity.HIGH));
        stat(sb, "Medium alerts", r.count(Severity.MEDIUM));
        stat(sb, "Failed logins", r.count(EventType.LOGIN_FAILED));
        stat(sb, "Firewall blocks", r.count(EventType.FIREWALL_BLOCK));
        sb.append("</div>\n<h2>Alerts</h2>\n");

        if (r.alerts().isEmpty()) {
            sb.append("<p>No suspicious activity found.</p>\n");
        }
        for (Alert a : r.alerts()) {
            String cls = a.severity().name().toLowerCase(Locale.ROOT);
            sb.append("<div class=\"alert ").append(cls).append("\">")
                    .append("<div class=\"sev\">").append(a.severity()).append("</div>")
                    .append("<strong>").append(esc(a.rule())).append("</strong> from <code>")
                    .append(esc(a.sourceIp())).append("</code>")
                    .append("<div class=\"muted\">MITRE ATT&amp;CK ").append(esc(a.mitreId())).append(" ")
                    .append(esc(a.mitreName())).append(" · ")
                    .append(a.first().format(TextReport.TIME)).append(" to ")
                    .append(a.last().format(TextReport.TIME)).append(" · ")
                    .append(a.eventCount()).append(" events</div>")
                    .append("<p>").append(esc(a.detail())).append("</p></div>\n");
        }

        Map<String, Long> top = r.topSources(EventType.LOGIN_FAILED, 10);
        if (!top.isEmpty()) {
            sb.append("<h2>Top sources of failed logins</h2>\n<table><tr><th>IP address</th><th>Failed logins</th></tr>\n");
            top.forEach((ip, c) -> sb.append("<tr><td><code>").append(esc(ip)).append("</code></td><td>")
                    .append(c).append("</td></tr>\n"));
            sb.append("</table>\n");
        }
        sb.append("</main></body></html>\n");
        return sb.toString();
    }

    private static void stat(StringBuilder sb, String label, long value) {
        sb.append("<div class=\"stat\"><b>").append(value).append("</b><span class=\"muted\">")
                .append(label).append("</span></div>");
    }

    /** Escapes text so it is shown as text, never run as HTML. */
    public static String esc(String s) {
        StringBuilder out = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '<' -> out.append("&lt;");
                case '>' -> out.append("&gt;");
                case '&' -> out.append("&amp;");
                case '"' -> out.append("&quot;");
                case '\'' -> out.append("&#39;");
                default -> out.append(c);
            }
        }
        return out.toString();
    }
}
