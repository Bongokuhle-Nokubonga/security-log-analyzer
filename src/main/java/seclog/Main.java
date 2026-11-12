package seclog;

import seclog.report.HtmlReport;
import seclog.report.TextReport;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Year;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Command-line entry point.
 * <pre>
 * java -cp out seclog.Main [--year 2026] [--html report.html] auth.log ufw.log ...
 * </pre>
 */
public final class Main {
    private static final String USAGE = """
            Usage: java -cp out seclog.Main [options] <log file>...

            Reads Linux SSH auth logs and UFW firewall logs and reports attacks.

            Options:
              --year YYYY       year for log lines without one (default: this year)
              --html FILE       also write an HTML report to FILE
              --help            show this help
            """;

    private Main() { }

    public static void main(String[] args) {
        int year = Year.now().getValue();
        Path html = null;
        List<Path> files = new ArrayList<>();
        try {
            for (int i = 0; i < args.length; i++) {
                switch (args[i]) {
                    case "--year" -> year = Integer.parseInt(next(args, ++i, "--year"));
                    case "--html" -> html = Path.of(next(args, ++i, "--html"));
                    case "--help", "-h" -> {
                        System.out.print(USAGE);
                        return;
                    }
                    default -> files.add(Path.of(args[i]));
                }
            }
        } catch (IllegalArgumentException e) {
            System.err.println("Error: " + e.getMessage() + "\n\n" + USAGE);
            System.exit(1);
        }
        if (files.isEmpty()) {
            System.err.print(USAGE);
            System.exit(1);
        }

        Map<String, List<String>> contents = new LinkedHashMap<>();
        for (Path f : files) {
            try {
                // Decode leniently: real logs sometimes contain bytes that are not valid UTF-8.
                String text = new String(Files.readAllBytes(f), StandardCharsets.UTF_8);
                contents.put(f.getFileName().toString(), text.lines().toList());
            } catch (IOException e) {
                System.err.println("Cannot read " + f + ": " + e.getMessage());
                System.exit(1);
            }
        }

        AnalysisResult result = Analyzer.withDefaultRules().analyze(contents, year);
        System.out.print(TextReport.format(result));

        if (html != null) {
            try {
                Files.writeString(html, HtmlReport.render(result), StandardCharsets.UTF_8);
                System.out.println("HTML report written to " + html.toAbsolutePath());
            } catch (IOException e) {
                System.err.println("Cannot write " + html + ": " + e.getMessage());
                System.exit(1);
            }
        }
    }

    private static String next(String[] args, int i, String option) {
        if (i >= args.length) throw new IllegalArgumentException(option + " needs a value");
        return args[i];
    }
}
