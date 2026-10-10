package com.k7titan.analyzer;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.k7titan.analyzer.analyzer.HeuristicAnalyzer;
import com.k7titan.analyzer.io.FileWalker;
import com.k7titan.analyzer.model.Finding;
import com.k7titan.analyzer.report.JsonReport;

/**
 * K7 TITAN analyzer CLI.
 *
 * Usage: java -jar k7titan-analyzer.jar &lt;path&gt; [more paths...]
 */
public class Main {

    private static final String VERSION = "0.2.0";

    public static void main(String[] args) {
        System.out.println("K7 TITAN Analyzer " + VERSION);
        if (args.length == 0) {
            System.out.println("Usage: k7titan-analyzer <file-or-folder> [more...]");
            System.exit(2);
        }

        List<Finding> findings = new ArrayList<>();
        int scanned = 0;
        int threats = 0;

        for (String arg : args) {
            Path target = Path.of(arg);
            try {
                for (Path file : FileWalker.collect(target, true)) {
                    scanned++;
                    Finding finding = HeuristicAnalyzer.analyze(file);
                    findings.add(finding);
                    if (finding.isThreat()) {
                        threats++;
                        System.out.printf("  [%s] %s  (%s, %.2f)%n",
                                finding.level(), finding.filePath(), finding.threatName(), finding.score());
                    }
                }
            } catch (IOException e) {
                System.err.println("  error scanning " + arg + ": " + e.getMessage());
            }
        }

        System.out.printf("Scanned %d file(s), %d threat(s).%n", scanned, threats);

        try {
            Path out = Path.of("k7titan-analysis.json");
            JsonReport.write(findings, out);
            System.out.println("Report written to " + out.toAbsolutePath());
        } catch (IOException e) {
            System.err.println("Could not write report: " + e.getMessage());
        }

        System.exit(threats > 0 ? 1 : 0);
    }
}
