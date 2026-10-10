package com.k7titan.analyzer.analyzer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.k7titan.analyzer.model.Finding;
import com.k7titan.analyzer.model.ThreatLevel;

/**
 * Lightweight heuristic analyzer shared by the CLI. Mirrors the scoring model
 * used by the native engine so results stay comparable.
 */
public final class HeuristicAnalyzer {

    private static final String EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";

    private static final String[][] MARKERS = {
            {"cmd.exe /c", "0.20"},
            {"powershell", "0.20"},
            {"frombase64string", "0.20"},
            {"downloadstring", "0.25"},
            {"net.webclient", "0.20"},
            {"wscript.shell", "0.20"},
            {"currentversion\\run", "0.20"},
            {"your files have been encrypted", "0.60"},
    };

    private HeuristicAnalyzer() {
    }

    public static double entropy(byte[] data) {
        if (data.length == 0) {
            return 0.0;
        }
        long[] counts = new long[256];
        for (byte b : data) {
            counts[b & 0xFF]++;
        }
        double len = data.length;
        double entropy = 0.0;
        for (long c : counts) {
            if (c == 0) {
                continue;
            }
            double p = c / len;
            entropy -= p * (Math.log(p) / Math.log(2.0));
        }
        return entropy;
    }

    public static Finding analyze(Path path) throws IOException {
        byte[] data;
        try {
            if (Files.size(path) > 64L * 1024 * 1024) {
                return new Finding(path.toString(), ThreatLevel.CLEAN, "TooLarge", 0.0, "io");
            }
            data = Files.readAllBytes(path);
        } catch (IOException e) {
            return new Finding(path.toString(), ThreatLevel.CLEAN, "Unreadable", 0.0, "io");
        }

        String text = new String(data, StandardCharsets.ISO_8859_1).toLowerCase();

        if (text.contains(EICAR.toLowerCase())) {
            return new Finding(path.toString(), ThreatLevel.MALICIOUS, "EICAR-Test-File", 1.0, "signature");
        }

        double score = 0.0;
        String topTag = "heuristic";
        for (String[] marker : MARKERS) {
            if (text.contains(marker[0])) {
                score += Double.parseDouble(marker[1]);
                topTag = marker[0];
            }
        }

        if (data.length > 4096) {
            double entropy = entropy(data);
            if (entropy > 7.9) {
                score += 0.30;
                topTag = "high-entropy";
            } else if (entropy > 7.2) {
                score += 0.15;
            }
        }

        score = Math.min(1.0, score);
        ThreatLevel level = score >= 0.85 ? ThreatLevel.MALICIOUS
                : score >= 0.40 ? ThreatLevel.SUSPICIOUS
                : ThreatLevel.CLEAN;
        String name = level == ThreatLevel.CLEAN ? "None" : "Heuristic." + topTag;
        return new Finding(path.toString(), level, name, score, "heuristic");
    }
}
