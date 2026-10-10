package com.k7titan.analyzer.report;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.k7titan.analyzer.model.Finding;

public final class JsonReport {

    private JsonReport() {
    }

    public static void write(List<Finding> findings, Path out) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n  \"engine\": \"k7titan-analyzer\",\n  \"findings\": [\n");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            sb.append("    {")
                    .append("\"file\": \"").append(escape(f.filePath())).append("\", ")
                    .append("\"level\": \"").append(f.level()).append("\", ")
                    .append("\"threat\": \"").append(escape(f.threatName())).append("\", ")
                    .append("\"score\": ").append(String.format("%.3f", f.score())).append(", ")
                    .append("\"layer\": \"").append(f.layer()).append("\"")
                    .append("}")
                    .append(i + 1 < findings.size() ? "," : "")
                    .append('\n');
        }
        sb.append("  ]\n}\n");
        Files.writeString(out, sb.toString(), StandardCharsets.UTF_8);
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
