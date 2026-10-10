package com.k7titan.analyzer.model;

public record Finding(
        String filePath,
        ThreatLevel level,
        String threatName,
        double score,
        String layer) {

    public boolean isThreat() {
        return level != ThreatLevel.CLEAN;
    }
}
