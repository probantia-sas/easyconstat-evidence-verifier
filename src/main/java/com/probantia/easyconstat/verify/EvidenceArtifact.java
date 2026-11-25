package com.probantia.easyconstat.verify;

public record EvidenceArtifact(
        String path,
        String role,
        String mediaType,
        long size,
        String sha256) {
}
