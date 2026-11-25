package com.probantia.easyconstat.release;

import java.util.List;

public record ReleaseManifest(
        String format,
        int schemaVersion,
        String product,
        String artifactId,
        String version,
        String buildTimestamp,
        String digestAlgorithm,
        String signatureAlgorithm,
        String signingKeySha256,
        List<ReleaseArtifact> artifacts) {
}
