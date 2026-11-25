package com.probantia.easyconstat.verify;

import java.util.List;

public record EvidenceManifest(
        int schemaVersion,
        String packageType,
        String constatId,
        String createdAt,
        String capturedAt,
        String locale,
        String channel,
        String hashAlgorithm,
        String signatureProfile,
        String reportPath,
        Producer producer,
        List<EvidenceArtifact> artifacts) {

    public record Producer(String legalName, String country, String siret) {
    }
}
