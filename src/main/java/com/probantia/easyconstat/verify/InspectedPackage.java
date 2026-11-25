package com.probantia.easyconstat.verify;

record InspectedPackage(
        EvidenceManifest manifest,
        int payloadCount,
        long totalPayloadBytes,
        String signatureEntry,
        String asicManifestEntry) {
}
