package com.probantia.easyconstat.verify;

import java.nio.file.Path;
import java.util.List;

record PreparedEvidence(
        Path directory,
        Path manifestPath,
        EvidenceManifest manifest,
        List<Path> payloadPaths) {
}
