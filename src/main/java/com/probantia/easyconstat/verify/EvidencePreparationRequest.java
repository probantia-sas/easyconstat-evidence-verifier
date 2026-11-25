package com.probantia.easyconstat.verify;

import java.nio.file.Path;

record EvidencePreparationRequest(
        Path sourceArchive,
        Path outputDirectory,
        String constatId,
        String createdAt,
        String capturedAt,
        String locale,
        String channel) {
}
