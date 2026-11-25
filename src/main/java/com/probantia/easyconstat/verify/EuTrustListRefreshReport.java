package com.probantia.easyconstat.verify;

record EuTrustListRefreshReport(
        String status,
        String releaseId,
        String updatedAt,
        String lotlUrl,
        String officialJournalUrl,
        String bootstrapKeystoreSha256,
        int processedLotls,
        int processedTls,
        int trustAnchors) {
}
