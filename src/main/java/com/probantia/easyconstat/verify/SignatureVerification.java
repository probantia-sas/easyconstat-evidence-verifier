package com.probantia.easyconstat.verify;

record SignatureVerification(
        VerificationStatus status,
        String code,
        String message,
        String signatureLevel,
        int timestampCount,
        String indication,
        String subIndication,
        boolean trustSourceConfigured) {
}
