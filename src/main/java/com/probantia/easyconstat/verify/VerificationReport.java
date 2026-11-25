package com.probantia.easyconstat.verify;

record VerificationReport(
        String verifierVersion,
        String verifiedAt,
        VerificationStatus status,
        String code,
        String message,
        String packagePath,
        String constatId,
        String locale,
        String channel,
        Integer payloadCount,
        Long payloadBytes,
        Boolean structureAndHashesValid,
        Boolean cryptographicSignatureValid,
        String signatureLevel,
        Integer timestampCount,
        String dssIndication,
        String dssSubIndication,
        boolean trustSourceConfigured) {
}
