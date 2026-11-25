package com.probantia.easyconstat.verify;

final class VerificationException extends Exception {
    private final VerificationStatus status;
    private final String code;

    private VerificationException(
            VerificationStatus status,
            String code,
            String message,
            Throwable cause) {
        super(message, cause);
        this.status = status;
        this.code = code;
    }

    static VerificationException invalid(String code, String message) {
        return new VerificationException(VerificationStatus.INVALID, code, message, null);
    }

    static VerificationException invalid(String code, String message, Throwable cause) {
        return new VerificationException(VerificationStatus.INVALID, code, message, cause);
    }

    static VerificationException indeterminate(String code, String message) {
        return new VerificationException(VerificationStatus.INDETERMINATE, code, message, null);
    }

    static VerificationException indeterminate(String code, String message, Throwable cause) {
        return new VerificationException(VerificationStatus.INDETERMINATE, code, message, cause);
    }

    VerificationStatus status() {
        return status;
    }

    String code() {
        return code;
    }
}
