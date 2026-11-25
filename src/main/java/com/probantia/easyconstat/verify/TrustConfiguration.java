package com.probantia.easyconstat.verify;

import java.nio.file.Path;

record TrustConfiguration(Path trustStore, String type, char[] password) {
    TrustConfiguration {
        if (trustStore == null) {
            throw new IllegalArgumentException("trustStore is required");
        }
        type = type == null || type.isBlank() ? "JKS" : type;
        password = password == null ? new char[0] : password.clone();
    }

    @Override
    public char[] password() {
        return password.clone();
    }
}
