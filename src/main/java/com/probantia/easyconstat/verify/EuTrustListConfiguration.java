package com.probantia.easyconstat.verify;

import java.nio.file.Path;

record EuTrustListConfiguration(Path bundleRoot) {
    EuTrustListConfiguration {
        if (bundleRoot == null) {
            throw new IllegalArgumentException("bundleRoot is required");
        }
        bundleRoot = bundleRoot.toAbsolutePath().normalize();
    }
}
