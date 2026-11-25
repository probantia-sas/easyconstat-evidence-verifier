package com.probantia.easyconstat.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class EuTrustListBootstrapTest {
    @Test
    void embeddedOjCertificatesMatchThePublishedFingerprints() throws Exception {
        assertEquals(
                EuTrustListBootstrap.CERTIFICATE_SHA256,
                EuTrustListBootstrap.inspectCertificateDigests());
    }

    @Test
    void verifiedBootstrapContainsExactlySixCertificates() throws Exception {
        assertEquals(
                6,
                EuTrustListBootstrap.loadVerifiedCertificateSource().getNumberOfCertificates());
    }
}
