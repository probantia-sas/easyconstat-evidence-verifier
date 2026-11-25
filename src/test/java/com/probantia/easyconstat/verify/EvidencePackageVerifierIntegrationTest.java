package com.probantia.easyconstat.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EvidencePackageVerifierIntegrationTest {
    @TempDir
    static Path temporaryDirectory;

    private static SyntheticEvidenceFixtureFactory.Fixture fixture;
    private final EvidencePackageVerifier verifier = new EvidencePackageVerifier();

    @BeforeAll
    static void createSyntheticCryptographicFixture() throws Exception {
        fixture = SyntheticEvidenceFixtureFactory.create(temporaryDirectory);
    }

    @Test
    void acceptsValidLtPackageOfflineWhenCrlEndpointIsUnavailable() {
        VerificationReport report = verifier.verify(
                fixture.packagePath(), Optional.of(fixture.trustedConfiguration()));

        assertEquals(VerificationStatus.VALID, report.status(), report.code() + ": " + report.message());
        assertEquals("PACKAGE_VALID", report.code());
        assertEquals(Boolean.TRUE, report.structureAndHashesValid());
        assertEquals(Boolean.TRUE, report.cryptographicSignatureValid());
        assertEquals(1, report.timestampCount());
        assertTrue(report.signatureLevel().contains("LT"));
    }

    @Test
    void acceptsHistoricalSignatureAfterSignerCertificateExpiry() {
        VerificationReport report = verifier.verify(
                fixture.historicallyExpiredPackagePath(),
                Optional.of(fixture.trustedConfiguration()));

        assertEquals(VerificationStatus.VALID, report.status(), report.code() + ": " + report.message());
        assertEquals("PACKAGE_VALID", report.code());
        assertTrue(report.signatureLevel().contains("LT"));
    }

    @Test
    void rejectsTimestampedPackageWithoutEmbeddedLtRevocationMaterial() {
        VerificationReport report = verifier.verify(
                fixture.timestampOnlyPackagePath(),
                Optional.of(fixture.trustedConfiguration()));

        assertEquals(VerificationStatus.INVALID, report.status());
        assertEquals("SIGNATURE_LT_PROFILE_MISSING", report.code());
    }

    @Test
    void returnsIndeterminateWhenNoTrustSourceIsConfigured() {
        VerificationReport report = verifier.verify(fixture.packagePath(), Optional.empty());

        assertEquals(VerificationStatus.INDETERMINATE, report.status());
        assertEquals("TRUST_SOURCE_MISSING", report.code());
        assertEquals(Boolean.TRUE, report.structureAndHashesValid());
    }

    @Test
    void neverAcceptsPackageAgainstUnrelatedTrustStore() {
        VerificationReport report = verifier.verify(
                fixture.packagePath(), Optional.of(fixture.unrelatedConfiguration()));

        assertNotEquals(VerificationStatus.VALID, report.status());
    }

    @Test
    void reportsAnUnavailableEuTrustBundleAsNotConfigured() {
        VerificationReport report = verifier.verify(
                fixture.packagePath(),
                Optional.empty(),
                Optional.of(new EuTrustListConfiguration(
                        temporaryDirectory.resolve("missing-eu-trust-bundle"))));

        assertEquals(VerificationStatus.INDETERMINATE, report.status());
        assertEquals("EU_TRUST_BUNDLE_INVALID", report.code());
        assertEquals(Boolean.FALSE, report.trustSourceConfigured());
    }

    @Test
    void rejectsPackageWhoseSignedPayloadWasAltered() throws Exception {
        Path altered = replaceEntry(fixture.packagePath(), "report.pdf", "altered".getBytes());

        VerificationReport report = verifier.verify(altered, Optional.of(fixture.trustedConfiguration()));

        assertEquals(VerificationStatus.INVALID, report.status());
        assertEquals("PAYLOAD_SIZE_MISMATCH", report.code());
        assertEquals(Boolean.FALSE, report.structureAndHashesValid());
    }

    private Path replaceEntry(Path source, String entryName, byte[] replacement) throws Exception {
        Path output = temporaryDirectory.resolve("synthetic-altered.asice");
        try (ZipFile input = new ZipFile(source.toFile());
                ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(output))) {
            var entries = input.entries();
            while (entries.hasMoreElements()) {
                ZipEntry original = entries.nextElement();
                ZipEntry copy = new ZipEntry(original.getName());
                if (original.getMethod() == ZipEntry.STORED) {
                    copy.setMethod(ZipEntry.STORED);
                    byte[] bytes = original.getName().equals(entryName)
                            ? replacement
                            : readAll(input, original);
                    copy.setSize(bytes.length);
                    copy.setCompressedSize(bytes.length);
                    var crc = new java.util.zip.CRC32();
                    crc.update(bytes);
                    copy.setCrc(crc.getValue());
                    zip.putNextEntry(copy);
                    zip.write(bytes);
                } else {
                    zip.putNextEntry(copy);
                    zip.write(original.getName().equals(entryName)
                            ? replacement
                            : readAll(input, original));
                }
                zip.closeEntry();
            }
        }
        return output;
    }

    private static byte[] readAll(ZipFile zip, ZipEntry entry) throws Exception {
        try (var input = zip.getInputStream(entry);
                var output = new ByteArrayOutputStream()) {
            input.transferTo(output);
            return output.toByteArray();
        }
    }
}
