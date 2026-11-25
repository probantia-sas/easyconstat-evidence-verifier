package com.probantia.easyconstat.verify;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Explicitly invoked utility used only to refresh the committed qualification fixture. */
final class SyntheticFixtureExporter {
    private static final String PACKAGE_NAME = "easyconstat-synthetic-valid.asice";
    private static final String TRUSTSTORE_NAME = "easyconstat-synthetic-trust.jks";

    @TempDir
    Path temporaryDirectory;

    @Test
    void exportSignedFixtureProvenance() throws Exception {
        String configuredOutput = System.getProperty("easyconstat.fixture.output");
        if (configuredOutput == null || configuredOutput.isBlank()) {
            throw new IllegalArgumentException("easyconstat.fixture.output is required");
        }
        Path output = Path.of(configuredOutput).toAbsolutePath().normalize();
        Files.createDirectories(output);

        SyntheticEvidenceFixtureFactory.Fixture fixture =
                SyntheticEvidenceFixtureFactory.create(temporaryDirectory);
        Path packagePath = output.resolve(PACKAGE_NAME);
        Path trustStorePath = output.resolve(TRUSTSTORE_NAME);
        Files.copy(fixture.packagePath(), packagePath, StandardCopyOption.REPLACE_EXISTING);
        Files.copy(fixture.trustedStore(), trustStorePath, StandardCopyOption.REPLACE_EXISTING);

        String provenance = """
                {
                  "schemaVersion": 1,
                  "fixture": "%s",
                  "fixtureSha256": "%s",
                  "trustStore": "%s",
                  "trustStoreSha256": "%s",
                  "trustStoreType": "JKS",
                  "generatedAt": "%s",
                  "purpose": "Non-production ASiC-E/CAdES-B-LT verifier qualification fixture"
                }
                """.formatted(
                        PACKAGE_NAME,
                        sha256(packagePath),
                        TRUSTSTORE_NAME,
                        sha256(trustStorePath),
                        Instant.parse("2026-11-19T12:00:00Z"));
        byte[] provenanceBytes = provenance.getBytes(StandardCharsets.UTF_8);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        var keyPair = generator.generateKeyPair();
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(provenanceBytes);

        Files.write(output.resolve("fixture-provenance.json"), provenanceBytes);
        Files.writeString(
                output.resolve("fixture-provenance.sig"),
                Base64.getEncoder().encodeToString(signer.sign()) + System.lineSeparator(),
                StandardCharsets.US_ASCII);
        Files.writeString(
                output.resolve("fixture-provenance-public-key.pem"),
                pem("PUBLIC KEY", keyPair.getPublic().getEncoded()),
                StandardCharsets.US_ASCII);
    }

    private static String sha256(Path path) throws Exception {
        return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }

    private static String pem(String type, byte[] encoded) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(encoded)
                + "\n-----END " + type + "-----\n";
    }
}
