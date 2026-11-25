package com.probantia.easyconstat.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DurableQualificationFixtureTest {
    private static final String RESOURCE_ROOT = "/qualification/";
    private static final char[] STORE_PASSWORD = "fixture-only".toCharArray();
    private static final ObjectMapper JSON = new ObjectMapper();

    @TempDir
    Path temporaryDirectory;

    @Test
    void verifiesSignedProvenanceAndDurableLtPackage() throws Exception {
        byte[] provenance = resource("fixture-provenance.json");
        byte[] signature = Base64.getDecoder().decode(
                new String(resource("fixture-provenance.sig"), StandardCharsets.US_ASCII).trim());
        byte[] publicKey = decodePem(resource("fixture-provenance-public-key.pem"));

        Signature provenanceVerifier = Signature.getInstance("SHA256withRSA");
        provenanceVerifier.initVerify(KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(publicKey)));
        provenanceVerifier.update(provenance);
        assertTrue(provenanceVerifier.verify(signature), "Fixture provenance signature is invalid");

        JsonNode metadata = JSON.readTree(provenance);
        Path packagePath = copyResource(metadata.path("fixture").asText());
        Path trustStorePath = copyResource(metadata.path("trustStore").asText());
        assertEquals(metadata.path("fixtureSha256").asText(), sha256(packagePath));
        assertEquals(metadata.path("trustStoreSha256").asText(), sha256(trustStorePath));

        VerificationReport report = new EvidencePackageVerifier().verify(
                packagePath,
                Optional.of(new TrustConfiguration(
                        trustStorePath,
                        metadata.path("trustStoreType").asText(),
                        STORE_PASSWORD)));
        assertEquals(VerificationStatus.VALID, report.status(), report.code() + ": " + report.message());
        assertEquals("PACKAGE_VALID", report.code());
        assertEquals("990002EXT001", report.constatId(), "Use the reserved synthetic report ID");
    }

    private Path copyResource(String name) throws Exception {
        Path output = temporaryDirectory.resolve(name);
        Files.write(output, resource(name));
        return output;
    }

    private static byte[] resource(String name) throws Exception {
        try (var input = DurableQualificationFixtureTest.class.getResourceAsStream(RESOURCE_ROOT + name)) {
            if (input == null) {
                throw new IllegalStateException("Missing qualification resource: " + name);
            }
            return input.readAllBytes();
        }
    }

    private static byte[] decodePem(byte[] pemBytes) {
        String pem = new String(pemBytes, StandardCharsets.US_ASCII)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(pem);
    }

    private static String sha256(Path path) throws Exception {
        return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }
}
