package com.probantia.easyconstat.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class ManifestParserTest {
    private final ManifestParser parser = new ManifestParser();

    @Test
    void acceptsStrictValidManifest() throws Exception {
        EvidenceManifest manifest = parser.parse(validManifest().getBytes(StandardCharsets.UTF_8));

        assertEquals("990002EXT001", manifest.constatId());
        assertEquals("report.pdf", manifest.reportPath());
        assertEquals(1, manifest.artifacts().size());
    }

    @Test
    void rejectsDuplicateJsonKeys() {
        String duplicate = validManifest().replace(
                "\"schemaVersion\":2,",
                "\"schemaVersion\":2,\"schemaVersion\":2,");

        VerificationException exception = assertThrows(
                VerificationException.class,
                () -> parser.parse(duplicate.getBytes(StandardCharsets.UTF_8)));
        assertEquals("MANIFEST_INVALID", exception.code());
    }

    @Test
    void rejectsUnknownProperties() {
        String unknown = validManifest().replace(
                "\"packageType\"",
                "\"unexpected\":true,\"packageType\"");

        assertThrows(
                VerificationException.class,
                () -> parser.parse(unknown.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void rejectsTrailingJson() {
        String trailing = validManifest() + " true";

        assertThrows(
                VerificationException.class,
                () -> parser.parse(trailing.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void rejectsMissingRequiredProperty() {
        String missingLocale = validManifest().replace("\"locale\":\"fr\",", "");

        VerificationException exception = assertThrows(
                VerificationException.class,
                () -> parser.parse(missingLocale.getBytes(StandardCharsets.UTF_8)));
        assertEquals("MANIFEST_INVALID", exception.code());
    }

    @Test
    void rejectsProducerWithoutSiret() {
        String missingSiret = validManifest().replace(
                ",\"siret\":\"94269495100016\"", "");

        VerificationException exception = assertThrows(
                VerificationException.class,
                () -> parser.parse(missingSiret.getBytes(StandardCharsets.UTF_8)));
        assertEquals("MANIFEST_INVALID", exception.code());
    }

    @Test
    void rejectsDuplicateArtifactPaths() {
        String artifact = artifact("report.pdf", "report", 3, "0".repeat(64));
        String duplicate = baseManifest("[" + artifact + "," + artifact + "]");

        assertThrows(
                VerificationException.class,
                () -> parser.parse(duplicate.getBytes(StandardCharsets.UTF_8)));
    }

    static String validManifest() {
        return baseManifest("[" + artifact("report.pdf", "report", 3, "0".repeat(64)) + "]");
    }

    static String baseManifest(String artifacts) {
        return "{"
                + "\"schemaVersion\":2,"
                + "\"packageType\":\"easyconstat-evidence\","
                + "\"constatId\":\"990002EXT001\","
                + "\"createdAt\":\"2026-11-19T12:00:00+01:00\","
                + "\"capturedAt\":\"2026-11-19T11:42:00+01:00\","
                + "\"locale\":\"fr\","
                + "\"channel\":\"operator-external\","
                + "\"hashAlgorithm\":\"SHA-256\","
                + "\"signatureProfile\":\"ASiC-E/CAdES-B-LT\","
                + "\"reportPath\":\"report.pdf\","
                + "\"producer\":{\"legalName\":\"PROBANTIA SAS\",\"country\":\"FR\","
                + "\"siret\":\"94269495100016\"},"
                + "\"artifacts\":" + artifacts
                + "}";
    }

    static String artifact(String path, String role, long size, String sha256) {
        return "{"
                + "\"path\":\"" + path + "\","
                + "\"role\":\"" + role + "\","
                + "\"mediaType\":\"application/pdf\","
                + "\"size\":" + size + ","
                + "\"sha256\":\"" + sha256 + "\""
                + "}";
    }
}
