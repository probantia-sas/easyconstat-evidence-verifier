package com.probantia.easyconstat.release;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReleaseManifestWriterTest {
    private static final String KEY_FINGERPRINT =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    @TempDir
    Path temporaryDirectory;

    @Test
    void writesDeterministicSortedManifest() throws Exception {
        Files.createDirectories(temporaryDirectory.resolve("artifacts"));
        Files.writeString(temporaryDirectory.resolve("artifacts/verifier.jar"), "verifier", StandardCharsets.UTF_8);
        Files.writeString(temporaryDirectory.resolve("README.md"), "documentation", StandardCharsets.UTF_8);

        ReleaseManifestWriter writer = new ReleaseManifestWriter();
        List<ReleaseManifestWriter.ArtifactInput> inputs = List.of(
                new ReleaseManifestWriter.ArtifactInput("documentation", "README.md"),
                new ReleaseManifestWriter.ArtifactInput("executable", "artifacts/verifier.jar"));
        ReleaseManifest first = writer.write(
                temporaryDirectory,
                temporaryDirectory.resolve("manifest-1.json"),
                "0.1.0-rc1",
                "2026-11-19T00:00:00Z",
                KEY_FINGERPRINT.toUpperCase(java.util.Locale.ROOT),
                inputs);
        writer.write(
                temporaryDirectory,
                temporaryDirectory.resolve("manifest-2.json"),
                "0.1.0-rc1",
                "2026-11-19T00:00:00Z",
                KEY_FINGERPRINT,
                inputs);

        assertArrayEquals(
                Files.readAllBytes(temporaryDirectory.resolve("manifest-1.json")),
                Files.readAllBytes(temporaryDirectory.resolve("manifest-2.json")));
        assertEquals("README.md", first.artifacts().get(0).path());
        assertEquals("artifacts/verifier.jar", first.artifacts().get(1).path());
        assertEquals(KEY_FINGERPRINT, first.signingKeySha256());

        JsonNode json = new ObjectMapper().readTree(temporaryDirectory.resolve("manifest-1.json").toFile());
        assertEquals("easyconstat-release-manifest", json.path("format").asText());
        assertEquals("Ed25519", json.path("signatureAlgorithm").asText());
        assertTrue(json.path("artifacts").get(0).path("sha256").asText().matches("[0-9a-f]{64}"));
    }

    @Test
    void rejectsTraversalAndDuplicatePaths() throws Exception {
        Files.writeString(temporaryDirectory.resolve("artifact.txt"), "artifact", StandardCharsets.UTF_8);
        ReleaseManifestWriter writer = new ReleaseManifestWriter();

        assertThrows(IllegalArgumentException.class, () -> writer.write(
                temporaryDirectory,
                temporaryDirectory.resolve("traversal.json"),
                "0.1.0",
                "2026-11-19T00:00:00Z",
                KEY_FINGERPRINT,
                List.of(new ReleaseManifestWriter.ArtifactInput("source", "../artifact.txt"))));
        assertThrows(IllegalArgumentException.class, () -> writer.write(
                temporaryDirectory,
                temporaryDirectory.resolve("duplicate.json"),
                "0.1.0",
                "2026-11-19T00:00:00Z",
                KEY_FINGERPRINT,
                List.of(
                        new ReleaseManifestWriter.ArtifactInput("source", "artifact.txt"),
                        new ReleaseManifestWriter.ArtifactInput("documentation", "artifact.txt"))));
    }

    @Test
    void refusesToOverwriteAnExistingManifest() throws Exception {
        Files.writeString(temporaryDirectory.resolve("artifact.txt"), "artifact", StandardCharsets.UTF_8);
        Path output = temporaryDirectory.resolve("release-manifest.json");
        Files.writeString(output, "existing", StandardCharsets.UTF_8);

        assertThrows(java.io.IOException.class, () -> new ReleaseManifestWriter().write(
                temporaryDirectory,
                output,
                "0.1.0",
                "2026-11-19T00:00:00Z",
                KEY_FINGERPRINT,
                List.of(new ReleaseManifestWriter.ArtifactInput("source", "artifact.txt"))));
        assertEquals("existing", Files.readString(output, StandardCharsets.UTF_8));
    }
}
