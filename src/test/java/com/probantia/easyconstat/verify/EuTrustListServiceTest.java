package com.probantia.easyconstat.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EuTrustListServiceTest {
    @TempDir
    Path temporaryDirectory;

    @Test
    void resolvesOnlyThePublishedImmutableCache() throws Exception {
        String releaseId = "tl-20261121T120000Z-1234abcd";
        Path release = temporaryDirectory.resolve("releases").resolve(releaseId);
        Path cache = release.resolve("cache");
        Files.createDirectories(cache);
        Files.writeString(release.resolve("release.json"), "{}", StandardCharsets.UTF_8);
        Files.writeString(temporaryDirectory.resolve("current"), releaseId + "\n", StandardCharsets.US_ASCII);

        assertEquals(cache, EuTrustListService.resolveCurrentCache(temporaryDirectory));
    }

    @Test
    void rejectsAReleasePointerThatCouldEscapeTheBundle() throws Exception {
        Files.createDirectories(temporaryDirectory.resolve("releases"));
        Files.writeString(
                temporaryDirectory.resolve("current"),
                "../../outside\n",
                StandardCharsets.US_ASCII);

        assertThrows(
                IOException.class,
                () -> EuTrustListService.resolveCurrentCache(temporaryDirectory));
    }

    @Test
    void rejectsAnIncompleteCurrentRelease() throws Exception {
        String releaseId = "tl-20261121T120000Z-1234abcd";
        Files.createDirectories(temporaryDirectory.resolve("releases").resolve(releaseId));
        Files.writeString(temporaryDirectory.resolve("current"), releaseId, StandardCharsets.US_ASCII);

        assertThrows(
                IOException.class,
                () -> EuTrustListService.resolveCurrentCache(temporaryDirectory));
    }
}
