package com.probantia.easyconstat.verify;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EvidencePackagePreparerTest {
    private static final String CREATED_AT = "2026-11-20T18:00:00+01:00";
    private static final String CAPTURED_AT = "2026-11-20T17:42:13+01:00";

    @TempDir
    Path temporaryDirectory;

    private final EvidencePackagePreparer preparer = new EvidencePackagePreparer();

    @Test
    void preparesAutomaticWebArchiveWithDeterministicManifest() throws Exception {
        String id = "990001AUTO01";
        Map<String, byte[]> files = archiveFiles(id, false);
        Path archive = writeArchive("automatic.zip", files);

        PreparedEvidence first = prepare(archive, "automatic-one", id, "automatic");
        PreparedEvidence second = prepare(archive, "automatic-two", id, "automatic");

        assertEquals(id, first.manifest().constatId());
        assertEquals(CAPTURED_AT, first.manifest().capturedAt());
        assertEquals("rapport_" + id + ".pdf", first.manifest().reportPath());
        assertEquals(files.size(), first.manifest().artifacts().size());
        assertArrayEquals(Files.readAllBytes(first.manifestPath()), Files.readAllBytes(second.manifestPath()));
        assertPayloadsUnchanged(first, files);

        Map<String, String> roles = roles(first);
        assertEquals("report", roles.get("rapport_" + id + ".pdf"));
        assertEquals("source", roles.get("source_" + id + ".txt"));
        assertEquals("capture-image", roles.get("capture_" + id + ".jpg"));
        assertEquals("activity-log", roles.get("log_" + id + ".pdf"));
        assertEquals("network-report", roles.get("har_" + id + ".pdf"));
    }

    @Test
    void preparesCentralAndExternalOperatorArchivesWithVideo() throws Exception {
        String centralId = "990003OVH001";
        PreparedEvidence central = prepare(
                writeArchive("central.zip", archiveFiles(centralId, true)),
                "central",
                centralId,
                "operator-central");
        assertEquals(
                "navigation-video",
                roles(central).get("video_" + centralId + ".mp4"));

        String externalId = "990002EXT001";
        PreparedEvidence external = prepare(
                writeArchive("external.zip", archiveFiles(externalId, true)),
                "external",
                externalId,
                "operator-external");
        assertEquals("operator-external", external.manifest().channel());
        assertEquals(
                "navigation-video",
                roles(external).get("video_" + externalId + ".mp4"));
    }

    @Test
    void classifiesNativePdfAndHttpMetadata() throws Exception {
        String id = "0042500PDF01";
        Map<String, byte[]> files = new LinkedHashMap<>();
        files.put("rapport_" + id + ".pdf", bytes("report"));
        files.put("document_" + id + ".pdf", bytes("target document"));
        files.put("document_" + id + ".http.json", bytes("{\"status\":200}"));
        files.put("log_" + id + ".pdf", bytes("activity"));

        PreparedEvidence prepared = prepare(
                writeArchive("native-pdf.zip", files),
                "native-pdf",
                id,
                "automatic");
        Map<String, String> roles = roles(prepared);
        assertEquals("target-document", roles.get("document_" + id + ".pdf"));
        assertEquals("http-metadata", roles.get("document_" + id + ".http.json"));
    }

    @Test
    void classifiesStandaloneCapturePdfWithoutConfusingItWithReport() throws Exception {
        String id = "0042500A4PDF";
        Map<String, byte[]> files = archiveFiles(id, false);
        files.put("capture_" + id + ".formatA4.pdf", bytes("rendered capture"));

        PreparedEvidence prepared = prepare(
                writeArchive("capture-pdf.zip", files),
                "capture-pdf",
                id,
                "automatic");
        assertEquals(
                "capture-rendering",
                roles(prepared).get("capture_" + id + ".formatA4.pdf"));
    }

    @Test
    void rejectsTraversalAndLeavesNoOutput() throws Exception {
        String id = "0042500BAD01";
        Map<String, byte[]> files = new LinkedHashMap<>();
        files.put("rapport_" + id + ".pdf", bytes("report"));
        files.put("../source_" + id + ".txt", bytes("unsafe"));
        Path archive = writeArchive("traversal.zip", files);
        Path output = temporaryDirectory.resolve("traversal-output");

        assertThrows(
                IllegalArgumentException.class,
                () -> preparer.prepare(request(archive, output, id, "automatic")));
        assertFalse(Files.exists(output));
    }

    @Test
    void rejectsCaseInsensitiveDuplicateNames() throws Exception {
        String id = "0042500DUP01";
        Map<String, byte[]> files = new LinkedHashMap<>();
        files.put("rapport_" + id + ".pdf", bytes("report"));
        files.put("source_" + id + ".txt", bytes("one"));
        files.put("SOURCE_" + id + ".TXT", bytes("two"));

        assertThrows(
                IllegalArgumentException.class,
                () -> prepare(writeArchive("duplicates.zip", files), "duplicates", id, "automatic"));
    }

    @Test
    void rejectsArtifactBelongingToAnotherReport() throws Exception {
        String id = "0042500OWNER";
        Map<String, byte[]> files = new LinkedHashMap<>();
        files.put("rapport_" + id + ".pdf", bytes("report"));
        files.put("source_0042500OTHER.txt", bytes("wrong report"));
        Path output = temporaryDirectory.resolve("wrong-owner");

        assertThrows(
                IllegalArgumentException.class,
                () -> preparer.prepare(request(
                        writeArchive("wrong-owner.zip", files), output, id, "automatic")));
        assertFalse(Files.exists(output));
    }

    @Test
    void refusesToOverwriteAnExistingOutputDirectory() throws Exception {
        String id = "0042500EXIST";
        Path archive = writeArchive("existing.zip", archiveFiles(id, false));
        Path output = Files.createDirectory(temporaryDirectory.resolve("existing-output"));
        Files.writeString(output.resolve("sentinel.txt"), "keep");

        assertThrows(
                IllegalArgumentException.class,
                () -> preparer.prepare(request(archive, output, id, "automatic")));
        assertTrue(Files.exists(output.resolve("sentinel.txt")));
    }

    private PreparedEvidence prepare(Path archive, String outputName, String id, String channel)
            throws IOException {
        return preparer.prepare(request(
                archive,
                temporaryDirectory.resolve(outputName),
                id,
                channel));
    }

    private static EvidencePreparationRequest request(
            Path archive,
            Path output,
            String id,
            String channel) {
        return new EvidencePreparationRequest(
                archive,
                output,
                id,
                CREATED_AT,
                CAPTURED_AT,
                "fr",
                channel);
    }

    private Path writeArchive(String name, Map<String, byte[]> files) throws IOException {
        Path archive = temporaryDirectory.resolve(name);
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
            for (Map.Entry<String, byte[]> file : files.entrySet()) {
                zip.putNextEntry(new ZipEntry(file.getKey()));
                zip.write(file.getValue());
                zip.closeEntry();
            }
        }
        return archive;
    }

    private static Map<String, byte[]> archiveFiles(String id, boolean video) {
        Map<String, byte[]> files = new LinkedHashMap<>();
        files.put("rapport_" + id + ".pdf", bytes("report"));
        files.put("source_" + id + ".txt", bytes("source"));
        files.put("har_" + id + ".pdf", bytes("network"));
        files.put("capture_" + id + ".jpg", bytes("capture"));
        if (video) {
            files.put("video_" + id + ".mp4", bytes("video"));
        }
        files.put("log_" + id + ".pdf", bytes("activity"));
        return files;
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static Map<String, String> roles(PreparedEvidence prepared) {
        return prepared.manifest().artifacts().stream().collect(Collectors.toMap(
                EvidenceArtifact::path,
                EvidenceArtifact::role,
                (left, right) -> {
                    throw new IllegalStateException("Duplicate artifact path");
                },
                LinkedHashMap::new));
    }

    private static void assertPayloadsUnchanged(
            PreparedEvidence prepared,
            Map<String, byte[]> expected) throws IOException {
        for (Map.Entry<String, byte[]> file : expected.entrySet()) {
            assertArrayEquals(file.getValue(), Files.readAllBytes(prepared.directory().resolve(file.getKey())));
        }
    }
}
