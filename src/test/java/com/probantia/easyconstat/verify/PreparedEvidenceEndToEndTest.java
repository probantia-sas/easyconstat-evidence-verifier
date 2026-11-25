package com.probantia.easyconstat.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PreparedEvidenceEndToEndTest {
    private static final String CONSTAT_ID = "0042500E2E01";

    @TempDir
    Path temporaryDirectory;

    @Test
    void preparesSignsAndVerifiesSelfContainedEvidence() throws Exception {
        PreparedEvidence prepared = prepareRepresentativeArchive();
        SyntheticEvidenceFixtureFactory.PreparedFixture fixture =
                SyntheticEvidenceFixtureFactory.createFromPreparedEvidence(
                        temporaryDirectory,
                        prepared);

        VerificationReport report = new EvidencePackageVerifier().verify(
                fixture.packagePath(),
                Optional.of(fixture.trustedConfiguration()));

        assertEquals(VerificationStatus.VALID, report.status(), report.code() + ": " + report.message());
        assertEquals("PACKAGE_VALID", report.code());
        assertEquals(Boolean.TRUE, report.structureAndHashesValid());
        assertEquals(Boolean.TRUE, report.cryptographicSignatureValid());
        assertEquals(1, report.timestampCount());
    }

    @Test
    void rejectsPreparedPackageAfterCaptureAlteration() throws Exception {
        PreparedEvidence prepared = prepareRepresentativeArchive();
        SyntheticEvidenceFixtureFactory.PreparedFixture fixture =
                SyntheticEvidenceFixtureFactory.createFromPreparedEvidence(
                        temporaryDirectory,
                        prepared);
        Path altered = replaceEntry(
                fixture.packagePath(),
                "capture_" + CONSTAT_ID + ".jpg",
                "altered capture".getBytes(StandardCharsets.UTF_8));

        VerificationReport report = new EvidencePackageVerifier().verify(
                altered,
                Optional.of(fixture.trustedConfiguration()));

        assertEquals(VerificationStatus.INVALID, report.status());
        assertEquals("PAYLOAD_SIZE_MISMATCH", report.code());
        assertEquals(Boolean.FALSE, report.structureAndHashesValid());
    }

    private PreparedEvidence prepareRepresentativeArchive() throws Exception {
        Map<String, byte[]> files = new LinkedHashMap<>();
        files.put("rapport_" + CONSTAT_ID + ".pdf", bytes("signed report"));
        files.put("capture_" + CONSTAT_ID + ".jpg", bytes("full page capture"));
        files.put("har_" + CONSTAT_ID + ".pdf", bytes("network report"));
        files.put("log_" + CONSTAT_ID + ".pdf", bytes("activity log"));
        files.put("source_" + CONSTAT_ID + ".txt", bytes("captured source"));
        files.put("video_" + CONSTAT_ID + ".mp4", bytes("navigation video"));

        Path archive = temporaryDirectory.resolve("representative.zip");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(archive))) {
            for (Map.Entry<String, byte[]> file : files.entrySet()) {
                zip.putNextEntry(new ZipEntry(file.getKey()));
                zip.write(file.getValue());
                zip.closeEntry();
            }
        }

        return new EvidencePackagePreparer().prepare(new EvidencePreparationRequest(
                archive,
                temporaryDirectory.resolve("prepared"),
                CONSTAT_ID,
                "2026-11-20T19:00:00+01:00",
                "2026-11-20T18:55:00+01:00",
                "fr",
                "operator-central"));
    }

    private Path replaceEntry(Path source, String entryName, byte[] replacement) throws Exception {
        Path output = temporaryDirectory.resolve("prepared-evidence-altered.asice");
        try (ZipFile input = new ZipFile(source.toFile());
                ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(output))) {
            var entries = input.entries();
            while (entries.hasMoreElements()) {
                ZipEntry original = entries.nextElement();
                byte[] bytes = original.getName().equals(entryName)
                        ? replacement
                        : readAll(input, original);
                ZipEntry copy = new ZipEntry(original.getName());
                if (original.getMethod() == ZipEntry.STORED) {
                    copy.setMethod(ZipEntry.STORED);
                    copy.setSize(bytes.length);
                    copy.setCompressedSize(bytes.length);
                    CRC32 crc = new CRC32();
                    crc.update(bytes);
                    copy.setCrc(crc.getValue());
                }
                zip.putNextEntry(copy);
                zip.write(bytes);
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

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
