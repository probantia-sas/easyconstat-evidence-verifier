package com.probantia.easyconstat.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import java.nio.file.Files;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecureAsicInspectorTest {
    @TempDir
    Path temporaryDirectory;

    private final SecureAsicInspector inspector = new SecureAsicInspector();

    @Test
    void acceptsStructurallyValidPackageAndHashes() throws Exception {
        Path container = packageWith(Map.of("report.pdf", "PDF".getBytes(StandardCharsets.US_ASCII)), true);

        InspectedPackage inspected = inspector.inspect(container);

        assertEquals("990002EXT001", inspected.manifest().constatId());
        assertEquals(1, inspected.payloadCount());
        assertEquals(3, inspected.totalPayloadBytes());
    }

    @Test
    void rejectsTamperedPayload() throws Exception {
        byte[] expected = "PDF".getBytes(StandardCharsets.US_ASCII);
        byte[] actual = "BAD".getBytes(StandardCharsets.US_ASCII);
        String manifest = manifestFor(Map.of("report.pdf", expected));
        Path container = writeContainer(
                Map.of("report.pdf", actual), manifest, true, null);

        VerificationException exception = assertThrows(
                VerificationException.class, () -> inspector.inspect(container));
        assertEquals("PAYLOAD_HASH_MISMATCH", exception.code());
    }

    @Test
    void rejectsPayloadNotDeclaredByManifest() throws Exception {
        Map<String, byte[]> payloads = new LinkedHashMap<>();
        payloads.put("report.pdf", "PDF".getBytes(StandardCharsets.US_ASCII));
        payloads.put("hidden.txt", "hidden".getBytes(StandardCharsets.US_ASCII));
        String manifest = manifestFor(Map.of("report.pdf", payloads.get("report.pdf")));
        Path container = writeContainer(payloads, manifest, true, null);

        VerificationException exception = assertThrows(
                VerificationException.class, () -> inspector.inspect(container));
        assertEquals("PAYLOAD_SET_MISMATCH", exception.code());
    }

    @Test
    void rejectsPayloadDeclaredButMissing() throws Exception {
        byte[] report = "PDF".getBytes(StandardCharsets.US_ASCII);
        String manifest = manifestFor(Map.of("report.pdf", report));
        Path container = writeContainer(Map.of(), manifest, true, null);

        VerificationException exception = assertThrows(
                VerificationException.class, () -> inspector.inspect(container));
        assertEquals("PAYLOAD_SET_MISMATCH", exception.code());
    }

    @Test
    void rejectsDuplicateZipEntry() throws Exception {
        Path container = temporaryDirectory.resolve("duplicate.asice");
        byte[] mimetype = SecureAsicInspector.ASICE_MIMETYPE.getBytes(StandardCharsets.US_ASCII);
        try (ZipArchiveOutputStream zip = new ZipArchiveOutputStream(container)) {
            ZipArchiveEntry mimeEntry = new ZipArchiveEntry("mimetype");
            mimeEntry.setMethod(ZipEntry.STORED);
            mimeEntry.setSize(mimetype.length);
            CRC32 crc = new CRC32();
            crc.update(mimetype);
            mimeEntry.setCrc(crc.getValue());
            zip.putArchiveEntry(mimeEntry);
            zip.write(mimetype);
            zip.closeArchiveEntry();
            putArchive(zip, "evidence-manifest.json", "{}".getBytes(StandardCharsets.UTF_8));
            putArchive(zip, "report.pdf", new byte[] {1});
            putArchive(zip, "report.pdf", new byte[] {2});
            putArchive(zip, "META-INF/ASiCManifest.xml", "<manifest/>".getBytes(StandardCharsets.UTF_8));
            putArchive(zip, "META-INF/signature.p7s", new byte[] {1});
        }

        VerificationException exception = assertThrows(
                VerificationException.class, () -> inspector.inspect(container));
        assertEquals("DUPLICATE_ENTRY", exception.code());
    }

    @Test
    void rejectsParentTraversalEntry() throws Exception {
        Map<String, byte[]> payloads = Map.of("report.pdf", "PDF".getBytes(StandardCharsets.US_ASCII));
        Path container = writeContainer(
                payloads, manifestFor(payloads), true, "../outside.txt");

        VerificationException exception = assertThrows(
                VerificationException.class, () -> inspector.inspect(container));
        assertEquals("ENTRY_PATH_INVALID", exception.code());
    }

    @Test
    void rejectsCompressedMimetypeEntry() throws Exception {
        Path container = packageWith(Map.of("report.pdf", "PDF".getBytes(StandardCharsets.US_ASCII)), false);

        VerificationException exception = assertThrows(
                VerificationException.class, () -> inspector.inspect(container));
        assertEquals("MIMETYPE_ENTRY_INVALID", exception.code());
    }

    @Test
    void classifiesMalformedCryptographicSignatureAsInvalid() throws Exception {
        Path container = packageWith(
                Map.of("report.pdf", "PDF".getBytes(StandardCharsets.US_ASCII)), true);

        VerificationReport report = new EvidencePackageVerifier().verify(container, Optional.empty());

        assertEquals(
                VerificationStatus.INVALID,
                report.status(),
                report.code() + ": " + report.message());
    }

    private Path packageWith(Map<String, byte[]> payloads, boolean storedMimetype) throws Exception {
        return writeContainer(payloads, manifestFor(payloads), storedMimetype, null);
    }

    private Path writeContainer(
            Map<String, byte[]> payloads,
            String manifest,
            boolean storedMimetype,
            String unsafeEntry) throws IOException {
        Path output = temporaryDirectory.resolve("fixture-" + System.nanoTime() + ".asice");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(output))) {
            putMimetype(zip, storedMimetype);
            put(zip, ManifestValidator.MANIFEST_PATH, manifest.getBytes(StandardCharsets.UTF_8));
            for (Map.Entry<String, byte[]> payload : payloads.entrySet()) {
                put(zip, payload.getKey(), payload.getValue());
            }
            if (unsafeEntry != null) {
                put(zip, unsafeEntry, new byte[] {1});
            }
            put(zip, "META-INF/ASiCManifest.xml", "<manifest/>".getBytes(StandardCharsets.UTF_8));
            put(zip, "META-INF/signature.p7s", new byte[] {1, 2, 3});
        }
        return output;
    }

    private static void putMimetype(ZipOutputStream zip, boolean stored) throws IOException {
        byte[] value = SecureAsicInspector.ASICE_MIMETYPE.getBytes(StandardCharsets.US_ASCII);
        ZipEntry entry = new ZipEntry("mimetype");
        if (stored) {
            CRC32 crc = new CRC32();
            crc.update(value);
            entry.setMethod(ZipEntry.STORED);
            entry.setSize(value.length);
            entry.setCompressedSize(value.length);
            entry.setCrc(crc.getValue());
        }
        zip.putNextEntry(entry);
        zip.write(value);
        zip.closeEntry();
    }

    private static void put(ZipOutputStream zip, String name, byte[] value) throws IOException {
        zip.putNextEntry(new ZipEntry(name));
        zip.write(value);
        zip.closeEntry();
    }

    private static void putArchive(ZipArchiveOutputStream zip, String name, byte[] value)
            throws IOException {
        zip.putArchiveEntry(new ZipArchiveEntry(name));
        zip.write(value);
        zip.closeArchiveEntry();
    }

    private static String manifestFor(Map<String, byte[]> payloads) {
        byte[] report = payloads.get("report.pdf");
        String artifact = ManifestParserTest.artifact(
                "report.pdf", "report", report.length, sha256(report));
        return ManifestParserTest.baseManifest("[" + artifact + "]");
    }

    private static String sha256(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
