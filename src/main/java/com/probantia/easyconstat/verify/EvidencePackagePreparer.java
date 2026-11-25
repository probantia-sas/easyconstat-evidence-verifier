package com.probantia.easyconstat.verify;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

final class EvidencePackagePreparer {
    private static final int MAX_ENTRIES = 64;
    private static final long MAX_ARCHIVE_BYTES = 8L * 1024 * 1024 * 1024;
    private static final long MAX_ENTRY_BYTES = 4L * 1024 * 1024 * 1024;
    private static final long MAX_TOTAL_BYTES = 8L * 1024 * 1024 * 1024;
    private static final long RATIO_CHECK_MIN_BYTES = 64L * 1024 * 1024;
    private static final long MAX_COMPRESSION_RATIO = 250;
    private static final EvidenceManifest.Producer PRODUCER =
            new EvidenceManifest.Producer("PROBANTIA SAS", "FR", "94269495100016");

    private final ObjectMapper mapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    private final ManifestParser manifestParser = new ManifestParser();

    PreparedEvidence prepare(EvidencePreparationRequest request) throws IOException {
        validateRequest(request);
        Path source = request.sourceArchive().toAbsolutePath().normalize();
        Path output = request.outputDirectory().toAbsolutePath().normalize();
        Path parent = output.getParent();
        Path stage = Files.createTempDirectory(parent, "." + output.getFileName() + ".tmp-");
        boolean committed = false;
        try {
            List<EvidenceArtifact> artifacts = copyAndDigestArchive(source, stage, request.constatId());
            artifacts.sort(Comparator.comparing(EvidenceArtifact::path));
            String reportPath = artifacts.stream()
                    .filter(artifact -> "report".equals(artifact.role()))
                    .map(EvidenceArtifact::path)
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException("The source archive has no report."));
            EvidenceManifest manifest = new EvidenceManifest(
                    2,
                    "easyconstat-evidence",
                    request.constatId(),
                    request.createdAt(),
                    request.capturedAt(),
                    request.locale(),
                    request.channel(),
                    "SHA-256",
                    "ASiC-E/CAdES-B-LT",
                    reportPath,
                    PRODUCER,
                    List.copyOf(artifacts));
            ManifestValidator.validate(manifest);

            byte[] json = (mapper.writeValueAsString(manifest) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
            Path manifestPath = stage.resolve(ManifestValidator.MANIFEST_PATH);
            Files.write(manifestPath, json, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            try {
                manifestParser.parse(json);
            } catch (VerificationException exception) {
                throw new IllegalStateException("Generated manifest failed its own validation.", exception);
            }

            moveDirectory(stage, output);
            committed = true;
            List<Path> payloads = artifacts.stream()
                    .map(artifact -> output.resolve(artifact.path()))
                    .toList();
            return new PreparedEvidence(
                    output,
                    output.resolve(ManifestValidator.MANIFEST_PATH),
                    manifest,
                    payloads);
        } finally {
            if (!committed) {
                deleteTree(stage);
            }
        }
    }

    private static void validateRequest(EvidencePreparationRequest request) throws IOException {
        if (request == null) {
            throw new IllegalArgumentException("Preparation request is missing.");
        }
        Path source = request.sourceArchive().toAbsolutePath().normalize();
        if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(source)) {
            throw new IllegalArgumentException("Source archive is missing, symbolic or not a regular file.");
        }
        long archiveSize = Files.size(source);
        if (archiveSize == 0 || archiveSize > MAX_ARCHIVE_BYTES) {
            throw new IllegalArgumentException("Source archive size is outside allowed limits.");
        }
        Path output = request.outputDirectory().toAbsolutePath().normalize();
        if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            throw new IllegalArgumentException("Output directory already exists.");
        }
        Path parent = output.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(parent)) {
            throw new IllegalArgumentException("Output parent is missing, symbolic or not a directory.");
        }
    }

    private static List<EvidenceArtifact> copyAndDigestArchive(
            Path source,
            Path stage,
            String constatId) throws IOException {
        List<EvidenceArtifact> artifacts = new ArrayList<>();
        Set<String> names = new HashSet<>();
        Set<String> caseFoldedNames = new HashSet<>();
        long totalBytes = 0;
        int count = 0;
        try (ZipFile zip = new ZipFile(source.toFile(), StandardCharsets.UTF_8)) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                count++;
                if (count > MAX_ENTRIES) {
                    throw new IllegalArgumentException("Source archive contains too many entries.");
                }
                String name = entry.getName();
                validateSourceEntry(entry, name, constatId, names, caseFoldedNames);
                ArtifactClassifier.Classification classification =
                        ArtifactClassifier.classify(name, constatId);
                Path target = stage.resolve(name);
                DigestResult digest = copyAndDigest(zip, entry, target);
                totalBytes = Math.addExact(totalBytes, digest.size());
                if (totalBytes > MAX_TOTAL_BYTES) {
                    throw new IllegalArgumentException("Expanded evidence exceeds the allowed limit.");
                }
                artifacts.add(new EvidenceArtifact(
                        name,
                        classification.role(),
                        classification.mediaType(),
                        digest.size(),
                        digest.sha256()));
            }
        } catch (ZipException exception) {
            throw new IllegalArgumentException("Source archive is not a readable ZIP file.", exception);
        }
        if (artifacts.isEmpty()) {
            throw new IllegalArgumentException("Source archive is empty.");
        }
        return artifacts;
    }

    private static void validateSourceEntry(
            ZipEntry entry,
            String name,
            String constatId,
            Set<String> names,
            Set<String> caseFoldedNames) {
        if (entry.isDirectory() || name == null || !ManifestValidator.PAYLOAD_PATH.matcher(name).matches()
                || ManifestValidator.MANIFEST_PATH.equals(name)) {
            throw new IllegalArgumentException("Unsafe or reserved source entry: " + name);
        }
        if (!names.add(name) || !caseFoldedNames.add(name.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("Duplicate source entry: " + name);
        }
        if (!ArtifactClassifier.belongsToConstat(name, constatId)) {
            throw new IllegalArgumentException("Source entry does not belong to the report: " + name);
        }
        long size = entry.getSize();
        long compressedSize = entry.getCompressedSize();
        if (size > MAX_ENTRY_BYTES) {
            throw new IllegalArgumentException("Source entry is too large: " + name);
        }
        if (size >= RATIO_CHECK_MIN_BYTES && compressedSize > 0
                && size / compressedSize > MAX_COMPRESSION_RATIO) {
            throw new IllegalArgumentException("Suspicious source compression ratio: " + name);
        }
    }

    private static DigestResult copyAndDigest(ZipFile zip, ZipEntry entry, Path target)
            throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable.", exception);
        }
        long size = 0;
        byte[] buffer = new byte[64 * 1024];
        try (InputStream input = zip.getInputStream(entry);
                OutputStream output = Files.newOutputStream(
                        target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            int read;
            while ((read = input.read(buffer)) != -1) {
                size += read;
                if (size > MAX_ENTRY_BYTES) {
                    throw new IllegalArgumentException("Expanded source entry is too large: " + entry.getName());
                }
                output.write(buffer, 0, read);
                digest.update(buffer, 0, read);
            }
        }
        if (entry.getSize() >= 0 && entry.getSize() != size) {
            throw new IllegalArgumentException("Source entry size changed while reading: " + entry.getName());
        }
        return new DigestResult(size, HexFormat.of().formatHex(digest.digest()));
    }

    private static void moveDirectory(Path source, Path destination) throws IOException {
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, destination);
        }
    }

    private static void deleteTree(Path directory) throws IOException {
        if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        Files.walkFileTree(directory, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exception) throws IOException {
                if (exception != null) {
                    throw exception;
                }
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private record DigestResult(long size, String sha256) {
    }
}
