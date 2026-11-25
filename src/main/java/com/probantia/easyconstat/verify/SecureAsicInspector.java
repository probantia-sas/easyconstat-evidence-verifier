package com.probantia.easyconstat.verify;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

final class SecureAsicInspector {
    static final String ASICE_MIMETYPE = "application/vnd.etsi.asic-e+zip";
    private static final long MAX_CONTAINER_BYTES = 8L * 1024 * 1024 * 1024;
    private static final long MAX_EXPANDED_BYTES = 8L * 1024 * 1024 * 1024;
    private static final long MAX_ENTRY_BYTES = 4L * 1024 * 1024 * 1024;
    private static final long MAX_METADATA_ENTRY_BYTES = 64L * 1024 * 1024;
    private static final int MAX_ENTRIES = 96;
    private static final int MAX_MANIFEST_BYTES = 1024 * 1024;
    private static final long RATIO_CHECK_MIN_BYTES = 64L * 1024 * 1024;
    private static final long MAX_COMPRESSION_RATIO = 250;

    private final ManifestParser manifestParser = new ManifestParser();

    InspectedPackage inspect(Path container) throws VerificationException {
        validateContainerFile(container);
        try (ZipFile zip = new ZipFile(container.toFile(), StandardCharsets.UTF_8)) {
            ScanResult scan = scanEntries(zip);
            byte[] manifestBytes = readBounded(
                    zip,
                    scan.entries().get(ManifestValidator.MANIFEST_PATH),
                    MAX_MANIFEST_BYTES,
                    "MANIFEST_TOO_LARGE");
            EvidenceManifest manifest = manifestParser.parse(manifestBytes);
            return verifyPayloads(zip, scan, manifest);
        } catch (ZipException exception) {
            throw VerificationException.invalid(
                    "CONTAINER_NOT_ZIP",
                    "The evidence package is not a readable ZIP/ASiC-E container.",
                    exception);
        } catch (IOException exception) {
            throw VerificationException.invalid(
                    "CONTAINER_READ_FAILED",
                    "The evidence package could not be read: " + exception.getMessage(),
                    exception);
        }
    }

    private static void validateContainerFile(Path container) throws VerificationException {
        try {
            if (container == null || !Files.isRegularFile(container)) {
                throw VerificationException.invalid(
                        "CONTAINER_MISSING", "The evidence package does not exist or is not a file.");
            }
            long size = Files.size(container);
            if (size == 0 || size > MAX_CONTAINER_BYTES) {
                throw VerificationException.invalid(
                        "CONTAINER_SIZE_INVALID", "The evidence package size is outside allowed limits.");
            }
        } catch (IOException exception) {
            throw VerificationException.invalid(
                    "CONTAINER_STAT_FAILED", "The evidence package metadata could not be read.", exception);
        }
    }

    private static ScanResult scanEntries(ZipFile zip) throws IOException, VerificationException {
        Enumeration<? extends ZipEntry> entries = zip.entries();
        if (!entries.hasMoreElements()) {
            throw VerificationException.invalid("CONTAINER_EMPTY", "The ASiC-E container is empty.");
        }

        Map<String, ZipEntry> byName = new HashMap<>();
        ZipEntry first = entries.nextElement();
        validateMimetype(zip, first);
        byName.put(first.getName(), first);

        int entryCount = 1;
        long declaredExpandedBytes = ASICE_MIMETYPE.length();
        String signatureEntry = null;
        String asicManifestEntry = null;
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            entryCount++;
            if (entryCount > MAX_ENTRIES) {
                throw VerificationException.invalid(
                        "TOO_MANY_ENTRIES", "The ASiC-E container contains too many entries.");
            }
            String name = entry.getName();
            validateEntryName(name);
            if (byName.putIfAbsent(name, entry) != null) {
                throw VerificationException.invalid(
                        "DUPLICATE_ENTRY", "Duplicate ASiC-E entry: " + name);
            }
            validateEntrySize(entry);
            if (entry.getSize() > 0) {
                declaredExpandedBytes = Math.addExact(declaredExpandedBytes, entry.getSize());
                if (declaredExpandedBytes > MAX_EXPANDED_BYTES) {
                    throw VerificationException.invalid(
                            "EXPANDED_SIZE_EXCEEDED",
                            "The expanded ASiC-E payload exceeds the allowed limit.");
                }
            }

            if (entry.isDirectory()) {
                if (!"META-INF/".equals(name)) {
                    throw VerificationException.invalid(
                            "DIRECTORY_NOT_ALLOWED", "Unexpected directory entry: " + name);
                }
                continue;
            }
            if (name.startsWith("META-INF/")) {
                String lower = name.toLowerCase(java.util.Locale.ROOT);
                if (lower.endsWith(".p7s")) {
                    if (signatureEntry != null) {
                        throw VerificationException.invalid(
                                "SIGNATURE_COUNT_INVALID",
                                "The ASiC-E container must contain exactly one CAdES signature.");
                    }
                    signatureEntry = name;
                } else if (lower.contains("manifest") && lower.endsWith(".xml")) {
                    if (asicManifestEntry != null) {
                        throw VerificationException.invalid(
                                "ASIC_MANIFEST_COUNT_INVALID",
                                "The ASiC-E container must contain exactly one ASiC manifest.");
                    }
                    asicManifestEntry = name;
                } else {
                    throw VerificationException.invalid(
                            "METADATA_ENTRY_UNEXPECTED", "Unexpected ASiC-E metadata entry: " + name);
                }
            }
        }

        if (signatureEntry == null) {
            throw VerificationException.invalid(
                    "SIGNATURE_MISSING", "The ASiC-E CAdES signature is missing.");
        }
        if (asicManifestEntry == null) {
            throw VerificationException.invalid(
                    "ASIC_MANIFEST_MISSING", "The ASiC manifest is missing.");
        }
        if (!byName.containsKey(ManifestValidator.MANIFEST_PATH)) {
            throw VerificationException.invalid(
                    "EVIDENCE_MANIFEST_MISSING", "The evidence manifest is missing.");
        }
        return new ScanResult(Map.copyOf(byName), signatureEntry, asicManifestEntry);
    }

    private static void validateMimetype(ZipFile zip, ZipEntry first)
            throws IOException, VerificationException {
        if (!"mimetype".equals(first.getName()) || first.getMethod() != ZipEntry.STORED) {
            throw VerificationException.invalid(
                    "MIMETYPE_ENTRY_INVALID",
                    "The first ASiC-E entry must be the uncompressed mimetype entry.");
        }
        byte[] bytes = readBounded(zip, first, 128, "MIMETYPE_TOO_LARGE");
        String actual = new String(bytes, StandardCharsets.US_ASCII);
        if (!ASICE_MIMETYPE.equals(actual)) {
            throw VerificationException.invalid(
                    "MIMETYPE_VALUE_INVALID", "The ASiC-E mimetype value is invalid.");
        }
    }

    private static void validateEntryName(String name) throws VerificationException {
        if (name == null || name.isEmpty() || name.startsWith("/") || name.startsWith("\\")
                || name.contains("\\") || name.contains("//")) {
            throw VerificationException.invalid("ENTRY_PATH_INVALID", "Unsafe ASiC-E entry path.");
        }
        String[] segments = name.split("/", -1);
        for (int index = 0; index < segments.length; index++) {
            String segment = segments[index];
            boolean trailingDirectoryMarker = index == segments.length - 1 && segment.isEmpty();
            if (trailingDirectoryMarker) {
                continue;
            }
            if (segment.isEmpty() || ".".equals(segment) || "..".equals(segment)) {
                throw VerificationException.invalid(
                        "ENTRY_PATH_INVALID", "Unsafe ASiC-E entry path: " + name);
            }
        }
        for (int index = 0; index < name.length(); index++) {
            char value = name.charAt(index);
            if (value < 0x20 || value == 0x7f) {
                throw VerificationException.invalid(
                        "ENTRY_PATH_INVALID", "Control character in ASiC-E entry path.");
            }
        }
        if (!name.startsWith("META-INF/") && !"mimetype".equals(name)
                && !ManifestValidator.PAYLOAD_PATH.matcher(name).matches()) {
            throw VerificationException.invalid(
                    "PAYLOAD_PATH_INVALID", "Invalid evidence payload path: " + name);
        }
    }

    private static void validateEntrySize(ZipEntry entry) throws VerificationException {
        long size = entry.getSize();
        long compressed = entry.getCompressedSize();
        if (size > MAX_ENTRY_BYTES) {
            throw VerificationException.invalid(
                    "ENTRY_SIZE_EXCEEDED", "ASiC-E entry is too large: " + entry.getName());
        }
        if (entry.getName().startsWith("META-INF/") && size > MAX_METADATA_ENTRY_BYTES) {
            throw VerificationException.invalid(
                    "METADATA_SIZE_EXCEEDED",
                    "ASiC-E metadata entry is too large: " + entry.getName());
        }
        if (size >= RATIO_CHECK_MIN_BYTES && compressed > 0
                && size / compressed > MAX_COMPRESSION_RATIO) {
            throw VerificationException.invalid(
                    "COMPRESSION_RATIO_EXCEEDED",
                    "Suspicious compression ratio for ASiC-E entry: " + entry.getName());
        }
    }

    private static InspectedPackage verifyPayloads(
            ZipFile zip,
            ScanResult scan,
            EvidenceManifest manifest) throws IOException, VerificationException {
        Map<String, EvidenceArtifact> artifacts = new HashMap<>();
        for (EvidenceArtifact artifact : manifest.artifacts()) {
            artifacts.put(artifact.path(), artifact);
        }
        Set<String> actualPayloads = new LinkedHashSet<>();
        for (Map.Entry<String, ZipEntry> item : scan.entries().entrySet()) {
            String name = item.getKey();
            if (!"mimetype".equals(name) && !name.startsWith("META-INF/")
                    && !ManifestValidator.MANIFEST_PATH.equals(name)) {
                actualPayloads.add(name);
            }
        }
        if (!actualPayloads.equals(new HashSet<>(artifacts.keySet()))) {
            Set<String> missing = new HashSet<>(artifacts.keySet());
            missing.removeAll(actualPayloads);
            Set<String> extra = new HashSet<>(actualPayloads);
            extra.removeAll(artifacts.keySet());
            throw VerificationException.invalid(
                    "PAYLOAD_SET_MISMATCH",
                    "The evidence payload set does not match the manifest; missing="
                            + missing + ", extra=" + extra + ".");
        }

        long totalBytes = 0;
        for (EvidenceArtifact artifact : manifest.artifacts()) {
            ZipEntry entry = scan.entries().get(artifact.path());
            DigestResult digest = digestEntry(zip, entry);
            if (digest.size() != artifact.size()) {
                throw VerificationException.invalid(
                        "PAYLOAD_SIZE_MISMATCH",
                        "Payload size does not match the manifest: " + artifact.path());
            }
            if (!digest.sha256().equals(artifact.sha256())) {
                throw VerificationException.invalid(
                        "PAYLOAD_HASH_MISMATCH",
                        "Payload SHA-256 does not match the manifest: " + artifact.path());
            }
            totalBytes = Math.addExact(totalBytes, digest.size());
            if (totalBytes > MAX_EXPANDED_BYTES) {
                throw VerificationException.invalid(
                        "EXPANDED_SIZE_EXCEEDED",
                        "The expanded evidence payload exceeds the allowed limit.");
            }
        }
        return new InspectedPackage(
                manifest,
                manifest.artifacts().size(),
                totalBytes,
                scan.signatureEntry(),
                scan.asicManifestEntry());
    }

    private static DigestResult digestEntry(ZipFile zip, ZipEntry entry)
            throws IOException, VerificationException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
        long size = 0;
        byte[] buffer = new byte[64 * 1024];
        try (InputStream input = zip.getInputStream(entry)) {
            int count;
            while ((count = input.read(buffer)) != -1) {
                size += count;
                if (size > MAX_ENTRY_BYTES) {
                    throw VerificationException.invalid(
                            "ENTRY_SIZE_EXCEEDED", "ASiC-E entry is too large: " + entry.getName());
                }
                digest.update(buffer, 0, count);
            }
        }
        return new DigestResult(size, HexFormat.of().formatHex(digest.digest()));
    }

    private static byte[] readBounded(ZipFile zip, ZipEntry entry, int maximum, String code)
            throws IOException, VerificationException {
        if (entry == null) {
            throw VerificationException.invalid("ENTRY_MISSING", "Required ASiC-E entry is missing.");
        }
        try (InputStream input = zip.getInputStream(entry);
                ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[8192];
            int total = 0;
            int count;
            while ((count = input.read(buffer)) != -1) {
                total += count;
                if (total > maximum) {
                    throw VerificationException.invalid(code, "ASiC-E entry exceeds its size limit.");
                }
                output.write(buffer, 0, count);
            }
            return output.toByteArray();
        }
    }

    private record ScanResult(
            Map<String, ZipEntry> entries,
            String signatureEntry,
            String asicManifestEntry) {
    }

    private record DigestResult(long size, String sha256) {
    }
}
