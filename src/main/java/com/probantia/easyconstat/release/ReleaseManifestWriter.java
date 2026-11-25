package com.probantia.easyconstat.release;

import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class ReleaseManifestWriter {
    private static final Pattern VERSION = Pattern.compile("[0-9A-Za-z][0-9A-Za-z._+-]{0,127}");
    private static final Pattern ROLE = Pattern.compile("[a-z][a-z0-9-]{0,63}");
    private static final Pattern SHA256 = Pattern.compile("[0-9a-fA-F]{64}");
    private static final Pattern SAFE_PATH = Pattern.compile("[0-9A-Za-z][0-9A-Za-z._/-]{0,511}");
    private static final int BUFFER_SIZE = 64 * 1024;

    private final ObjectMapper mapper = JsonMapper.builder()
            .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
            .enable(SerializationFeature.INDENT_OUTPUT)
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .build();

    public ReleaseManifest write(
            Path baseDirectory,
            Path output,
            String version,
            String buildTimestamp,
            String signingKeySha256,
            List<ArtifactInput> inputs) throws IOException {
        validateVersion(version);
        String canonicalTimestamp = canonicalTimestamp(buildTimestamp);
        String canonicalKeyFingerprint = canonicalSha256(signingKeySha256, "signing-key fingerprint");
        if (inputs == null || inputs.isEmpty()) {
            throw new IllegalArgumentException("At least one release artifact is required.");
        }

        Path base = baseDirectory.toRealPath();
        Path target = output.toAbsolutePath().normalize();
        if (Files.exists(target)) {
            throw new IOException("Release manifest already exists: " + target);
        }
        if (target.getParent() == null || !Files.isDirectory(target.getParent())) {
            throw new IOException("Release manifest parent directory does not exist: " + target);
        }

        Set<String> seenPaths = new HashSet<>();
        List<ReleaseArtifact> artifacts = new ArrayList<>();
        for (ArtifactInput input : inputs) {
            String role = validateRole(input.role());
            String relativePath = validateRelativePath(input.path());
            if (!seenPaths.add(relativePath)) {
                throw new IllegalArgumentException("Duplicate release artifact: " + relativePath);
            }
            Path artifact = resolveArtifact(base, relativePath);
            artifacts.add(new ReleaseArtifact(
                    relativePath,
                    role,
                    Files.size(artifact),
                    sha256(artifact)));
        }
        artifacts.sort(Comparator.comparing(ReleaseArtifact::path));

        ReleaseManifest manifest = new ReleaseManifest(
                "easyconstat-release-manifest",
                1,
                "EasyConstat Evidence Verifier",
                "easyconstat-evidence-verifier",
                version,
                canonicalTimestamp,
                "SHA-256",
                "Ed25519",
                canonicalKeyFingerprint,
                List.copyOf(artifacts));

        Path temporary = Files.createTempFile(target.getParent(), ".release-manifest-", ".tmp");
        try {
            byte[] json = mapper.writeValueAsBytes(manifest);
            Files.write(temporary, json);
            Files.writeString(temporary, "\n", java.nio.file.StandardOpenOption.APPEND);
            moveAtomically(temporary, target);
        } finally {
            Files.deleteIfExists(temporary);
        }
        return manifest;
    }

    private static Path resolveArtifact(Path base, String relativePath) throws IOException {
        Path candidate = base;
        for (String segment : relativePath.split("/")) {
            candidate = candidate.resolve(segment);
        }
        Path normalized = candidate.normalize();
        if (!normalized.startsWith(base)) {
            throw new IllegalArgumentException("Release artifact escapes its base directory: " + relativePath);
        }
        Path real = normalized.toRealPath();
        if (!real.startsWith(base) || !Files.isRegularFile(real)) {
            throw new IllegalArgumentException("Release artifact is not a regular in-scope file: " + relativePath);
        }
        return real;
    }

    private static String validateRelativePath(String value) {
        if (value == null || !SAFE_PATH.matcher(value).matches() || value.contains("\\")) {
            throw new IllegalArgumentException("Unsafe release artifact path: " + value);
        }
        for (String segment : value.split("/", -1)) {
            if (segment.isEmpty() || ".".equals(segment) || "..".equals(segment)) {
                throw new IllegalArgumentException("Unsafe release artifact path: " + value);
            }
        }
        return value;
    }

    private static String validateRole(String value) {
        if (value == null || !ROLE.matcher(value).matches()) {
            throw new IllegalArgumentException("Invalid release artifact role: " + value);
        }
        return value;
    }

    private static void validateVersion(String value) {
        if (value == null || !VERSION.matcher(value).matches()) {
            throw new IllegalArgumentException("Invalid release version: " + value);
        }
    }

    private static String canonicalTimestamp(String value) {
        try {
            return Instant.parse(value).toString();
        } catch (DateTimeParseException | NullPointerException exception) {
            throw new IllegalArgumentException("Invalid release build timestamp: " + value, exception);
        }
    }

    private static String canonicalSha256(String value, String field) {
        if (value == null || !SHA256.matcher(value).matches()) {
            throw new IllegalArgumentException("Invalid SHA-256 " + field + ": " + value);
        }
        return value.toLowerCase(Locale.ROOT);
    }

    private static String sha256(Path path) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable.", exception);
        }
        byte[] buffer = new byte[BUFFER_SIZE];
        try (InputStream input = Files.newInputStream(path)) {
            int read;
            while ((read = input.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void moveAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target);
        }
    }

    public record ArtifactInput(String role, String path) {
    }
}
