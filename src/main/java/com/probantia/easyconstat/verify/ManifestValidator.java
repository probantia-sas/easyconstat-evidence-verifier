package com.probantia.easyconstat.verify;

import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

final class ManifestValidator {
    static final String MANIFEST_PATH = "evidence-manifest.json";
    static final Pattern PAYLOAD_PATH = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$");
    private static final Pattern CONSTAT_ID = Pattern.compile("^[A-Z0-9]{10,16}$");
    private static final Pattern MEDIA_TYPE =
            Pattern.compile("^[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+$");
    private static final Pattern SHA_256 = Pattern.compile("^[a-f0-9]{64}$");
    private static final Set<String> LOCALES = Set.of("fr", "en");
    private static final Set<String> CHANNELS =
            Set.of("automatic", "operator-central", "operator-external");
    private static final Set<String> ROLES = Set.of(
            "report",
            "capture-image",
            "capture-rendering",
            "activity-log",
            "network-report",
            "source",
            "navigation-video",
            "target-document",
            "http-metadata",
            "other");
    private static final int MAX_ARTIFACTS = 64;
    private static final long MAX_ARTIFACT_SIZE = 4_294_967_296L;

    private ManifestValidator() {
    }

    static void validate(EvidenceManifest manifest) {
        require(manifest != null, "manifest is null");
        require(manifest.schemaVersion() == 2, "schemaVersion must be 2");
        require("easyconstat-evidence".equals(manifest.packageType()), "packageType is invalid");
        require(matches(CONSTAT_ID, manifest.constatId()), "constatId is invalid");
        requireValidDateTime(manifest.createdAt(), "createdAt");
        requireValidDateTime(manifest.capturedAt(), "capturedAt");
        require(LOCALES.contains(manifest.locale()), "locale is invalid");
        require(CHANNELS.contains(manifest.channel()), "channel is invalid");
        require("SHA-256".equals(manifest.hashAlgorithm()), "hashAlgorithm must be SHA-256");
        require(
                "ASiC-E/CAdES-B-LT".equals(manifest.signatureProfile()),
                "signatureProfile is invalid");
        requirePayloadPath(manifest.reportPath(), "reportPath");
        require(!MANIFEST_PATH.equals(manifest.reportPath()), "reportPath is reserved");
        validateProducer(manifest.producer());
        validateArtifacts(manifest.artifacts(), manifest.reportPath());
    }

    private static void validateProducer(EvidenceManifest.Producer producer) {
        require(producer != null, "producer is missing");
        require("PROBANTIA SAS".equals(producer.legalName()), "producer.legalName is invalid");
        require("FR".equals(producer.country()), "producer.country is invalid");
        require("94269495100016".equals(producer.siret()), "producer.siret is invalid");
    }

    private static void validateArtifacts(List<EvidenceArtifact> artifacts, String reportPath) {
        require(artifacts != null && !artifacts.isEmpty(), "artifacts is empty");
        require(artifacts.size() <= MAX_ARTIFACTS, "too many artifacts");

        Set<String> paths = new HashSet<>();
        int reports = 0;
        for (EvidenceArtifact artifact : artifacts) {
            require(artifact != null, "artifact is null");
            requirePayloadPath(artifact.path(), "artifact.path");
            require(!MANIFEST_PATH.equals(artifact.path()), "artifact.path is reserved");
            require(paths.add(artifact.path()), "artifact.path is duplicated: " + artifact.path());
            require(ROLES.contains(artifact.role()), "artifact.role is invalid: " + artifact.path());
            require(matches(MEDIA_TYPE, artifact.mediaType()),
                    "artifact.mediaType is invalid: " + artifact.path());
            require(artifact.size() >= 0 && artifact.size() <= MAX_ARTIFACT_SIZE,
                    "artifact.size is invalid: " + artifact.path());
            require(matches(SHA_256, artifact.sha256()),
                    "artifact.sha256 is invalid: " + artifact.path());
            if ("report".equals(artifact.role())) {
                reports++;
                require(reportPath.equals(artifact.path()),
                        "the report artifact does not match reportPath");
            }
        }
        require(reports == 1, "exactly one report artifact is required");
        require(paths.contains(reportPath), "reportPath is not listed in artifacts");
    }

    private static void requireValidDateTime(String value, String field) {
        require(value != null, field + " is missing");
        try {
            OffsetDateTime.parse(value);
        } catch (DateTimeParseException exception) {
            throw new IllegalArgumentException(field + " is not an offset date-time", exception);
        }
    }

    private static void requirePayloadPath(String value, String field) {
        require(matches(PAYLOAD_PATH, value), field + " is invalid");
    }

    private static boolean matches(Pattern pattern, String value) {
        return value != null && pattern.matcher(value).matches();
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }
}
