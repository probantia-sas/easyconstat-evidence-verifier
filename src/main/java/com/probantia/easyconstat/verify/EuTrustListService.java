package com.probantia.easyconstat.verify;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.europa.esig.dss.model.job.DocumentInfo;
import eu.europa.esig.dss.model.job.InfoRecord;
import eu.europa.esig.dss.model.tsl.TLValidationJobSummary;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

final class EuTrustListService {
    private static final Pattern RELEASE_ID = Pattern.compile("tl-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}");
    private static final DateTimeFormatter RELEASE_TIME =
            DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

    TrustedListsCertificateSource loadOffline(EuTrustListConfiguration configuration)
            throws VerificationException {
        try {
            Path cache = resolveCurrentCache(configuration.bundleRoot());
            TrustedListsCertificateSource trusted = new TrustedListsCertificateSource();
            TLValidationJob job = createJob(cache, trusted, false);
            job.offlineRefresh();
            validateSummary(job.getSummary(), trusted);
            return trusted;
        } catch (IOException | RuntimeException exception) {
            throw VerificationException.indeterminate(
                    "EU_TRUST_BUNDLE_INVALID",
                    "The authenticated EU trusted-list bundle could not be loaded.",
                    exception);
        }
    }

    EuTrustListRefreshReport refreshOnline(Path requestedRoot) throws IOException {
        Path root = requestedRoot.toAbsolutePath().normalize();
        ensureDirectory(root);
        Path releases = root.resolve("releases");
        ensureDirectory(releases);
        Path lockPath = root.resolve("update.lock");
        try (FileChannel channel = FileChannel.open(
                        lockPath, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
                FileLock lock = channel.tryLock()) {
            if (lock == null) {
                throw new IOException("Another EU trusted-list update is already running.");
            }
            return refreshLocked(root, releases);
        } catch (java.nio.channels.OverlappingFileLockException exception) {
            throw new IOException("Another EU trusted-list update is already running.", exception);
        }
    }

    static Path resolveCurrentCache(Path requestedRoot) throws IOException {
        Path root = requestedRoot.toAbsolutePath().normalize();
        Path pointer = root.resolve("current");
        rejectSymbolicLink(pointer);
        if (!Files.isRegularFile(pointer)) {
            throw new IOException("The EU trusted-list bundle has no current release.");
        }
        String releaseId = Files.readString(pointer, StandardCharsets.US_ASCII).trim();
        if (!RELEASE_ID.matcher(releaseId).matches()) {
            throw new IOException("The EU trusted-list current pointer is invalid.");
        }
        Path releases = root.resolve("releases").normalize();
        Path release = releases.resolve(releaseId).normalize();
        Path cache = release.resolve("cache").normalize();
        if (!release.startsWith(releases) || !cache.startsWith(release)) {
            throw new IOException("The EU trusted-list release escapes its bundle root.");
        }
        rejectSymbolicLink(release);
        rejectSymbolicLink(cache);
        if (!Files.isRegularFile(release.resolve("release.json")) || !Files.isDirectory(cache)) {
            throw new IOException("The EU trusted-list current release is incomplete.");
        }
        return cache;
    }

    private EuTrustListRefreshReport refreshLocked(Path root, Path releases) throws IOException {
        String releaseId = "tl-" + RELEASE_TIME.format(Instant.now()) + "-"
                + UUID.randomUUID().toString().replace("-", "").substring(0, 8);
        Path incoming = releases.resolve(".incoming-" + releaseId);
        Path published = releases.resolve(releaseId);
        Path cache = incoming.resolve("cache");
        Files.createDirectory(incoming);
        Files.createDirectory(cache);
        boolean moved = false;
        try {
            TrustedListsCertificateSource trusted = new TrustedListsCertificateSource();
            TLValidationJob job = createJob(cache, trusted, true);
            job.onlineRefresh();
            TLValidationJobSummary summary = job.getSummary();
            validateSummary(summary, trusted);

            EuTrustListRefreshReport report = new EuTrustListRefreshReport(
                    "ok",
                    releaseId,
                    Instant.now().toString(),
                    EuTrustListBootstrap.LOTL_URL,
                    EuTrustListBootstrap.OJ_URL,
                    EuTrustListBootstrap.KEYSTORE_SHA256,
                    summary.getNumberOfProcessedLOTLs(),
                    summary.getNumberOfProcessedTLs(),
                    trusted.getNumberOfTrustedEntityKeys());
            ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            mapper.writeValue(incoming.resolve("release.json").toFile(), report);
            copyBootstrapMetadata(incoming.resolve("bootstrap.json"));

            moveDirectory(incoming, published);
            moved = true;
            publishPointer(root, releaseId);
            return report;
        } finally {
            if (!moved && Files.exists(incoming)) {
                deleteRecursively(incoming);
            }
        }
    }

    private static TLValidationJob createJob(
            Path cache,
            TrustedListsCertificateSource trusted,
            boolean online) throws IOException {
        LOTLSource lotl = new LOTLSource();
        lotl.setUrl(EuTrustListBootstrap.LOTL_URL);
        lotl.setCertificateSource(EuTrustListBootstrap.loadVerifiedCertificateSource());
        lotl.setSigningCertificatesAnnouncementPredicate(
                new OfficialJournalSchemeInformationURI(EuTrustListBootstrap.OJ_URL));
        lotl.setPivotSupport(true);
        lotl.setTLVersions(List.of(5, 6));
        lotl.setTrustAnchorValidityPredicate(
                new GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate());

        ExpirationAndSignatureCheckStrategy strict = new ExpirationAndSignatureCheckStrategy();
        strict.setAcceptExpiredListOfTrustedLists(false);
        strict.setAcceptInvalidListOfTrustedLists(false);
        strict.setAcceptExpiredTrustedList(false);
        strict.setAcceptInvalidTrustedList(false);

        TLValidationJob job = new TLValidationJob();
        job.setTrustedListCertificateSource(trusted);
        job.setListOfTrustedListSources(lotl);
        job.setSynchronizationStrategy(strict);
        job.setOfflineDataLoader(offlineLoader(cache));
        if (online) {
            job.setOnlineDataLoader(onlineLoader(cache));
        }
        return job;
    }

    private static FileCacheDataLoader offlineLoader(Path cache) {
        FileCacheDataLoader loader = new FileCacheDataLoader();
        loader.setCacheExpirationTime(-1);
        loader.setDataLoader(new IgnoreDataLoader());
        loader.setFileCacheDirectory(cache.toFile());
        return loader;
    }

    private static FileCacheDataLoader onlineLoader(Path cache) {
        CommonsDataLoader network = new CommonsDataLoader();
        network.setTimeoutConnection(15_000);
        network.setTimeoutConnectionRequest(15_000);
        network.setTimeoutResponse(60_000);
        network.setTimeoutSocket(60_000);
        network.setRedirectsEnabled(true);
        network.setUseSystemProperties(true);

        FileCacheDataLoader loader = new FileCacheDataLoader();
        loader.setCacheExpirationTime(0);
        loader.setDataLoader(network);
        loader.setFileCacheDirectory(cache.toFile());
        return loader;
    }

    private static void validateSummary(
            TLValidationJobSummary summary,
            TrustedListsCertificateSource trusted) throws IOException {
        if (summary == null || summary.getNumberOfProcessedLOTLs() < 1) {
            throw new IOException("No EU List of Trusted Lists was processed.");
        }
        if (summary.getNumberOfProcessedTLs() < 20) {
            throw new IOException("The EU trusted-list set is unexpectedly incomplete.");
        }
        for (DocumentInfo info : summary.getLOTLInfos()) {
            validateDocumentInfo(info);
        }
        for (DocumentInfo info : summary.getOtherTLInfos()) {
            validateDocumentInfo(info);
        }
        if (trusted.getNumberOfTrustedEntityKeys() < 1) {
            throw new IOException("No trust anchor was extracted from the EU trusted lists.");
        }
    }

    private static void validateDocumentInfo(DocumentInfo info) throws IOException {
        rejectRecordError(info.getDownloadCacheInfo(), info.getUrl(), "download");
        rejectRecordError(info.getParsingCacheInfo(), info.getUrl(), "parsing");
        rejectRecordError(info.getValidationCacheInfo(), info.getUrl(), "validation");
        if (info.getValidationCacheInfo() == null || !info.getValidationCacheInfo().isValid()) {
            throw new IOException("Trusted-list signature validation failed for " + info.getUrl() + ".");
        }
    }

    private static void rejectRecordError(InfoRecord record, String url, String stage) throws IOException {
        if (record == null || record.isError()) {
            String detail = record == null ? "missing status" : record.getExceptionMessage();
            throw new IOException("Trusted-list " + stage + " failed for " + url + ": " + detail);
        }
    }

    private static void copyBootstrapMetadata(Path target) throws IOException {
        try (var input = EuTrustListService.class.getResourceAsStream(
                EuTrustListBootstrap.RESOURCE_METADATA)) {
            if (input == null) {
                throw new IOException("The EU LOTL bootstrap metadata is missing.");
            }
            Files.copy(input, target);
        }
    }

    private static void publishPointer(Path root, String releaseId) throws IOException {
        Path temporary = root.resolve(".current-" + UUID.randomUUID() + ".tmp");
        Files.writeString(
                temporary,
                releaseId + System.lineSeparator(),
                StandardCharsets.US_ASCII,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE);
        try {
            atomicMove(temporary, root.resolve("current"), true);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void moveDirectory(Path source, Path target) throws IOException {
        if (Files.exists(target)) {
            throw new IOException("The EU trusted-list release already exists.");
        }
        atomicMove(source, target, false);
    }

    private static void atomicMove(Path source, Path target, boolean replace) throws IOException {
        try {
            if (replace) {
                Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } else {
                Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
            }
        } catch (AtomicMoveNotSupportedException exception) {
            if (replace) {
                Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
            } else {
                Files.move(source, target);
            }
        }
    }

    private static void ensureDirectory(Path directory) throws IOException {
        if (Files.exists(directory)) {
            rejectSymbolicLink(directory);
            if (!Files.isDirectory(directory)) {
                throw new IOException("Expected a directory: " + directory);
            }
        } else {
            Files.createDirectories(directory);
        }
    }

    private static void rejectSymbolicLink(Path path) throws IOException {
        if (Files.isSymbolicLink(path)) {
            throw new IOException("Symbolic links are not allowed in the EU trusted-list bundle.");
        }
    }

    private static void deleteRecursively(Path root) throws IOException {
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }
}
