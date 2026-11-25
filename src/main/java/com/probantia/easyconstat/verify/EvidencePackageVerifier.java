package com.probantia.easyconstat.verify;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

final class EvidencePackageVerifier {
    static final String VERSION = "0.1.0";
    private final SecureAsicInspector inspector = new SecureAsicInspector();
    private final DssAsicSignatureVerifier signatureVerifier = new DssAsicSignatureVerifier();

    VerificationReport verify(Path packagePath, Optional<TrustConfiguration> trustConfiguration) {
        return verify(packagePath, trustConfiguration, Optional.empty());
    }

    VerificationReport verify(
            Path packagePath,
            Optional<TrustConfiguration> trustConfiguration,
            Optional<EuTrustListConfiguration> euTrustConfiguration) {
        boolean trustRequested = trustConfiguration.isPresent() || euTrustConfiguration.isPresent();
        String verifiedAt = Instant.now().toString();
        String displayPath = packagePath.toAbsolutePath().normalize().toString();
        InspectedPackage inspected;
        try {
            inspected = inspector.inspect(packagePath);
        } catch (VerificationException exception) {
            return new VerificationReport(
                    VERSION,
                    verifiedAt,
                    exception.status(),
                    exception.code(),
                    exception.getMessage(),
                    displayPath,
                    null,
                    null,
                    null,
                    null,
                    null,
                    false,
                    null,
                    null,
                    null,
                    null,
                    null,
                    trustRequested);
        } catch (RuntimeException exception) {
            return internalError(verifiedAt, displayPath, exception, trustRequested);
        }

        EvidenceManifest manifest = inspected.manifest();
        try {
            SignatureVerification signature = signatureVerifier.verify(
                    packagePath, trustConfiguration, euTrustConfiguration);
            return new VerificationReport(
                    VERSION,
                    verifiedAt,
                    signature.status(),
                    signature.code(),
                    signature.message(),
                    displayPath,
                    manifest.constatId(),
                    manifest.locale(),
                    manifest.channel(),
                    inspected.payloadCount(),
                    inspected.totalPayloadBytes(),
                    true,
                    true,
                    signature.signatureLevel(),
                    signature.timestampCount(),
                    signature.indication(),
                    signature.subIndication(),
                    signature.trustSourceConfigured());
        } catch (VerificationException exception) {
            Boolean cryptographicIntegrity = "SIGNATURE_CRYPTOGRAPHICALLY_INVALID".equals(
                    exception.code()) ? false : null;
            boolean trustAvailable = trustRequested && !isTrustConfigurationFailure(exception.code());
            return new VerificationReport(
                    VERSION,
                    verifiedAt,
                    exception.status(),
                    exception.code(),
                    exception.getMessage(),
                    displayPath,
                    manifest.constatId(),
                    manifest.locale(),
                    manifest.channel(),
                    inspected.payloadCount(),
                    inspected.totalPayloadBytes(),
                    true,
                    cryptographicIntegrity,
                    null,
                    null,
                    null,
                    null,
                    trustAvailable);
        } catch (RuntimeException exception) {
            return new VerificationReport(
                    VERSION,
                    verifiedAt,
                    VerificationStatus.INDETERMINATE,
                    "VERIFIER_INTERNAL_ERROR",
                    "The verifier could not complete the cryptographic checks.",
                    displayPath,
                    manifest.constatId(),
                    manifest.locale(),
                    manifest.channel(),
                    inspected.payloadCount(),
                    inspected.totalPayloadBytes(),
                    true,
                    null,
                    null,
                    null,
                    null,
                    null,
                    trustRequested);
        }
    }

    private static boolean isTrustConfigurationFailure(String code) {
        return "TRUST_CONFIGURATION_AMBIGUOUS".equals(code)
                || "TRUSTSTORE_MISSING".equals(code)
                || "TRUSTSTORE_READ_FAILED".equals(code)
                || "EU_TRUST_BUNDLE_INVALID".equals(code);
    }

    private static VerificationReport internalError(
            String verifiedAt,
            String displayPath,
            RuntimeException exception,
            boolean trustConfigured) {
        return new VerificationReport(
                VERSION,
                verifiedAt,
                VerificationStatus.INDETERMINATE,
                "VERIFIER_INTERNAL_ERROR",
                "The verifier could not complete the package checks: "
                        + exception.getClass().getSimpleName(),
                displayPath,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                trustConfigured);
    }
}
