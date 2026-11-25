package com.probantia.easyconstat.verify;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.signature.SignatureCryptographicVerification;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

final class DssAsicSignatureVerifier {
    SignatureVerification verify(
            Path container,
            Optional<TrustConfiguration> trustConfiguration,
            Optional<EuTrustListConfiguration> euTrustConfiguration)
            throws VerificationException {
        try {
            CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
            certificateVerifier.setCheckRevocationForUntrustedChains(true);
            boolean trustConfigured = configureTrust(
                    certificateVerifier, trustConfiguration, euTrustConfiguration);

            SignedDocumentValidator validator;
            List<AdvancedSignature> signatures;
            try {
                validator = SignedDocumentValidator.fromDocument(new FileDocument(container.toFile()));
                validator.setCertificateVerifier(certificateVerifier);
                signatures = validator.getSignatures();
            } catch (RuntimeException exception) {
                throw VerificationException.invalid(
                        "SIGNATURE_FORMAT_INVALID",
                        "The ASiC-E package does not contain a readable CAdES signature.",
                        exception);
            }
            if (signatures.size() != 1) {
                throw VerificationException.invalid(
                        "SIGNATURE_COUNT_INVALID",
                        "The ASiC-E package must contain exactly one advanced signature.");
            }

            AdvancedSignature signature = signatures.get(0);
            SignatureCryptographicVerification cryptographic;
            try {
                signature.checkSignatureIntegrity();
                cryptographic = signature.getSignatureCryptographicVerification();
            } catch (RuntimeException exception) {
                throw VerificationException.invalid(
                        "SIGNATURE_FORMAT_INVALID",
                        "The CAdES signature structure is invalid.",
                        exception);
            }
            if (cryptographic == null || !cryptographic.isSignatureValid()) {
                throw VerificationException.invalid(
                        "SIGNATURE_CRYPTOGRAPHICALLY_INVALID",
                        "The ASiC-E signature is cryptographically invalid.");
            }
            if (!signature.hasTProfile() || signature.getSignatureTimestamps().isEmpty()) {
                throw VerificationException.invalid(
                        "SIGNATURE_TIMESTAMP_MISSING",
                        "The CAdES signature does not contain a signature timestamp.");
            }
            if (!signature.hasLTProfile()) {
                throw VerificationException.invalid(
                        "SIGNATURE_LT_PROFILE_MISSING",
                        "The CAdES signature does not contain the required LT validation material.");
            }

            Reports reports;
            try {
                reports = validator.validateDocument();
            } catch (DSSException exception) {
                throw VerificationException.indeterminate(
                        "DSS_VALIDATION_ERROR",
                        "DSS could not complete the trust and revocation validation.",
                        exception);
            }
            SimpleReport report = reports.getSimpleReport();
            String signatureId = report.getFirstSignatureId();
            if (signatureId == null) {
                throw VerificationException.invalid(
                        "SIGNATURE_NOT_RECOGNISED",
                        "DSS did not recognise an advanced signature in the ASiC-E package.");
            }
            Indication indication = report.getIndication(signatureId);
            String indicationName = indication == null ? "UNKNOWN" : indication.name();
            String subIndication = report.getSubIndication(signatureId) == null
                    ? "NONE"
                    : report.getSubIndication(signatureId).name();
            String level = signature.getDataFoundUpToLevel() == null
                    ? "UNKNOWN"
                    : signature.getDataFoundUpToLevel().name();

            if (isFailed(indicationName)) {
                return new SignatureVerification(
                        VerificationStatus.INVALID,
                        "DSS_VALIDATION_FAILED",
                        "DSS rejected the signature or its validation material.",
                        level,
                        signature.getSignatureTimestamps().size(),
                        indicationName,
                        subIndication,
                        trustConfigured);
            }
            if (isPassed(indicationName) && trustConfigured) {
                return new SignatureVerification(
                        VerificationStatus.VALID,
                        "PACKAGE_VALID",
                        "The package structure, payloads, signature, timestamp and trust chain are valid.",
                        level,
                        signature.getSignatureTimestamps().size(),
                        indicationName,
                        subIndication,
                        true);
            }
            String message = trustConfigured
                    ? "Integrity is valid, but DSS could not establish a conclusive trust status."
                    : "Integrity is valid, but no approved trust source was configured.";
            return new SignatureVerification(
                    VerificationStatus.INDETERMINATE,
                    trustConfigured ? "TRUST_STATUS_INDETERMINATE" : "TRUST_SOURCE_MISSING",
                    message,
                    level,
                    signature.getSignatureTimestamps().size(),
                    indicationName,
                    subIndication,
                    trustConfigured);
        } catch (VerificationException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw VerificationException.indeterminate(
                    "DSS_VALIDATION_ERROR",
                    "DSS could not complete signature validation: " + exception.getMessage(),
                    exception);
        }
    }

    private static boolean configureTrust(
            CommonCertificateVerifier verifier,
            Optional<TrustConfiguration> configuration,
            Optional<EuTrustListConfiguration> euConfiguration) throws VerificationException {
        if (configuration.isPresent() && euConfiguration.isPresent()) {
            throw VerificationException.indeterminate(
                    "TRUST_CONFIGURATION_AMBIGUOUS",
                    "A static trust store and an EU trusted-list bundle cannot be combined.");
        }
        if (euConfiguration.isPresent()) {
            TrustedListsCertificateSource trusted =
                    new EuTrustListService().loadOffline(euConfiguration.get());
            verifier.setTrustedCertSources(trusted);
            return true;
        }
        if (configuration.isEmpty()) {
            return false;
        }
        TrustConfiguration trust = configuration.get();
        if (!Files.isRegularFile(trust.trustStore())) {
            throw VerificationException.indeterminate(
                    "TRUSTSTORE_MISSING",
                    "The configured trust store does not exist.");
        }
        char[] password = trust.password();
        try {
            CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
            trusted.importAsTrusted(new KeyStoreCertificateSource(
                    trust.trustStore().toFile(), trust.type(), password));
            verifier.setTrustedCertSources(trusted);
            return true;
        } catch (IOException | RuntimeException exception) {
            throw VerificationException.indeterminate(
                    "TRUSTSTORE_READ_FAILED",
                    "The configured trust store could not be loaded.",
                    exception);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static boolean isFailed(String indication) {
        return indication.contains("FAILED") || indication.contains("NO_SIGNATURE");
    }

    private static boolean isPassed(String indication) {
        return indication.contains("PASSED");
    }
}
