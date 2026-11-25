package com.probantia.easyconstat.verify;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.tsp.KeyEntityTSPSource;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

final class SyntheticEvidenceFixtureFactory {
    private static final char[] STORE_PASSWORD = "fixture-only".toCharArray();
    private static final Instant FIXED_TIME = Instant.parse("2026-11-19T12:00:00Z");
    private static final Instant HISTORICAL_TIME = Instant.parse("2024-01-15T12:00:00Z");

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private SyntheticEvidenceFixtureFactory() {
    }

    static Fixture create(Path directory) throws Exception {
        KeyMaterial root = rootCertificate(
                "CN=EasyConstat synthetic root CA,O=PROBANTIA SAS,C=FR",
                HISTORICAL_TIME,
                FIXED_TIME.plus(3650, ChronoUnit.DAYS));
        KeyMaterial signer = issuedCertificate(
                "CN=EasyConstat synthetic signer,O=PROBANTIA SAS,C=FR",
                root,
                false,
                FIXED_TIME.minus(1, ChronoUnit.DAYS),
                FIXED_TIME.plus(3650, ChronoUnit.DAYS));
        KeyMaterial tsa = issuedCertificate(
                "CN=EasyConstat synthetic TSA,O=PROBANTIA SAS,C=FR",
                root,
                true,
                HISTORICAL_TIME.minus(1, ChronoUnit.DAYS),
                FIXED_TIME.plus(3650, ChronoUnit.DAYS));
        X509CRL crl = emptyCrl(root, FIXED_TIME);
        KeyMaterial unrelated = rootCertificate(
                "CN=Unrelated synthetic trust anchor,O=Example,C=FR",
                FIXED_TIME,
                FIXED_TIME.plus(3650, ChronoUnit.DAYS));

        Path packagePath = directory.resolve("synthetic-valid.asice");
        signPackage(packagePath, root, signer, tsa, crl, FIXED_TIME, true);
        Path timestampOnlyPackagePath = directory.resolve("synthetic-timestamp-only.asice");
        signPackage(timestampOnlyPackagePath, root, signer, tsa, crl, FIXED_TIME, false);

        KeyMaterial historicalSigner = issuedCertificate(
                "CN=EasyConstat synthetic historically expired signer,O=PROBANTIA SAS,C=FR",
                root,
                false,
                HISTORICAL_TIME.minus(1, ChronoUnit.DAYS),
                HISTORICAL_TIME.plus(30, ChronoUnit.DAYS));
        Path historicallyExpiredPackagePath = directory.resolve("synthetic-historically-valid.asice");
        signPackage(
                historicallyExpiredPackagePath,
                root,
                historicalSigner,
                tsa,
                emptyCrl(root, HISTORICAL_TIME),
                HISTORICAL_TIME,
                true);
        Path trustedStore = writeTrustStore(
                directory.resolve("synthetic-trusted.jks"), root.certificate());
        Path unrelatedStore = writeTrustStore(
                directory.resolve("synthetic-untrusted.jks"), unrelated.certificate());
        return new Fixture(
                packagePath,
                timestampOnlyPackagePath,
                historicallyExpiredPackagePath,
                trustedStore,
                unrelatedStore,
                STORE_PASSWORD.clone());
    }

    static PreparedFixture createFromPreparedEvidence(
            Path directory,
            PreparedEvidence prepared) throws Exception {
        KeyMaterial root = rootCertificate(
                "CN=EasyConstat synthetic root CA,O=PROBANTIA SAS,C=FR",
                HISTORICAL_TIME,
                FIXED_TIME.plus(3650, ChronoUnit.DAYS));
        KeyMaterial signer = issuedCertificate(
                "CN=EasyConstat synthetic signer,O=PROBANTIA SAS,C=FR",
                root,
                false,
                FIXED_TIME.minus(1, ChronoUnit.DAYS),
                FIXED_TIME.plus(3650, ChronoUnit.DAYS));
        KeyMaterial tsa = issuedCertificate(
                "CN=EasyConstat synthetic TSA,O=PROBANTIA SAS,C=FR",
                root,
                true,
                HISTORICAL_TIME.minus(1, ChronoUnit.DAYS),
                FIXED_TIME.plus(3650, ChronoUnit.DAYS));

        List<DSSDocument> documents = new ArrayList<>();
        documents.add(new InMemoryDocument(
                Files.readAllBytes(prepared.manifestPath()),
                ManifestValidator.MANIFEST_PATH));
        prepared.payloadPaths().stream()
                .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                .forEach(path -> {
                    try {
                        documents.add(new InMemoryDocument(
                                Files.readAllBytes(path),
                                path.getFileName().toString()));
                    } catch (java.io.IOException exception) {
                        throw new IllegalStateException("Unable to read prepared payload: " + path, exception);
                    }
                });

        Path packagePath = directory.resolve("prepared-evidence.asice");
        signDocuments(
                packagePath,
                root,
                signer,
                tsa,
                emptyCrl(root, FIXED_TIME),
                FIXED_TIME,
                true,
                documents);
        Path trustedStore = writeTrustStore(
                directory.resolve("prepared-evidence-trust.jks"), root.certificate());
        return new PreparedFixture(packagePath, trustedStore, STORE_PASSWORD.clone());
    }

    private static void signPackage(
            Path output,
            KeyMaterial root,
            KeyMaterial signer,
            KeyMaterial tsa,
            X509CRL crl,
            Instant productionTime,
            boolean extendToBaselineLt) throws Exception {
        byte[] report = "%PDF-1.4\n% synthetic evidence fixture\n".getBytes(StandardCharsets.US_ASCII);
        String artifact = ManifestParserTest.artifact(
                "report.pdf", "report", report.length, sha256(report));
        byte[] manifest = ManifestParserTest.baseManifest("[" + artifact + "]")
                .getBytes(StandardCharsets.UTF_8);

        signDocuments(
                output,
                root,
                signer,
                tsa,
                crl,
                productionTime,
                extendToBaselineLt,
                List.of(
                        new InMemoryDocument(manifest, ManifestValidator.MANIFEST_PATH),
                        new InMemoryDocument(report, "report.pdf")));
    }

    private static void signDocuments(
            Path output,
            KeyMaterial root,
            KeyMaterial signer,
            KeyMaterial tsa,
            X509CRL crl,
            Instant productionTime,
            boolean extendToBaselineLt,
            List<DSSDocument> documents) throws Exception {

        CertificateToken signerToken = new CertificateToken(signer.certificate());
        CertificateToken tsaToken = new CertificateToken(tsa.certificate());
        CertificateToken rootToken = new CertificateToken(root.certificate());
        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        trusted.addCertificate(rootToken);

        CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setTrustedCertSources(trusted);
        ExternalResourcesCRLSource crlSource = new ExternalResourcesCRLSource(
                new ByteArrayInputStream(crl.getEncoded()));
        if (crlSource.getRevocationTokens(signerToken, rootToken).isEmpty()
                || crlSource.getRevocationTokens(tsaToken, rootToken).isEmpty()) {
            throw new IllegalStateException("Synthetic CRL is not applicable to the issued certificates");
        }
        certificateVerifier.setCrlSource(crlSource);
        ASiCWithCAdESService service = new ASiCWithCAdESService(certificateVerifier);
        KeyEntityTSPSource timestampSource = new KeyEntityTSPSource(
                tsa.privateKey(),
                tsa.certificate(),
                List.of(tsa.certificate(), root.certificate()));
        timestampSource.setTsaPolicy("1.3.6.1.4.1.55555.1.1");
        timestampSource.setProductionTime(Date.from(productionTime));
        timestampSource.setAcceptedDigestAlgorithms(
                List.of(DigestAlgorithm.SHA256, DigestAlgorithm.SHA512));
        service.setTspSource(timestampSource);

        ASiCWithCAdESSignatureParameters parameters = new ASiCWithCAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_T);
        parameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(signerToken);
        parameters.setCertificateChain(List.of(signerToken, rootToken));
        parameters.bLevel().setSigningDate(Date.from(productionTime));

        ToBeSigned dataToSign = service.getDataToSign(documents, parameters);
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(signer.privateKey());
        signature.update(dataToSign.getBytes());
        DSSDocument baselineT = service.signDocument(
                documents,
                parameters,
                new SignatureValue(SignatureAlgorithm.RSA_SHA256, signature.sign()));

        if (!extendToBaselineLt) {
            baselineT.save(output.toString());
            return;
        }

        ASiCWithCAdESSignatureParameters extension = new ASiCWithCAdESSignatureParameters();
        extension.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LT);
        extension.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        DSSDocument baselineLt = service.extendDocument(baselineT, extension);
        baselineLt.save(output.toString());
    }

    private static KeyMaterial rootCertificate(
            String distinguishedName,
            Instant issuanceTime,
            Instant notAfterInstant) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, SecureRandom.getInstanceStrong());
        KeyPair keyPair = generator.generateKeyPair();
        X500Name subject = new X500Name(distinguishedName);
        Date notBefore = Date.from(issuanceTime.minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(notAfterInstant);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                new BigInteger(128, new SecureRandom()).abs(),
                notBefore,
                notAfter,
                subject,
                keyPair.getPublic());
        JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
        builder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extensions.createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extensions.createAuthorityKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(1));
        builder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        ContentSigner certificateSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(certificateSigner);
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
        certificate.checkValidity(Date.from(issuanceTime));
        certificate.verify(keyPair.getPublic());
        return new KeyMaterial(keyPair.getPrivate(), certificate);
    }

    private static KeyMaterial issuedCertificate(
            String distinguishedName,
            KeyMaterial issuer,
            boolean timestampAuthority,
            Instant notBeforeInstant,
            Instant notAfterInstant) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, SecureRandom.getInstanceStrong());
        KeyPair keyPair = generator.generateKeyPair();
        Date notBefore = Date.from(notBeforeInstant);
        Date notAfter = Date.from(notAfterInstant);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer.certificate(),
                new BigInteger(128, new SecureRandom()).abs(),
                notBefore,
                notAfter,
                new X500Name(distinguishedName),
                keyPair.getPublic());
        JcaX509ExtensionUtils extensions = new JcaX509ExtensionUtils();
        builder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                extensions.createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                extensions.createAuthorityKeyIdentifier(issuer.certificate()));
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(
                Extension.keyUsage,
                true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        GeneralNames crlLocation = new GeneralNames(new GeneralName(
                GeneralName.uniformResourceIdentifier,
                "http://synthetic.invalid/easyconstat-test.crl"));
        builder.addExtension(
                Extension.cRLDistributionPoints,
                false,
                new CRLDistPoint(new DistributionPoint[] {
                    new DistributionPoint(new DistributionPointName(crlLocation), null, null)
                }));
        if (timestampAuthority) {
            builder.addExtension(
                    Extension.extendedKeyUsage,
                    true,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        }
        ContentSigner certificateSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(issuer.privateKey());
        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(certificateSigner));
        certificate.checkValidity(Date.from(notBeforeInstant.plus(1, ChronoUnit.HOURS)));
        certificate.verify(issuer.certificate().getPublicKey());
        return new KeyMaterial(keyPair.getPrivate(), certificate);
    }

    private static X509CRL emptyCrl(KeyMaterial issuer, Instant productionTime) throws Exception {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(
                X500Name.getInstance(issuer.certificate().getSubjectX500Principal().getEncoded()),
                Date.from(productionTime.minus(1, ChronoUnit.HOURS)));
        builder.setNextUpdate(Date.from(productionTime.plus(3650, ChronoUnit.DAYS)));
        builder.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
        builder.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuer.certificate()));
        ContentSigner crlSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(issuer.privateKey());
        X509CRLHolder holder = builder.build(crlSigner);
        X509CRL crl = new JcaX509CRLConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCRL(holder);
        crl.verify(issuer.certificate().getPublicKey());
        return crl;
    }

    private static Path writeTrustStore(Path output, X509Certificate... certificates)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, STORE_PASSWORD);
        for (int index = 0; index < certificates.length; index++) {
            keyStore.setCertificateEntry("synthetic-" + index, certificates[index]);
        }
        try (var stream = Files.newOutputStream(output)) {
            keyStore.store(stream, STORE_PASSWORD);
        }
        return output;
    }

    private static String sha256(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    record Fixture(
            Path packagePath,
            Path timestampOnlyPackagePath,
            Path historicallyExpiredPackagePath,
            Path trustedStore,
            Path unrelatedStore,
            char[] password) {
        TrustConfiguration trustedConfiguration() {
            return new TrustConfiguration(trustedStore, "JKS", password);
        }

        TrustConfiguration unrelatedConfiguration() {
            return new TrustConfiguration(unrelatedStore, "JKS", password);
        }
    }

    record PreparedFixture(Path packagePath, Path trustedStore, char[] password) {
        TrustConfiguration trustedConfiguration() {
            return new TrustConfiguration(trustedStore, "JKS", password);
        }
    }

    private record KeyMaterial(PrivateKey privateKey, X509Certificate certificate) {
    }
}
