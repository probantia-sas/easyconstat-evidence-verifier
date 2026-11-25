package com.probantia.easyconstat.verify;

import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;

final class EuTrustListBootstrap {
    static final String LOTL_URL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml";
    static final String OJ_URL = "https://eur-lex.europa.eu/eli/C/2026/1944/oj";
    static final String RESOURCE = "/eu-lotl-oj-2026-1944.p12";
    static final String RESOURCE_METADATA = "/eu-lotl-oj-2026-1944.json";
    static final String KEYSTORE_SHA256 =
            "98a76fbcd726e3553ecdf8dec59eef1b015b0579e7514d8c26f7c6124ce382e6";
    static final Set<String> CERTIFICATE_SHA256 = Set.of(
            "c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5",
            "e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1",
            "df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5",
            "b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18",
            "236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b",
            "d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474");

    private static final char[] PASSWORD = "dss-password".toCharArray();

    private EuTrustListBootstrap() {
    }

    static KeyStoreCertificateSource loadVerifiedCertificateSource() throws IOException {
        byte[] bytes = readResource();
        verifyKeystoreDigest(bytes);
        verifyCertificateDigests(bytes);
        char[] password = PASSWORD.clone();
        try {
            return new KeyStoreCertificateSource(
                    new ByteArrayInputStream(bytes), "PKCS12", password);
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(bytes, (byte) 0);
        }
    }

    static Set<String> inspectCertificateDigests() throws IOException {
        byte[] bytes = readResource();
        try {
            verifyKeystoreDigest(bytes);
            return certificateDigests(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static byte[] readResource() throws IOException {
        try (InputStream input = EuTrustListBootstrap.class.getResourceAsStream(RESOURCE)) {
            if (input == null) {
                throw new IOException("The embedded EU LOTL bootstrap keystore is missing.");
            }
            return input.readAllBytes();
        }
    }

    private static void verifyKeystoreDigest(byte[] bytes) throws IOException {
        String actual = digest(bytes);
        if (!KEYSTORE_SHA256.equals(actual)) {
            throw new IOException("The embedded EU LOTL bootstrap keystore digest is invalid.");
        }
    }

    private static void verifyCertificateDigests(byte[] bytes) throws IOException {
        Set<String> actual = certificateDigests(bytes);
        if (!CERTIFICATE_SHA256.equals(actual)) {
            throw new IOException("The EU LOTL bootstrap certificates do not match OJ C/2026/1944.");
        }
    }

    private static Set<String> certificateDigests(byte[] bytes) throws IOException {
        char[] password = PASSWORD.clone();
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new ByteArrayInputStream(bytes), password);
            Set<String> digests = new HashSet<>();
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                Certificate certificate = keyStore.getCertificate(aliases.nextElement());
                if (certificate != null) {
                    digests.add(digest(certificate.getEncoded()));
                }
            }
            return Set.copyOf(digests);
        } catch (GeneralSecurityException exception) {
            throw new IOException("Unable to inspect the EU LOTL bootstrap keystore.", exception);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static String digest(byte[] bytes) throws IOException {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (GeneralSecurityException exception) {
            throw new IOException("SHA-256 is unavailable.", exception);
        }
    }
}
