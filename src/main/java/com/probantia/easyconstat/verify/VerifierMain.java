package com.probantia.easyconstat.verify;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public final class VerifierMain {
    private VerifierMain() {
    }

    public static void main(String[] args) throws IOException {
        OutputLocale outputLocale = OutputLocale.detect(args);
        Arguments arguments;
        try {
            arguments = Arguments.parse(args, outputLocale);
        } catch (IllegalArgumentException exception) {
            System.err.println(exception.getMessage());
            printUsage(outputLocale);
            System.exit(64);
            return;
        }

        VerificationReport report = new EvidencePackageVerifier().verify(
                arguments.packagePath(),
                arguments.trustConfiguration(),
                arguments.euTrustConfiguration());
        if (arguments.json()) {
            ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            System.out.println(mapper.writeValueAsString(report));
        } else {
            System.out.print(new HumanReportRenderer().render(report, arguments.outputLocale()));
        }
        System.exit(switch (report.status()) {
            case VALID -> 0;
            case INVALID -> 1;
            case INDETERMINATE -> 2;
        });
    }

    private static void printUsage(OutputLocale locale) {
        System.err.println("Usage: java -jar verifier.jar [--json] [--lang fr|en] "
                + "[--truststore PATH | --eu-trust-bundle DIRECTORY] "
                + "[--truststore-type JKS|PKCS12] PACKAGE.asice");
        System.err.println(locale == OutputLocale.FR
                ? "Le mot de passe du magasin de confiance est lu depuis EASYCONSTAT_TRUSTSTORE_PASSWORD."
                : "The trust-store password is read from EASYCONSTAT_TRUSTSTORE_PASSWORD.");
    }

    private record Arguments(
            Path packagePath,
            boolean json,
            OutputLocale outputLocale,
            Optional<TrustConfiguration> trustConfiguration,
            Optional<EuTrustListConfiguration> euTrustConfiguration) {
        static Arguments parse(String[] args, OutputLocale defaultLocale) {
            List<String> values = new ArrayList<>(Arrays.asList(args));
            boolean json = values.remove("--json");
            Path trustStore = null;
            Path euTrustBundle = null;
            String trustStoreType = "JKS";
            OutputLocale outputLocale = defaultLocale;
            for (int index = 0; index < values.size();) {
                String value = values.get(index);
                if ("--truststore".equals(value)
                        || "--eu-trust-bundle".equals(value)
                        || "--truststore-type".equals(value)
                        || "--lang".equals(value)) {
                    if (index + 1 >= values.size()) {
                        throw new IllegalArgumentException("Missing value for " + value + ".");
                    }
                    String optionValue = values.get(index + 1);
                    if ("--truststore".equals(value)) {
                        trustStore = Path.of(optionValue);
                    } else if ("--eu-trust-bundle".equals(value)) {
                        euTrustBundle = Path.of(optionValue);
                    } else if ("--truststore-type".equals(value)) {
                        trustStoreType = optionValue.toUpperCase(java.util.Locale.ROOT);
                    } else {
                        outputLocale = OutputLocale.parse(optionValue);
                    }
                    values.subList(index, index + 2).clear();
                } else if (value.startsWith("--")) {
                    throw new IllegalArgumentException("Unknown option: " + value + ".");
                } else {
                    index++;
                }
            }
            if (values.size() != 1) {
                throw new IllegalArgumentException("Exactly one ASiC-E package is required.");
            }
            if (!SetHolder.TRUSTSTORE_TYPES.contains(trustStoreType)) {
                throw new IllegalArgumentException("Unsupported trust-store type: " + trustStoreType + ".");
            }
            Optional<TrustConfiguration> trust = Optional.empty();
            if (trustStore != null && euTrustBundle != null) {
                throw new IllegalArgumentException(
                        "--truststore and --eu-trust-bundle are mutually exclusive.");
            }
            if (trustStore != null) {
                String password = System.getenv("EASYCONSTAT_TRUSTSTORE_PASSWORD");
                if (password == null) {
                    throw new IllegalArgumentException(
                            "EASYCONSTAT_TRUSTSTORE_PASSWORD is required with --truststore.");
                }
                trust = Optional.of(new TrustConfiguration(
                        trustStore.toAbsolutePath().normalize(),
                        trustStoreType,
                        password.toCharArray()));
            }
            Optional<EuTrustListConfiguration> euTrust = euTrustBundle == null
                    ? Optional.empty()
                    : Optional.of(new EuTrustListConfiguration(euTrustBundle));
            return new Arguments(Path.of(values.get(0)), json, outputLocale, trust, euTrust);
        }
    }

    private static final class SetHolder {
        private static final java.util.Set<String> TRUSTSTORE_TYPES = java.util.Set.of("JKS", "PKCS12");

        private SetHolder() {
        }
    }
}
