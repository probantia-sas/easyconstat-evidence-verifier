package com.probantia.easyconstat.verify;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class EuTrustListUpdaterMain {
    private EuTrustListUpdaterMain() {
    }

    public static void main(String[] args) throws IOException {
        OutputLocale locale = OutputLocale.detect(args);
        Arguments arguments;
        try {
            arguments = Arguments.parse(args, locale);
        } catch (IllegalArgumentException exception) {
            System.err.println(exception.getMessage());
            printUsage(locale);
            System.exit(64);
            return;
        }

        try {
            EuTrustListRefreshReport report =
                    new EuTrustListService().refreshOnline(arguments.bundleRoot());
            if (arguments.json()) {
                ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
                System.out.println(mapper.writeValueAsString(report));
            } else {
                printHuman(report, arguments.locale());
            }
        } catch (IOException | RuntimeException exception) {
            System.err.println(arguments.locale() == OutputLocale.FR
                    ? "Échec de la mise à jour des listes de confiance européennes : "
                            + exception.getMessage()
                    : "EU trusted-list update failed: " + exception.getMessage());
            System.exit(1);
        }
    }

    private static void printHuman(EuTrustListRefreshReport report, OutputLocale locale) {
        boolean french = locale == OutputLocale.FR;
        System.out.println(french ? "Listes de confiance européennes mises à jour." :
                "EU trusted lists updated.");
        System.out.println((french ? "Version du cache : " : "Cache release: ") + report.releaseId());
        System.out.println((french ? "Listes nationales contrôlées : " : "National lists checked: ")
                + report.processedTls());
        System.out.println((french ? "Clés de confiance chargées : " : "Trust keys loaded: ")
                + report.trustAnchors());
    }

    private static void printUsage(OutputLocale locale) {
        System.err.println("Usage: java -cp verifier.jar "
                + "com.probantia.easyconstat.verify.EuTrustListUpdaterMain "
                + "[--json] [--lang fr|en] --bundle DIRECTORY");
        if (locale == OutputLocale.FR) {
            System.err.println("La mise à jour utilise le LOTL européen et le bootstrap OJ intégré.");
        }
    }

    private record Arguments(Path bundleRoot, boolean json, OutputLocale locale) {
        static Arguments parse(String[] args, OutputLocale defaultLocale) {
            List<String> values = new ArrayList<>(Arrays.asList(args));
            boolean json = values.remove("--json");
            OutputLocale locale = defaultLocale;
            Path bundle = null;
            for (int index = 0; index < values.size();) {
                String value = values.get(index);
                if ("--bundle".equals(value) || "--lang".equals(value)) {
                    if (index + 1 >= values.size()) {
                        throw new IllegalArgumentException("Missing value for " + value + ".");
                    }
                    if ("--bundle".equals(value)) {
                        bundle = Path.of(values.get(index + 1));
                    } else {
                        locale = OutputLocale.parse(values.get(index + 1));
                    }
                    values.subList(index, index + 2).clear();
                } else if (value.startsWith("--")) {
                    throw new IllegalArgumentException("Unknown option: " + value + ".");
                } else {
                    index++;
                }
            }
            if (!values.isEmpty() || bundle == null) {
                throw new IllegalArgumentException("Exactly one --bundle directory is required.");
            }
            return new Arguments(bundle.toAbsolutePath().normalize(), json, locale);
        }
    }
}
