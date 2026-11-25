package com.probantia.easyconstat.verify;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public final class EvidencePackagePreparerMain {
    private EvidencePackagePreparerMain() {
    }

    public static void main(String[] arguments) {
        try {
            Map<String, String> values = parse(arguments);
            PreparedEvidence prepared = new EvidencePackagePreparer().prepare(
                    new EvidencePreparationRequest(
                            Path.of(required(values, "--archive")),
                            Path.of(required(values, "--output")),
                            required(values, "--constat-id"),
                            required(values, "--created-at"),
                            required(values, "--captured-at"),
                            required(values, "--locale"),
                            required(values, "--channel")));
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("status", "prepared");
            result.put("directory", prepared.directory().toString());
            result.put("manifest", prepared.manifestPath().toString());
            result.put("constatId", prepared.manifest().constatId());
            result.put("channel", prepared.manifest().channel());
            result.put("artifactCount", prepared.manifest().artifacts().size());
            ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
            System.out.println(mapper.writeValueAsString(result));
        } catch (IllegalArgumentException exception) {
            System.err.println("error=invalid_arguments message=" + exception.getMessage());
            printUsage();
            System.exit(64);
        } catch (Exception exception) {
            System.err.println("error=preparation_failed type=" + exception.getClass().getSimpleName()
                    + " message=" + exception.getMessage());
            System.exit(1);
        }
    }

    private static Map<String, String> parse(String[] arguments) {
        if (arguments.length != 14) {
            throw new IllegalArgumentException("Seven option/value pairs are required.");
        }
        Map<String, String> values = new LinkedHashMap<>();
        for (int index = 0; index < arguments.length; index += 2) {
            String option = arguments[index];
            String value = arguments[index + 1];
            if (!option.startsWith("--") || value.isBlank() || values.putIfAbsent(option, value) != null) {
                throw new IllegalArgumentException("Invalid or duplicate option: " + option);
            }
        }
        for (String option : new String[] {
                "--archive", "--output", "--constat-id", "--created-at",
                "--captured-at", "--locale", "--channel"
        }) {
            required(values, option);
        }
        if (values.size() != 7) {
            throw new IllegalArgumentException("Unknown option supplied.");
        }
        return values;
    }

    private static String required(Map<String, String> values, String option) {
        String value = values.get(option);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing option: " + option);
        }
        return value;
    }

    private static void printUsage() {
        System.err.println("Usage: EvidencePackagePreparerMain"
                + " --archive REPORT.zip --output DIRECTORY --constat-id ID"
                + " --created-at OFFSET_DATE_TIME --captured-at OFFSET_DATE_TIME"
                + " --locale fr|en --channel automatic|operator-central|operator-external");
    }
}
