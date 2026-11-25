package com.probantia.easyconstat.release;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class ReleaseManifestMain {
    private ReleaseManifestMain() {
    }

    public static void main(String[] args) {
        try {
            Arguments arguments = Arguments.parse(args);
            ReleaseManifest manifest = new ReleaseManifestWriter().write(
                    arguments.baseDirectory(),
                    arguments.output(),
                    arguments.version(),
                    arguments.buildTimestamp(),
                    arguments.signingKeySha256(),
                    arguments.artifacts());
            System.out.println("release_manifest=" + arguments.output().toAbsolutePath().normalize());
            System.out.println("release_artifacts=" + manifest.artifacts().size());
        } catch (Exception exception) {
            System.err.println("error=" + exception.getMessage());
            System.exit(1);
        }
    }

    private record Arguments(
            Path baseDirectory,
            Path output,
            String version,
            String buildTimestamp,
            String signingKeySha256,
            List<ReleaseManifestWriter.ArtifactInput> artifacts) {
        static Arguments parse(String[] args) {
            Path baseDirectory = null;
            Path output = null;
            String version = null;
            String buildTimestamp = null;
            String signingKeySha256 = null;
            List<ReleaseManifestWriter.ArtifactInput> artifacts = new ArrayList<>();
            for (int index = 0; index < args.length; index++) {
                String option = args[index];
                if (index + 1 >= args.length) {
                    throw new IllegalArgumentException("Missing value for " + option + ".");
                }
                String value = args[++index];
                switch (option) {
                    case "--base-dir" -> baseDirectory = Path.of(value);
                    case "--output" -> output = Path.of(value);
                    case "--version" -> version = value;
                    case "--build-timestamp" -> buildTimestamp = value;
                    case "--signing-key-sha256" -> signingKeySha256 = value;
                    case "--artifact" -> artifacts.add(parseArtifact(value));
                    default -> throw new IllegalArgumentException("Unknown option: " + option + ".");
                }
            }
            if (baseDirectory == null || output == null || version == null
                    || buildTimestamp == null || signingKeySha256 == null || artifacts.isEmpty()) {
                throw new IllegalArgumentException(
                        "Required options: --base-dir, --output, --version, --build-timestamp, "
                                + "--signing-key-sha256 and one or more --artifact ROLE=PATH.");
            }
            return new Arguments(
                    baseDirectory,
                    output,
                    version,
                    buildTimestamp,
                    signingKeySha256,
                    List.copyOf(artifacts));
        }

        private static ReleaseManifestWriter.ArtifactInput parseArtifact(String value) {
            int separator = value.indexOf('=');
            if (separator <= 0 || separator == value.length() - 1) {
                throw new IllegalArgumentException("Invalid --artifact value: " + value + ".");
            }
            return new ReleaseManifestWriter.ArtifactInput(
                    value.substring(0, separator),
                    value.substring(separator + 1));
        }
    }
}
