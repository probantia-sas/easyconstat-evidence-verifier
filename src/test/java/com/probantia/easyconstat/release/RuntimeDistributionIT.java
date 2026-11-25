package com.probantia.easyconstat.release;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.regex.Pattern;
import java.util.stream.StreamSupport;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RuntimeDistributionIT {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Pattern NOTICE = Pattern.compile(
            "(?:META-INF/)?(?:LICENSE|LICENCE|NOTICE|COPYING|COPYRIGHT)[^/]*");
    private static final String MAIN = "com.probantia.easyconstat.verify.VerifierMain";
    private static final String DSS_LICENSE_SHA256 =
            "dc626520dcd53a22f727af3ee42c770e56c97a64fe3adb063799d8ab032fe551";

    @TempDir
    Path temporary;

    @Test
    void shipsOriginalLibrariesAndNoticesAndRunsFromTheExtractedZip() throws Exception {
        Path build = Path.of(System.getProperty("easyconstat.build.directory"));
        String name = System.getProperty("easyconstat.build.finalName");
        var components = JSON.readTree(build.resolve(name + "-sbom.json").toFile()).path("components");
        assertTrue(components.isArray() && !components.isEmpty());

        Path runtime = temporary.resolve("extracted release");
        Files.createDirectory(runtime);
        Set<String> expected = new HashSet<>(Set.of(
                "verifier.jar", "README.md", "LICENSE", "NOTICE", "THIRD_PARTY_INVENTORY.md",
                "licenses/DSS-LICENSE.txt"));
        Set<String> classpath = new HashSet<>();
        try (var zip = new ZipFile(build.resolve(name + "-runtime.zip").toFile())) {
            extract(zip, name, "verifier.jar", runtime);
            assertEquals(DSS_LICENSE_SHA256, entryHash(zip, name + "/licenses/DSS-LICENSE.txt"));
            for (var component : components) {
                String artifact = component.path("name").asText() + "-" + component.path("version").asText();
                String jar = "lib/" + artifact + ".jar";
                assertTrue(classpath.add(jar), "Library name collision: " + jar);
                expected.add(jar);
                Path file = extract(zip, name, jar, runtime);
                var sha = StreamSupport.stream(component.path("hashes").spliterator(), false)
                        .filter(hash -> "SHA-256".equals(hash.path("alg").asText()))
                        .findFirst().orElseThrow().path("content").asText();
                assertEquals(sha, sha256(Files.newInputStream(file)), jar);

                try (var library = new JarFile(file.toFile())) {
                    for (var entry : library.stream().filter(e -> !e.isDirectory()
                            && NOTICE.matcher(e.getName()).matches()).toList()) {
                        String notice = "licenses/" + artifact + "-jar/" + entry.getName();
                        expected.add(notice);
                        assertEquals(sha256(library.getInputStream(entry)), entryHash(zip, name + "/" + notice), notice);
                    }
                }
            }

            var packaged = zip.stream().filter(entry -> !entry.isDirectory()).map(entry -> entry.getName()).toList();
            assertEquals(expected.size(), packaged.size(), "Extra or duplicate runtime ZIP entries");
            assertEquals(expected, new HashSet<>(packaged.stream().map(entry -> {
                assertTrue(entry.startsWith(name + "/"), entry);
                return entry.substring(name.length() + 1);
            }).toList()));
        }

        try (var core = new JarFile(runtime.resolve("verifier.jar").toFile())) {
            var attributes = core.getManifest().getMainAttributes();
            assertEquals(MAIN, attributes.getValue(Attributes.Name.MAIN_CLASS));
            assertEquals(classpath, Set.of(attributes.getValue(Attributes.Name.CLASS_PATH).split(" +")));
            assertFalse(core.stream().anyMatch(e -> e.getName().startsWith("eu/europa/esig/dss/")),
                    "The verifier must not contain shaded DSS code");
        }

        Path fixtures = build.resolve("test-classes/qualification").toAbsolutePath();
        Path result = temporary.resolve("runtime.log");
        assertEquals(0, run(runtime, fixtures, result), Files.readString(result));
        assertEquals("VALID", JSON.readTree(Files.readString(result)).path("status").asText());

        String modelJar = classpath.stream().filter(path -> path.startsWith("lib/dss-model-"))
                .findFirst().orElseThrow();
        Path installed = runtime.resolve(modelJar);
        Path replacement = Files.move(installed, temporary.resolve("dss-model.jar"));
        assertNotEquals(0, run(runtime, fixtures, result), "DSS must be loaded from lib/");
        Files.copy(replacement, installed);
        assertEquals(0, run(runtime, fixtures, result), Files.readString(result));
        assertEquals("VALID", JSON.readTree(Files.readString(result)).path("status").asText());
    }

    private int run(Path runtime, Path fixtures, Path result) throws Exception {
        Path javaBin = Path.of(System.getProperty("java.home"), "bin");
        Path java = javaBin.resolve(Files.exists(javaBin.resolve("java.exe")) ? "java.exe" : "java");
        var builder = new ProcessBuilder(java.toString(), "-jar", runtime.resolve("verifier.jar").toString(),
                "--json", "--truststore", fixtures.resolve("easyconstat-synthetic-trust.jks").toString(),
                fixtures.resolve("easyconstat-synthetic-valid.asice").toString());
        builder.environment().put("EASYCONSTAT_TRUSTSTORE_PASSWORD", "fixture-only");
        builder.directory(temporary.toFile());
        builder.redirectOutput(result.toFile());
        builder.redirectError(temporary.resolve("runtime.stderr").toFile());
        Process process = builder.start();
        if (!process.waitFor(30, TimeUnit.SECONDS)) {
            process.destroyForcibly().waitFor();
            throw new IllegalStateException("Runtime verifier did not exit");
        }
        return process.exitValue();
    }

    private static Path extract(ZipFile zip, String name, String file, Path runtime) throws Exception {
        Path output = runtime.resolve(file).normalize();
        assertTrue(output.startsWith(runtime), file);
        Files.createDirectories(output.getParent());
        var entry = zip.getEntry(name + "/" + file);
        assertNotNull(entry, file);
        try (var input = zip.getInputStream(entry)) {
            Files.copy(input, output);
        }
        return output;
    }

    private static String entryHash(ZipFile zip, String path) throws Exception {
        var entry = zip.getEntry(path);
        assertNotNull(entry, path);
        return sha256(zip.getInputStream(entry));
    }

    private static String sha256(InputStream stream) throws Exception {
        try (var input = new DigestInputStream(stream, MessageDigest.getInstance("SHA-256"))) {
            input.transferTo(OutputStream.nullOutputStream());
            return HexFormat.of().formatHex(input.getMessageDigest().digest());
        }
    }
}
