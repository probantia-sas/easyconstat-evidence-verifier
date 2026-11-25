package com.probantia.easyconstat.verify;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

final class ManifestParser {
    private final ObjectMapper mapper = new ObjectMapper()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION.mappedFeature())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
            .enable(DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES);

    EvidenceManifest parse(byte[] json) throws VerificationException {
        try {
            EvidenceManifest manifest = mapper.readValue(json, EvidenceManifest.class);
            ManifestValidator.validate(manifest);
            return manifest;
        } catch (IOException | IllegalArgumentException exception) {
            throw VerificationException.invalid(
                    "MANIFEST_INVALID",
                    "The evidence manifest is not valid: " + exception.getMessage(),
                    exception);
        }
    }
}
