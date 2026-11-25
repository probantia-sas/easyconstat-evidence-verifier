package com.probantia.easyconstat.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class HumanReportRendererTest {
    private final HumanReportRenderer renderer = new HumanReportRenderer();

    @Test
    void rendersACompleteFrenchReportWithoutEnglishLabels() {
        String output = renderer.render(validReport(), OutputLocale.FR);

        assertTrue(output.contains("Résultat : VALIDE"));
        assertTrue(output.contains("Conclusion : La structure, les empreintes"));
        assertTrue(output.contains("Canal : Opérateur - nœud externe"));
        assertTrue(output.contains("Langue du constat : Français"));
        assertTrue(output.contains("Source de confiance approuvée : Oui"));
        assertTrue(output.contains("Portée : ce résultat contrôle"));
        assertFalse(output.contains("Status:"));
        assertFalse(output.contains("Trust source"));
    }

    @Test
    void rendersACompleteEnglishReportWithoutFrenchLabels() {
        String output = renderer.render(validReport(), OutputLocale.EN);

        assertTrue(output.contains("Result : VALID"));
        assertTrue(output.contains("Conclusion : The package structure, hashes"));
        assertTrue(output.contains("Channel : Operator - external node"));
        assertTrue(output.contains("Report language : French"));
        assertTrue(output.contains("Approved trust source : Yes"));
        assertTrue(output.contains("Scope: this result checks"));
        assertFalse(output.contains("Résultat"));
        assertFalse(output.contains("Portée"));
    }

    @Test
    void rendersIndeterminateFrenchTrustResultUnambiguously() {
        VerificationReport report = new VerificationReport(
                "0.1.0", "2026-11-21T10:00:00Z", VerificationStatus.INDETERMINATE,
                "TRUST_SOURCE_MISSING", "English machine message", "proof.asice",
                "0042500TEST", "en", "automatic", 4, 1024L, true, true,
                "CAdES_BASELINE_LT", 1, "INDETERMINATE", "NO_CERTIFICATE_CHAIN_FOUND", false);

        String output = renderer.render(report, OutputLocale.FR);

        assertTrue(output.contains("Résultat : INDÉTERMINÉ"));
        assertTrue(output.contains("aucune source de confiance approuvée"));
        assertFalse(output.contains("English machine message"));
    }

    @Test
    void detectsRequestedOutputLanguage() {
        assertEquals(OutputLocale.FR, OutputLocale.detect(new String[] {"--lang", "fr", "proof.asice"}));
        assertEquals(OutputLocale.EN, OutputLocale.detect(new String[] {"--lang", "en", "proof.asice"}));
    }

    private static VerificationReport validReport() {
        return new VerificationReport(
                "0.1.0", "2026-11-21T10:00:00Z", VerificationStatus.VALID,
                "PACKAGE_VALID", "The package is valid.", "proof.asice",
                "990002EXT001", "fr", "operator-external", 6, 4096L, true, true,
                "CAdES_BASELINE_LT", 1, "TOTAL_PASSED", "NONE", true);
    }
}
