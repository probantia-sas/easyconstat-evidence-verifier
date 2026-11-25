package com.probantia.easyconstat.verify;

import java.util.Map;

final class HumanReportRenderer {
    private static final Map<String, String> FR_MESSAGES = Map.ofEntries(
            Map.entry("PACKAGE_VALID", "La structure, les empreintes, la signature, l'horodatage et la chaîne de confiance du paquet sont valides."),
            Map.entry("SIGNATURE_FORMAT_INVALID", "Le paquet ne contient pas une signature CAdES lisible et conforme."),
            Map.entry("SIGNATURE_COUNT_INVALID", "Le paquet doit contenir exactement une signature électronique avancée."),
            Map.entry("SIGNATURE_CRYPTOGRAPHICALLY_INVALID", "La signature électronique du paquet est cryptographiquement invalide."),
            Map.entry("SIGNATURE_TIMESTAMP_MISSING", "La signature ne contient pas l'horodatage requis."),
            Map.entry("SIGNATURE_LT_PROFILE_MISSING", "La signature ne contient pas les éléments de validation LT requis."),
            Map.entry("DSS_VALIDATION_ERROR", "La validation de la confiance et des informations de révocation n'a pas pu être menée à son terme."),
            Map.entry("SIGNATURE_NOT_RECOGNISED", "Aucune signature électronique avancée reconnue n'a été trouvée."),
            Map.entry("DSS_VALIDATION_FAILED", "La signature ou ses éléments de validation ont été rejetés."),
            Map.entry("TRUST_STATUS_INDETERMINATE", "L'intégrité est valide, mais le statut de confiance ne peut pas être établi avec certitude."),
            Map.entry("TRUST_SOURCE_MISSING", "L'intégrité est valide, mais aucune source de confiance approuvée n'est configurée."),
            Map.entry("TRUSTSTORE_MISSING", "Le magasin de confiance configuré est introuvable."),
            Map.entry("TRUSTSTORE_READ_FAILED", "Le magasin de confiance configuré ne peut pas être lu."),
            Map.entry("VERIFIER_INTERNAL_ERROR", "Le vérificateur n'a pas pu terminer tous les contrôles."),
            Map.entry("MANIFEST_INVALID", "Le manifeste de preuve est absent, incomplet ou invalide."),
            Map.entry("CONTAINER_MISSING", "Le paquet de preuve est introuvable."),
            Map.entry("CONTAINER_NOT_ZIP", "Le fichier fourni n'est pas un conteneur ASiC-E lisible."),
            Map.entry("CONTAINER_READ_FAILED", "Le paquet de preuve ne peut pas être lu."),
            Map.entry("CONTAINER_SIZE_INVALID", "La taille du paquet de preuve est invalide ou dépasse la limite autorisée."),
            Map.entry("CONTAINER_STAT_FAILED", "Les métadonnées du paquet de preuve ne peuvent pas être lues."),
            Map.entry("CONTAINER_EMPTY", "Le conteneur ASiC-E est vide."),
            Map.entry("TOO_MANY_ENTRIES", "Le conteneur contient trop d'éléments."),
            Map.entry("DUPLICATE_ENTRY", "Le conteneur contient un nom d'élément en double."),
            Map.entry("EXPANDED_SIZE_EXCEEDED", "La taille totale décompressée dépasse la limite autorisée."),
            Map.entry("DIRECTORY_NOT_ALLOWED", "Le conteneur contient un répertoire non autorisé."),
            Map.entry("ASIC_MANIFEST_COUNT_INVALID", "Le conteneur doit contenir exactement un manifeste ASiC."),
            Map.entry("METADATA_ENTRY_UNEXPECTED", "Le conteneur contient une métadonnée ASiC inattendue."),
            Map.entry("SIGNATURE_MISSING", "La signature CAdES du conteneur est absente."),
            Map.entry("ASIC_MANIFEST_MISSING", "Le manifeste ASiC est absent."),
            Map.entry("EVIDENCE_MANIFEST_MISSING", "Le manifeste EasyConstat est absent."),
            Map.entry("MIMETYPE_ENTRY_INVALID", "L'entrée mimetype ASiC-E est absente ou mal positionnée."),
            Map.entry("MIMETYPE_TOO_LARGE", "L'entrée mimetype ASiC-E dépasse la taille autorisée."),
            Map.entry("MIMETYPE_VALUE_INVALID", "La valeur mimetype du conteneur ASiC-E est invalide."),
            Map.entry("ENTRY_PATH_INVALID", "Le conteneur contient un chemin dangereux ou invalide."),
            Map.entry("PAYLOAD_PATH_INVALID", "Le nom d'une pièce probatoire est invalide."),
            Map.entry("ENTRY_SIZE_EXCEEDED", "Un élément du conteneur dépasse la taille autorisée."),
            Map.entry("METADATA_SIZE_EXCEEDED", "Une métadonnée ASiC-E dépasse la taille autorisée."),
            Map.entry("COMPRESSION_RATIO_EXCEEDED", "Le taux de compression d'un élément est anormalement élevé."),
            Map.entry("MANIFEST_TOO_LARGE", "Le manifeste EasyConstat dépasse la taille autorisée."),
            Map.entry("PAYLOAD_SET_MISMATCH", "La liste des pièces ne correspond pas au manifeste signé."),
            Map.entry("PAYLOAD_SIZE_MISMATCH", "La taille d'une pièce ne correspond pas au manifeste signé."),
            Map.entry("PAYLOAD_HASH_MISMATCH", "L'empreinte SHA-256 d'une pièce ne correspond pas au manifeste signé."),
            Map.entry("ENTRY_MISSING", "Un élément obligatoire du conteneur est absent."));

    private static final Map<String, String> EN_MESSAGES = Map.ofEntries(
            Map.entry("PACKAGE_VALID", "The package structure, hashes, signature, timestamp and trust chain are valid."),
            Map.entry("SIGNATURE_FORMAT_INVALID", "The package does not contain a readable, conforming CAdES signature."),
            Map.entry("SIGNATURE_COUNT_INVALID", "The package must contain exactly one advanced electronic signature."),
            Map.entry("SIGNATURE_CRYPTOGRAPHICALLY_INVALID", "The package electronic signature is cryptographically invalid."),
            Map.entry("SIGNATURE_TIMESTAMP_MISSING", "The signature does not contain the required timestamp."),
            Map.entry("SIGNATURE_LT_PROFILE_MISSING", "The signature does not contain the required LT validation material."),
            Map.entry("DSS_VALIDATION_ERROR", "Trust and revocation validation could not be completed."),
            Map.entry("SIGNATURE_NOT_RECOGNISED", "No recognised advanced electronic signature was found."),
            Map.entry("DSS_VALIDATION_FAILED", "The signature or its validation material was rejected."),
            Map.entry("TRUST_STATUS_INDETERMINATE", "Integrity is valid, but the trust status cannot be established conclusively."),
            Map.entry("TRUST_SOURCE_MISSING", "Integrity is valid, but no approved trust source is configured."),
            Map.entry("TRUSTSTORE_MISSING", "The configured trust store cannot be found."),
            Map.entry("TRUSTSTORE_READ_FAILED", "The configured trust store cannot be read."),
            Map.entry("VERIFIER_INTERNAL_ERROR", "The verifier could not complete all checks."),
            Map.entry("MANIFEST_INVALID", "The evidence manifest is missing, incomplete or invalid."),
            Map.entry("CONTAINER_MISSING", "The evidence package cannot be found."),
            Map.entry("CONTAINER_NOT_ZIP", "The supplied file is not a readable ASiC-E container."),
            Map.entry("CONTAINER_READ_FAILED", "The evidence package cannot be read."),
            Map.entry("CONTAINER_SIZE_INVALID", "The evidence package size is invalid or exceeds the allowed limit."),
            Map.entry("CONTAINER_STAT_FAILED", "The evidence package metadata cannot be read."),
            Map.entry("CONTAINER_EMPTY", "The ASiC-E container is empty."),
            Map.entry("TOO_MANY_ENTRIES", "The container contains too many entries."),
            Map.entry("DUPLICATE_ENTRY", "The container contains a duplicate entry name."),
            Map.entry("EXPANDED_SIZE_EXCEEDED", "The total expanded size exceeds the allowed limit."),
            Map.entry("DIRECTORY_NOT_ALLOWED", "The container contains a directory that is not allowed."),
            Map.entry("ASIC_MANIFEST_COUNT_INVALID", "The container must contain exactly one ASiC manifest."),
            Map.entry("METADATA_ENTRY_UNEXPECTED", "The container contains unexpected ASiC metadata."),
            Map.entry("SIGNATURE_MISSING", "The container CAdES signature is missing."),
            Map.entry("ASIC_MANIFEST_MISSING", "The ASiC manifest is missing."),
            Map.entry("EVIDENCE_MANIFEST_MISSING", "The EasyConstat manifest is missing."),
            Map.entry("MIMETYPE_ENTRY_INVALID", "The ASiC-E mimetype entry is missing or incorrectly positioned."),
            Map.entry("MIMETYPE_TOO_LARGE", "The ASiC-E mimetype entry exceeds the allowed size."),
            Map.entry("MIMETYPE_VALUE_INVALID", "The ASiC-E container mimetype value is invalid."),
            Map.entry("ENTRY_PATH_INVALID", "The container contains an unsafe or invalid path."),
            Map.entry("PAYLOAD_PATH_INVALID", "An evidence payload name is invalid."),
            Map.entry("ENTRY_SIZE_EXCEEDED", "A container entry exceeds the allowed size."),
            Map.entry("METADATA_SIZE_EXCEEDED", "An ASiC-E metadata entry exceeds the allowed size."),
            Map.entry("COMPRESSION_RATIO_EXCEEDED", "A container entry has an abnormally high compression ratio."),
            Map.entry("MANIFEST_TOO_LARGE", "The EasyConstat manifest exceeds the allowed size."),
            Map.entry("PAYLOAD_SET_MISMATCH", "The evidence payload set does not match the signed manifest."),
            Map.entry("PAYLOAD_SIZE_MISMATCH", "An evidence payload size does not match the signed manifest."),
            Map.entry("PAYLOAD_HASH_MISMATCH", "An evidence payload SHA-256 does not match the signed manifest."),
            Map.entry("ENTRY_MISSING", "A required container entry is missing."));

    String render(VerificationReport report, OutputLocale locale) {
        boolean french = locale == OutputLocale.FR;
        StringBuilder output = new StringBuilder();
        line(output, french ? "Vérificateur de preuves EasyConstat" : "EasyConstat Evidence Verifier",
                report.verifierVersion());
        line(output, french ? "Résultat" : "Result", status(report.status(), locale));
        line(output, french ? "Code technique" : "Technical code", report.code());
        line(output, french ? "Conclusion" : "Conclusion", message(report, locale));
        line(output, french ? "Fichier contrôlé" : "Verified file", report.packagePath());
        line(output, french ? "Contrôle effectué le" : "Verified at", report.verifiedAt());
        if (report.constatId() != null) {
            line(output, french ? "Identifiant du constat" : "Report ID", report.constatId());
            line(output, french ? "Canal" : "Channel", channel(report.channel(), locale));
            line(output, french ? "Langue du constat" : "Report language",
                    reportLocale(report.locale(), locale));
            line(output, french ? "Pièces contrôlées" : "Verified payloads",
                    report.payloadCount() + " (" + report.payloadBytes() + " "
                            + (french ? "octets" : "bytes") + ")");
        }
        line(output, french ? "Structure et empreintes" : "Structure and hashes",
                booleanValue(report.structureAndHashesValid(), locale));
        line(output, french ? "Signature cryptographique" : "Cryptographic signature",
                booleanValue(report.cryptographicSignatureValid(), locale));
        if (report.signatureLevel() != null) {
            line(output, french ? "Niveau de signature" : "Signature level", report.signatureLevel());
            line(output, french ? "Horodatages de signature" : "Signature timestamps",
                    String.valueOf(report.timestampCount()));
            line(output, french ? "Indication DSS" : "DSS indication", report.dssIndication());
            line(output, french ? "Sous-indication DSS" : "DSS sub-indication", report.dssSubIndication());
        }
        line(output, french ? "Source de confiance approuvée" : "Approved trust source",
                report.trustSourceConfigured() ? (french ? "Oui" : "Yes") : (french ? "Non" : "No"));
        output.append('\n');
        output.append(french
                ? "Portée : ce résultat contrôle l'intégrité et la validation cryptographique du paquet. "
                        + "Il ne se prononce pas, à lui seul, sur la véracité du contenu capturé."
                : "Scope: this result checks the package integrity and cryptographic validation. "
                        + "It does not, by itself, determine whether the captured content is factually true.");
        output.append('\n');
        return output.toString();
    }

    private static String message(VerificationReport report, OutputLocale locale) {
        Map<String, String> messages = locale == OutputLocale.FR ? FR_MESSAGES : EN_MESSAGES;
        String translated = messages.get(report.code());
        if (translated != null) {
            return translated;
        }
        return locale == OutputLocale.FR
                ? "Aucune conclusion localisée n'est disponible pour ce code technique."
                : report.message();
    }

    private static String status(VerificationStatus status, OutputLocale locale) {
        if (locale == OutputLocale.EN) {
            return status.name();
        }
        return switch (status) {
            case VALID -> "VALIDE";
            case INVALID -> "INVALIDE";
            case INDETERMINATE -> "INDÉTERMINÉ";
        };
    }

    private static String booleanValue(Boolean value, OutputLocale locale) {
        if (value == null) {
            return locale == OutputLocale.FR ? "Non contrôlé" : "Not checked";
        }
        if (value) {
            return locale == OutputLocale.FR ? "Valide" : "Valid";
        }
        return locale == OutputLocale.FR ? "Invalide" : "Invalid";
    }

    private static String channel(String channel, OutputLocale locale) {
        if (channel == null) {
            return locale == OutputLocale.FR ? "Non renseigné" : "Not specified";
        }
        return switch (channel) {
            case "automatic" -> locale == OutputLocale.FR ? "Automatique" : "Automatic";
            case "operator-central" -> locale == OutputLocale.FR
                    ? "Opérateur - nœud central"
                    : "Operator - central node";
            case "operator-external" -> locale == OutputLocale.FR
                    ? "Opérateur - nœud externe"
                    : "Operator - external node";
            default -> channel;
        };
    }

    private static String reportLocale(String reportLocale, OutputLocale locale) {
        if ("fr".equals(reportLocale)) {
            return locale == OutputLocale.FR ? "Français" : "French";
        }
        if ("en".equals(reportLocale)) {
            return locale == OutputLocale.FR ? "Anglais" : "English";
        }
        return reportLocale == null ? (locale == OutputLocale.FR ? "Non renseignée" : "Not specified") : reportLocale;
    }

    private static void line(StringBuilder output, String label, String value) {
        output.append(label).append(" : ").append(value == null ? "-" : value).append('\n');
    }
}
