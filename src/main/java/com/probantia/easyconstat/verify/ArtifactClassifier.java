package com.probantia.easyconstat.verify;

import java.util.Locale;

final class ArtifactClassifier {
    private ArtifactClassifier() {
    }

    static Classification classify(String fileName, String constatId) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        String id = constatId.toLowerCase(Locale.ROOT);
        if (lower.equals("rapport_" + id + ".pdf")) {
            return new Classification("report", "application/pdf");
        }
        if (lower.equals("capture_" + id + ".jpg")
                || lower.equals("capture_" + id + ".jpeg")) {
            return new Classification("capture-image", "image/jpeg");
        }
        if (lower.equals("capture_" + id + ".png")) {
            return new Classification("capture-image", "image/png");
        }
        if (lower.equals("capture_" + id + ".pdf")
                || lower.equals("capture_" + id + ".formata4.pdf")) {
            return new Classification("capture-rendering", "application/pdf");
        }
        if (lower.equals("log_" + id + ".pdf")) {
            return new Classification("activity-log", "application/pdf");
        }
        if (lower.equals("har_" + id + ".pdf")) {
            return new Classification("network-report", "application/pdf");
        }
        if (lower.equals("source_" + id + ".txt")) {
            return new Classification("source", "text/plain");
        }
        if (lower.equals("video_" + id + ".mp4")) {
            return new Classification("navigation-video", "video/mp4");
        }
        if (lower.equals("video_" + id + ".webm")) {
            return new Classification("navigation-video", "video/webm");
        }
        if (lower.equals("document_" + id + ".pdf")) {
            return new Classification("target-document", "application/pdf");
        }
        if (lower.equals("document_" + id + ".http.json")) {
            return new Classification("http-metadata", "application/json");
        }
        return new Classification("other", mediaType(lower));
    }

    static boolean belongsToConstat(String fileName, String constatId) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        String id = constatId.toLowerCase(Locale.ROOT);
        return lower.contains("_" + id + ".");
    }

    private static String mediaType(String lower) {
        if (lower.endsWith(".pdf")) {
            return "application/pdf";
        }
        if (lower.endsWith(".json")) {
            return "application/json";
        }
        if (lower.endsWith(".txt") || lower.endsWith(".log")) {
            return "text/plain";
        }
        if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) {
            return "image/jpeg";
        }
        if (lower.endsWith(".png")) {
            return "image/png";
        }
        if (lower.endsWith(".mp4")) {
            return "video/mp4";
        }
        if (lower.endsWith(".webm")) {
            return "video/webm";
        }
        return "application/octet-stream";
    }

    record Classification(String role, String mediaType) {
    }
}
