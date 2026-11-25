package com.probantia.easyconstat.verify;

import java.util.Locale;

enum OutputLocale {
    FR("fr"),
    EN("en");

    private final String code;

    OutputLocale(String code) {
        this.code = code;
    }

    String code() {
        return code;
    }

    static OutputLocale systemDefault() {
        return "fr".equalsIgnoreCase(Locale.getDefault().getLanguage()) ? FR : EN;
    }

    static OutputLocale parse(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Output language is missing.");
        }
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "fr" -> FR;
            case "en" -> EN;
            default -> throw new IllegalArgumentException(
                    "Unsupported output language: " + value + ". Expected fr or en.");
        };
    }

    static OutputLocale detect(String[] arguments) {
        for (int index = 0; index + 1 < arguments.length; index++) {
            if ("--lang".equals(arguments[index])) {
                try {
                    return parse(arguments[index + 1]);
                } catch (IllegalArgumentException ignored) {
                    return systemDefault();
                }
            }
        }
        return systemDefault();
    }
}
