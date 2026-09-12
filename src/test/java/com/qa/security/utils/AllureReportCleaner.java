package com.qa.security.utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class AllureReportCleaner {

    private static final Path ALLURE_RESULTS =
            Path.of("allure-results");

    private AllureReportCleaner() {
    }

    public static void cleanResults() {

        if (!Files.exists(ALLURE_RESULTS)) {
            return;
        }

        try (var paths = Files.walk(ALLURE_RESULTS)) {

            paths
                    .sorted((a, b) -> b.compareTo(a))
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            throw new RuntimeException(
                                    "Failed to delete Allure result: " + path,
                                    e
                            );
                        }
                    });

        } catch (IOException e) {
            throw new RuntimeException(
                    "Failed to clean Allure results directory",
                    e
            );
        }
    }
}