package com.qa.security.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public final class ConfigManager {

    private static final Properties PROPERTIES = new Properties();

    static {
        loadProperties();
    }

    private ConfigManager() {
    }

    private static void loadProperties() {
        try (InputStream inputStream =
                     ConfigManager.class
                             .getClassLoader()
                             .getResourceAsStream("config.properties")) {

            if (inputStream == null) {
                throw new IllegalStateException(
                        "config.properties was not found");
            }

            PROPERTIES.load(inputStream);

        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to load configuration", e);
        }
    }

    public static String getBaseUrl() {
        return PROPERTIES.getProperty("base.url");
    }

    /**
     * Connection timeout in milliseconds. Defaults to 5000ms if not
     * configured, so the suite still fails fast even if the property
     * is accidentally omitted.
     */
    public static int getConnectTimeoutMs() {
        return getIntProperty("http.connect.timeout.ms", 5000);
    }

    /**
     * Socket/read timeout in milliseconds. Must comfortably exceed the
     * documented `delay` query param range DummyJSON exposes (0-5000ms)
     * or resilience tests exercising it will fail for the wrong reason.
     */
    public static int getReadTimeoutMs() {
        return getIntProperty("http.read.timeout.ms", 10000);
    }

    private static int getIntProperty(String key, int defaultValue) {
        String raw = PROPERTIES.getProperty(key);

        if (raw == null || raw.isBlank()) {
            return defaultValue;
        }

        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException(
                    "Configuration property '%s' is not a valid integer: %s"
                            .formatted(key, raw)
            );
        }
    }
}
