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
}
