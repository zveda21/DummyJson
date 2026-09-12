package com.qa.security.matrix;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;
import org.testng.annotations.DataProvider;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * Loads the security matrix from an external JSON resource and exposes it as a
 * TestNG @DataProvider, so new cases can be added by editing data, not test code.
 *
 * File lives at: src/test/resources/matrix/security-matrix.json
 */
public final class SecurityMatrixProvider {

    private static final String DEFAULT_MATRIX_PATH = "/matrix/security-matrix.json";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SecurityMatrixProvider() {
    }

    /**
     * TestNG data provider. Reference from a test method with:
     *   @Test(dataProvider = "securityMatrix", dataProviderClass = SecurityMatrixProvider.class)
     */
    @DataProvider(name = "securityMatrix")
    public static Object[][] rows() {
        return toDataProviderFormat(load(DEFAULT_MATRIX_PATH));
    }

    static List<SecurityMatrixRow> load(String classpathResource) {
        try (InputStream is = SecurityMatrixProvider.class.getResourceAsStream(classpathResource)) {
            if (is == null) {
                throw new IllegalStateException("Matrix file not found on classpath: " + classpathResource);
            }
            return MAPPER.readValue(is, new TypeReference<List<SecurityMatrixRow>>() {
            });
        } catch (IOException e) {
            throw new IllegalStateException("Failed to parse security matrix: " + classpathResource, e);
        }
    }

    /** TestNG data providers must return Object[][] - one row = one Object[] with one element. */
    private static Object[][] toDataProviderFormat(List<SecurityMatrixRow> matrixRows) {
        Object[][] data = new Object[matrixRows.size()][1];
        for (int i = 0; i < matrixRows.size(); i++) {
            data[i][0] = matrixRows.get(i);
        }
        return data;
    }
}