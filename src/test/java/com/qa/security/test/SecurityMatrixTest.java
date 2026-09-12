package com.qa.security.test;

import com.qa.security.matrix.SecurityMatrixProvider;
import com.qa.security.matrix.SecurityMatrixRow;
import org.testng.annotations.Test;

public class SecurityMatrixTest extends BaseSecurityTest {

    @Test(dataProvider = "securityMatrix", dataProviderClass = SecurityMatrixProvider.class)
    public void securityMatrix(SecurityMatrixRow row) {
        runRow(row);
    }
}