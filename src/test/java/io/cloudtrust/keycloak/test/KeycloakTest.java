package io.cloudtrust.keycloak.test;

import java.io.IOException;

import org.keycloak.test.TestsHelper;

public class KeycloakTest {
    protected static final String KEYCLOAK_URL = TestsHelper.keycloakBaseUrl;

    static {
        TestsHelper.baseUrl = KEYCLOAK_URL;
    }

    public static void importRealm(final String realmName) throws IOException {
        TestsHelper.importTestRealm("admin", "admin", "/" + realmName + "-realm.json");
    }

    public static void deleteRealm(final String realmName) throws IOException {
        TestsHelper.deleteRealm("admin", "admin", realmName);
    }
}
