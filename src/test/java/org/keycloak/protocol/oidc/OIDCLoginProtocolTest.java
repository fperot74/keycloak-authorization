package org.keycloak.protocol.oidc;

import org.jboss.logging.Logger;
import org.junit.*;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;

import io.cloudtrust.keycloak.test.KeycloakTest;

import javax.ws.rs.ForbiddenException;
import java.io.IOException;

//TODO put back arquillian when classloader order is fixed
//@RunWith(Arquillian.class)
//@RunAsClient
public class OIDCLoginProtocolTest extends KeycloakTest {
    protected static final Logger logger = Logger.getLogger(OIDCLoginProtocolTest.class);

    private static final String CLIENT = "authorization";
    private static final String SECRET = "**********";
    private static final String TEST_REALM_NAME = "test-authorization";

    @BeforeClass
    public static void initRealmAndUsers() throws IOException {
        importRealm(TEST_REALM_NAME);
    }

    @AfterClass
    public static void resetRealm() {
        try {
            deleteRealm(TEST_REALM_NAME);
        } catch (IOException e) {
            logger.error("delete realm failed, catching excpetion to allow arquillian to undeploy correctly");
            e.printStackTrace();
        }
    }

//    @Deployment(name=MODULE_JAR, testable = false)
//    @TargetsContainer("keycloak-remote")
//    public static Archive<?> createProviderArchive() throws IOException {
//        JavaArchive archive = ShrinkWrap.create(JavaArchive.class, "keycloak-authorization.jar")
//                .addClasses(
//                        TokenEndpoint.class,
//                        OIDCLoginProtocolService.class,
//                        LocalAuthorizationService.class,
//                        OIDCLoginProtocol.class,
//                        OIDCLoginProtocolFactory.class
//                )
//                .addAsManifestResource(new File("src/test/resources", "MANIFEST.MF"))
//                .addAsServiceProvider(LoginProtocolFactory.class, OIDCLoginProtocolFactory.class);
//        return archive;
//    }

    @Ignore
    @Test
    public void user1CantLoginUsingTokenEndpointAccessToken() throws IOException {
        Keycloak keycloak = Keycloak.getInstance(KEYCLOAK_URL, TEST_REALM_NAME, "user1", "password", CLIENT, SECRET);
        String token = keycloak.tokenManager().getAccessTokenString();
        Assert.assertNotNull(token);
    }

    @Ignore
    @Test(expected = ForbiddenException.class)
    public void user2CantLoginUsingTokenEndpointAccessToken() throws IOException {
        Keycloak keycloak = Keycloak.getInstance(KEYCLOAK_URL, TEST_REALM_NAME, "user2", "password", CLIENT, SECRET);
        keycloak.tokenManager().getAccessTokenString();
    }

    @Ignore
    @Test
    public void user1CantLoginUsingTokenEndpointRefreshToken() throws IOException {
        Keycloak keycloak = Keycloak.getInstance(KEYCLOAK_URL, TEST_REALM_NAME, "user1", "password", CLIENT, SECRET);
        keycloak.tokenManager().getAccessToken();
        String token = keycloak.tokenManager().refreshToken().getToken();
        Assert.assertNotNull(token);
    }

    @Ignore
    @Test(expected = ForbiddenException.class)
    public void user2CantLoginUsingTokenEndpointRefreshToken() throws IOException {
        String clientSecret = null;
        Keycloak keycloakAdmin = Keycloak.getInstance(KEYCLOAK_URL, "master", "admin", "admin", "admin-cli", clientSecret);
        ClientRepresentation client = keycloakAdmin.realm(TEST_REALM_NAME).clients().findByClientId(CLIENT).get(0);
        ResourceServerRepresentation resourceServer = keycloakAdmin.realm(TEST_REALM_NAME).clients().get(client.getId()).authorization().getSettings();
        resourceServer.setPolicyEnforcementMode(PolicyEnforcementMode.DISABLED);
        keycloakAdmin.realm(TEST_REALM_NAME).clients().get(client.getId()).authorization().update(resourceServer);
        Keycloak keycloak = Keycloak.getInstance(KEYCLOAK_URL, TEST_REALM_NAME, "user2", "password", CLIENT, SECRET);
        keycloak.tokenManager().getAccessToken();
        resourceServer.setPolicyEnforcementMode(PolicyEnforcementMode.ENFORCING);
        keycloakAdmin.realm(TEST_REALM_NAME).clients().get(client.getId()).authorization().update(resourceServer);
        keycloak.tokenManager().refreshToken().getToken();
    }

//    @Test
//    public void user1CantLoginUsingTokenEndpointAuthorizationCode() throws IOException {
//        Keycloak keycloak = Keycloak.getInstance(TestsHelper.keycloakBaseUrl, TEST_REALM_NAME, "user1", "password", CLIENT, SECRET);
//        String token=keycloak.
//        Assert.assertNotNull(token);
//    }
//
//    @Test(expected = ForbiddenException.class)
//    public void user2CantLoginUsingTokenEndpointAuthorizationCode() throws IOException {
//        Keycloak keycloak = Keycloak.getInstance(TestsHelper.keycloakBaseUrl, TEST_REALM_NAME, "user2", "password", CLIENT, SECRET);
//        keycloak.tokenManager().getAccessTokenString();
//    }
}
