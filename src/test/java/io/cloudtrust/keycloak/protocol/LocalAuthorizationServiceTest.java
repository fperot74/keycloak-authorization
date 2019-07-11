package io.cloudtrust.keycloak.protocol;

import io.cloudtrust.keycloak.test.MockHelper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import javax.ws.rs.core.Response;
import java.io.IOException;

import static org.junit.Assert.*;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.Silent.class)
public class LocalAuthorizationServiceTest {
    private MockHelper mh;

    @Before
    public void beforeEach() throws IOException {
        mh = new MockHelper();
        mh.initMocks();
    }

    @Test
    public void testIsAuthorizedNoResourceServer() {
        when(mh.getResourceServerStore().findById(any())).thenReturn(null);
        checkResponse(null);
    }

    @Test
    public void testIsAuthorizedUserNotOk() {
        mh.setPolicy(mh.getUserPolicy());
        checkResponse(Response.Status.FORBIDDEN);
    }

    @Test
    public void testIsAuthorizeUserOk() {
        //when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        mh.setPolicy(mh.getUserPolicy());
        checkResponse(null);
    }

    @Test
    public void testIsAuthorizeGroupOIDCNotOk() {
        mh.setPolicy(mh.getGroupPolicy());
        mh.enableOidcGroupMapper();
        checkResponse(Response.Status.FORBIDDEN);
    }

    @Test
    public void testIsAuthorizeGroupOIDCOk() {
        mh.setPolicy(mh.getGroupPolicy());
        mh.enableOidcGroupMapper();
        mh.setGroup();
        checkResponse(null);
    }

    @Test
    public void testIsAuthorizedErrorProcessingPolicies() {
        mh.setPolicy(mh.getUserPolicy());
        when(mh.getUserPolicy().getType()).thenReturn("js");
        checkResponse(Response.Status.INTERNAL_SERVER_ERROR);
    }

    private void checkResponse(Response.Status expectedStatus) {
        LocalAuthorizationService las = new LocalAuthorizationService(mh.getSession(), mh.getRealm());
        Response r = las.isAuthorizedResponse(mh.getClient(), mh.getUserSession(), mh.getClientSessionContext(), null);
        if (expectedStatus==null) {
            assertNull(r);
        } else {
            assertNotNull(r);
            assertEquals(expectedStatus.getStatusCode(), r.getStatus());
        }
    }
}
