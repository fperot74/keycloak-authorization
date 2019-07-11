package org.keycloak.protocol.docker;

import io.cloudtrust.keycloak.test.MockHelper;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

public class DockerAuthV2ProtocolTest {
    private MockHelper mh = new MockHelper();

    @Mock
    ClientConnection clientConnection;

    DockerAuthV2Protocol protocol;

    @Before
    public void init() throws IOException {
        MockitoAnnotations.initMocks(this);
        mh.initMocks();
        when(clientConnection.getRemoteAddr()).thenReturn("127.0.0.1");
        protocol = new DockerAuthV2Protocol();
        protocol.setSession(mh.getSession());
        protocol.setRealm(mh.getRealm());
        protocol.setUriInfo(mh.getUriInfo());
        protocol.setEventBuilder((new EventBuilder(mh.getRealm(), mh.getSession(), clientConnection)).event(EventType.LOGIN));
    }

    @Test
    public void testAuthenticatedNotAuthorized() {
        mh.setPolicy(mh.getUserPolicy());
        Response r = protocol.authenticated(mh.getAuthenticationSession(), mh.getUserSession(), mh.getClientSessionContext());
        assertNotNull(r);
        assertEquals(Response.Status.FORBIDDEN.getStatusCode(), r.getStatus());
    }

    @Test
    public void testAuthenticatedAuthorized() {
        mh.setPolicy(mh.getUserPolicy());
        when(mh.getUser().getId()).thenReturn(UUID.randomUUID().toString());
        Response r = protocol.authenticated(mh.getAuthenticationSession(), mh.getUserSession(), mh.getClientSessionContext());
        assertNotNull(r);
        assertEquals(Response.Status.OK.getStatusCode(), r.getStatus());
    }
}
