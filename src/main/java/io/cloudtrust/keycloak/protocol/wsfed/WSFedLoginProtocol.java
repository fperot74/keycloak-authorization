package io.cloudtrust.keycloak.protocol.wsfed;

import com.quest.keycloak.protocol.wsfed.WSFedLoginContext;
import io.cloudtrust.keycloak.protocol.LocalAuthorizationService;

import org.jboss.logging.Logger;

import javax.ws.rs.core.Response;
import java.security.GeneralSecurityException;

public class WSFedLoginProtocol extends com.quest.keycloak.protocol.wsfed.WSFedLoginProtocol {
    protected static final Logger logger = Logger.getLogger(WSFedLoginProtocol.class);

    @Override
    protected Response evaluateAuthenticatedResponse(WSFedLoginContext ctx) throws GeneralSecurityException {
        // Check for authorization
        LocalAuthorizationService authorize = new LocalAuthorizationService(this.getKeycloakSession(), this.getRealm());
        Response authResponse = authorize.isAuthorizedResponse(ctx.getClient(), ctx.getUserSession(), ctx.getClientSessionContext(), ctx.getSamlAssertion());
        if (authResponse != null) {
            return authResponse;
        }

        return super.evaluateAuthenticatedResponse(ctx);
    }
}
