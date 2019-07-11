package com.quest.keycloak.protocol.wsfed;

import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.LoginProtocol;

import com.quest.keycloak.protocol.wsfed.AbstractWSFedLoginProtocolFactory;

import io.cloudtrust.keycloak.protocol.wsfed.WSFedLoginProtocol;

public class WSFedLoginProtocolFactory extends AbstractWSFedLoginProtocolFactory {
    @Override
    public LoginProtocol create(KeycloakSession session) {
        return new WSFedLoginProtocol().setSession(session);
    }

    @Override
    protected void addDefaults(ClientModel client) {
        //!!! IMPORTANT: here we don't add the defaultBuiltins as this is handled by the default OIDCLoginProtocolFactory which is also instantiated but not used as the factory
    }
}
