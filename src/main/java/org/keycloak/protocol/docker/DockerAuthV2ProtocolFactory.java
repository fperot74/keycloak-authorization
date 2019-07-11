package org.keycloak.protocol.docker;

import org.keycloak.common.Profile;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.AbstractLoginProtocolFactory;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.docker.mapper.AllowAllDockerProtocolMapper;
import org.keycloak.provider.EnvironmentDependentProviderFactory;
import org.keycloak.representations.idm.ClientRepresentation;

import java.util.HashMap;
import java.util.Collections;
import java.util.Map;

public class DockerAuthV2ProtocolFactory extends AbstractLoginProtocolFactory implements EnvironmentDependentProviderFactory {
    private static Map<String, ProtocolMapperModel> builtins = new HashMap<>();

    static {
        final ProtocolMapperModel addAllRequestedScopeMapper = new ProtocolMapperModel();
        addAllRequestedScopeMapper.setName(AllowAllDockerProtocolMapper.PROVIDER_ID);
        addAllRequestedScopeMapper.setProtocolMapper(AllowAllDockerProtocolMapper.PROVIDER_ID);
        addAllRequestedScopeMapper.setProtocol(DockerAuthV2Protocol.LOGIN_PROTOCOL);
        //addAllRequestedScopeMapper.setConsentRequired(false);
        addAllRequestedScopeMapper.setConfig(Collections.emptyMap());
        builtins.put(addAllRequestedScopeMapper.getName(), addAllRequestedScopeMapper);
    }

    @Override
    protected void addDefaults(ClientModel client) {
//        for (ProtocolMapperModel model : defaultBuiltins) client.addProtocolMapper(model);
        //!!! IMPORTANT: here we don't add the defaultBuiltins as this is handled by the default OIDCLoginProtocolFactory which is also instanciated but not used as the factory
    }

    @Override
    protected void createDefaultClientScopesImpl(RealmModel newRealm) {
    }

    @Override
    public Map<String, ProtocolMapperModel> getBuiltinMappers() {
        return builtins;
    }

    @Override
    public Object createProtocolEndpoint(final RealmModel realm, final EventBuilder event) {
        return new DockerV2LoginProtocolService(realm, event);
    }

    @Override
    public void setupClientDefaults(final ClientRepresentation rep, final ClientModel newClient) {
        // no-op
    }

    @Override
    public LoginProtocol create(final KeycloakSession session) {
        return new DockerAuthV2Protocol().setSession(session);
    }

    @Override
    public String getId() {
        return DockerAuthV2Protocol.LOGIN_PROTOCOL;
    }

    @Override
    public boolean isSupported() {
        return Profile.isFeatureEnabled(Profile.Feature.DOCKER);
    }

    @Override
    public int order() {
        return -100;
    }
}
