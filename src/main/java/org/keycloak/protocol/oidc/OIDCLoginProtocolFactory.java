/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.protocol.oidc;

import org.jboss.logging.Logger;
import org.keycloak.common.constants.KerberosConstants;
import org.keycloak.common.util.UriUtils;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.AbstractLoginProtocolFactory;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.services.ServicesLogger;

import java.util.*;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class OIDCLoginProtocolFactory extends AbstractLoginProtocolFactory {
    private static final Logger logger = Logger.getLogger(OIDCLoginProtocolFactory.class);

    public static final String USERNAME = "username";
    public static final String EMAIL = "email";
    public static final String EMAIL_VERIFIED = "email verified";
    public static final String GIVEN_NAME = "given name";
    public static final String FAMILY_NAME = "family name";
    public static final String FULL_NAME = "full name";
    public static final String LOCALE = "locale";
    public static final String USERNAME_CONSENT_TEXT = "${username}";
    public static final String EMAIL_CONSENT_TEXT = "${email}";
    public static final String EMAIL_VERIFIED_CONSENT_TEXT = "${emailVerified}";
    public static final String GIVEN_NAME_CONSENT_TEXT = "${givenName}";
    public static final String FAMILY_NAME_CONSENT_TEXT = "${familyName}";
    public static final String FULL_NAME_CONSENT_TEXT = "${fullName}";
    public static final String LOCALE_CONSENT_TEXT = "${locale}";

    private static final String T_STRING = "String";
    private static final String T_BOOL = "boolean";

    @Override
    public LoginProtocol create(KeycloakSession session) {
        return new OIDCLoginProtocol().setSession(session);
    }

    @Override
    public Map<String, ProtocolMapperModel> getBuiltinMappers() {
        return null;
    }

    @Override
    protected void createDefaultClientScopesImpl(RealmModel newRealm) {
        // no-op
    }

    static Map<String, ProtocolMapperModel> builtins = new HashMap<>();

    static {
        ProtocolMapperModel fullName = new ProtocolMapperModel();
        fullName.setName(FULL_NAME);
        fullName.setProtocolMapper(FullNameMapper.PROVIDER_ID);
        fullName.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        //fullName.setConsentRequired(true);
        //fullName.setConsentText(FULL_NAME_CONSENT_TEXT);
        Map<String, String> config = new HashMap<>();
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        fullName.setConfig(config);

        Arrays.asList(
                UserPropertyMapper.createClaimMapper(USERNAME, USERNAME, "preferred_username", T_STRING, true, true),
                UserPropertyMapper.createClaimMapper(EMAIL, EMAIL, EMAIL, T_STRING, true, true),
                UserPropertyMapper.createClaimMapper(GIVEN_NAME, "firstName", "given_name", T_STRING, true, true),
                UserPropertyMapper.createClaimMapper(FAMILY_NAME, "lastName", "family_name", T_STRING, true, true),
                UserPropertyMapper.createClaimMapper(EMAIL_VERIFIED, "emailVerified", "email_verified", T_BOOL, true, true),
                UserAttributeMapper.createClaimMapper(LOCALE, LOCALE, LOCALE, T_STRING, true, true, false),
                fullName,
                AddressMapper.createAddressMapper(),
                UserSessionNoteMapper.createClaimMapper(KerberosConstants.GSS_DELEGATION_CREDENTIAL_DISPLAY_NAME, KerberosConstants.GSS_DELEGATION_CREDENTIAL,
                        KerberosConstants.GSS_DELEGATION_CREDENTIAL, T_STRING, true, false)
        ).forEach(m -> builtins.put(m.getName(), m));
    }

    @Override
    protected void addDefaults(ClientModel client) {
        // for (ProtocolMapperModel model : defaultBuiltins) client.addProtocolMapper(model);
        //!!! IMPORTANT: here we don't add the defaultBuiltins as this is handled by the default OIDCLoginProtocolFactory which is also instanciated but not used as the factory
    }

    @Override
    public Object createProtocolEndpoint(RealmModel realm, EventBuilder event) {
        return new OIDCLoginProtocolService(realm, event);
    }

    @Override
    public String getId() {
        return OIDCLoginProtocol.LOGIN_PROTOCOL;
    }

    @Override
    public void setupClientDefaults(ClientRepresentation rep, ClientModel newClient) {
        if (rep.getRootUrl() != null && (rep.getRedirectUris() == null || rep.getRedirectUris().isEmpty())) {
            String root = rep.getRootUrl();
            root += root.endsWith("/") ? "*" : "/*";
            newClient.addRedirectUri(root);

            Set<String> origins = new HashSet<>();
            String origin = UriUtils.getOrigin(root);
            logger.debugv("adding default client origin: {0}", origin);
            origins.add(origin);
            newClient.setWebOrigins(origins);
        }
        if (rep.isBearerOnly() == null && rep.isPublicClient() == null) {
            newClient.setPublicClient(true);
        }
        if (rep.isBearerOnly() == null) newClient.setBearerOnly(false);
        if (rep.getAdminUrl() == null && rep.getRootUrl() != null) {
            newClient.setManagementUrl(rep.getRootUrl());
        }


        // Backwards compatibility only
        if (rep.isDirectGrantsOnly() != null) {
            ServicesLogger.LOGGER.usingDeprecatedDirectGrantsOnly();
            newClient.setStandardFlowEnabled(!rep.isDirectGrantsOnly());
            newClient.setDirectAccessGrantsEnabled(rep.isDirectGrantsOnly());
        } else {
            if (rep.isStandardFlowEnabled() == null) newClient.setStandardFlowEnabled(true);
            if (rep.isDirectAccessGrantsEnabled() == null) newClient.setDirectAccessGrantsEnabled(true);
        }

        if (rep.isImplicitFlowEnabled() == null) newClient.setImplicitFlowEnabled(false);
        if (rep.isPublicClient() == null) newClient.setPublicClient(true);
        if (rep.isFrontchannelLogout() == null) newClient.setFrontchannelLogout(false);
    }
}
