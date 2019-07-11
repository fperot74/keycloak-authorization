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

package org.keycloak.protocol.saml;

import org.keycloak.Config;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.AbstractLoginProtocolFactory;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.saml.mappers.AttributeStatementHelper;
import org.keycloak.protocol.saml.mappers.RoleListMapper;
import org.keycloak.protocol.saml.mappers.UserPropertyAttributeStatementMapper;
import org.keycloak.representations.idm.CertificateRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.saml.SignatureAlgorithm;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.processing.core.saml.v2.constants.X500SAMLProfileConstants;
import org.keycloak.saml.validators.DestinationValidator;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class SamlProtocolFactory extends AbstractLoginProtocolFactory {
    private DestinationValidator destValidator;

    @Override
    public Object createProtocolEndpoint(RealmModel realm, EventBuilder event) {
        return new SamlService(realm, event, destValidator);
    }

    @Override
    public LoginProtocol create(KeycloakSession session) {
        return new SamlProtocol().setSession(session);
    }

    @Override
    public void init(Config.Scope config) {
        //PicketLinkCoreSTS sts = PicketLinkCoreSTS.instance();
        //sts.installDefaultConfiguration();

        this.destValidator = DestinationValidator.forProtocolMap(config.getArray("knownProtocols"));
    }

    @Override
    public String getId() {
        return SamlProtocol.LOGIN_PROTOCOL;
    }

    @Override
    public Map<String, ProtocolMapperModel> getBuiltinMappers() {
        return builtins;
    }

    static Map<String, ProtocolMapperModel> builtins = new HashMap<>();

    static {
        Arrays.asList(
                UserPropertyAttributeStatementMapper.createAttributeMapper("X500 email", "email", X500SAMLProfileConstants.EMAIL.get(),
                        JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.get(), X500SAMLProfileConstants.EMAIL.getFriendlyName(), true, "${email}"),
                UserPropertyAttributeStatementMapper.createAttributeMapper("X500 givenName", "firstName", X500SAMLProfileConstants.GIVEN_NAME.get(),
                        JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.get(), X500SAMLProfileConstants.GIVEN_NAME.getFriendlyName(), true, "${givenName}"),
                UserPropertyAttributeStatementMapper.createAttributeMapper("X500 surname", "lastName", X500SAMLProfileConstants.SURNAME.get(),
                        JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.get(), X500SAMLProfileConstants.SURNAME.getFriendlyName(), true, "${familyName}"),
                RoleListMapper.create("role list", "Role", AttributeStatementHelper.BASIC, null, false)
        ).forEach(m -> builtins.put(m.getName(), m));
    }

    @Override
    protected void createDefaultClientScopesImpl(RealmModel newRealm) {
        // no-op
    }

    @Override
    protected void addDefaults(ClientModel client) {
        // for (ProtocolMapperModel model : defaultBuiltins) client.addProtocolMapper(model);
        //!!! IMPORTANT: here we don't add the defaultBuiltins as this is handled by the default OIDCLoginProtocolFactory which is also instanciated but not used as the factory
    }

    @Override
    public void setupClientDefaults(ClientRepresentation clientRep, ClientModel newClient) {
        SamlRepresentationAttributes rep = new SamlRepresentationAttributes(clientRep.getAttributes());
        SamlClient client = new SamlClient(newClient);
        if (clientRep.isStandardFlowEnabled() == null) newClient.setStandardFlowEnabled(true);
        if (rep.getCanonicalizationMethod() == null) {
            client.setCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE);
        }
        if (rep.getSignatureAlgorithm() == null) {
            client.setSignatureAlgorithm(SignatureAlgorithm.RSA_SHA256);
        }

        if (rep.getNameIDFormat() == null) {
            client.setNameIDFormat("username");
        }

        if (rep.getIncludeAuthnStatement() == null) {
            client.setIncludeAuthnStatement(true);
        }

        if (rep.getForceNameIDFormat() == null) {
            client.setForceNameIDFormat(false);
        }

        if (rep.getSamlServerSignature() == null) {
            client.setRequiresRealmSignature(true);
        }
        if (rep.getForcePostBinding() == null) {
            client.setForcePostBinding(true);
        }

        if (rep.getClientSignature() == null) {
            client.setRequiresClientSignature(true);
        }

        if (client.requiresClientSignature() && client.getClientSigningCertificate() == null) {
            CertificateRepresentation info = KeycloakModelUtils.generateKeyPairCertificate(newClient.getClientId());
            client.setClientSigningCertificate(info.getCertificate());
            client.setClientSigningPrivateKey(info.getPrivateKey());
        }

        if (clientRep.isFrontchannelLogout() == null) {
            newClient.setFrontchannelLogout(true);
        }
    }
}
