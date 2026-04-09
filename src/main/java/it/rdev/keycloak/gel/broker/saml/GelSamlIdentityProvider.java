package it.rdev.keycloak.gel.broker.saml;

import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlSessionUtils;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.saml.SAML2AuthnRequestBuilder;
import org.keycloak.saml.SAML2NameIDPolicyBuilder;
import org.keycloak.saml.SAML2RequestedAuthnContextBuilder;
import org.keycloak.saml.SamlProtocolExtensionsAwareBuilder.NodeGenerator;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.processing.core.util.KeycloakKeySamlExtensionGenerator;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.util.JsonSerialization;

/**
 * Custom SAML Identity Provider that enriches outbound AuthnRequest messages with GEL-specific data.
 *
 * <p>The implementation preserves the behavior of the standard Keycloak SAML broker and adds:
 * <ul>
 *   <li>GEL extension tags under {@code samlp:Extensions};</li>
 *   <li>optional {@code SPNameQualifier} in {@code NameIDPolicy};</li>
 *   <li>SPID level convenience mapping ({@code L2}/{@code L3}) to AuthnContext class refs.</li>
 * </ul>
 * </p>
 */
public class GelSamlIdentityProvider extends SAMLIdentityProvider {

    private static final String GEL_ENABLED_VALUE = "SI";
    private static final String GEL_EXTENSION_VALUE_ATTRIBUTE = "value";

    private static final String GEL_TAG_ENABLE_CIE = "ENABLE_CIE";
    private static final String GEL_TAG_CNS = "CNS";
    private static final String GEL_TAG_CIE_ONLY = "CIEONLY";
    private static final String GEL_TAG_EIDAS = "EIDAS";
    private static final String GEL_TAG_USO_PROFESSIONALE = "usoProfessionale";
    private static final String GEL_TAG_USO_PROFESSIONALE_GIURIDICO = "usoProfessionaleGiuridico";

    private static final String SPID_LEVEL_L2 = "L2";
    private static final String SPID_LEVEL_L3 = "L3";
    private static final String SPID_LEVEL_URI_L2 = "https://www.spid.gov.it/SpidL2";
    private static final String SPID_LEVEL_URI_L3 = "https://www.spid.gov.it/SpidL3";

    private static final Pattern EXTENSION_NAME_PATTERN = Pattern.compile("[A-Za-z_][A-Za-z0-9_.-]*");

    public GelSamlIdentityProvider(KeycloakSession session,
                                   GelSamlIdentityProviderConfig config,
                                   DestinationValidator destinationValidator) {
        super(session, config, destinationValidator);
    }

    /**
     * Creates a SAML AuthnRequest enriched with GEL-specific extensions.
     */
    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            UriInfo uriInfo = request.getUriInfo();
            RealmModel realm = request.getRealm();
            GelSamlIdentityProviderConfig config = getGelConfig();

            String issuerURL = getEntityId(uriInfo, realm);
            String destinationUrl = config.getSingleSignOnServiceUrl();

            String nameIDPolicyFormat = config.getNameIDPolicyFormat();
            if (nameIDPolicyFormat == null) {
                nameIDPolicyFormat = JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get();
            }

            String protocolBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();
            if (config.isPostBindingResponse()) {
                protocolBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get();
            }

            SAML2RequestedAuthnContextBuilder requestedAuthnContext =
                    new SAML2RequestedAuthnContextBuilder().setComparison(config.getAuthnContextComparisonType());

            for (String authnContextClassRef : resolveAuthnContextClassRefUris(config)) {
                requestedAuthnContext.addAuthnContextClassRef(authnContextClassRef);
            }
            for (String authnContextDeclRef : getAuthnContextDeclRefUris(config)) {
                requestedAuthnContext.addAuthnContextDeclRef(authnContextDeclRef);
            }

            String loginHint = config.isLoginHint()
                    ? request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM)
                    : null;

            Boolean allowCreate = null;
            if (config.getConfig().get(GelSamlIdentityProviderConfig.ALLOW_CREATE) == null || config.isAllowCreate()) {
                allowCreate = Boolean.TRUE;
            }

            SAML2NameIDPolicyBuilder nameIDPolicyBuilder = SAML2NameIDPolicyBuilder
                    .format(nameIDPolicyFormat)
                    .setAllowCreate(allowCreate);

            String spNameQualifier = trimToNull(config.getGelNameIdSpNameQualifier());
            if (spNameQualifier != null) {
                nameIDPolicyBuilder.setSPNameQualifier(spNameQualifier);
            }

            SAML2AuthnRequestBuilder authnRequestBuilder = new SAML2AuthnRequestBuilder()
                    .assertionConsumerUrl(request.getRedirectUri())
                    .destination(destinationUrl)
                    .issuer(issuerURL)
                    .forceAuthn(config.isForceAuthn())
                    .protocolBinding(protocolBinding)
                    .nameIdPolicy(nameIDPolicyBuilder)
                    .attributeConsumingServiceIndex(config.getAttributeConsumingServiceIndex())
                    .requestedAuthnContext(requestedAuthnContext)
                    .subject(loginHint);

            addGelExtensions(authnRequestBuilder, config);

            JaxrsSAML2BindingBuilder binding = new JaxrsSAML2BindingBuilder(session)
                    .relayState(request.getState().getEncoded());
            boolean postBinding = config.isPostBindingAuthnRequest();

            if (config.isWantAuthnRequestsSigned()) {
                KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);
                String keyName = config.getXmlSigKeyInfoKeyNameTransformer().getKeyName(keys.getKid(), keys.getCertificate());
                binding.signWith(keyName, keys.getPrivateKey(), keys.getPublicKey(), keys.getCertificate())
                        .signatureAlgorithm(getSignatureAlgorithm())
                        .signDocument();

                if (!postBinding && config.isAddExtensionsElementWithKeyInfo()) {
                    authnRequestBuilder.addExtension(new KeycloakKeySamlExtensionGenerator(keyName));
                }
            }

            AuthnRequestType authnRequest = authnRequestBuilder.createAuthnRequest();
            for (Iterator<SamlAuthenticationPreprocessor> it =
                         SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session); it.hasNext(); ) {
                authnRequest = it.next().beforeSendingLoginRequest(authnRequest, request.getAuthenticationSession());
            }

            if (authnRequest.getDestination() != null) {
                destinationUrl = authnRequest.getDestination().toString();
            }

            request.getAuthenticationSession().setClientNote(SamlProtocol.SAML_REQUEST_ID_BROKER, authnRequest.getID());

            org.w3c.dom.Document authnRequestDocument = authnRequestBuilder.toDocument();

            if (postBinding) {
                JaxrsSAML2BindingBuilder.PostBindingBuilder postBindingBuilder = binding.postBinding(authnRequestDocument);
                if (config.isGelLogAuthnRequest()) {
                    // For POST binding this document has already passed through sign/encrypt hooks.
                    logger.infof("GEL AuthnRequest generated for IdP '%s' (post-binding): %s",
                            config.getAlias(),
                            DocumentUtil.asString(postBindingBuilder.getDocument()));
                }
                return postBindingBuilder.request(destinationUrl);
            }

            JaxrsSAML2BindingBuilder.RedirectBindingBuilder redirectBindingBuilder = binding.redirectBinding(authnRequestDocument);
            if (config.isGelLogAuthnRequest()) {
                // Redirect signatures are added at query-string level, not as ds:Signature in the XML.
                logger.infof("GEL AuthnRequest generated for IdP '%s' (redirect-binding): %s",
                        config.getAlias(),
                        DocumentUtil.asString(redirectBindingBuilder.getDocument()));
            }
            return redirectBindingBuilder.request(destinationUrl);
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create GEL-authentication request.", e);
        }
    }

    private void addGelExtensions(SAML2AuthnRequestBuilder authnRequestBuilder, GelSamlIdentityProviderConfig config) {
        Map<String, String> extensionValues = new LinkedHashMap<>();

        if (config.isGelEnableCie()) {
            extensionValues.put(GEL_TAG_ENABLE_CIE, GEL_ENABLED_VALUE);
        }
        if (config.isGelEnableCns()) {
            extensionValues.put(GEL_TAG_CNS, GEL_ENABLED_VALUE);
        }
        if (config.isGelCieOnly()) {
            extensionValues.put(GEL_TAG_CIE_ONLY, GEL_ENABLED_VALUE);
        }
        if (config.isGelEidas()) {
            extensionValues.put(GEL_TAG_EIDAS, GEL_ENABLED_VALUE);
        }
        if (config.isGelUsoProfessionale()) {
            extensionValues.put(GEL_TAG_USO_PROFESSIONALE, GEL_ENABLED_VALUE);
        }
        if (config.isGelUsoProfessionaleGiuridico()) {
            extensionValues.put(GEL_TAG_USO_PROFESSIONALE_GIURIDICO, GEL_ENABLED_VALUE);
        }

        extensionValues.putAll(parseCustomExtensions(config.getGelCustomExtensions(), config.getAlias()));

        for (Map.Entry<String, String> extension : extensionValues.entrySet()) {
            authnRequestBuilder.addExtension(new KeyValueExtensionNodeGenerator(extension.getKey(), extension.getValue()));
        }
    }

    private Map<String, String> parseCustomExtensions(String source, String idpAlias) {
        if (source == null || source.trim().isEmpty()) {
            return Collections.emptyMap();
        }

        Map<String, String> customExtensions = new LinkedHashMap<>();
        String[] lines = source.split("\\R");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i].trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            String[] keyValue = line.split("=", 2);
            String extensionName = keyValue[0].trim();
            String extensionValue = keyValue.length == 2 ? keyValue[1].trim() : GEL_ENABLED_VALUE;

            if (!EXTENSION_NAME_PATTERN.matcher(extensionName).matches()) {
                logger.warnf("Skipping GEL extension with invalid name '%s' (line %d, IdP '%s').",
                        extensionName,
                        Integer.valueOf(i + 1),
                        idpAlias);
                continue;
            }

            if (extensionValue.isEmpty()) {
                extensionValue = GEL_ENABLED_VALUE;
            }
            customExtensions.put(extensionName, extensionValue);
        }

        return customExtensions;
    }

    private List<String> resolveAuthnContextClassRefUris(GelSamlIdentityProviderConfig config) {
        String spidLevel = trimToNull(config.getGelSpidLevel());
        if (spidLevel != null) {
            String normalized = spidLevel.toUpperCase();
            if (SPID_LEVEL_L2.equals(normalized)) {
                return Collections.singletonList(SPID_LEVEL_URI_L2);
            }
            if (SPID_LEVEL_L3.equals(normalized)) {
                return Collections.singletonList(SPID_LEVEL_URI_L3);
            }
            if (spidLevel.startsWith("http://") || spidLevel.startsWith("https://")) {
                return Collections.singletonList(spidLevel);
            }

            logger.warnf("Unknown GEL SPID level '%s' for IdP '%s'. Falling back to AuthnContextClassRefs config.",
                    spidLevel,
                    config.getAlias());
        }

        String authnContextClassRefs = config.getAuthnContextClassRefs();
        if (authnContextClassRefs == null || authnContextClassRefs.isEmpty()) {
            return new LinkedList<>();
        }

        try {
            return Arrays.asList(JsonSerialization.readValue(authnContextClassRefs, String[].class));
        } catch (Exception e) {
            logger.warnf(e,
                    "Could not json-deserialize AuthContextClassRefs config entry for IdP '%s': %s",
                    config.getAlias(),
                    authnContextClassRefs);
            return new LinkedList<>();
        }
    }

    private List<String> getAuthnContextDeclRefUris(GelSamlIdentityProviderConfig config) {
        String authnContextDeclRefs = config.getAuthnContextDeclRefs();
        if (authnContextDeclRefs == null || authnContextDeclRefs.isEmpty()) {
            return new LinkedList<>();
        }

        try {
            return Arrays.asList(JsonSerialization.readValue(authnContextDeclRefs, String[].class));
        } catch (Exception e) {
            logger.warnf(e,
                    "Could not json-deserialize AuthContextDeclRefs config entry for IdP '%s': %s",
                    config.getAlias(),
                    authnContextDeclRefs);
            return new LinkedList<>();
        }
    }

    private String getEntityId(UriInfo uriInfo, RealmModel realm) {
        String configEntityId = getGelConfig().getEntityId();
        if (configEntityId == null || configEntityId.isEmpty()) {
            return UriBuilder.fromUri(uriInfo.getBaseUri()).path("realms").path(realm.getName()).build().toString();
        }
        return configEntityId;
    }

    private GelSamlIdentityProviderConfig getGelConfig() {
        return (GelSamlIdentityProviderConfig) getConfig();
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    /**
     * Writes a simple GEL extension node with a single attribute in the form:
     * {@code <TAG value="X"/>}.
     */
    private static final class KeyValueExtensionNodeGenerator implements NodeGenerator {

        private final String tagName;
        private final String value;

        private KeyValueExtensionNodeGenerator(String tagName, String value) {
            this.tagName = tagName;
            this.value = value;
        }

        @Override
        public void write(XMLStreamWriter writer) throws ProcessingException {
            try {
                writer.writeEmptyElement(tagName);
                writer.writeAttribute(GEL_EXTENSION_VALUE_ATTRIBUTE, value);
            } catch (XMLStreamException e) {
                throw new ProcessingException(e);
            }
        }
    }
}
