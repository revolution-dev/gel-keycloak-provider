package it.rdev.keycloak.gel.broker.saml;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.net.URI;
import java.net.URISyntaxException;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.dom.saml.v2.protocol.LogoutRequestType;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
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
import org.keycloak.saml.processing.api.saml.v2.request.SAML2Request;
import org.keycloak.saml.processing.core.util.KeycloakKeySamlExtensionGenerator;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.util.JsonSerialization;
import org.keycloak.sessions.AuthenticationSessionModel;

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
    private static final String KEY_TYPE_RSA = "RSA";
    private static final String PEM_BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String PEM_END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    private static final String PEM_BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String PEM_END_RSA_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";
    private static final String PEM_BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_END_CERTIFICATE = "-----END CERTIFICATE-----";

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
                SigningMaterial signingMaterial = resolveSigningMaterial(realm, config);
                binding.signWith(
                                signingMaterial.getKeyName(),
                                signingMaterial.getPrivateKey(),
                                signingMaterial.getPublicKey(),
                                signingMaterial.getCertificate())
                        .signatureAlgorithm(getSignatureAlgorithm())
                        .signDocument();

                if (!postBinding && config.isAddExtensionsElementWithKeyInfo()) {
                    authnRequestBuilder.addExtension(new KeycloakKeySamlExtensionGenerator(signingMaterial.getKeyName()));
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

    /**
     * Customizes logout RelayState for GEL interoperability while preserving Keycloak behavior.
     */
    @Override
    public Response keycloakInitiatedBrowserLogout(KeycloakSession session,
                                                   UserSessionModel userSession,
                                                   UriInfo uriInfo,
                                                   RealmModel realm) {
        GelSamlIdentityProviderConfig config = getGelConfig();
        String logoutDestination = trimToNull(config.getSingleLogoutServiceUrl());
        if (logoutDestination == null) {
            return null;
        }

        if (config.isBackchannelSupported()) {
            super.backchannelLogout(session, userSession, uriInfo, realm);
            return null;
        }

        try {
            LogoutRequestType logoutRequest = super.buildLogoutRequest(
                    userSession,
                    uriInfo,
                    realm,
                    logoutDestination);

            if (logoutRequest.getDestination() != null) {
                logoutDestination = logoutRequest.getDestination().toString();
            }

            JaxrsSAML2BindingBuilder binding = buildLogoutBindingForGel(session, userSession, realm);
            if (config.isPostBindingLogout()) {
                return binding.postBinding(SAML2Request.convert(logoutRequest)).request(logoutDestination);
            }
            return binding.redirectBinding(SAML2Request.convert(logoutRequest)).request(logoutDestination);
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }

    private JaxrsSAML2BindingBuilder buildLogoutBindingForGel(KeycloakSession session,
                                                              UserSessionModel userSession,
                                                              RealmModel realm) {
        String relayState = resolveLogoutRelayState(session, userSession);
        JaxrsSAML2BindingBuilder binding = new JaxrsSAML2BindingBuilder(session)
                .relayState(relayState);

        GelSamlIdentityProviderConfig config = getGelConfig();
        if (config.isWantAuthnRequestsSigned()) {
            KeyManager.ActiveRsaKey key = session.keys().getActiveRsaKey(realm);
            binding.signWith(
                            config.getXmlSigKeyInfoKeyNameTransformer().getKeyName(key.getKid(), key.getCertificate()),
                            key.getPrivateKey(),
                            key.getPublicKey(),
                            key.getCertificate())
                    .signatureAlgorithm(getSignatureAlgorithm());
        }

        return binding;
    }

    /**
     * Resolves relay state for logout with GEL-specific priority:
     * <ol>
     *   <li>OIDC post_logout_redirect_uri captured by Keycloak logout flow;</li>
     *   <li>SAML logout relay state captured in authentication client notes;</li>
     *   <li>configured GEL Logout Return URL;</li>
     *   <li>user session id (Keycloak default).</li>
     * </ol>
     */
    private String resolveLogoutRelayState(KeycloakSession session, UserSessionModel userSession) {
        AuthenticationSessionModel authenticationSession = session.getContext().getAuthenticationSession();
        if (authenticationSession != null) {
            String postLogoutRedirectUri = trimToNull(authenticationSession.getAuthNote(OIDCLoginProtocol.LOGOUT_REDIRECT_URI));
            if (isAbsoluteHttpUrl(postLogoutRedirectUri)) {
                return postLogoutRedirectUri;
            }

            String samlRelayState = trimToNull(authenticationSession.getClientNote(SamlProtocol.SAML_LOGOUT_RELAY_STATE));
            if (isAbsoluteHttpUrl(samlRelayState)) {
                return samlRelayState;
            }
        }

        String configuredReturnUrl = trimToNull(getGelConfig().getGelLogoutReturnUrl());
        if (isAbsoluteHttpUrl(configuredReturnUrl)) {
            return configuredReturnUrl;
        }

        return userSession.getId();
    }

    private boolean isAbsoluteHttpUrl(String value) {
        if (value == null) {
            return false;
        }

        try {
            URI uri = new URI(value);
            String scheme = uri.getScheme();
            return uri.isAbsolute()
                    && scheme != null
                    && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme));
        } catch (URISyntaxException ignored) {
            return false;
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
     * Resolves the signing material for AuthnRequest generation.
     *
     * <p>If GEL-specific private key and certificate are configured, those values are used only
     * for this Identity Provider. Otherwise, realm active RSA key is used to preserve standard
     * behavior for existing installations.</p>
     */
    private SigningMaterial resolveSigningMaterial(RealmModel realm, GelSamlIdentityProviderConfig config) {
        String configuredPrivateKey = trimToNull(config.getGelSigningPrivateKeyPem());
        String configuredCertificate = trimToNull(config.getGelSigningCertificatePem());

        if (configuredPrivateKey == null && configuredCertificate == null) {
            KeyManager.ActiveRsaKey realmKey = session.keys().getActiveRsaKey(realm);
            String keyName = config.getXmlSigKeyInfoKeyNameTransformer()
                    .getKeyName(realmKey.getKid(), realmKey.getCertificate());
            return new SigningMaterial(keyName, realmKey.getPrivateKey(), realmKey.getPublicKey(), realmKey.getCertificate());
        }

        if (configuredPrivateKey == null || configuredCertificate == null) {
            throw new IdentityBrokerException(String.format(
                    "GEL custom signing for IdP '%s' requires both private key and certificate.", config.getAlias()));
        }

        try {
            X509Certificate x509Certificate = parseCertificate(configuredCertificate);
            PrivateKey privateKey = parsePrivateKey(configuredPrivateKey);
            PublicKey publicKey = extractPublicKey(privateKey, x509Certificate);
            String keyName = config.getXmlSigKeyInfoKeyNameTransformer().getKeyName(
                    "gel-custom-" + config.getAlias(),
                    x509Certificate);
            return new SigningMaterial(keyName, privateKey, publicKey, x509Certificate);
        } catch (Exception exception) {
            throw new IdentityBrokerException(String.format(
                    "Invalid GEL custom signing material for IdP '%s'.", config.getAlias()), exception);
        }
    }

    /**
     * Parses X509 certificate from PEM payload.
     */
    private X509Certificate parseCertificate(String certificatePem) throws Exception {
        String base64Body = extractPemBodyOrRaw(certificatePem, PEM_BEGIN_CERTIFICATE, PEM_END_CERTIFICATE);
        byte[] certificateBytes = Base64.getDecoder().decode(base64Body);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(new java.io.ByteArrayInputStream(certificateBytes));
    }

    /**
     * Parses private RSA key from PKCS#8 or PKCS#1 PEM payload.
     */
    private PrivateKey parsePrivateKey(String privateKeyPem) throws Exception {
        byte[] privateKeyBytes;
        if (privateKeyPem.contains(PEM_BEGIN_RSA_PRIVATE_KEY)) {
            String body = extractPemBodyOrRaw(privateKeyPem, PEM_BEGIN_RSA_PRIVATE_KEY, PEM_END_RSA_PRIVATE_KEY);
            byte[] pkcs1Bytes = Base64.getDecoder().decode(body);
            privateKeyBytes = wrapPkcs1ToPkcs8(pkcs1Bytes);
        } else {
            String body = extractPemBodyOrRaw(privateKeyPem, PEM_BEGIN_PRIVATE_KEY, PEM_END_PRIVATE_KEY);
            privateKeyBytes = Base64.getDecoder().decode(body);
        }

        return KeyFactory.getInstance(KEY_TYPE_RSA).generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    /**
     * Returns the effective public key to be passed to the SAML signer.
     */
    private PublicKey extractPublicKey(PrivateKey privateKey, X509Certificate certificate) throws Exception {
        if (privateKey instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaPrivateCrtKey = (RSAPrivateCrtKey) privateKey;
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                    rsaPrivateCrtKey.getModulus(),
                    rsaPrivateCrtKey.getPublicExponent());
            return KeyFactory.getInstance(KEY_TYPE_RSA).generatePublic(publicKeySpec);
        }
        return certificate.getPublicKey();
    }

    /**
     * Extracts the base64 body of a PEM block.
     */
    private String extractPemBody(String source, String beginMarker, String endMarker) {
        int beginIndex = source.indexOf(beginMarker);
        int endIndex = source.indexOf(endMarker);
        if (beginIndex < 0 || endIndex < 0 || endIndex <= beginIndex) {
            throw new IllegalArgumentException("Missing PEM block markers.");
        }

        int contentStart = beginIndex + beginMarker.length();
        String body = source.substring(contentStart, endIndex).replaceAll("\\s+", "");
        if (body.isEmpty()) {
            throw new IllegalArgumentException("Empty PEM payload.");
        }

        return body;
    }

    /**
     * Supports both full PEM blocks and raw base64 payloads.
     */
    private String extractPemBodyOrRaw(String source, String beginMarker, String endMarker) {
        if (source == null) {
            throw new IllegalArgumentException("Missing key material.");
        }

        if (source.contains(beginMarker) && source.contains(endMarker)) {
            return extractPemBody(source, beginMarker, endMarker);
        }

        String normalized = source.replaceAll("\\s+", "");
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("Empty key material.");
        }
        return normalized;
    }

    /**
     * Wraps a PKCS#1 RSAPrivateKey ASN.1 sequence into a PKCS#8 PrivateKeyInfo envelope.
     */
    private byte[] wrapPkcs1ToPkcs8(byte[] pkcs1Bytes) {
        final byte[] rsaAlgorithmIdentifier = new byte[] {
                0x30, 0x0d,
                0x06, 0x09,
                0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01,
                0x05, 0x00
        };

        byte[] versionInteger = new byte[] { 0x02, 0x01, 0x00 };
        byte[] privateKeyOctetString = encodeDerOctetString(pkcs1Bytes);
        byte[] privateKeyInfoSequence = concat(versionInteger, rsaAlgorithmIdentifier, privateKeyOctetString);

        return encodeDerSequence(privateKeyInfoSequence);
    }

    private byte[] encodeDerSequence(byte[] value) {
        return encodeDerConstructed((byte) 0x30, value);
    }

    private byte[] encodeDerOctetString(byte[] value) {
        return encodeDerConstructed((byte) 0x04, value);
    }

    private byte[] encodeDerConstructed(byte tag, byte[] value) {
        byte[] lengthBytes = encodeDerLength(value.length);
        byte[] encoded = new byte[1 + lengthBytes.length + value.length];
        encoded[0] = tag;
        System.arraycopy(lengthBytes, 0, encoded, 1, lengthBytes.length);
        System.arraycopy(value, 0, encoded, 1 + lengthBytes.length, value.length);
        return encoded;
    }

    private byte[] encodeDerLength(int length) {
        if (length < 0x80) {
            return new byte[] { (byte) length };
        }

        int tempLength = length;
        int byteCount = 0;
        while (tempLength > 0) {
            byteCount++;
            tempLength >>= 8;
        }

        byte[] encoded = new byte[1 + byteCount];
        encoded[0] = (byte) (0x80 | byteCount);

        for (int i = byteCount; i > 0; i--) {
            encoded[i] = (byte) (length & 0xff);
            length >>= 8;
        }

        return encoded;
    }

    private byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        byte[] combined = new byte[totalLength];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, combined, offset, array.length);
            offset += array.length;
        }

        return combined;
    }

    /**
     * Immutable signing key material used to create signed AuthnRequest messages.
     */
    private static final class SigningMaterial {
        private final String keyName;
        private final PrivateKey privateKey;
        private final PublicKey publicKey;
        private final X509Certificate certificate;

        private SigningMaterial(String keyName, PrivateKey privateKey, PublicKey publicKey, X509Certificate certificate) {
            this.keyName = keyName;
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.certificate = certificate;
        }

        private String getKeyName() {
            return keyName;
        }

        private PrivateKey getPrivateKey() {
            return privateKey;
        }

        private PublicKey getPublicKey() {
            return publicKey;
        }

        private X509Certificate getCertificate() {
            return certificate;
        }
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
