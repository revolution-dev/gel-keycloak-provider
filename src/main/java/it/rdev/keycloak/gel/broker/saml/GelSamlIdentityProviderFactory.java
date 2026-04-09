package it.rdev.keycloak.gel.broker.saml;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.keycloak.Config.Scope;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.validators.DestinationValidator;

/**
 * Factory for the GEL custom SAML identity provider.
 *
 * <p>The provider is intentionally separated from standard {@code saml} so we can maintain
 * GEL-specific behavior without impacting existing realms.</p>
 */
public class GelSamlIdentityProviderFactory extends SAMLIdentityProviderFactory implements ConfiguredProvider {

    public static final String PROVIDER_ID = "gel-saml";

    private static final List<String> SPID_LEVEL_OPTIONS = List.of("L2", "L3");
    private static final List<String> ATTRIBUTE_SET_OPTIONS = List.of("0", "1", "2", "3", "4", "5");

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES;

    static {
        List<ProviderConfigProperty> properties = new ArrayList<>();

        properties.add(new ProviderConfigProperty(
                SAMLIdentityProviderConfig.SINGLE_SIGN_ON_SERVICE_URL,
                "Single Sign-On Service URL",
                "Endpoint SSO GEL/IdP (es. .../SSOService).",
                ProviderConfigProperty.STRING_TYPE,
                null));

        properties.add(new ProviderConfigProperty(
                SAMLIdentityProviderConfig.SINGLE_LOGOUT_SERVICE_URL,
                "Single Logout Service URL",
                "Endpoint SLO remoto. Campo opzionale.",
                ProviderConfigProperty.STRING_TYPE,
                null));

        properties.add(new ProviderConfigProperty(
                SAMLIdentityProviderConfig.IDP_ENTITY_ID,
                "IdP Entity ID",
                "Entity ID del metadata IdP GEL.",
                ProviderConfigProperty.STRING_TYPE,
                null));

        properties.add(new ProviderConfigProperty(
                SAMLIdentityProviderConfig.ENTITY_ID,
                "SP Entity ID (Issuer)",
                "Entity ID da usare come Issuer nella AuthnRequest.",
                ProviderConfigProperty.STRING_TYPE,
                null));

        properties.add(new ProviderConfigProperty(
                SAMLIdentityProviderConfig.NAME_ID_POLICY_FORMAT,
                "NameID Policy Format",
                "Formato NameID da inviare nel NameIDPolicy.",
                ProviderConfigProperty.STRING_TYPE,
                JBossSAMLURIConstants.NAMEID_FORMAT_TRANSIENT.get()));

        ProviderConfigProperty attributeSet = new ProviderConfigProperty(
                GelSamlIdentityProviderConfig.GEL_ATTRIBUTE_SET,
                "GEL Attribute Set",
                "Indice set attributi GEL (0..5), come da documentazione GEL. Se valorizzato sovrascrive Attribute Consuming Service Index.",
                ProviderConfigProperty.LIST_TYPE,
                "4");
        attributeSet.setOptions(ATTRIBUTE_SET_OPTIONS);
        properties.add(attributeSet);

        ProviderConfigProperty spidLevel = new ProviderConfigProperty(
                GelSamlIdentityProviderConfig.GEL_SPID_LEVEL,
                "SPID Level",
                "Livello SPID richiesto (L2/L3).",
                ProviderConfigProperty.LIST_TYPE,
                "L2");
        spidLevel.setOptions(SPID_LEVEL_OPTIONS);
        properties.add(spidLevel);

        properties.add(new ProviderConfigProperty(
                GelSamlIdentityProviderConfig.GEL_NAME_ID_SP_NAME_QUALIFIER,
                "NameID SPNameQualifier",
                "Valore opzionale da valorizzare in samlp:NameIDPolicy@SPNameQualifier.",
                ProviderConfigProperty.STRING_TYPE,
                null));

        properties.add(new ProviderConfigProperty(
                GelSamlIdentityProviderConfig.GEL_ENABLE_CIE,
                "Extension ENABLE_CIE",
                "Se attivo aggiunge <ENABLE_CIE value=\"SI\"/>.",
                ProviderConfigProperty.BOOLEAN_TYPE,
                Boolean.FALSE));

        properties.add(new ProviderConfigProperty(
                GelSamlIdentityProviderConfig.GEL_ENABLE_CNS,
                "Extension CNS",
                "Se attivo aggiunge <CNS value=\"SI\"/>.",
                ProviderConfigProperty.BOOLEAN_TYPE,
                Boolean.FALSE));

        properties.add(new ProviderConfigProperty(
                GelSamlIdentityProviderConfig.GEL_CIE_ONLY,
                "Extension CIEONLY",
                "Se attivo aggiunge <CIEONLY value=\"SI\"/>.",
                ProviderConfigProperty.BOOLEAN_TYPE,
                Boolean.FALSE));

        properties.add(new ProviderConfigProperty(
                GelSamlIdentityProviderConfig.GEL_EIDAS,
                "Extension EIDAS",
                "Se attivo aggiunge <EIDAS value=\"SI\"/>.",
                ProviderConfigProperty.BOOLEAN_TYPE,
                Boolean.FALSE));

        properties.add(new ProviderConfigProperty(
                GelSamlIdentityProviderConfig.GEL_USO_PROFESSIONALE,
                "Extension usoProfessionale",
                "Se attivo aggiunge <usoProfessionale value=\"SI\"/>.",
                ProviderConfigProperty.BOOLEAN_TYPE,
                Boolean.FALSE));

        properties.add(new ProviderConfigProperty(
                GelSamlIdentityProviderConfig.GEL_USO_PROFESSIONALE_GIURIDICO,
                "Extension usoProfessionaleGiuridico",
                "Se attivo aggiunge <usoProfessionaleGiuridico value=\"SI\"/>.",
                ProviderConfigProperty.BOOLEAN_TYPE,
                Boolean.FALSE));

        properties.add(new ProviderConfigProperty(
                GelSamlIdentityProviderConfig.GEL_CUSTOM_EXTENSIONS,
                "Custom GEL Extensions",
                "Estensioni aggiuntive: una per riga nel formato TAG=VALORE (es. CUSTOM=SI).",
                ProviderConfigProperty.TEXT_TYPE,
                null));

        properties.add(new ProviderConfigProperty(
                GelSamlIdentityProviderConfig.GEL_LOG_AUTHN_REQUEST,
                "Log AuthnRequest",
                "Se attivo logga l'XML AuthnRequest generato (solo per troubleshooting PoC).",
                ProviderConfigProperty.BOOLEAN_TYPE,
                Boolean.FALSE));

        properties.add(new ProviderConfigProperty(
                SAMLIdentityProviderConfig.WANT_AUTHN_REQUESTS_SIGNED,
                "Sign AuthnRequest",
                "Firma AuthnRequest verso GEL.",
                ProviderConfigProperty.BOOLEAN_TYPE,
                Boolean.TRUE));

        properties.add(new ProviderConfigProperty(
                SAMLIdentityProviderConfig.VALIDATE_SIGNATURE,
                "Validate Signature",
                "Valida la firma delle risposte SAML ricevute.",
                ProviderConfigProperty.BOOLEAN_TYPE,
                Boolean.TRUE));

        properties.add(new ProviderConfigProperty(
                SAMLIdentityProviderConfig.SIGNING_CERTIFICATE_KEY,
                "Validating X509 Certificates",
                "Certificati X509 (uno o piu') usati per validare le firme IdP.",
                ProviderConfigProperty.TEXT_TYPE,
                null));

        properties.add(new ProviderConfigProperty(
                SAMLIdentityProviderConfig.POST_BINDING_AUTHN_REQUEST,
                "AuthnRequest POST Binding",
                "Usa HTTP-POST per inviare AuthnRequest.",
                ProviderConfigProperty.BOOLEAN_TYPE,
                Boolean.FALSE));

        properties.add(new ProviderConfigProperty(
                SAMLIdentityProviderConfig.POST_BINDING_RESPONSE,
                "Response POST Binding",
                "Atteso binding HTTP-POST in risposta.",
                ProviderConfigProperty.BOOLEAN_TYPE,
                Boolean.TRUE));

        CONFIG_PROPERTIES = Collections.unmodifiableList(properties);
    }

    private DestinationValidator destinationValidator;

    @Override
    public String getName() {
        return "GEL SAML v2.0";
    }

    /**
     * Creates the runtime provider instance with GEL config wrapper.
     */
    @Override
    public GelSamlIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new GelSamlIdentityProvider(session, new GelSamlIdentityProviderConfig(model), destinationValidator);
    }

    @Override
    public GelSamlIdentityProviderConfig createConfig() {
        return new GelSamlIdentityProviderConfig();
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, InputStream inputStream) {
        Map<String, String> config = super.parseConfig(session, inputStream);

        // GEL-oriented defaults to reduce manual setup in PoC phase.
        config.putIfAbsent(SAMLIdentityProviderConfig.NAME_ID_POLICY_FORMAT, JBossSAMLURIConstants.NAMEID_FORMAT_TRANSIENT.get());
        config.putIfAbsent(SAMLIdentityProviderConfig.ATTRIBUTE_CONSUMING_SERVICE_INDEX, "4");
        config.putIfAbsent(GelSamlIdentityProviderConfig.GEL_ATTRIBUTE_SET, "4");
        config.putIfAbsent(GelSamlIdentityProviderConfig.GEL_SPID_LEVEL, "L2");

        return config;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Scope config) {
        super.init(config);
        destinationValidator = DestinationValidator.forProtocolMap(config.getArray("knownProtocols"));
    }

    @Override
    public String getHelpText() {
        return "SAML Identity Provider customizzato per GEL (Gateway Enti Locali).";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }
}
