package it.rdev.keycloak.gel.broker.saml;

import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * GEL-specific extension of {@link SAMLIdentityProviderConfig}.
 *
 * <p>This class stores additional configuration keys needed to align outbound AuthnRequest
 * messages with GEL conventions documented in the provided functional kit.</p>
 */
public class GelSamlIdentityProviderConfig extends SAMLIdentityProviderConfig {

    public static final String GEL_ATTRIBUTE_SET = "gelAttributeSet";
    public static final String GEL_SPID_LEVEL = "gelSpidLevel";
    public static final String GEL_NAME_ID_SP_NAME_QUALIFIER = "gelNameIdSpNameQualifier";

    public static final String GEL_ENABLE_CIE = "gelEnableCie";
    public static final String GEL_ENABLE_CNS = "gelEnableCns";
    public static final String GEL_CIE_ONLY = "gelCieOnly";
    public static final String GEL_EIDAS = "gelEidas";
    public static final String GEL_USO_PROFESSIONALE = "gelUsoProfessionale";
    public static final String GEL_USO_PROFESSIONALE_GIURIDICO = "gelUsoProfessionaleGiuridico";

    public static final String GEL_CUSTOM_EXTENSIONS = "gelCustomExtensions";
    public static final String GEL_LOG_AUTHN_REQUEST = "gelLogAuthnRequest";
    public static final String GEL_SIGNING_PRIVATE_KEY_PEM = "gelSigningPrivateKeyPem";
    public static final String GEL_SIGNING_CERTIFICATE_PEM = "gelSigningCertificatePem";
    public static final String GEL_LOGOUT_RETURN_URL = "gelLogoutReturnUrl";
    public static final String GEL_IDP_ENTITY_ID = "idpEntityId";
    public static final String GEL_IDP_SSO_URL = "singleSignOnServiceUrl";
    public static final String GEL_IDP_SLO_URL = "singleLogoutServiceUrl";

    public GelSamlIdentityProviderConfig() {
    }

    public GelSamlIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
    }

    /**
     * Returns the GEL-specific attribute set. When configured, this value overrides
     * the standard SAML {@code AttributeConsumingServiceIndex}.
     *
     * @return GEL attribute set index ({@code 0..5}) or {@code null} when absent.
     */
    public String getGelAttributeSet() {
        return getConfig().get(GEL_ATTRIBUTE_SET);
    }

    public void setGelAttributeSet(String attributeSet) {
        putOrRemove(GEL_ATTRIBUTE_SET, attributeSet);
    }

    /**
     * GEL-specific attribute set has precedence over the standard SAML field so the
     * broker always emits the index selected from the dedicated GEL UI.
     */
    @Override
    public Integer getAttributeConsumingServiceIndex() {
        Integer gelAttributeSet = parseInteger(getGelAttributeSet());
        return gelAttributeSet != null ? gelAttributeSet : super.getAttributeConsumingServiceIndex();
    }

    /**
     * @return SPID level required by GEL (L2 or L3), if configured.
     */
    public String getGelSpidLevel() {
        return getConfig().get(GEL_SPID_LEVEL);
    }

    public void setGelSpidLevel(String spidLevel) {
        putOrRemove(GEL_SPID_LEVEL, spidLevel);
    }

    /**
     * @return Optional SPNameQualifier value to emit in samlp:NameIDPolicy.
     */
    public String getGelNameIdSpNameQualifier() {
        return getConfig().get(GEL_NAME_ID_SP_NAME_QUALIFIER);
    }

    public void setGelNameIdSpNameQualifier(String spNameQualifier) {
        putOrRemove(GEL_NAME_ID_SP_NAME_QUALIFIER, spNameQualifier);
    }

    public boolean isGelEnableCie() {
        return readBoolean(GEL_ENABLE_CIE);
    }

    public void setGelEnableCie(boolean value) {
        putBoolean(GEL_ENABLE_CIE, value);
    }

    public boolean isGelEnableCns() {
        return readBoolean(GEL_ENABLE_CNS);
    }

    public void setGelEnableCns(boolean value) {
        putBoolean(GEL_ENABLE_CNS, value);
    }

    public boolean isGelCieOnly() {
        return readBoolean(GEL_CIE_ONLY);
    }

    public void setGelCieOnly(boolean value) {
        putBoolean(GEL_CIE_ONLY, value);
    }

    public boolean isGelEidas() {
        return readBoolean(GEL_EIDAS);
    }

    public void setGelEidas(boolean value) {
        putBoolean(GEL_EIDAS, value);
    }

    public boolean isGelUsoProfessionale() {
        return readBoolean(GEL_USO_PROFESSIONALE);
    }

    public void setGelUsoProfessionale(boolean value) {
        putBoolean(GEL_USO_PROFESSIONALE, value);
    }

    public boolean isGelUsoProfessionaleGiuridico() {
        return readBoolean(GEL_USO_PROFESSIONALE_GIURIDICO);
    }

    public void setGelUsoProfessionaleGiuridico(boolean value) {
        putBoolean(GEL_USO_PROFESSIONALE_GIURIDICO, value);
    }

    /**
     * @return Custom extension definitions, one per line in the form "TAG=VALUE".
     */
    public String getGelCustomExtensions() {
        return getConfig().get(GEL_CUSTOM_EXTENSIONS);
    }

    public void setGelCustomExtensions(String customExtensions) {
        putOrRemove(GEL_CUSTOM_EXTENSIONS, customExtensions);
    }

    /**
     * @return True when generated AuthnRequest XML should be logged for troubleshooting.
     */
    public boolean isGelLogAuthnRequest() {
        return readBoolean(GEL_LOG_AUTHN_REQUEST);
    }

    public void setGelLogAuthnRequest(boolean value) {
        putBoolean(GEL_LOG_AUTHN_REQUEST, value);
    }

    /**
     * @return Optional PEM/private-key payload used only for this GEL IdP AuthnRequest signing.
     */
    public String getGelSigningPrivateKeyPem() {
        return getConfig().get(GEL_SIGNING_PRIVATE_KEY_PEM);
    }

    public void setGelSigningPrivateKeyPem(String privateKeyPem) {
        putOrRemove(GEL_SIGNING_PRIVATE_KEY_PEM, privateKeyPem);
    }

    /**
     * @return Optional PEM/certificate payload used only for this GEL IdP AuthnRequest signing.
     */
    public String getGelSigningCertificatePem() {
        return getConfig().get(GEL_SIGNING_CERTIFICATE_PEM);
    }

    public void setGelSigningCertificatePem(String certificatePem) {
        putOrRemove(GEL_SIGNING_CERTIFICATE_PEM, certificatePem);
    }

    /**
     * @return Optional absolute URL appended as {@code return=} on GEL logout endpoint.
     */
    public String getGelLogoutReturnUrl() {
        return getConfig().get(GEL_LOGOUT_RETURN_URL);
    }

    public void setGelLogoutReturnUrl(String logoutReturnUrl) {
        putOrRemove(GEL_LOGOUT_RETURN_URL, logoutReturnUrl);
    }

    private boolean readBoolean(String key) {
        return Boolean.parseBoolean(getConfig().get(key));
    }

    private void putBoolean(String key, boolean value) {
        getConfig().put(key, String.valueOf(value));
    }

    private void putOrRemove(String key, String value) {
        if (value == null || value.trim().isEmpty()) {
            getConfig().remove(key);
            return;
        }
        getConfig().put(key, value.trim());
    }

    private Integer parseInteger(String value) {
        if (value == null || value.trim().isEmpty()) {
            return null;
        }

        try {
            return Integer.valueOf(value.trim());
        } catch (NumberFormatException ignored) {
            return null;
        }
    }
}
