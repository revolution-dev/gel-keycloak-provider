package it.rdev.keycloak.gel.broker.saml.mappers;

import org.keycloak.broker.saml.mappers.UsernameTemplateMapper;

/**
 * GEL-compatible wrapper for Keycloak's standard SAML {@link UsernameTemplateMapper}.
 */
public class GelSamlUsernameTemplateMapper extends UsernameTemplateMapper {

    public static final String PROVIDER_ID = "gel-saml-username-idp-mapper";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return AbstractGelSamlMapper.COMPATIBLE_PROVIDERS;
    }
}
