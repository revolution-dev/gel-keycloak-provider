package it.rdev.keycloak.gel.broker.saml.mappers;

import org.keycloak.broker.saml.mappers.UserAttributeMapper;

/**
 * GEL-compatible wrapper for Keycloak's standard SAML {@link UserAttributeMapper}.
 */
public class GelSamlUserAttributeMapper extends UserAttributeMapper {

    public static final String PROVIDER_ID = "gel-saml-user-attribute-idp-mapper";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return AbstractGelSamlMapper.COMPATIBLE_PROVIDERS;
    }
}
