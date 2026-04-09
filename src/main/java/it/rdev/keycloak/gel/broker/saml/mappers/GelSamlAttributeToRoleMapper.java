package it.rdev.keycloak.gel.broker.saml.mappers;

import org.keycloak.broker.saml.mappers.AttributeToRoleMapper;

/**
 * GEL-compatible wrapper for Keycloak's standard SAML {@link AttributeToRoleMapper}.
 */
public class GelSamlAttributeToRoleMapper extends AttributeToRoleMapper {

    public static final String PROVIDER_ID = "gel-saml-role-idp-mapper";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return AbstractGelSamlMapper.COMPATIBLE_PROVIDERS;
    }
}
