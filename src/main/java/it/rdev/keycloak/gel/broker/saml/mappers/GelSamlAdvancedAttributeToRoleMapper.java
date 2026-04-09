package it.rdev.keycloak.gel.broker.saml.mappers;

import org.keycloak.broker.saml.mappers.AdvancedAttributeToRoleMapper;

/**
 * GEL-compatible wrapper for Keycloak's standard SAML {@link AdvancedAttributeToRoleMapper}.
 */
public class GelSamlAdvancedAttributeToRoleMapper extends AdvancedAttributeToRoleMapper {

    public static final String PROVIDER_ID = "gel-saml-advanced-role-idp-mapper";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return AbstractGelSamlMapper.COMPATIBLE_PROVIDERS;
    }
}
