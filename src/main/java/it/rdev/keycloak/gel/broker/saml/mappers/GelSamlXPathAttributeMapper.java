package it.rdev.keycloak.gel.broker.saml.mappers;

import org.keycloak.broker.saml.mappers.XPathAttributeMapper;

/**
 * GEL-compatible wrapper for Keycloak's standard SAML {@link XPathAttributeMapper}.
 */
public class GelSamlXPathAttributeMapper extends XPathAttributeMapper {

    public static final String PROVIDER_ID = "gel-saml-xpath-attribute-idp-mapper";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return AbstractGelSamlMapper.COMPATIBLE_PROVIDERS;
    }
}
