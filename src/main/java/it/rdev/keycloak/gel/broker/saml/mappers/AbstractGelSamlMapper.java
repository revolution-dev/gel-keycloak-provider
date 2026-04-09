package it.rdev.keycloak.gel.broker.saml.mappers;

import it.rdev.keycloak.gel.broker.saml.GelSamlIdentityProviderFactory;

/**
 * Shared constants for GEL-compatible SAML identity provider mappers.
 *
 * <p>Keycloak SAML broker mappers shipped by default only declare compatibility
 * with the standard {@code saml} provider id. The GEL provider uses a distinct
 * id ({@code gel-saml}), therefore the Admin Console hides those mapper types.
 * Wrapper mappers extend the standard implementations and only broaden the
 * compatibility contract to {@code gel-saml}.</p>
 */
abstract class AbstractGelSamlMapper {

    static final String[] COMPATIBLE_PROVIDERS = {
            GelSamlIdentityProviderFactory.PROVIDER_ID
    };

    private AbstractGelSamlMapper() {
        // Utility class.
    }
}
