package it.rdev.keycloak.gel.admin.ui;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.ui.extend.UiTabProvider;
import org.keycloak.services.ui.extend.UiTabProviderFactory;

/**
 * Admin Console tab extension for GEL SAML providers.
 *
 * <p>This extension targets the identity provider details page route and adds a
 * dedicated {@code gel-params} tab for provider type {@code gel-saml}.</p>
 */
public class GelSamlUiTabProvider implements UiTabProvider, UiTabProviderFactory<ComponentModel> {

    /** Stable provider id for Keycloak service registration. */
    public static final String ID = "gel-saml-ui-tab";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getPath() {
        return "/:realm/identity-providers/:providerId/:alias/:tab";
    }

    @Override
    public Map<String, String> getParams() {
        return Map.of(
                "providerId", "gel-saml",
                "tab", "gel-params"
        );
    }

    @Override
    public String getHelpText() {
        return "Adds a dedicated GEL settings tab in identity provider details.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public ComponentModel create(KeycloakSession session, ComponentModel model) {
        return UiTabProviderFactory.super.create(session, model);
    }

    @Override
    public void init(Config.Scope config) {
        // No runtime configuration required.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization hook required.
    }

    @Override
    public void close() {
        // No resources to release.
    }
}
