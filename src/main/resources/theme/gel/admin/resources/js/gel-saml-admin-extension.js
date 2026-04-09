/*
 * GEL SAML Admin Console extension.
 *
 * This script adds a dedicated configuration panel when editing
 * Identity Providers with providerId "gel-saml".
 */
(function () {
  "use strict";

  var PANEL_ID = "gel-saml-custom-panel";
  var STATUS_ID = "gel-saml-custom-status";
  var SAVE_BUTTON_ID = "gel-saml-custom-save";
  var CUSTOM_TAB_ID = "gel-saml-custom-tab";
  var SETTINGS_SECTION_ID = "pf-tab-section-settings-settings";
  var JUMP_HIDDEN_STATE_ATTRIBUTE = "data-gel-prev-jump-hidden";

  var TARGET_PROVIDER_ID = "gel-saml";
  var SAML_PROVIDER_ID = "saml";
  var ROUTE_ACTION_ADD = "add";
  var ROUTE_ACTION_DETAILS = "details";
  var PROXY_QUERY_FLAG = "gelSamlProxy";
  var PROXY_QUERY_TARGET = "gelProviderId";
  var PROXY_QUERY_ENABLED = "1";
  var PROXY_STORAGE_ACTIVE_KEY = "gelSamlProxyActive";
  var PROXY_STORAGE_ALIAS_KEY = "gelSamlProxyAlias";
  var GEL_TAB_QUERY_FLAG = "gelTab";
  var GEL_TAB_QUERY_VALUE = "params";
  var SETTINGS_TAB = "settings";
  var TAB_SECTION_ID_PREFIX = "pf-tab-section-settings-";
  var STANDARD_SAML_ATTRIBUTE_SET_KEY = "attributeConsumingServiceIndex";
  var DEFAULT_GEL_ATTRIBUTE_SET = "4";
  var DEFAULT_SPID_LEVEL = "L2";
  var FIELD_SECTION_GENERAL = "general";
  var FIELD_SECTION_EXTENSIONS = "extensions";

  var GEL_KEYS = {
    attributeSet: "gelAttributeSet",
    spidLevel: "gelSpidLevel",
    spNameQualifier: "gelNameIdSpNameQualifier",
    enableCie: "gelEnableCie",
    enableCns: "gelEnableCns",
    cieOnly: "gelCieOnly",
    eidas: "gelEidas",
    usoProfessionale: "gelUsoProfessionale",
    usoProfessionaleGiuridico: "gelUsoProfessionaleGiuridico",
    customExtensions: "gelCustomExtensions",
    logAuthnRequest: "gelLogAuthnRequest"
  };

  var BOOLEAN_FIELDS = [
    GEL_KEYS.enableCie,
    GEL_KEYS.enableCns,
    GEL_KEYS.cieOnly,
    GEL_KEYS.eidas,
    GEL_KEYS.usoProfessionale,
    GEL_KEYS.usoProfessionaleGiuridico,
    GEL_KEYS.logAuthnRequest
  ];

  var ATTRIBUTE_SET_OPTIONS = ["0", "1", "2", "3", "4", "5"];
  var SPID_LEVEL_OPTIONS = ["L2", "L3"];

  var FIELD_DEFINITIONS = [
    {
      type: "select",
      id: GEL_KEYS.attributeSet,
      section: FIELD_SECTION_GENERAL,
      label: "GEL Attribute Set",
      helpText: "Se valorizzato, sovrascrive il campo SAML Attribute Consuming Service Index.",
      options: ATTRIBUTE_SET_OPTIONS
    },
    {
      type: "select",
      id: GEL_KEYS.spidLevel,
      section: FIELD_SECTION_GENERAL,
      label: "SPID Level",
      helpText: "Livello SPID richiesto da GEL.",
      options: SPID_LEVEL_OPTIONS
    },
    {
      type: "text",
      id: GEL_KEYS.spNameQualifier,
      section: FIELD_SECTION_GENERAL,
      label: "NameID SPNameQualifier",
      helpText: "Valore opzionale da valorizzare in samlp:NameIDPolicy@SPNameQualifier.",
      placeholder: "es. https://sp.example.it"
    },
    {
      type: "toggle",
      id: GEL_KEYS.enableCie,
      section: FIELD_SECTION_EXTENSIONS,
      label: "ENABLE_CIE",
      helpText: "Aggiunge l'estensione ENABLE_CIE con valore SI."
    },
    {
      type: "toggle",
      id: GEL_KEYS.enableCns,
      section: FIELD_SECTION_EXTENSIONS,
      label: "CNS",
      helpText: "Aggiunge l'estensione CNS con valore SI."
    },
    {
      type: "toggle",
      id: GEL_KEYS.cieOnly,
      section: FIELD_SECTION_EXTENSIONS,
      label: "CIEONLY",
      helpText: "Aggiunge l'estensione CIEONLY con valore SI."
    },
    {
      type: "toggle",
      id: GEL_KEYS.eidas,
      section: FIELD_SECTION_EXTENSIONS,
      label: "EIDAS",
      helpText: "Aggiunge l'estensione EIDAS con valore SI."
    },
    {
      type: "toggle",
      id: GEL_KEYS.usoProfessionale,
      section: FIELD_SECTION_EXTENSIONS,
      label: "usoProfessionale",
      helpText: "Aggiunge l'estensione usoProfessionale con valore SI."
    },
    {
      type: "toggle",
      id: GEL_KEYS.usoProfessionaleGiuridico,
      section: FIELD_SECTION_EXTENSIONS,
      label: "usoProfessionaleGiuridico",
      helpText: "Aggiunge l'estensione usoProfessionaleGiuridico con valore SI."
    },
    {
      type: "textarea",
      id: GEL_KEYS.customExtensions,
      section: FIELD_SECTION_EXTENSIONS,
      label: "Custom Extensions",
      helpText: "Una estensione per riga nel formato TAG=VALORE.",
      placeholder: "CUSTOM=SI",
      rows: "5"
    },
    {
      type: "toggle",
      id: GEL_KEYS.logAuthnRequest,
      label: "Log AuthnRequest",
      helpText: "Da usare solo in ambienti di test per debug."
    }
  ];

  var TEMPLATE_ENGINE = {
    render: function render(template, model) {
      return String(template).replace(/\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}/g, function (_, key) {
        var value = model && Object.prototype.hasOwnProperty.call(model, key) ? model[key] : "";
        return typeof value === "undefined" || value === null ? "" : String(value);
      });
    }
  };

  var PANEL_TEMPLATE = [
    '<div class="gel-saml-panel__header">',
    '  <h2 class="gel-saml-panel__title">Configurazione GEL SAML</h2>',
    '  <p class="gel-saml-panel__subtitle">Parametri aggiuntivi GEL per l\'Identity Provider <strong>{{alias}}</strong>.</p>',
    '</div>',
    '<div class="pf-c-form pf-m-horizontal gel-saml-form" data-gel-form="true">',
    '  {{fieldsMarkup}}',
    '  <div class="pf-c-form__group gel-saml-form__group gel-saml-form__group--actions">',
    '    <div class="pf-c-form__group-label gel-saml-form__label-wrapper"></div>',
    '    <div class="pf-c-form__group-control gel-saml-form__control gel-saml-actions">',
    '      <button id="' + SAVE_BUTTON_ID + '" type="button" class="pf-c-button pf-m-primary gel-saml-button">Salva parametri GEL</button>',
    '      <span id="' + STATUS_ID + '" class="gel-saml-status" role="status" aria-live="polite"></span>',
    '    </div>',
    '  </div>',
    '</div>'
  ].join("");

  var FORM_GROUP_TEMPLATE = [
    '<div class="pf-c-form__group gel-saml-form__group">',
    '  <div class="pf-c-form__group-label gel-saml-form__label-wrapper">',
    '    <label class="pf-c-form__label gel-saml-form__label" for="{{inputId}}">',
    '      <span class="pf-c-form__label-text">{{label}}</span>',
    '    </label>',
    '  </div>',
    '  <div class="pf-c-form__group-control gel-saml-form__control">',
    '    {{controlMarkup}}',
    '    {{helpMarkup}}',
    '  </div>',
    '</div>'
  ].join("");

  var SECTION_TEMPLATE = [
    '<section class="gel-saml-section">',
    '  <h1 class="gel-saml-section__title">{{title}}</h1>',
    '  {{contentMarkup}}',
    '</section>'
  ].join("");

  var SELECT_TEMPLATE = [
    '<select id="{{id}}" class="pf-c-form-control gel-saml-input">',
    '  {{optionsMarkup}}',
    '</select>'
  ].join("");

  var SELECT_OPTION_TEMPLATE = '<option value="{{value}}">{{label}}</option>';
  var INPUT_TEMPLATE = '<input id="{{id}}" type="text" class="pf-c-form-control gel-saml-input" placeholder="{{placeholder}}" />';
  var TEXTAREA_TEMPLATE = '<textarea id="{{id}}" class="pf-c-form-control gel-saml-input gel-saml-textarea" rows="{{rows}}" placeholder="{{placeholder}}"></textarea>';
  var HELP_TEXT_TEMPLATE = '<div class="pf-c-form__helper-text gel-saml-form__helper-text">{{helpText}}</div>';
  var TOGGLE_TEMPLATE = [
    '<div class="gel-saml-toggle" data-gel-toggle="{{id}}" role="group" aria-label="{{label}}">',
    '  <input id="{{id}}" type="hidden" value="false" />',
    '  <button type="button" class="pf-c-button pf-m-secondary gel-saml-toggle__button" data-gel-toggle-value="true">On</button>',
    '  <button type="button" class="pf-c-button pf-m-secondary gel-saml-toggle__button" data-gel-toggle-value="false">Off</button>',
    '</div>'
  ].join("");

  var TOKEN_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

  var capturedToken = null;
  var capturedRefreshToken = null;
  var capturedClientId = null;
  var capturedIssuer = null;
  var capturedKeycloak = null;
  var currentRouteKey = null;
  var observedTokenVersion = 0;

  interceptFetch();
  interceptXmlHttpRequest();
  bootstrap();

  function bootstrap() {
    runOnce();
    window.addEventListener("hashchange", runOnce);
    window.addEventListener("popstate", runOnce);
    window.setInterval(runOnce, 1000);
  }

  function runOnce() {
    var context = resolveIdentityProviderContext();
    handleSamlCreateFormProxy(context);

    if (!context || context.action !== ROUTE_ACTION_DETAILS || context.providerId !== TARGET_PROVIDER_ID) {
      removeCustomTab();
      applyNativeSectionVisibility({
        tab: SETTINGS_TAB
      });
      restoreJumpToSectionVisibility();
      removePanel();
      currentRouteKey = null;
      return;
    }

    ensureCustomTab(context);

    var newRouteKey = [
      context.realm,
      context.providerId,
      context.alias,
      context.tab,
      context.action,
      String(isGelParamsView(context))
    ].join("|");
    if (currentRouteKey !== newRouteKey) {
      currentRouteKey = newRouteKey;
      syncGelView(context);
      return;
    }

    syncGelView(context);
  }

  function resolveIdentityProviderContext() {
    var hash = String(window.location.hash || "");
    var isHashNavigation = hash && hash.indexOf("#/") === 0;
    var rawPath = isHashNavigation
      ? hash.substring(1)
      : String(window.location.pathname || "") + String(window.location.search || "");
    var querySplit = rawPath.split("?");
    var pathWithoutQuery = querySplit[0];
    var queryString = querySplit.length > 1 ? querySplit.slice(1).join("?") : "";
    var segments = pathWithoutQuery.split("/").filter(Boolean);

    var markerIndex = segments.indexOf("identity-providers");
    if (markerIndex < 0) {
      return null;
    }

    var providerId = segments[markerIndex + 1] || "";
    var rawAlias = segments[markerIndex + 2] || "";
    var rawTab = segments[markerIndex + 3] || "";
    var action = rawAlias === ROUTE_ACTION_ADD ? ROUTE_ACTION_ADD : ROUTE_ACTION_DETAILS;
    var alias = action === ROUTE_ACTION_ADD ? "" : rawAlias;
    var tab = action === ROUTE_ACTION_ADD ? "" : rawTab;

    var realm = "";
    if (markerIndex >= 2 && segments[markerIndex - 2] === "realms") {
      realm = segments[markerIndex - 1];
    } else if (markerIndex >= 1) {
      realm = segments[markerIndex - 1];
    }

    if (!realm || !providerId || !rawAlias) {
      return null;
    }

    return {
      realm: realm,
      providerId: providerId,
      alias: decodeURIComponent(alias),
      tab: decodeURIComponent(tab),
      action: action,
      query: parseQueryParams(queryString),
      queryString: queryString,
      isHashNavigation: isHashNavigation
    };
  }

  function handleSamlCreateFormProxy(context) {
    if (!context) {
      if (isProxyActive() && !readProxyAlias()) {
        clearProxyState();
      }
      return;
    }

    if (context.action === ROUTE_ACTION_ADD && context.providerId === TARGET_PROVIDER_ID) {
      setProxyActive(true);
      setProxyAlias(null);
      navigateToIdentityProviderRoute(
        context,
        SAML_PROVIDER_ID,
        ROUTE_ACTION_ADD,
        null,
        withMergedQuery(context.query, {
          [PROXY_QUERY_FLAG]: PROXY_QUERY_ENABLED,
          [PROXY_QUERY_TARGET]: TARGET_PROVIDER_ID
        })
      );
      return;
    }

    if (context.action === ROUTE_ACTION_ADD && context.providerId === SAML_PROVIDER_ID) {
      if (context.query[PROXY_QUERY_FLAG] === PROXY_QUERY_ENABLED) {
        setProxyActive(true);
      } else if (isProxyActive() && !readProxyAlias()) {
        clearProxyState();
      }
      return;
    }

    if (!isProxyActive() || !readProxyAlias()) {
      return;
    }

    if (context.action !== ROUTE_ACTION_DETAILS || context.providerId !== SAML_PROVIDER_ID) {
      return;
    }

    if (context.alias !== readProxyAlias()) {
      return;
    }

    clearProxyState();
    navigateToIdentityProviderRoute(context, TARGET_PROVIDER_ID, ROUTE_ACTION_DETAILS, context.alias, null);
  }

  function navigateToIdentityProviderRoute(context, providerId, action, alias, queryObject) {
    var targetPath = buildIdentityProviderPath(context.realm, providerId, action, alias, context.tab);
    var targetQuery = queryObject ? new URLSearchParams(queryObject).toString() : "";
    var target = targetPath + (targetQuery ? "?" + targetQuery : "");

    if (context.isHashNavigation) {
      var currentHash = String(window.location.hash || "");
      if (currentHash === "#" + target) {
        return;
      }
      window.location.hash = "#" + target;
      return;
    }

    var currentLocation = String(window.location.pathname || "") + String(window.location.search || "");
    if (currentLocation === target) {
      return;
    }
    window.history.replaceState({}, "", target);
  }

  function buildIdentityProviderPath(realm, providerId, action, alias, tab) {
    var pathParts = [
      "",
      encodeURIComponent(String(realm || "")),
      "identity-providers",
      encodeURIComponent(String(providerId || ""))
    ];

    if (action === ROUTE_ACTION_ADD) {
      pathParts.push(ROUTE_ACTION_ADD);
      return pathParts.join("/");
    }

    pathParts.push(encodeURIComponent(String(alias || "")));
    if (tab) {
      pathParts.push(encodeURIComponent(String(tab)));
    }
    return pathParts.join("/");
  }

  function withMergedQuery(existingQuery, additions) {
    var merged = Object.assign({}, existingQuery || {});
    Object.keys(additions || {}).forEach(function (key) {
      var value = additions[key];
      if (value === null || typeof value === "undefined" || value === "") {
        delete merged[key];
        return;
      }
      merged[key] = String(value);
    });
    return merged;
  }

  function parseQueryParams(queryString) {
    var query = {};
    if (!queryString) {
      return query;
    }

    var params = new URLSearchParams(queryString);
    params.forEach(function (value, key) {
      query[key] = value;
    });
    return query;
  }

  function setProxyActive(active) {
    var storage = safeStorage(window.sessionStorage);
    if (!storage) {
      return;
    }

    if (active) {
      storage.setItem(PROXY_STORAGE_ACTIVE_KEY, "true");
      return;
    }

    storage.removeItem(PROXY_STORAGE_ACTIVE_KEY);
  }

  function isProxyActive() {
    var storage = safeStorage(window.sessionStorage);
    if (!storage) {
      return false;
    }
    return storage.getItem(PROXY_STORAGE_ACTIVE_KEY) === "true";
  }

  function setProxyAlias(alias) {
    var storage = safeStorage(window.sessionStorage);
    if (!storage) {
      return;
    }

    if (typeof alias === "string" && alias.trim() !== "") {
      storage.setItem(PROXY_STORAGE_ALIAS_KEY, alias.trim());
      return;
    }

    storage.removeItem(PROXY_STORAGE_ALIAS_KEY);
  }

  function readProxyAlias() {
    var storage = safeStorage(window.sessionStorage);
    if (!storage) {
      return "";
    }
    return String(storage.getItem(PROXY_STORAGE_ALIAS_KEY) || "");
  }

  function clearProxyState() {
    setProxyActive(false);
    setProxyAlias(null);
  }

  function syncGelView(context) {
    if (isGelParamsView(context)) {
      renderPanel(context);
      applyGelSectionVisibility();
      applyJumpToSectionVisibility();
      return;
    }

    applyNativeSectionVisibility(context);
    restoreJumpToSectionVisibility();
    hidePanel();
  }

  function isGelParamsView(context) {
    return context.tab === SETTINGS_TAB && context.query[GEL_TAB_QUERY_FLAG] === GEL_TAB_QUERY_VALUE;
  }

  function renderPanel(context) {
    var settingsSection = findSettingsSection();
    if (!settingsSection || !settingsSection.parentElement) {
      return;
    }

    var contextKey = [context.realm, context.alias].join("|");
    var mount = settingsSection.parentElement;
    var panel = document.getElementById(PANEL_ID);
    var isNewPanel = false;
    if (!panel) {
      isNewPanel = true;
      panel = document.createElement("section");
      panel.id = PANEL_ID;
      panel.className = "gel-saml-panel";
      panel.innerHTML = TEMPLATE_ENGINE.render(PANEL_TEMPLATE, {
        alias: escapeHtml(context.alias),
        fieldsMarkup: buildFieldGroupsMarkup()
      });
    }

    panel.hidden = false;

    if (panel.parentElement !== mount || panel.previousElementSibling !== settingsSection) {
      settingsSection.insertAdjacentElement("afterend", panel);
    }

    panel.setAttribute("data-gel-context", contextKey);

    hideMisleadingClientCredentialFields();
    bindPanelInteractions(panel);

    var saveButton = panel.querySelector("#" + SAVE_BUTTON_ID);
    if (saveButton && saveButton.getAttribute("data-gel-bound") !== "true") {
      saveButton.setAttribute("data-gel-bound", "true");
      saveButton.addEventListener("click", function () {
        void saveGelConfiguration(context);
      });
    }

    if (isNewPanel || panel.getAttribute("data-gel-loaded-context") !== contextKey) {
      panel.setAttribute("data-gel-loaded-context", "");
      void loadGelConfiguration(context).then(function () {
        panel.setAttribute("data-gel-loaded-context", contextKey);
      }).catch(function () {
        panel.setAttribute("data-gel-loaded-context", "");
      });
    }
  }

  function buildFieldGroupsMarkup() {
    var baseFields = FIELD_DEFINITIONS.filter(function (field) {
      return field.section === FIELD_SECTION_GENERAL || !field.section;
    });

    var extensionFields = FIELD_DEFINITIONS.filter(function (field) {
      return field.section === FIELD_SECTION_EXTENSIONS;
    });

    var markup = TEMPLATE_ENGINE.render(SECTION_TEMPLATE, {
      title: "General Params",
      contentMarkup: renderFieldGroups(baseFields)
    });

    if (extensionFields.length) {
      markup += TEMPLATE_ENGINE.render(SECTION_TEMPLATE, {
        title: "Extensions",
        contentMarkup: renderFieldGroups(extensionFields)
      });
    }

    return markup;
  }

  function renderFieldGroups(fields) {
    return (fields || []).map(function (field) {
      return TEMPLATE_ENGINE.render(FORM_GROUP_TEMPLATE, {
        inputId: escapeHtml(field.id),
        label: escapeHtml(field.label),
        controlMarkup: buildControlMarkup(field),
        helpMarkup: buildHelpMarkup(field.helpText)
      });
    }).join("");
  }

  function buildControlMarkup(field) {
    if (field.type === "select") {
      return TEMPLATE_ENGINE.render(SELECT_TEMPLATE, {
        id: escapeHtml(field.id),
        optionsMarkup: buildSelectOptionsMarkup(field.options || [])
      });
    }

    if (field.type === "textarea") {
      return TEMPLATE_ENGINE.render(TEXTAREA_TEMPLATE, {
        id: escapeHtml(field.id),
        placeholder: escapeHtml(field.placeholder || ""),
        rows: escapeHtml(field.rows || "4")
      });
    }

    if (field.type === "toggle") {
      return TEMPLATE_ENGINE.render(TOGGLE_TEMPLATE, {
        id: escapeHtml(field.id),
        label: escapeHtml(field.label)
      });
    }

    return TEMPLATE_ENGINE.render(INPUT_TEMPLATE, {
      id: escapeHtml(field.id),
      placeholder: escapeHtml(field.placeholder || "")
    });
  }

  function buildSelectOptionsMarkup(options) {
    return (options || []).map(function (option) {
      return TEMPLATE_ENGINE.render(SELECT_OPTION_TEMPLATE, {
        value: escapeHtml(option),
        label: escapeHtml(option)
      });
    }).join("");
  }

  function buildHelpMarkup(helpText) {
    if (!helpText) {
      return "";
    }

    return TEMPLATE_ENGINE.render(HELP_TEXT_TEMPLATE, {
      helpText: escapeHtml(helpText)
    });
  }

  function bindPanelInteractions(panel) {
    if (!panel || panel.getAttribute("data-gel-interactions-bound") === "true") {
      return;
    }

    panel.setAttribute("data-gel-interactions-bound", "true");
    panel.addEventListener("click", function (event) {
      var toggleButton = event.target && event.target.closest("[data-gel-toggle-value]");
      if (!toggleButton) {
        return;
      }

      var toggleGroup = toggleButton.closest("[data-gel-toggle]");
      if (!toggleGroup) {
        return;
      }

      var hiddenInput = toggleGroup.querySelector("input[type='hidden']");
      if (!hiddenInput) {
        return;
      }

      hiddenInput.value = toggleButton.getAttribute("data-gel-toggle-value") === "true" ? "true" : "false";
      syncToggleGroupState(toggleGroup);
    });

    var attributeSetNode = panel.querySelector("#" + GEL_KEYS.attributeSet);
    if (attributeSetNode) {
      attributeSetNode.addEventListener("change", function () {
        syncNativeAttributeSetField(attributeSetNode.value);
      });
    }

    syncAllToggleGroups(panel);
  }

  function removePanel() {
    var existing = document.getElementById(PANEL_ID);
    if (existing && existing.parentNode) {
      existing.parentNode.removeChild(existing);
    }
  }

  function hidePanel() {
    var panel = document.getElementById(PANEL_ID);
    if (panel) {
      panel.hidden = true;
    }
  }

  function findSettingsSection() {
    return document.getElementById(SETTINGS_SECTION_ID);
  }

  function applyGelSectionVisibility() {
    var managedSections = findManagedSections();
    if (!managedSections.length) {
      return;
    }

    for (var i = 0; i < managedSections.length; i++) {
      var section = managedSections[i];
      section.hidden = section.id !== PANEL_ID;
    }
  }

  function applyNativeSectionVisibility(context) {
    var managedSections = findManagedSections();
    if (!managedSections.length) {
      return;
    }

    var activeSectionId = buildNativeSectionId(context.tab);
    for (var i = 0; i < managedSections.length; i++) {
      var section = managedSections[i];
      if (section.id === PANEL_ID) {
        section.hidden = true;
        continue;
      }

      section.hidden = section.id !== activeSectionId;
    }
  }

  function findManagedSections() {
    var settingsSection = findSettingsSection();
    if (!settingsSection || !settingsSection.parentElement) {
      return [];
    }

    var managedSections = [];
    var siblings = settingsSection.parentElement.children;
    for (var i = 0; i < siblings.length; i++) {
      var sibling = siblings[i];
      if (!sibling || sibling.tagName !== "SECTION") {
        continue;
      }
      if (sibling.id === PANEL_ID || String(sibling.id || "").indexOf(TAB_SECTION_ID_PREFIX) === 0) {
        managedSections.push(sibling);
      }
    }
    return managedSections;
  }

  function buildNativeSectionId(tab) {
    return TAB_SECTION_ID_PREFIX + String(tab || SETTINGS_TAB);
  }

  function findJumpToSectionContainer() {
    var jumpSection = document.querySelector(".kc-scroll-form--sticky");
    if (!jumpSection) {
      return null;
    }

    return jumpSection.closest(".pf-v5-l-grid__item")
      || jumpSection.closest(".pf-l-grid__item")
      || jumpSection.closest(".pf-c-sidebar__panel")
      || jumpSection.parentElement;
  }

  function applyJumpToSectionVisibility() {
    var jumpContainer = findJumpToSectionContainer();
    if (!jumpContainer) {
      return;
    }

    if (!jumpContainer.hasAttribute(JUMP_HIDDEN_STATE_ATTRIBUTE)) {
      jumpContainer.setAttribute(JUMP_HIDDEN_STATE_ATTRIBUTE, jumpContainer.hasAttribute("hidden") ? "true" : "false");
    }
    jumpContainer.hidden = true;
  }

  function restoreJumpToSectionVisibility() {
    var jumpContainer = findJumpToSectionContainer();
    if (!jumpContainer) {
      return;
    }

    var previousHidden = jumpContainer.getAttribute(JUMP_HIDDEN_STATE_ATTRIBUTE);
    if (previousHidden === "true") {
      jumpContainer.hidden = true;
    } else {
      jumpContainer.hidden = false;
    }
    jumpContainer.removeAttribute(JUMP_HIDDEN_STATE_ATTRIBUTE);
  }

  function ensureCustomTab(context) {
    var settingsTabAnchor = findSettingsTabAnchor();
    if (!settingsTabAnchor) {
      return;
    }

    var settingsTabItem = settingsTabAnchor.closest("li") || settingsTabAnchor.parentElement;
    if (!settingsTabItem || !settingsTabItem.parentElement) {
      return;
    }

    var customTabItem = document.getElementById(CUSTOM_TAB_ID);
    if (!customTabItem) {
      customTabItem = settingsTabItem.cloneNode(true);
      customTabItem.id = CUSTOM_TAB_ID;
      settingsTabItem.insertAdjacentElement("afterend", customTabItem);
    }

    var customTabAnchor = customTabItem.querySelector("a, button");
    if (!customTabAnchor) {
      return;
    }

    var gelParamsUrl = buildGelParamsUrl(context);
    customTabAnchor.textContent = "Gel Params";
    if (customTabAnchor.tagName.toLowerCase() === "a") {
      customTabAnchor.setAttribute("href", gelParamsUrl);
    }

    customTabAnchor.onclick = function (event) {
      event.preventDefault();
      navigateToGelParams(context);
    };

    updateSettingsTabTarget(settingsTabAnchor, context);
    updateTabVisualState(settingsTabItem, settingsTabAnchor, !isGelParamsView(context) && context.tab === SETTINGS_TAB);
    updateTabVisualState(customTabItem, customTabAnchor, isGelParamsView(context));
  }

  function removeCustomTab() {
    var customTabItem = document.getElementById(CUSTOM_TAB_ID);
    if (customTabItem && customTabItem.parentElement) {
      customTabItem.parentElement.removeChild(customTabItem);
    }
  }

  function findSettingsTabAnchor() {
    var anchors = document.querySelectorAll("a[href], button");
    for (var i = 0; i < anchors.length; i++) {
      var anchor = anchors[i];
      var text = String(anchor.textContent || "").replace(/\s+/g, " ").trim().toLowerCase();
      if (text === SETTINGS_TAB) {
        return anchor;
      }
    }
    return null;
  }

  function updateSettingsTabTarget(settingsTabAnchor, context) {
    var settingsUrl = buildSettingsUrl(context);
    if (settingsTabAnchor.tagName.toLowerCase() === "a") {
      settingsTabAnchor.setAttribute("href", settingsUrl);
    }

    settingsTabAnchor.onclick = function (event) {
      if (!isGelParamsView(context)) {
        return;
      }
      event.preventDefault();
      navigateToSettings(context);
    };
  }

  function updateTabVisualState(tabItem, tabAnchor, active) {
    if (!tabItem || !tabAnchor) {
      return;
    }

    toggleCurrentClass(tabItem, active);
    toggleCurrentClass(tabAnchor, active);

    if (active) {
      tabAnchor.setAttribute("aria-current", "page");
      tabAnchor.setAttribute("tabindex", "0");
      return;
    }

    tabAnchor.removeAttribute("aria-current");
  }

  function toggleCurrentClass(node, active) {
    if (!node) {
      return;
    }

    node.classList.toggle("pf-m-current", active);
    node.classList.toggle("pf-v5-m-current", active);
    node.classList.toggle("gel-saml-tab-current", active);
  }

  function buildGelParamsUrl(context) {
    return buildConsoleUrl(context, SETTINGS_TAB, withMergedQuery(context.query, {
      [GEL_TAB_QUERY_FLAG]: GEL_TAB_QUERY_VALUE
    }));
  }

  function buildSettingsUrl(context) {
    return buildConsoleUrl(context, SETTINGS_TAB, withMergedQuery(context.query, {
      [GEL_TAB_QUERY_FLAG]: null
    }));
  }

  function navigateToGelParams(context) {
    navigateWithinConsole(buildGelParamsUrl(context), context.isHashNavigation);
  }

  function navigateToSettings(context) {
    navigateWithinConsole(buildSettingsUrl(context), context.isHashNavigation);
  }

  function buildConsoleUrl(context, tab, queryObject) {
    var targetPath = buildIdentityProviderPath(context.realm, context.providerId, ROUTE_ACTION_DETAILS, context.alias, tab);
    var targetQuery = queryObject ? new URLSearchParams(queryObject).toString() : "";
    return targetPath + (targetQuery ? "?" + targetQuery : "");
  }

  function navigateWithinConsole(url, isHashNavigation) {
    if (isHashNavigation) {
      if (String(window.location.hash || "") !== "#" + url) {
        window.location.hash = "#" + url;
      }
      return;
    }

    var currentLocation = String(window.location.pathname || "") + String(window.location.search || "");
    if (currentLocation !== url) {
      window.history.pushState({}, "", url);
      runOnce();
    }
  }

  function hideMisleadingClientCredentialFields() {
    var labelsToHide = ["Client ID", "Client Secret", "ClientID", "ClientSecret"];
    var labels = document.querySelectorAll("label");

    labels.forEach(function (label) {
      var text = String(label.textContent || "").replace(/\s+/g, " ").trim();
      if (labelsToHide.indexOf(text) === -1) {
        return;
      }

      var container = label.closest(".pf-v5-c-form__group") || label.closest(".pf-c-form__group") || label.parentElement;
      if (container && !container.hasAttribute("data-gel-hidden")) {
        container.setAttribute("data-gel-hidden", "true");
        container.classList.add("gel-saml-hidden");
      }
    });
  }

  function getStatusNode() {
    return document.getElementById(STATUS_ID);
  }

  function setStatus(message, type) {
    var status = getStatusNode();
    if (!status) {
      return;
    }

    status.textContent = message;
    status.classList.remove("gel-saml-status--error", "gel-saml-status--success", "gel-saml-status--info");
    status.classList.add("gel-saml-status--" + type);
  }

  function setLoading(isLoading) {
    var saveButton = document.getElementById(SAVE_BUTTON_ID);
    if (!saveButton) {
      return;
    }
    saveButton.disabled = isLoading;
  }

  async function loadGelConfiguration(context) {
    setLoading(true);
    setStatus("Caricamento configurazione GEL in corso...", "info");

    try {
      var representation = await loadIdentityProviderRepresentation(context.realm, context.alias);
      fillFormFromConfig(representation && representation.config ? representation.config : {});
      setStatus("Configurazione GEL caricata.", "success");
    } catch (error) {
      setStatus("Impossibile leggere la configurazione GEL: " + toErrorMessage(error), "error");
    } finally {
      setLoading(false);
    }
  }

  async function saveGelConfiguration(context) {
    setLoading(true);
    setStatus("Salvataggio configurazione GEL in corso...", "info");

    try {
      var representation = await loadIdentityProviderRepresentation(context.realm, context.alias);
      var existingConfig = representation.config || {};
      representation.config = mergeGelConfig(existingConfig, readFormValues());

      await updateIdentityProviderRepresentation(context.realm, context.alias, representation);
      setStatus("Configurazione GEL salvata con successo.", "success");
    } catch (error) {
      setStatus("Errore durante il salvataggio GEL: " + toErrorMessage(error), "error");
    } finally {
      setLoading(false);
    }
  }

  function fillFormFromConfig(config) {
    var attributeSet = readAttributeSetValue(config);
    selectValue(GEL_KEYS.attributeSet, attributeSet);
    syncNativeAttributeSetField(attributeSet);

    selectValue(GEL_KEYS.spidLevel, readConfigValue(config, GEL_KEYS.spidLevel, DEFAULT_SPID_LEVEL));
    inputValue(GEL_KEYS.spNameQualifier, readConfigValue(config, GEL_KEYS.spNameQualifier, ""));

    BOOLEAN_FIELDS.forEach(function (field) {
      checkboxValue(field, readBoolean(config[field]));
    });

    inputValue(GEL_KEYS.customExtensions, readConfigValue(config, GEL_KEYS.customExtensions, ""));
  }

  function readFormValues() {
    var values = {};
    var attributeSet = valueOf(GEL_KEYS.attributeSet);

    values[GEL_KEYS.attributeSet] = attributeSet;
    values[STANDARD_SAML_ATTRIBUTE_SET_KEY] = attributeSet;
    values[GEL_KEYS.spidLevel] = valueOf(GEL_KEYS.spidLevel);
    values[GEL_KEYS.spNameQualifier] = valueOf(GEL_KEYS.spNameQualifier);
    values[GEL_KEYS.customExtensions] = valueOf(GEL_KEYS.customExtensions);

    BOOLEAN_FIELDS.forEach(function (field) {
      values[field] = checkedOf(field) ? "true" : "false";
    });

    return values;
  }

  function mergeGelConfig(existingConfig, gelValues) {
    var merged = Object.assign({}, existingConfig);

    Object.keys(gelValues).forEach(function (key) {
      var value = gelValues[key];
      if (typeof value !== "string") {
        delete merged[key];
        return;
      }

      var trimmed = value.trim();
      if (trimmed === "") {
        delete merged[key];
        return;
      }

      merged[key] = trimmed;
    });

    return merged;
  }

  function readAttributeSetValue(config) {
    return readConfigValue(
      config,
      GEL_KEYS.attributeSet,
      readConfigValue(config, STANDARD_SAML_ATTRIBUTE_SET_KEY, DEFAULT_GEL_ATTRIBUTE_SET)
    );
  }

  function syncNativeAttributeSetField(value) {
    selectValue(STANDARD_SAML_ATTRIBUTE_SET_KEY, value);
    inputValue(STANDARD_SAML_ATTRIBUTE_SET_KEY, value);
  }

  async function loadIdentityProviderRepresentation(realm, alias) {
    var url = buildIdentityProviderUrl(realm, alias);
    var response = await authorizedFetch(url, {
      method: "GET"
    });

    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    return response.json();
  }

  async function updateIdentityProviderRepresentation(realm, alias, representation) {
    var url = buildIdentityProviderUrl(realm, alias);
    var response = await authorizedFetch(url, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(representation)
    });

    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }
  }

  async function authorizedFetch(url, init) {
    var options = Object.assign({}, init || {});
    options.credentials = "include";

    var headers = new Headers(options.headers || {});
    var token = await resolveValidAccessToken();
    if (!token) {
      token = await waitForAccessToken(1500);
    }
    if (token) {
      headers.set("Authorization", "Bearer " + token);
    }
    headers.set("Accept", "application/json");
    options.headers = headers;

    var response = await window.fetch(url, options);
    if (response.status !== 401) {
      return response;
    }

    // Retry once after observing a newer bearer token from native console traffic.
    var previousObservedTokenVersion = observedTokenVersion;
    capturedToken = null;
    var refreshedToken = await refreshAccessTokenIfPossible();
    if (!refreshedToken) {
      refreshedToken = await waitForObservedTokenRefresh(previousObservedTokenVersion, 4000);
    }
    if (!refreshedToken) {
      refreshedToken = await waitForAccessToken(1500);
    }
    if (!refreshedToken || refreshedToken === token) {
      return response;
    }

    var retryHeaders = new Headers(options.headers || {});
    retryHeaders.set("Authorization", "Bearer " + refreshedToken);
    options.headers = retryHeaders;
    return window.fetch(url, options);
  }

  async function resolveValidAccessToken() {
    var token = resolveAccessToken();
    if (!token) {
      return null;
    }

    // Proactively refresh if the token is near expiration to avoid 401 on save.
    if (!isTokenNearExpiry(token, 20)) {
      return token;
    }

    var refreshedToken = await refreshAccessTokenIfPossible();
    return refreshedToken || token;
  }

  function resolveAccessToken() {
    var keycloakToken = extractTokenFromKeycloak(resolveKeycloakInstance());
    if (keycloakToken) {
      rememberObservedToken(keycloakToken);
      return keycloakToken;
    }

    if (capturedToken) {
      return capturedToken;
    }

    var authContext = discoverAuthContextFromStorage();
    if (authContext) {
      hydrateCapturedAuthContext(authContext);
      if (authContext.accessToken) {
        return authContext.accessToken;
      }
    }

    return capturedToken;
  }

  async function waitForAccessToken(timeoutMs) {
    var startedAt = Date.now();
    var timeout = typeof timeoutMs === "number" ? timeoutMs : 1500;

    while ((Date.now() - startedAt) < timeout) {
      var token = resolveAccessToken();
      if (token) {
        return token;
      }
      await sleep(100);
    }

    return resolveAccessToken();
  }

  function sleep(ms) {
    return new Promise(function (resolve) {
      window.setTimeout(resolve, ms);
    });
  }

  function interceptFetch() {
    if (typeof window.fetch !== "function") {
      return;
    }

    var originalFetch = window.fetch.bind(window);

    window.fetch = function patchedFetch(input, init) {
      var rewrittenRequest = rewriteIdentityProviderCreateRequest(input, init);
      captureAuthorizationHeader(rewrittenRequest.input, rewrittenRequest.init);
      return originalFetch(rewrittenRequest.input, rewrittenRequest.init);
    };
  }

  function interceptXmlHttpRequest() {
    if (typeof XMLHttpRequest === "undefined") {
      return;
    }

    var originalOpen = XMLHttpRequest.prototype.open;
    var originalSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

    XMLHttpRequest.prototype.open = function patchedOpen(method, url) {
      this.__gelRequestUrl = String(url || "");
      this.__gelRequestMethod = String(method || "GET").toUpperCase();
      return originalOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.setRequestHeader = function patchedSetRequestHeader(name, value) {
      if (String(name || "").toLowerCase() === "authorization") {
        var token = String(value || "").replace(/^Bearer\s+/i, "").trim();
        if (TOKEN_PATTERN.test(token)) {
          rememberObservedToken(token);
        }
      }
      return originalSetRequestHeader.apply(this, arguments);
    };
  }

  function rewriteIdentityProviderCreateRequest(input, init) {
    if (!isProxyCreateRouteActive()) {
      return {
        input: input,
        init: init
      };
    }

    var requestInfo = extractRequestInfo(input, init);
    if (!requestInfo) {
      return {
        input: input,
        init: init
      };
    }

    if (requestInfo.method !== "POST" || !isIdentityProviderCreateRequestUrl(requestInfo.url)) {
      return {
        input: input,
        init: init
      };
    }

    if (typeof requestInfo.body !== "string" || requestInfo.body.trim() === "") {
      return {
        input: input,
        init: init
      };
    }

    var payload;
    try {
      payload = JSON.parse(requestInfo.body);
    } catch (error) {
      return {
        input: input,
        init: init
      };
    }

    if (!payload || payload.providerId !== SAML_PROVIDER_ID) {
      return {
        input: input,
        init: init
      };
    }

    payload.providerId = TARGET_PROVIDER_ID;
    if (typeof payload.alias === "string" && payload.alias.trim() !== "") {
      setProxyAlias(payload.alias.trim());
    }

    var rewrittenInit = Object.assign({}, init || {});
    rewrittenInit.method = requestInfo.method;
    rewrittenInit.body = JSON.stringify(payload);

    if (!rewrittenInit.headers && input && typeof Request !== "undefined" && input instanceof Request) {
      rewrittenInit.headers = input.headers;
    }

    return {
      input: requestInfo.url,
      init: rewrittenInit
    };
  }

  function isProxyCreateRouteActive() {
    var context = resolveIdentityProviderContext();
    if (!context) {
      return false;
    }

    return context.action === ROUTE_ACTION_ADD
      && context.providerId === SAML_PROVIDER_ID
      && context.query[PROXY_QUERY_FLAG] === PROXY_QUERY_ENABLED;
  }

  function extractRequestInfo(input, init) {
    var url = "";
    var method = "GET";
    var body = null;

    if (typeof input === "string") {
      url = input;
    } else if (input && typeof Request !== "undefined" && input instanceof Request) {
      url = String(input.url || "");
      method = String(input.method || "GET");
    } else if (input && typeof input.url === "string") {
      url = String(input.url);
      method = String(input.method || "GET");
    }

    if (init) {
      if (init.method) {
        method = String(init.method);
      }
      if (typeof init.body === "string") {
        body = init.body;
      }
    }

    return {
      url: url,
      method: method.toUpperCase(),
      body: body
    };
  }

  function isIdentityProviderCreateRequestUrl(url) {
    if (!url) {
      return false;
    }

    try {
      var absoluteUrl = new URL(url, window.location.origin);
      return /\/identity-provider\/instances\/?$/.test(absoluteUrl.pathname);
    } catch (error) {
      return /\/identity-provider\/instances\/?$/.test(String(url));
    }
  }

  function captureAuthorizationHeader(input, init) {
    var headerValue = null;

    if (init && init.headers) {
      headerValue = readAuthorizationFromHeaders(init.headers);
    }

    if (!headerValue && input && typeof Request !== "undefined" && input instanceof Request) {
      headerValue = input.headers ? input.headers.get("Authorization") : null;
    }

    if (!headerValue) {
      return;
    }

    var token = headerValue.replace(/^Bearer\s+/i, "").trim();
    if (TOKEN_PATTERN.test(token)) {
      rememberObservedToken(token);
    }
  }

  function rememberObservedToken(token) {
    if (!TOKEN_PATTERN.test(String(token || ""))) {
      return;
    }

    if (capturedToken !== token) {
      observedTokenVersion += 1;
    }
    capturedToken = token;
    hydrateCapturedAuthContext(resolveAuthContextFromToken(token));
  }

  async function waitForObservedTokenRefresh(previousVersion, timeoutMs) {
    var startedAt = Date.now();
    var timeout = typeof timeoutMs === "number" ? timeoutMs : 4000;

    while ((Date.now() - startedAt) < timeout) {
      if (observedTokenVersion > previousVersion && capturedToken) {
        return capturedToken;
      }
      await sleep(100);
    }

    if (observedTokenVersion > previousVersion && capturedToken) {
      return capturedToken;
    }
    return null;
  }

  function readAuthorizationFromHeaders(headers) {
    if (headers instanceof Headers) {
      return headers.get("Authorization");
    }

    if (Array.isArray(headers)) {
      for (var i = 0; i < headers.length; i++) {
        var pair = headers[i];
        if (!pair || pair.length < 2) {
          continue;
        }
        if (String(pair[0]).toLowerCase() === "authorization") {
          return String(pair[1]);
        }
      }
      return null;
    }

    if (typeof headers === "object") {
      var keys = Object.keys(headers);
      for (var j = 0; j < keys.length; j++) {
        var key = keys[j];
        if (String(key).toLowerCase() === "authorization") {
          return String(headers[key]);
        }
      }
    }

    return null;
  }

  async function refreshAccessTokenIfPossible() {
    var keycloakToken = await refreshUsingKeycloakInstance();
    if (keycloakToken) {
      return keycloakToken;
    }

    var refreshToken = resolveRefreshToken();
    if (!refreshToken) {
      return null;
    }

    var token = resolveAccessToken();
    var tokenContext = resolveAuthContextFromToken(token);
    var issuer = capturedIssuer || tokenContext.issuer;
    var clientId = capturedClientId || tokenContext.clientId || "security-admin-console";
    if (!issuer) {
      return null;
    }

    var tokenEndpoint = trimTrailingSlash(issuer) + "/protocol/openid-connect/token";
    var body = new URLSearchParams();
    body.set("grant_type", "refresh_token");
    body.set("client_id", clientId);
    body.set("refresh_token", refreshToken);

    try {
      var response = await window.fetch(tokenEndpoint, {
        method: "POST",
        credentials: "include",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept": "application/json"
        },
        body: body.toString()
      });

      if (!response.ok) {
        return null;
      }

      var payload = await response.json();
      if (!payload || !TOKEN_PATTERN.test(String(payload.access_token || ""))) {
        return null;
      }

      rememberObservedToken(payload.access_token);
      if (payload.refresh_token && TOKEN_PATTERN.test(String(payload.refresh_token))) {
        capturedRefreshToken = payload.refresh_token;
      }

      if (payload.iss && typeof payload.iss === "string") {
        capturedIssuer = payload.iss;
      }
      if (payload.client_id && typeof payload.client_id === "string") {
        capturedClientId = payload.client_id;
      }

      return payload.access_token;
    } catch (error) {
      return null;
    }
  }

  function resolveRefreshToken() {
    if (capturedRefreshToken && TOKEN_PATTERN.test(String(capturedRefreshToken))) {
      return capturedRefreshToken;
    }

    var authContext = discoverAuthContextFromStorage();
    if (!authContext || !authContext.refreshToken) {
      return null;
    }

    hydrateCapturedAuthContext(authContext);
    return capturedRefreshToken;
  }

  function discoverAuthContextFromStorage() {
    var storages = [safeStorage(window.localStorage), safeStorage(window.sessionStorage)];

    for (var i = 0; i < storages.length; i++) {
      var storage = storages[i];
      if (!storage) {
        continue;
      }

      for (var index = 0; index < storage.length; index++) {
        var key = storage.key(index);
        if (!key) {
          continue;
        }

        var rawValue = storage.getItem(key);
        var authContext = findAuthContextInValue(rawValue);
        if (authContext && (authContext.accessToken || authContext.refreshToken)) {
          return authContext;
        }
      }
    }

    return null;
  }

  async function refreshUsingKeycloakInstance() {
    var keycloak = resolveKeycloakInstance();
    if (!keycloak || typeof keycloak.updateToken !== "function") {
      return null;
    }

    try {
      await keycloak.updateToken(20);
      var token = extractTokenFromKeycloak(keycloak);
      if (!token) {
        return null;
      }

      rememberObservedToken(token);
      if (TOKEN_PATTERN.test(String(keycloak.refreshToken || ""))) {
        capturedRefreshToken = String(keycloak.refreshToken);
      }
      return token;
    } catch (error) {
      return null;
    }
  }

  function resolveKeycloakInstance() {
    if (isKeycloakCandidate(capturedKeycloak)) {
      return capturedKeycloak;
    }

    var windowCandidate = findKeycloakInWindow();
    if (isKeycloakCandidate(windowCandidate)) {
      capturedKeycloak = windowCandidate;
      return capturedKeycloak;
    }

    var reactCandidate = findKeycloakInReactFiberTree();
    if (isKeycloakCandidate(reactCandidate)) {
      capturedKeycloak = reactCandidate;
      return capturedKeycloak;
    }

    return null;
  }

  function extractTokenFromKeycloak(keycloak) {
    if (!isKeycloakCandidate(keycloak)) {
      return null;
    }

    var token = String(keycloak.token || "").trim();
    return TOKEN_PATTERN.test(token) ? token : null;
  }

  function findKeycloakInWindow() {
    var candidates = [
      window.keycloak,
      window.kc,
      window.__keycloak,
      window.Keycloak
    ];

    for (var i = 0; i < candidates.length; i++) {
      if (isKeycloakCandidate(candidates[i])) {
        return candidates[i];
      }
    }

    return null;
  }

  function findKeycloakInReactFiberTree() {
    var rootFiber = findReactRootFiber();
    if (!rootFiber) {
      return null;
    }

    var queue = [rootFiber];
    var visited = [];
    var maxNodes = 12000;

    while (queue.length > 0 && visited.length < maxNodes) {
      var node = queue.shift();
      if (!node || visited.indexOf(node) >= 0) {
        continue;
      }

      visited.push(node);
      var fromProps = readKeycloakFromValue(node.memoizedProps);
      if (fromProps) {
        return fromProps;
      }

      var fromState = readKeycloakFromValue(node.memoizedState);
      if (fromState) {
        return fromState;
      }

      if (node.child) {
        queue.push(node.child);
      }
      if (node.sibling) {
        queue.push(node.sibling);
      }
    }

    return null;
  }

  function findReactRootFiber() {
    var appRoot = document.getElementById("app");
    if (!appRoot) {
      return null;
    }

    var keys = Object.keys(appRoot);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      if (key.indexOf("__reactContainer$") !== 0 && key.indexOf("__reactFiber$") !== 0) {
        continue;
      }

      var candidate = appRoot[key];
      if (!candidate) {
        continue;
      }

      if (candidate.current) {
        return candidate.current;
      }
      return candidate;
    }

    return null;
  }

  function readKeycloakFromValue(value) {
    if (!value) {
      return null;
    }

    if (isKeycloakCandidate(value.keycloak)) {
      return value.keycloak;
    }

    if (isKeycloakCandidate(value.value && value.value.keycloak)) {
      return value.value.keycloak;
    }

    return null;
  }

  function isKeycloakCandidate(candidate) {
    return Boolean(candidate)
      && typeof candidate === "object"
      && typeof candidate.updateToken === "function"
      && typeof candidate.login === "function";
  }

  function safeStorage(storage) {
    try {
      var length = storage.length;
      if (typeof length === "number") {
        return storage;
      }
    } catch (error) {
      return null;
    }
    return null;
  }

  function findAuthContextInValue(rawValue) {
    if (!rawValue) {
      return null;
    }

    if (TOKEN_PATTERN.test(rawValue.trim())) {
      return resolveAuthContextFromToken(rawValue.trim());
    }

    var parsed;
    try {
      parsed = JSON.parse(rawValue);
    } catch (error) {
      return null;
    }

    return findAuthContextInObject(parsed);
  }

  function findAuthContextInObject(value) {
    if (!value) {
      return null;
    }

    if (typeof value === "string") {
      var candidate = value.trim();
      if (TOKEN_PATTERN.test(candidate)) {
        return resolveAuthContextFromToken(candidate);
      }
      return null;
    }

    if (Array.isArray(value)) {
      for (var i = 0; i < value.length; i++) {
        var itemContext = findAuthContextInObject(value[i]);
        if (itemContext && (itemContext.accessToken || itemContext.refreshToken)) {
          return itemContext;
        }
      }
      return null;
    }

    if (typeof value === "object") {
      var accessToken = firstTokenValue(value, ["token", "accessToken", "kcToken", "authToken", "access_token"]);
      var refreshToken = firstTokenValue(value, ["refreshToken", "kcRefreshToken", "refresh_token"]);
      var clientId = firstStringValue(value, ["clientId", "client_id", "azp"]);
      var issuer = firstStringValue(value, ["issuer", "iss", "authServerUrl"]);

      if (accessToken || refreshToken) {
        var contextFromToken = resolveAuthContextFromToken(accessToken);
        return {
          accessToken: accessToken || contextFromToken.accessToken || null,
          refreshToken: refreshToken || null,
          clientId: clientId || contextFromToken.clientId || null,
          issuer: issuer || contextFromToken.issuer || null
        };
      }

      var keys = Object.keys(value);
      for (var k = 0; k < keys.length; k++) {
        var nestedContext = findAuthContextInObject(value[keys[k]]);
        if (nestedContext && (nestedContext.accessToken || nestedContext.refreshToken)) {
          return nestedContext;
        }
      }
    }

    return null;
  }

  function firstTokenValue(source, keys) {
    var value = firstStringValue(source, keys);
    if (!value) {
      return null;
    }
    var trimmed = value.trim();
    return TOKEN_PATTERN.test(trimmed) ? trimmed : null;
  }

  function firstStringValue(source, keys) {
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      if (!Object.prototype.hasOwnProperty.call(source, key)) {
        continue;
      }

      var value = source[key];
      if (typeof value === "string" && value.trim() !== "") {
        return value.trim();
      }
    }
    return null;
  }

  function resolveAuthContextFromToken(token) {
    if (!TOKEN_PATTERN.test(String(token || ""))) {
      return {
        accessToken: null,
        refreshToken: null,
        clientId: null,
        issuer: null
      };
    }

    var payload = decodeJwtPayload(token);
    return {
      accessToken: token,
      refreshToken: null,
      clientId: payload && typeof payload.azp === "string" ? payload.azp : null,
      issuer: payload && typeof payload.iss === "string" ? payload.iss : null
    };
  }

  function hydrateCapturedAuthContext(context) {
    if (!context) {
      return;
    }

    if (context.accessToken && TOKEN_PATTERN.test(String(context.accessToken))) {
      capturedToken = context.accessToken;
    }
    if (context.refreshToken && TOKEN_PATTERN.test(String(context.refreshToken))) {
      capturedRefreshToken = context.refreshToken;
    }
    if (context.clientId && typeof context.clientId === "string") {
      capturedClientId = context.clientId;
    }
    if (context.issuer && typeof context.issuer === "string") {
      capturedIssuer = context.issuer;
    }
  }

  function isTokenNearExpiry(token, skewSeconds) {
    var payload = decodeJwtPayload(token);
    if (!payload || typeof payload.exp !== "number") {
      return false;
    }

    var now = Math.floor(Date.now() / 1000);
    var skew = typeof skewSeconds === "number" ? skewSeconds : 0;
    return payload.exp <= (now + skew);
  }

  function decodeJwtPayload(token) {
    if (!TOKEN_PATTERN.test(String(token || ""))) {
      return null;
    }

    var parts = String(token).split(".");
    if (parts.length < 2) {
      return null;
    }

    try {
      var payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
      while (payload.length % 4 !== 0) {
        payload += "=";
      }

      return JSON.parse(window.atob(payload));
    } catch (error) {
      return null;
    }
  }

  function buildIdentityProviderUrl(realm, alias) {
    var base = resolveAdminApiBaseUrl();
    return joinUrl(base, "realms", realm, "identity-provider", "instances", alias);
  }

  function resolveAdminApiBaseUrl() {
    var environment = readEnvironment();

    if (environment.adminBaseUrl) {
      return trimTrailingSlash(toAbsoluteUrl(environment.adminBaseUrl, window.location.origin));
    }

    if (environment.authServerUrl) {
      return trimTrailingSlash(toAbsoluteUrl(environment.authServerUrl, window.location.origin)) + "/admin";
    }

    if (environment.serverBaseUrl) {
      return trimTrailingSlash(toAbsoluteUrl(environment.serverBaseUrl, window.location.origin)) + "/admin";
    }

    return trimTrailingSlash(window.location.origin) + "/admin";
  }

  function readEnvironment() {
    var node = document.getElementById("environment");
    if (!node || !node.textContent) {
      return {};
    }

    try {
      return JSON.parse(node.textContent);
    } catch (error) {
      return {};
    }
  }

  function toAbsoluteUrl(value, base) {
    try {
      return new URL(value, base).toString();
    } catch (error) {
      return value;
    }
  }

  function joinUrl(base) {
    var pathParts = Array.prototype.slice.call(arguments, 1).map(function (part) {
      return encodeURIComponent(String(part || "").trim());
    });
    return trimTrailingSlash(base) + "/" + pathParts.join("/");
  }

  function trimTrailingSlash(value) {
    return String(value || "").replace(/\/+$/, "");
  }

  function readConfigValue(config, key, fallback) {
    var value = config[key];
    return typeof value === "string" ? value : fallback;
  }

  function readBoolean(value) {
    return String(value).toLowerCase() === "true";
  }

  function selectValue(id, value) {
    var node = document.getElementById(id);
    if (node) {
      node.value = value;
    }
  }

  function inputValue(id, value) {
    var node = document.getElementById(id);
    if (node) {
      node.value = value;
    }
  }

  function checkboxValue(id, checked) {
    var node = document.getElementById(id);
    if (node) {
      if (String(node.type || "").toLowerCase() === "checkbox") {
        node.checked = checked;
      } else {
        node.value = checked ? "true" : "false";
        syncToggleGroupState(node.closest("[data-gel-toggle]"));
      }
    }
  }

  function valueOf(id) {
    var node = document.getElementById(id);
    return node ? String(node.value || "") : "";
  }

  function checkedOf(id) {
    var node = document.getElementById(id);
    if (!node) {
      return false;
    }

    if (String(node.type || "").toLowerCase() === "checkbox") {
      return Boolean(node.checked);
    }

    return String(node.value || "").toLowerCase() === "true";
  }

  function syncAllToggleGroups(scope) {
    var root = scope || document;
    var toggleGroups = root.querySelectorAll("[data-gel-toggle]");
    for (var i = 0; i < toggleGroups.length; i++) {
      syncToggleGroupState(toggleGroups[i]);
    }
  }

  function syncToggleGroupState(toggleGroup) {
    if (!toggleGroup) {
      return;
    }

    var hiddenInput = toggleGroup.querySelector("input[type='hidden']");
    if (!hiddenInput) {
      return;
    }

    var currentValue = String(hiddenInput.value || "false").toLowerCase() === "true" ? "true" : "false";
    var buttons = toggleGroup.querySelectorAll("[data-gel-toggle-value]");

    for (var i = 0; i < buttons.length; i++) {
      var button = buttons[i];
      var isActive = button.getAttribute("data-gel-toggle-value") === currentValue;
      button.classList.toggle("pf-m-primary", isActive);
      button.classList.toggle("pf-m-secondary", !isActive);
      button.classList.toggle("gel-saml-toggle__button--active", isActive);
      button.setAttribute("aria-pressed", isActive ? "true" : "false");
    }
  }

  function toErrorMessage(error) {
    if (!error) {
      return "errore sconosciuto";
    }
    if (typeof error.message === "string") {
      return error.message;
    }
    return String(error);
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
})();
