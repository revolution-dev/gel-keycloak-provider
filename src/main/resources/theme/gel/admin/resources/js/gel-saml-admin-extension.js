/*
 * GEL SAML Admin Console extension.
 *
 * Strategy:
 * - UI create route proxy: /identity-providers/gel-saml/add -> /identity-providers/saml/add
 *   so Keycloak renders the full native SAML create form.
 * - Keep Keycloak native submit flow and native HTTP calls.
 * - Intercept create/import payloads and rewrite only providerId to gel-saml.
 * - Group GEL fields in a dedicated "GEL settings" section in Provider details.
 */
(function () {
  "use strict";

  var TARGET_PROVIDER_ID = "gel-saml";
  var SAML_PROVIDER_ID = "saml";
  var ROUTE_ACTION_ADD = "add";
  var ROUTE_ACTION_DETAILS = "details";
  var ROUTE_SEGMENT_IDENTITY_PROVIDERS = "identity-providers";
  var ROUTE_SEGMENT_IDENTITY_PROVIDER = "identity-provider";

  var PROXY_QUERY_FLAG = "gelSamlProxy";
  var PROXY_QUERY_TARGET = "gelProviderId";
  var PROXY_QUERY_ENABLED = "1";

  var STORAGE_ACTIVE_KEY = "gelSamlProxyActive";
  var STORAGE_LAST_SELECTION_KEY = "gelSamlProxyLastSelection";
  var STORAGE_METADATA_CERTS_KEY = "gelSamlProxyMetadataCertificates";

  var STORAGE_LAST_REWRITE_KEY = "gelSamlLastProviderRewrite";
  var STORAGE_LAST_REQUEST_KEY = "gelSamlLastIdentityProviderRequest";

  var STANDARD_SAML_ATTRIBUTE_SET_KEY = "attributeConsumingServiceIndex";

  var GEL_KEYS = {
    attributeSet: "gelAttributeSet",
    spidLevel: "gelSpidLevel",
    spNameQualifier: "gelNameIdSpNameQualifier",
    idpEntityId: "idpEntityId",
    idpSsoUrl: "singleSignOnServiceUrl",
    idpSloUrl: "singleLogoutServiceUrl"
  };

  var capturedMetadataCertificates = readProxyMetadataCertificates();
  var clientDefaultsRetryId = null;
  var EXTENSION_BUILD = "gel-saml-ext-2026-05-19-02";

  window.__gelSamlAdminExtensionLoaded = true;
  window.__gelSamlExtensionBuild = EXTENSION_BUILD;
  window.__gelSamlNetTrace = [];
  window.__gelSamlLastProviderRewrite = readJsonStorage(STORAGE_LAST_REWRITE_KEY);
  window.__gelSamlLastIdentityProviderRequest = readJsonStorage(STORAGE_LAST_REQUEST_KEY);

  interceptFetch();
  interceptXmlHttpRequest();
  bootstrap();

  function bootstrap() {
    installGelProviderSelectionListener();
    runOnce();
    window.addEventListener("hashchange", runOnce);
    window.addEventListener("popstate", runOnce);
    window.setInterval(runOnce, 1000);
  }

  function runOnce() {
    markGelProviderLinks();
    var context = resolveIdentityProviderContext();
    handleCreateRouteProxy(context);
    prepareGelCreateForm(context);
    if (!context || context.action !== ROUTE_ACTION_ADD) {
      groupGelSettingsSection();
    }
  }

  function installGelProviderSelectionListener() {
    document.addEventListener("click", rememberGelProviderSelection, true);
    document.addEventListener("mousedown", rememberGelProviderSelection, true);
    document.addEventListener("keydown", function (event) {
      if (!event || (event.key !== "Enter" && event.key !== " ")) {
        return;
      }
      rememberGelProviderSelection(event);
    }, true);
  }

  function rememberGelProviderSelection(event) {
    var target = event && event.target ? event.target : null;
    if (!target || !isGelProviderSelectionTarget(target)) {
      return;
    }

    setProxyActive(true);
    rememberGelProviderSelectionState();
  }

  function markGelProviderLinks() {
    var nodes = document.querySelectorAll("a, button, [role='menuitem'], [role='option']");
    for (var i = 0; i < nodes.length; i++) {
      if (isGelProviderSelectionTarget(nodes[i])) {
        nodes[i].setAttribute("data-gel-saml-provider-option", "true");
      }
    }
  }

  function isGelProviderSelectionTarget(target) {
    var candidate = target.closest
      ? target.closest("a, button, [role='menuitem'], [role='option'], li")
      : target;
    if (!candidate) {
      return false;
    }

    var label = normalizeText(candidate.textContent);
    var href = candidate.getAttribute ? String(candidate.getAttribute("href") || "") : "";

    return label.indexOf("gel saml v2.0") >= 0
      || label === TARGET_PROVIDER_ID
      || href.toLowerCase().indexOf("/" + TARGET_PROVIDER_ID + "/") >= 0;
  }

  function handleCreateRouteProxy(context) {
    if (!context || context.action !== ROUTE_ACTION_ADD) {
      return;
    }

    if (isProviderId(context.providerId, TARGET_PROVIDER_ID)) {
      setProxyActive(true);
      rememberGelProviderSelectionState();
      return;
    }

    if (isProviderId(context.providerId, SAML_PROVIDER_ID) && context.query[PROXY_QUERY_FLAG] === PROXY_QUERY_ENABLED) {
      setProxyActive(true);
      rememberGelProviderSelectionState();
    }
  }

  function prepareGelCreateForm(context) {
    if (!context || context.action !== ROUTE_ACTION_ADD) {
      return;
    }

    if (!isProviderId(context.providerId, SAML_PROVIDER_ID) && !isProviderId(context.providerId, TARGET_PROVIDER_ID)) {
      return;
    }

    if (!(context.query[PROXY_QUERY_FLAG] === PROXY_QUERY_ENABLED || isProviderId(context.providerId, TARGET_PROVIDER_ID))) {
      return;
    }

    hideClientCredentialsInputs();
    ensureClientCredentialDefaults();
    ensureClientCredentialDefaultsWithRetry();
    ensureSamlCreateInputs();
  }

  function ensureClientCredentialDefaults() {
    setInputDefaultIfEmpty("config.clientId", "gel-saml");
    setInputDefaultIfEmpty("config.clientSecret", "gel-saml-placeholder-secret");
  }

  function ensureClientCredentialDefaultsWithRetry() {
    if (clientDefaultsRetryId) {
      return;
    }

    var attempts = 0;
    clientDefaultsRetryId = window.setInterval(function () {
      attempts += 1;
      var doneClientId = setInputDefaultIfEmpty("config.clientId", "gel-saml");
      var doneClientSecret = setInputDefaultIfEmpty("config.clientSecret", "gel-saml-placeholder-secret");

      if ((doneClientId && doneClientSecret) || attempts >= 50) {
        window.clearInterval(clientDefaultsRetryId);
        clientDefaultsRetryId = null;
      }
    }, 100);
  }

  function setInputDefaultIfEmpty(name, value) {
    var node = document.querySelector("[name='" + name + "']");
    if (!node) {
      return false;
    }

    var current = String(node.value || "").trim();
    if (current.length > 0) {
      return true;
    }

    setNativeInputValue(node, value);
    try {
      node.dispatchEvent(new Event("input", { bubbles: true }));
      node.dispatchEvent(new Event("change", { bubbles: true }));
      node.dispatchEvent(new Event("blur", { bubbles: true }));
    } catch (error) {
      // Ignore browsers that block synthetic events in this context.
    }

    return String(node.value || "").trim().length > 0;
  }

  function setNativeInputValue(node, value) {
    if (!node) {
      return;
    }

    var previousValue = node.value;
    var prototype = Object.getPrototypeOf(node);
    var descriptor = prototype ? Object.getOwnPropertyDescriptor(prototype, "value") : null;
    var valueSetter = descriptor && descriptor.set;

    if (valueSetter) {
      valueSetter.call(node, value);
    } else {
      node.value = value;
    }

    node.setAttribute("value", value);

    if (node._valueTracker && typeof node._valueTracker.setValue === "function") {
      node._valueTracker.setValue(previousValue);
    }
  }

  function hideClientCredentialsInputs() {
    hideFormGroupByInputName("config.clientId");
    hideFormGroupByInputName("config.clientSecret");
  }

  function hideFormGroupByInputName(inputName) {
    var node = document.querySelector("[name='" + inputName + "']");
    if (!node || !node.closest) {
      return;
    }
    var group = node.closest(".pf-v5-c-form__group, .pf-c-form__group");
    if (group) {
      group.style.display = "none";
    }
  }

  function ensureSamlCreateInputs() {
    ensureInput("config." + GEL_KEYS.idpEntityId, "Identity provider entity ID");
    ensureInput("config." + GEL_KEYS.idpSsoUrl, "Single Sign-On service URL");
    ensureInput("config." + GEL_KEYS.idpSloUrl, "Single logout service URL");
  }

  function ensureInput(name, label) {
    if (document.querySelector("[name='" + name + "']")) {
      return;
    }

    var container = document.querySelector("form .pf-v5-c-form, form");
    if (!container) {
      return;
    }

    var group = document.createElement("div");
    group.className = "pf-v5-c-form__group";
    group.innerHTML = ""
      + "<label class='pf-v5-c-form__label' for='" + name + "'><span class='pf-v5-c-form__label-text'>" + label + "</span></label>"
      + "<div class='pf-v5-c-form__group-control'>"
      + "<input class='pf-v5-c-form-control' id='" + name + "' name='" + name + "' type='text' />"
      + "</div>";
    var submitButton = document.querySelector("[data-testid='createProvider']");
    var actionGroup = submitButton && submitButton.closest ? submitButton.closest(".pf-v5-c-form__group, .pf-c-form__group, .pf-v5-c-action-group, .pf-c-action-group") : null;
    if (actionGroup && actionGroup.parentNode === container) {
      container.insertBefore(group, actionGroup);
    } else {
      container.appendChild(group);
    }
  }

  function interceptFetch() {
    if (typeof window.fetch !== "function") {
      return;
    }

    var originalFetch = window.fetch.bind(window);
    window.fetch = function patchedFetch(input, init) {
      traceNetwork("fetch", extractRequestInfo(input, init));
      var asyncRewrite = rewriteFetchRequestBodyFromRequest(input, init, originalFetch);
      if (asyncRewrite) {
        return asyncRewrite;
      }

      var rewritten = rewriteIdentityProviderProxyRequest(input, init);
      return originalFetch(rewritten.input, rewritten.init);
    };
  }

  function rewriteFetchRequestBodyFromRequest(input, init, originalFetch) {
    if (!input || typeof Request === "undefined" || !(input instanceof Request)) {
      return null;
    }

    var requestInfo = extractRequestInfo(input, init);
    if (!requestInfo || (typeof requestInfo.body !== "undefined" && requestInfo.body !== null)) {
      return null;
    }

    if (!isIdentityProviderCreateRequestUrl(requestInfo.url) && !isIdentityProviderImportConfigRequestUrl(requestInfo.url)) {
      return null;
    }

    rememberLastIdentityProviderRequest(requestInfo);

    return input.clone().text().then(function (bodyText) {
      var rewrittenInit = Object.assign({}, init || {});
      rewrittenInit.body = bodyText;
      var rewritten = rewriteIdentityProviderProxyRequest(input, rewrittenInit);
      return originalFetch(rewritten.input, rewritten.init);
    }).catch(function () {
      return originalFetch(input, init);
    });
  }

  function interceptXmlHttpRequest() {
    if (typeof XMLHttpRequest === "undefined") {
      return;
    }

    var originalOpen = XMLHttpRequest.prototype.open;
    var originalSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function patchedOpen(method, url) {
      this.__gelRequestUrl = String(url || "");
      this.__gelRequestMethod = String(method || "GET").toUpperCase();
      traceNetwork("xhr-open", {
        url: this.__gelRequestUrl,
        method: this.__gelRequestMethod,
        body: null
      });
      return originalOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function patchedSend(body) {
      traceNetwork("xhr-send", {
        url: String(this.__gelRequestUrl || ""),
        method: String(this.__gelRequestMethod || "GET").toUpperCase(),
        body: typeof body === "string" ? body : null
      });
      var rewrittenBody = rewriteXmlHttpRequestProxyBody(
        String(this.__gelRequestMethod || "GET"),
        String(this.__gelRequestUrl || ""),
        body
      );
      return originalSend.call(this, rewrittenBody);
    };
  }

  function traceNetwork(source, requestInfo) {
    try {
      var trace = window.__gelSamlNetTrace;
      if (!Array.isArray(trace)) {
        trace = [];
        window.__gelSamlNetTrace = trace;
      }

      trace.push({
        source: source,
        method: requestInfo && requestInfo.method ? String(requestInfo.method) : "",
        url: requestInfo && requestInfo.url ? String(requestInfo.url) : "",
        hasBody: !!(requestInfo && requestInfo.body),
        timestamp: new Date().toISOString()
      });

      if (trace.length > 200) {
        trace.splice(0, trace.length - 200);
      }
    } catch (error) {
      // Ignore diagnostics failures.
    }
  }

  function rewriteIdentityProviderProxyRequest(input, init) {
    var requestInfo = extractRequestInfo(input, init);
    if (!requestInfo) {
      return { input: input, init: init };
    }

    if (isIdentityProviderCreateRequestUrl(requestInfo.url) || isIdentityProviderImportConfigRequestUrl(requestInfo.url)) {
      rememberLastIdentityProviderRequest(requestInfo);
    }

    if (isIdentityProviderCreateRequestUrl(requestInfo.url)) {
      return rewriteIdentityProviderCreatePayloadRequest(input, init, requestInfo);
    }

    if (isIdentityProviderImportConfigRequestUrl(requestInfo.url)) {
      return rewriteIdentityProviderImportConfigRequest(input, init, requestInfo);
    }

    return { input: input, init: init };
  }

  function rewriteIdentityProviderCreatePayloadRequest(input, init, requestInfo) {
    if (typeof requestInfo.body !== "string" || requestInfo.body.trim() === "") {
      return { input: input, init: init };
    }

    var payload;
    try {
      payload = JSON.parse(requestInfo.body);
    } catch (error) {
      return { input: input, init: init };
    }

    if (!shouldRewriteProviderPayload(payload)) {
      return { input: input, init: init };
    }

    payload.providerId = TARGET_PROVIDER_ID;
    normalizeCreatePayloadGelConfig(payload);
    applyCapturedMetadataCertificates(payload);
    rememberLastRewrite(payload.alias, payload);

    return {
      input: requestInfo.url && String(requestInfo.url).trim() !== "" ? requestInfo.url : input,
      init: withRewrittenBody(input, init, requestInfo.method, JSON.stringify(payload))
    };
  }

  function rewriteIdentityProviderImportConfigRequest(input, init, requestInfo) {
    var rewrittenBody = rewriteRequestBodyProviderId(requestInfo.body);
    if (!rewrittenBody.changed) {
      return { input: input, init: init };
    }

    return {
      input: requestInfo.url && String(requestInfo.url).trim() !== "" ? requestInfo.url : input,
      init: withRewrittenBody(input, init, requestInfo.method, rewrittenBody.body)
    };
  }

  function rewriteXmlHttpRequestProxyBody(method, url, body) {
    if (method !== "POST" && method !== "PUT" && method !== "PATCH") {
      return body;
    }

    if (isIdentityProviderCreateRequestUrl(url) || isIdentityProviderImportConfigRequestUrl(url)) {
      rememberLastIdentityProviderRequest({
        url: url,
        method: method,
        body: typeof body === "string" ? body : ""
      });
    }

    if (isIdentityProviderCreateRequestUrl(url)) {
      if (typeof body !== "string" || body.trim() === "") {
        return body;
      }

      try {
        var payload = JSON.parse(body);
        if (!shouldRewriteProviderPayload(payload)) {
          return body;
        }

        payload.providerId = TARGET_PROVIDER_ID;
        normalizeCreatePayloadGelConfig(payload);
        applyCapturedMetadataCertificates(payload);
        rememberLastRewrite(payload.alias, payload);
        return JSON.stringify(payload);
      } catch (error) {
        return body;
      }
    }

    if (isIdentityProviderImportConfigRequestUrl(url)) {
      var rewrittenBody = rewriteRequestBodyProviderId(body);
      return rewrittenBody.changed ? rewrittenBody.body : body;
    }

    return body;
  }

  function rewriteRequestBodyProviderId(body) {
    if (typeof body === "string") {
      var parsed;
      try {
        parsed = JSON.parse(body);
      } catch (error) {
        return { changed: false, body: body };
      }

      if (!shouldRewriteProviderPayload(parsed)) {
        return { changed: false, body: body };
      }

      captureMetadataCertificatesFromImportPayload(parsed);
      parsed.providerId = TARGET_PROVIDER_ID;
      rememberLastRewrite(parsed.alias, parsed);
      return { changed: true, body: JSON.stringify(parsed) };
    }

    if (typeof FormData !== "undefined" && body instanceof FormData) {
      if (!shouldRewriteProviderId(body.get("providerId"))) {
        return { changed: false, body: body };
      }

      captureMetadataCertificatesFromImportFormData(body);
      var rewrittenForm = new FormData();
      body.forEach(function (value, key) {
        rewrittenForm.append(key, value);
      });
      rewrittenForm.set("providerId", TARGET_PROVIDER_ID);
      return { changed: true, body: rewrittenForm };
    }

    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
      if (!shouldRewriteProviderId(body.get("providerId"))) {
        return { changed: false, body: body };
      }

      var rewrittenParams = new URLSearchParams(body.toString());
      rewrittenParams.set("providerId", TARGET_PROVIDER_ID);
      return { changed: true, body: rewrittenParams };
    }

    return { changed: false, body: body };
  }

  function shouldRewriteProviderPayload(payload) {
    return !!payload && shouldRewriteProviderId(payload.providerId);
  }

  function isProxyCreateRouteActive() {
    var context = resolveIdentityProviderContext();
    if (!context || context.action !== ROUTE_ACTION_ADD) {
      return false;
    }

    if (isProviderId(context.providerId, TARGET_PROVIDER_ID)) {
      return true;
    }

    return isProviderId(context.providerId, SAML_PROVIDER_ID)
      && (
        context.query[PROXY_QUERY_FLAG] === PROXY_QUERY_ENABLED
        || isProviderId(context.query[PROXY_QUERY_TARGET], TARGET_PROVIDER_ID)
        || isProxyActive()
      );
  }

  function shouldRewriteProviderId(providerId) {
    if (!isProviderId(providerId, SAML_PROVIDER_ID) && !isProviderId(providerId, TARGET_PROVIDER_ID)) {
      return false;
    }

    var context = resolveIdentityProviderContext();
    return isProxyActive()
      || hasRecentGelProviderSelection()
      || !!(context && context.action === ROUTE_ACTION_ADD && (
        isProviderId(context.providerId, TARGET_PROVIDER_ID)
        || context.query[PROXY_QUERY_FLAG] === PROXY_QUERY_ENABLED
        || isProviderId(context.query[PROXY_QUERY_TARGET], TARGET_PROVIDER_ID)
      ));
  }

  function normalizeCreatePayloadGelConfig(payload) {
    if (!payload || typeof payload !== "object") {
      return;
    }

    promoteFlatConfigEntries(payload);
    if (!payload.config || typeof payload.config !== "object") {
      payload.config = {};
    }

    var config = payload.config;
    var attributeSet = trimToNull(config[STANDARD_SAML_ATTRIBUTE_SET_KEY]);
    var gelAttributeSet = trimToNull(config[GEL_KEYS.attributeSet]);
    var entityId = trimToNull(config.entityId);
    var spNameQualifier = trimToNull(config[GEL_KEYS.spNameQualifier]);
    var idpEntityId = firstNonNull(
      trimToNull(config[GEL_KEYS.idpEntityId]),
      readInputValue("config." + GEL_KEYS.idpEntityId),
      readInputValue(GEL_KEYS.idpEntityId)
    );
    var idpSsoUrl = firstNonNull(
      trimToNull(config[GEL_KEYS.idpSsoUrl]),
      readInputValue("config." + GEL_KEYS.idpSsoUrl),
      readInputValue(GEL_KEYS.idpSsoUrl)
    );
    var idpSloUrl = firstNonNull(
      trimToNull(config[GEL_KEYS.idpSloUrl]),
      readInputValue("config." + GEL_KEYS.idpSloUrl),
      readInputValue(GEL_KEYS.idpSloUrl)
    );

    if (!gelAttributeSet && attributeSet) {
      config[GEL_KEYS.attributeSet] = attributeSet;
    } else if (!attributeSet && gelAttributeSet) {
      config[STANDARD_SAML_ATTRIBUTE_SET_KEY] = gelAttributeSet;
    }

    if (!spNameQualifier && entityId) {
      setConfigValue(payload, GEL_KEYS.spNameQualifier, entityId);
      config[GEL_KEYS.spNameQualifier] = entityId;
    }
    if (spNameQualifier && !entityId) {
      setConfigValue(payload, "entityId", spNameQualifier);
      config.entityId = spNameQualifier;
    } else if (spNameQualifier && entityId && spNameQualifier !== entityId) {
      // Keep GEL create flow aligned: SPNameQualifier takes precedence when explicitly provided.
      setConfigValue(payload, "entityId", spNameQualifier);
      config.entityId = spNameQualifier;
    }

    if (!trimToNull(config[GEL_KEYS.spidLevel])) {
      setConfigValue(payload, GEL_KEYS.spidLevel, "L2");
      config[GEL_KEYS.spidLevel] = "L2";
    }

    // Map GEL create-only helpers to standard SAML settings.
    if (idpEntityId) {
      setConfigValue(payload, GEL_KEYS.idpEntityId, idpEntityId);
      config[GEL_KEYS.idpEntityId] = idpEntityId;
    }
    if (idpSsoUrl) {
      setConfigValue(payload, "singleSignOnServiceUrl", idpSsoUrl);
      config.singleSignOnServiceUrl = idpSsoUrl;
    }
    if (idpSloUrl) {
      setConfigValue(payload, "singleLogoutServiceUrl", idpSloUrl);
      config.singleLogoutServiceUrl = idpSloUrl;
    }

    setConfigValue(payload, "postBindingResponse", "true");
    setConfigValue(payload, "postBindingAuthnRequest", "true");
    setConfigValue(payload, "postBindingLogout", "true");
    setConfigValue(payload, "wantAuthnRequestsSigned", "true");
    config.postBindingResponse = "true";
    config.postBindingAuthnRequest = "true";
    config.postBindingLogout = "true";
    config.wantAuthnRequestsSigned = "true";
  }

  function readInputValue(name) {
    if (!name || typeof document === "undefined") {
      return null;
    }

    var escaped = escapeAttributeValue(name);
    var input = document.querySelector("input[name=\"" + escaped + "\"], textarea[name=\"" + escaped + "\"]");
    if (!input) {
      return null;
    }

    return trimToNull(input.value);
  }

  function escapeAttributeValue(value) {
    return String(value).replace(/\\/g, "\\\\").replace(/\"/g, "\\\"");
  }

  function firstNonNull() {
    for (var i = 0; i < arguments.length; i++) {
      if (arguments[i]) {
        return arguments[i];
      }
    }

    return null;
  }

  function promoteFlatConfigEntries(payload) {
    if (!payload || typeof payload !== "object") {
      return;
    }

    if (!payload.config || typeof payload.config !== "object") {
      payload.config = {};
    }

    var keys = Object.keys(payload);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      if (key.indexOf("config.") !== 0) {
        continue;
      }

      var configKey = key.substring("config.".length);
      if (!configKey) {
        continue;
      }

      payload.config[configKey] = payload[key];
      delete payload[key];
    }
  }

  function setConfigValue(payload, key, value) {
    if (!payload || typeof payload !== "object") {
      return;
    }

    if (!payload.config || typeof payload.config !== "object") {
      payload.config = {};
    }

    payload.config[key] = value;
  }

  function applyCapturedMetadataCertificates(payload) {
    if (!payload || typeof payload !== "object") {
      return;
    }

    if (!payload.config || typeof payload.config !== "object") {
      payload.config = {};
    }

    var metadataCertificateCsv = resolveMetadataCertificateCsv(payload.config);
    if (!metadataCertificateCsv) {
      return;
    }

    var existing = normalizeCertificateCsv(payload.config.signingCertificate);
    payload.config.signingCertificate = existing
      ? mergeCertificateCsv(existing, metadataCertificateCsv)
      : metadataCertificateCsv;
  }

  function resolveMetadataCertificateCsv(config) {
    var fromDescriptor = extractMetadataCertificateCsvFromConfig(config);
    if (fromDescriptor) {
      rememberMetadataCertificates(fromDescriptor);
      return fromDescriptor;
    }

    if (capturedMetadataCertificates) {
      return capturedMetadataCertificates;
    }

    var fromForm = extractMetadataCertificateCsvFromFormDescriptor();
    if (fromForm) {
      rememberMetadataCertificates(fromForm);
      return fromForm;
    }

    return readProxyMetadataCertificates();
  }

  function captureMetadataCertificatesFromImportPayload(payload) {
    if (!payload || typeof payload !== "object") {
      return;
    }

    var csv = extractMetadataCertificateCsvFromConfig(payload.config || {});
    if (csv) {
      rememberMetadataCertificates(csv);
    }
  }

  function captureMetadataCertificatesFromImportFormData(formData) {
    if (!formData || typeof formData.get !== "function") {
      return;
    }

    var descriptor = formData.get("from") || formData.get("metadata") || formData.get("descriptor");
    var csv = extractMetadataCertificateCsvFromMetadataText(typeof descriptor === "string" ? descriptor : "");
    if (csv) {
      rememberMetadataCertificates(csv);
    }
  }

  function extractMetadataCertificateCsvFromConfig(config) {
    if (!config || typeof config !== "object") {
      return "";
    }

    var descriptor = config.from || config.metadata || config.descriptor || "";
    return extractMetadataCertificateCsvFromMetadataText(String(descriptor || ""));
  }

  function extractMetadataCertificateCsvFromFormDescriptor() {
    var field = document.querySelector("textarea[name='from'], textarea[name='metadata'], textarea[name='descriptor']");
    if (!field || typeof field.value !== "string") {
      return "";
    }

    return extractMetadataCertificateCsvFromMetadataText(field.value);
  }

  function extractMetadataCertificateCsvFromMetadataText(metadataText) {
    if (typeof metadataText !== "string" || metadataText.indexOf("X509Certificate") < 0) {
      return "";
    }

    var certificatePattern = /<[^>]*X509Certificate[^>]*>([\s\S]*?)<\/[\s\S]*?X509Certificate>/gi;
    var values = [];
    var seen = {};
    var match;

    while ((match = certificatePattern.exec(metadataText)) !== null) {
      var normalized = String(match[1] || "").replace(/\s+/g, "");
      if (!normalized || seen[normalized]) {
        continue;
      }

      seen[normalized] = true;
      values.push(normalized);
    }

    return values.join(",");
  }

  function groupGelSettingsSection() {
    var gelGroups = findGelFormGroups();
    if (!gelGroups.length) {
      return;
    }

    var firstGroup = gelGroups[0];
    var form = firstGroup.closest ? firstGroup.closest("form, .pf-v5-c-form, .pf-c-form") : null;
    if (!form) {
      return;
    }

    var section = form.querySelector("section[data-gel-saml-settings-section='true']");
    if (!section) {
      section = document.createElement("section");
      section.setAttribute("data-gel-saml-settings-section", "true");
      section.className = "gel-saml-settings-section pf-v5-u-mt-lg pf-v5-u-pt-md";

      var title = document.createElement("h2");
      title.className = "pf-v5-c-title pf-m-xl pf-v5-u-mb-md";
      title.textContent = "GEL settings";
      section.appendChild(title);

      firstGroup.parentNode.insertBefore(section, firstGroup);
    }

    gelGroups.forEach(function (group) {
      if (group.parentElement !== section) {
        section.appendChild(group);
      }
    });

    // Ensure core SAML endpoint fields stay outside GEL-only section.
    keepSamlCoreFieldsOutsideGelSection(section, form);
  }

  function keepSamlCoreFieldsOutsideGelSection(section, form) {
    if (!section || !form) {
      return;
    }

    var groups = section.querySelectorAll(".pf-v5-c-form__group, .pf-c-form__group");
    for (var i = 0; i < groups.length; i++) {
      var group = groups[i];
      if (isSamlCoreFieldGroup(group)) {
        form.insertBefore(group, section);
      }
    }
  }

  function isSamlCoreFieldGroup(group) {
    if (!group || !group.querySelector) {
      return false;
    }

    // Stable check by input names to avoid locale-dependent label matching.
    var coreNames = [
      "config." + GEL_KEYS.idpEntityId,
      "config." + GEL_KEYS.idpSsoUrl,
      "config." + GEL_KEYS.idpSloUrl
    ];

    for (var i = 0; i < coreNames.length; i++) {
      if (group.querySelector("[name='" + coreNames[i] + "']")) {
        return true;
      }
    }

    var labelNode = group.querySelector("label");
    var label = labelNode ? normalizeText(labelNode.textContent) : "";
    return isSamlCoreFieldLabel(label);
  }

  function findGelFormGroups() {
    var groups = [];
    var seen = [];
    var gelNames = [
      "config.gelAttributeSet",
      "gelAttributeSet",
      "config.gelSpidLevel",
      "gelSpidLevel",
      "config.gelNameIdSpNameQualifier",
      "gelNameIdSpNameQualifier",
      "config.gelEnableCie",
      "gelEnableCie",
      "config.gelEnableCns",
      "gelEnableCns",
      "config.gelCieOnly",
      "gelCieOnly",
      "config.gelEidas",
      "gelEidas",
      "config.gelUsoProfessionale",
      "gelUsoProfessionale",
      "config.gelUsoProfessionaleGiuridico",
      "gelUsoProfessionaleGiuridico",
      "config.gelCustomExtensions",
      "gelCustomExtensions",
      "config.gelLogAuthnRequest",
      "gelLogAuthnRequest",
      "config.gelSigningPrivateKeyPem",
      "gelSigningPrivateKeyPem",
      "config.gelSigningCertificatePem",
      "gelSigningCertificatePem"
    ];

    for (var i = 0; i < gelNames.length; i++) {
      var node = document.querySelector("[name='" + gelNames[i] + "']");
      if (!node || !node.closest) {
        continue;
      }

      var group = node.closest(".pf-v5-c-form__group, .pf-c-form__group");
      if (!group || seen.indexOf(group) >= 0) {
        continue;
      }

      seen.push(group);
      groups.push(group);
    }

    // Label-based pass is always executed to catch fields whose `name` differs across Keycloak versions.
    var labels = document.querySelectorAll("label");
    for (var j = 0; j < labels.length; j++) {
      var label = labels[j];
      if (!isGelSettingsLabel(label.textContent)) {
        continue;
      }

      var fallbackGroup = label.closest
        ? label.closest(".pf-v5-c-form__group, .pf-c-form__group")
        : null;
      if (!fallbackGroup || seen.indexOf(fallbackGroup) >= 0) {
        continue;
      }

      seen.push(fallbackGroup);
      groups.push(fallbackGroup);
    }

    return groups;
  }

  function isGelSettingsLabel(value) {
    var label = normalizeText(value);
    if (isSamlCoreFieldLabel(label)) {
      return false;
    }
    return label === "gel attribute set"
      || label === "spid level"
      || label === "nameid spnamequalifier"
      || label === "custom gel extensions"
      || label === "log authnrequest"
      || label === "gel signing private key (pem)"
      || label === "gel signing certificate (pem)"
      || label.indexOf("extension ") === 0;
  }

  function isSamlCoreFieldLabel(label) {
    return label === "identity provider entity id"
      || label === "single sign-on service url"
      || label === "single logout service url";
  }

  function resolveIdentityProviderContext() {
    var hashValue = String(window.location.hash || "");
    var pathValue = String(window.location.pathname || "");

    var hashContext = parseIdentityProviderRoute(hashValue, true);
    if (hashContext) {
      return hashContext;
    }

    return parseIdentityProviderRoute(pathValue + String(window.location.search || ""), false);
  }

  function parseIdentityProviderRoute(routeValue, isHashNavigation) {
    if (!routeValue) {
      return null;
    }

    var normalized = String(routeValue || "").trim();
    if (isHashNavigation) {
      normalized = normalized.replace(/^#\/?/, "");
    }

    var queryIndex = normalized.indexOf("?");
    var queryString = "";
    if (queryIndex >= 0) {
      queryString = normalized.substring(queryIndex + 1);
      normalized = normalized.substring(0, queryIndex);
    }

    var segments = normalized.split("/").filter(function (segment) {
      return !!segment;
    });

    var markerSegment = "";
    var markerIndex = -1;
    for (var i = 0; i < segments.length; i++) {
      if (segments[i] === ROUTE_SEGMENT_IDENTITY_PROVIDER || segments[i] === ROUTE_SEGMENT_IDENTITY_PROVIDERS) {
        markerSegment = segments[i];
        markerIndex = i;
        break;
      }
    }

    if (markerIndex < 0 || segments.length <= markerIndex + 1) {
      return null;
    }

    var firstSegment = segments[markerIndex + 1] || "";
    var secondSegment = segments[markerIndex + 2] || "";
    var thirdSegment = segments[markerIndex + 3] || "";

    var providerId = "";
    var rawAlias = "";
    var rawTab = "";

    if (firstSegment === ROUTE_ACTION_ADD && secondSegment) {
      providerId = secondSegment;
      rawAlias = ROUTE_ACTION_ADD;
      rawTab = thirdSegment || "";
    } else {
      providerId = firstSegment;
      rawAlias = secondSegment;
      rawTab = thirdSegment;
    }

    var action = rawAlias === ROUTE_ACTION_ADD ? ROUTE_ACTION_ADD : ROUTE_ACTION_DETAILS;
    var alias = action === ROUTE_ACTION_ADD ? "" : rawAlias;
    var tab = action === ROUTE_ACTION_ADD ? "" : rawTab;
    var realm = "";

    if (markerIndex >= 2 && segments[markerIndex - 2] === "realms") {
      realm = segments[markerIndex - 1];
    } else if (markerIndex >= 1) {
      realm = segments[markerIndex - 1];
    }

    if (!realm || !providerId || (action !== ROUTE_ACTION_ADD && !rawAlias)) {
      return null;
    }

    return {
      realm: decodeURIComponent(realm),
      providerId: canonicalProviderId(decodeURIComponent(providerId)),
      alias: decodeURIComponent(alias),
      tab: decodeURIComponent(tab),
      action: action,
      markerSegment: markerSegment,
      query: parseQueryParams(queryString),
      isHashNavigation: isHashNavigation
    };
  }

  function navigateToIdentityProviderRoute(context, providerId, action, alias, queryObject) {
    var targetPath = buildIdentityProviderPath(context.realm, providerId, action, alias, context.tab);
    var targetQuery = queryObject ? new URLSearchParams(queryObject).toString() : "";
    var target = targetPath + (targetQuery ? "?" + targetQuery : "");

    if (context.isHashNavigation) {
      if (String(window.location.hash || "") !== "#" + target) {
        window.location.hash = "#" + target;
      }
      return;
    }

    var current = String(window.location.pathname || "") + String(window.location.search || "");
    if (current !== target) {
      window.history.replaceState({}, "", target);
      dispatchNavigationSignal();
    }
  }

  function dispatchNavigationSignal() {
    try {
      window.dispatchEvent(new PopStateEvent("popstate"));
    } catch (error) {
      window.dispatchEvent(new Event("popstate"));
    }
  }

  function buildIdentityProviderPath(realm, providerId, action, alias, tab) {
    var routeSegment = resolveIdentityProviderRouteSegment();
    var parts = ["", encodeURIComponent(String(realm || "")), routeSegment, encodeURIComponent(String(providerId || ""))];

    if (action === ROUTE_ACTION_ADD) {
      parts.push(ROUTE_ACTION_ADD);
      return parts.join("/");
    }

    parts.push(encodeURIComponent(String(alias || "")));
    if (tab) {
      parts.push(encodeURIComponent(String(tab)));
    }

    return parts.join("/");
  }

  function resolveIdentityProviderRouteSegment() {
    var value = String(window.location.hash || "") + " " + String(window.location.pathname || "");
    if (value.indexOf("/" + ROUTE_SEGMENT_IDENTITY_PROVIDER + "/") >= 0) {
      return ROUTE_SEGMENT_IDENTITY_PROVIDER;
    }
    return ROUTE_SEGMENT_IDENTITY_PROVIDERS;
  }

  function isProviderId(value, expected) {
    return canonicalProviderId(value) === canonicalProviderId(expected);
  }

  function canonicalProviderId(value) {
    return String(value || "").trim().toLowerCase();
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
      if (typeof init.body !== "undefined") {
        body = init.body;
      }
    }

    return {
      url: url,
      method: method.toUpperCase(),
      body: body
    };
  }

  function withRewrittenBody(input, init, method, body) {
    var rewrittenInit = Object.assign({}, init || {});
    rewrittenInit.method = method;
    rewrittenInit.body = body;

    if (!rewrittenInit.headers && input && typeof Request !== "undefined" && input instanceof Request) {
      rewrittenInit.headers = input.headers;
    }

    return rewrittenInit;
  }

  function isIdentityProviderCreateRequestUrl(url) {
    // Match create/update calls for identity provider instances, including
    // endpoints with alias suffixes.
    if ((!url || String(url).trim() === "") && isProxyCreateRouteActive()) {
      return true;
    }
    return matchesAdminEndpoint(url, /\/identity-provider\/instances(?:\/[^\/?#]+)?\/?$/);
  }

  function isIdentityProviderImportConfigRequestUrl(url) {
    return matchesAdminEndpoint(url, /\/identity-provider\/import-config\/?$/);
  }

  function matchesAdminEndpoint(url, pattern) {
    if (!url) {
      return false;
    }

    try {
      return pattern.test(new URL(url, window.location.origin).pathname);
    } catch (error) {
      return pattern.test(String(url));
    }
  }

  function withMergedQuery(existingQuery, additions) {
    var merged = Object.assign({}, existingQuery || {});
    Object.keys(additions || {}).forEach(function (key) {
      var value = additions[key];
      if (value === null || typeof value === "undefined" || value === "") {
        delete merged[key];
      } else {
        merged[key] = String(value);
      }
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
      storage.setItem(STORAGE_ACTIVE_KEY, "true");
    } else {
      storage.removeItem(STORAGE_ACTIVE_KEY);
    }
  }

  function isProxyActive() {
    var storage = safeStorage(window.sessionStorage);
    return !!storage && storage.getItem(STORAGE_ACTIVE_KEY) === "true";
  }

  function setProxyMetadataCertificates(value) {
    var normalized = normalizeCertificateCsv(value);
    capturedMetadataCertificates = normalized;

    var storage = safeStorage(window.sessionStorage);
    if (!storage) {
      return;
    }

    if (normalized) {
      storage.setItem(STORAGE_METADATA_CERTS_KEY, normalized);
    } else {
      storage.removeItem(STORAGE_METADATA_CERTS_KEY);
    }
  }

  function readProxyMetadataCertificates() {
    var storage = safeStorage(window.sessionStorage);
    return storage ? normalizeCertificateCsv(storage.getItem(STORAGE_METADATA_CERTS_KEY)) : "";
  }

  function rememberMetadataCertificates(csv) {
    var normalized = normalizeCertificateCsv(csv);
    if (!normalized) {
      return;
    }

    setProxyMetadataCertificates(
      capturedMetadataCertificates ? mergeCertificateCsv(capturedMetadataCertificates, normalized) : normalized
    );
  }

  function rememberGelProviderSelectionState() {
    var storage = safeStorage(window.sessionStorage);
    if (!storage) {
      return;
    }
    storage.setItem(STORAGE_LAST_SELECTION_KEY, String(Date.now()));
  }

  function hasRecentGelProviderSelection() {
    var storage = safeStorage(window.sessionStorage);
    if (!storage) {
      return false;
    }

    var value = Number(storage.getItem(STORAGE_LAST_SELECTION_KEY) || "0");
    return value > 0 && Date.now() - value < 10 * 60 * 1000;
  }

  function rememberLastIdentityProviderRequest(requestInfo) {
    var diagnostic = {
      url: requestInfo && requestInfo.url ? String(requestInfo.url) : "",
      method: requestInfo && requestInfo.method ? String(requestInfo.method) : "",
      proxyActive: isProxyActive(),
      recentGelSelection: hasRecentGelProviderSelection(),
      timestamp: new Date().toISOString()
    };
    window.__gelSamlLastIdentityProviderRequest = diagnostic;
    writeJsonStorage(STORAGE_LAST_REQUEST_KEY, diagnostic);
  }

  function rememberLastRewrite(alias, payload) {
    var diagnostic = {
      providerId: TARGET_PROVIDER_ID,
      alias: typeof alias === "string" ? alias.trim() : "",
      payload: payload || null,
      timestamp: new Date().toISOString()
    };
    window.__gelSamlLastProviderRewrite = diagnostic;
    writeJsonStorage(STORAGE_LAST_REWRITE_KEY, diagnostic);
  }

  function mergeCertificateCsv(first, second) {
    var merged = [];
    var seen = {};
    [first, second].forEach(function (csv) {
      splitCertificateCsv(csv).forEach(function (value) {
        if (!value || seen[value]) {
          return;
        }
        seen[value] = true;
        merged.push(value);
      });
    });
    return merged.join(",");
  }

  function normalizeCertificateCsv(value) {
    return splitCertificateCsv(value).join(",");
  }

  function splitCertificateCsv(value) {
    if (typeof value !== "string" || value.trim() === "") {
      return [];
    }

    return value
      .split(",")
      .map(function (entry) {
        return String(entry || "").replace(/\s+/g, "");
      })
      .filter(function (entry) {
        return entry.length > 0;
      });
  }

  function trimToNull(value) {
    if (value === null || typeof value === "undefined") {
      return null;
    }

    var normalized = String(value).trim();
    return normalized.length > 0 ? normalized : null;
  }

  function normalizeText(value) {
    return String(value || "")
      .replace(/\s+/g, " ")
      .trim()
      .toLowerCase();
  }

  function safeStorage(storage) {
    try {
      return storage || null;
    } catch (error) {
      return null;
    }
  }

  function readJsonStorage(key) {
    var storage = safeStorage(window.sessionStorage);
    if (!storage) {
      return null;
    }

    var raw = storage.getItem(key);
    if (!raw) {
      return null;
    }

    try {
      return JSON.parse(raw);
    } catch (error) {
      return null;
    }
  }

  function writeJsonStorage(key, value) {
    var storage = safeStorage(window.sessionStorage);
    if (!storage) {
      return;
    }

    try {
      if (value === null || typeof value === "undefined") {
        storage.removeItem(key);
      } else {
        storage.setItem(key, JSON.stringify(value));
      }
    } catch (error) {
      // Ignore storage exceptions.
    }
  }
})();
