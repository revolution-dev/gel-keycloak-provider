#!/usr/bin/env bash

set -euo pipefail

# Configure a Keycloak realm to test the custom gel-saml broker against the
# remote GEL integration endpoint described by the provided kit.
#
# The script is host-side and talks to Keycloak Admin REST on localhost,
# which fits the user's docker compose setup.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin}"
CURL_INSECURE="${CURL_INSECURE:-false}"

REALM="${REALM:-gel-poc}"
REALM_DISPLAY_NAME="${REALM_DISPLAY_NAME:-GEL PoC}"
ADMIN_THEME="${ADMIN_THEME:-gel}"
ADMIN_THEME_REALM="${ADMIN_THEME_REALM:-master}"

CLIENT_ID="${CLIENT_ID:-gel-browser-test}"
CLIENT_NAME="${CLIENT_NAME:-GEL Browser Test}"
CLIENT_REDIRECT_URI="${CLIENT_REDIRECT_URI:-http://localhost:8080/}"

IDP_ALIAS="${IDP_ALIAS:-gel-saml-remote}"
IDP_DISPLAY_NAME="${IDP_DISPLAY_NAME:-GEL Remote Test}"

METADATA_FILE="${METADATA_FILE:-${ROOT_DIR}/GEL Kit Integrazione/IdpcGelMetadataIntegrazione_locale_PREIT-internet.xml}"
P12_FILE="${P12_FILE:-${ROOT_DIR}/GEL Kit Integrazione/gel-spid.p12}"
P12_PASSWORD="${P12_PASSWORD:-siss}"

# By default we use the shared GEL integration tenant identifier found in the
# Shibboleth kit documentation because it has the highest chance of being
# accepted by the remote integration environment.
SP_ENTITY_ID="${SP_ENTITY_ID:-https://idpcgel.integrazione.lispa.it/gelmetadata/test}"
SP_NAME_QUALIFIER="${SP_NAME_QUALIFIER:-${SP_ENTITY_ID}}"

ATTRIBUTE_SET="${ATTRIBUTE_SET:-3}"
SPID_LEVEL="${SPID_LEVEL:-L2}"
ENABLE_CIE="${ENABLE_CIE:-false}"
ENABLE_CNS="${ENABLE_CNS:-false}"
CIE_ONLY="${CIE_ONLY:-false}"
EIDAS="${EIDAS:-false}"
USO_PROFESSIONALE="${USO_PROFESSIONALE:-false}"
USO_PROFESSIONALE_GIURIDICO="${USO_PROFESSIONALE_GIURIDICO:-false}"
CUSTOM_EXTENSIONS="${CUSTOM_EXTENSIONS:-}"
LOG_AUTHN_REQUEST="${LOG_AUTHN_REQUEST:-true}"
PRINCIPAL_TYPE="${PRINCIPAL_TYPE:-ATTRIBUTE}"
#
# GEL can expose attributes using IdPC-style names in the assertion consumed by
# the SP/broker. For the current SPID-focused PoC we default to the tax code
# field as principal because the integration kit shows it as the remote user
# attribute used by Shibboleth.
PRINCIPAL_ATTRIBUTE="${PRINCIPAL_ATTRIBUTE:-codiceFiscale}"
# Keycloak UserAttributeMapper#updateMetadata expects the enum constant name
# (JBossSAMLURIConstants) rather than the raw URI value.
SAML_ATTRIBUTE_NAME_FORMAT="${SAML_ATTRIBUTE_NAME_FORMAT:-ATTRIBUTE_FORMAT_UNSPECIFIED}"
USERNAME_SOURCE_ATTRIBUTE="${USERNAME_SOURCE_ATTRIBUTE:-codiceFiscale}"
FIRST_NAME_SOURCE_ATTRIBUTE="${FIRST_NAME_SOURCE_ATTRIBUTE:-nome}"
LAST_NAME_SOURCE_ATTRIBUTE="${LAST_NAME_SOURCE_ATTRIBUTE:-cognome}"
EMAIL_SOURCE_ATTRIBUTE="${EMAIL_SOURCE_ATTRIBUTE:-emailAddress}"
USERNAME_TEMPLATE_TARGET="${USERNAME_TEMPLATE_TARGET:-LOCAL}"

KEY_PROVIDER_NAME="${KEY_PROVIDER_NAME:-gel-spid-kit-rsa}"
KEY_PRIORITY="${KEY_PRIORITY:-200}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

require_cmd() {
  local command_name="$1"
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "Missing required command: ${command_name}" >&2
    exit 1
  fi
}

for command_name in curl openssl python3; do
  require_cmd "${command_name}"
done

if [[ ! -f "${METADATA_FILE}" ]]; then
  echo "Metadata file not found: ${METADATA_FILE}" >&2
  exit 1
fi

if [[ ! -f "${P12_FILE}" ]]; then
  echo "PKCS12 file not found: ${P12_FILE}" >&2
  exit 1
fi

extract_metadata_value() {
  local mode="$1"
  python3 - <<'PY' "${METADATA_FILE}" "${mode}"
import sys
import xml.etree.ElementTree as ET

metadata_path = sys.argv[1]
mode = sys.argv[2]
ns = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}
root = ET.parse(metadata_path).getroot()

if mode == "entity-id":
    print(root.attrib.get("entityID", ""))
    raise SystemExit(0)

if mode == "post-sso":
    for node in root.findall(".//md:SingleSignOnService", ns):
        if node.attrib.get("Binding") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":
            print(node.attrib.get("Location", ""))
            raise SystemExit(0)
    raise SystemExit("POST SingleSignOnService not found in metadata")

raise SystemExit(f"Unsupported metadata mode: {mode}")
PY
}

extract_metadata_certificates() {
  python3 - <<'PY' "${METADATA_FILE}"
import sys
import xml.etree.ElementTree as ET

metadata_path = sys.argv[1]
ns = {
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
root = ET.parse(metadata_path).getroot()
seen = set()
pems = []
for node in root.findall(".//ds:X509Certificate", ns):
    value = "".join((node.text or "").split())
    if not value or value in seen:
        continue
    seen.add(value)
    pems.append(value)
print(",".join(pems))
PY
}

run_pkcs12_extract() {
  local mode="$1"
  local output_file="${TMP_DIR}/pkcs12-${mode}.out"
  local -a specific_args

  case "${mode}" in
    key)
      specific_args=(-nocerts -nodes)
      ;;
    cert)
      specific_args=(-clcerts -nokeys)
      ;;
    *)
      echo "Unsupported PKCS12 extraction mode: ${mode}" >&2
      return 1
      ;;
  esac

  if openssl pkcs12 -legacy -in "${P12_FILE}" "${specific_args[@]}" -passin "pass:${P12_PASSWORD}" >"${output_file}" 2>/dev/null; then
    cat "${output_file}"
    return 0
  fi

  if openssl pkcs12 -in "${P12_FILE}" "${specific_args[@]}" -passin "pass:${P12_PASSWORD}" >"${output_file}" 2>/dev/null; then
    cat "${output_file}"
    return 0
  fi

  echo "Unable to extract data from ${P12_FILE} with the available openssl implementation." >&2
  echo "Tried both 'openssl pkcs12 -legacy' and plain 'openssl pkcs12'." >&2
  return 1
}

extract_private_key() {
  run_pkcs12_extract key \
    | awk '/-----BEGIN PRIVATE KEY-----/,/-----END PRIVATE KEY-----/'
}

extract_client_certificate() {
  run_pkcs12_extract cert \
    | awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/'
}

request_token() {
  local response_file="${TMP_DIR}/token.json"
  local -a curl_args=(-fsS)

  if [[ "${CURL_INSECURE}" == "true" ]]; then
    curl_args+=(-k)
  fi

  curl "${curl_args[@]}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=admin-cli" \
    -d "username=${KEYCLOAK_ADMIN_USER}" \
    -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
    -d "grant_type=password" \
    "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    > "${response_file}"

  python3 - <<'PY' "${response_file}"
import json
import pathlib
import sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(data["access_token"])
PY
}

ACCESS_TOKEN="$(request_token)"

api_call() {
  local method="$1"
  local path="$2"
  local body_file="${3:-}"
  local response_file="$4"
  local http_code
  local -a curl_args=(-sS)

  if [[ "${CURL_INSECURE}" == "true" ]]; then
    curl_args+=(-k)
  fi

  if [[ -n "${body_file}" ]]; then
    http_code="$(
      curl "${curl_args[@]}" -o "${response_file}" -w '%{http_code}' \
        -X "${method}" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        -H "Content-Type: application/json" \
        --data @"${body_file}" \
        "${KEYCLOAK_URL}${path}"
    )"
  else
    http_code="$(
      curl "${curl_args[@]}" -o "${response_file}" -w '%{http_code}' \
        -X "${method}" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        "${KEYCLOAK_URL}${path}"
    )"
  fi

  printf '%s' "${http_code}"
}

assert_http_ok() {
  local http_code="$1"
  local response_file="$2"
  local context="$3"
  case "${http_code}" in
    200|201|204)
      return 0
      ;;
  esac

  echo "Request failed during: ${context}" >&2
  echo "HTTP status: ${http_code}" >&2
  if [[ -s "${response_file}" ]]; then
    echo "Response body:" >&2
    cat "${response_file}" >&2
  fi
  exit 1
}

write_realm_payload() {
  local destination="$1"
  python3 - <<'PY' "${destination}" "${REALM}" "${REALM_DISPLAY_NAME}"
import json
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
payload = {
    "realm": sys.argv[2],
    "enabled": True,
    "displayName": sys.argv[3],
}
destination.write_text(json.dumps(payload, indent=2))
PY
}

write_realm_update_payload() {
  local source="$1"
  local destination="$2"
  python3 - <<'PY' "${source}" "${destination}" "${REALM_DISPLAY_NAME}"
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
payload = json.loads(source.read_text())
payload["enabled"] = True
payload["displayName"] = sys.argv[3]
destination.write_text(json.dumps(payload, indent=2))
PY
}

write_realm_theme_update_payload() {
  local source="$1"
  local destination="$2"
  local admin_theme="$3"
  python3 - <<'PY' "${source}" "${destination}" "${admin_theme}"
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
payload = json.loads(source.read_text())
payload["adminTheme"] = sys.argv[3]
destination.write_text(json.dumps(payload, indent=2))
PY
}

write_client_payload() {
  local destination="$1"
  python3 - <<'PY' "${destination}" "${CLIENT_ID}" "${CLIENT_NAME}" "${CLIENT_REDIRECT_URI}"
import json
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
redirect_uri = sys.argv[4]
wildcard = redirect_uri.rstrip("/") + "/*"
payload = {
    "clientId": sys.argv[2],
    "name": sys.argv[3],
    "enabled": True,
    "protocol": "openid-connect",
    "publicClient": True,
    "standardFlowEnabled": True,
    "directAccessGrantsEnabled": False,
    "serviceAccountsEnabled": False,
    "redirectUris": [redirect_uri, wildcard],
    "webOrigins": ["+"],
    "rootUrl": redirect_uri,
    "baseUrl": redirect_uri,
}
destination.write_text(json.dumps(payload, indent=2))
PY
}

write_key_provider_payload() {
  local destination="$1"
  local realm_id="$2"
  local component_id="${3:-}"
  local private_key_file="${TMP_DIR}/private-key.pem"
  local certificate_file="${TMP_DIR}/client-certificate.pem"

  extract_private_key > "${private_key_file}"
  extract_client_certificate > "${certificate_file}"

  python3 - <<'PY' "${destination}" "${realm_id}" "${KEY_PROVIDER_NAME}" "${KEY_PRIORITY}" "${component_id}" "${private_key_file}" "${certificate_file}"
import json
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
payload = {
    "name": sys.argv[3],
    "providerId": "rsa",
    "providerType": "org.keycloak.keys.KeyProvider",
    "parentId": sys.argv[2],
    "config": {
        "priority": [sys.argv[4]],
        "enabled": ["true"],
        "active": ["true"],
        "algorithm": ["RS256"],
        "keyUse": ["SIG"],
        "privateKey": [pathlib.Path(sys.argv[6]).read_text()],
        "certificate": [pathlib.Path(sys.argv[7]).read_text()],
    },
}
if sys.argv[5]:
    payload["id"] = sys.argv[5]
destination.write_text(json.dumps(payload, indent=2))
PY
}

write_idp_payload() {
  local destination="$1"
  local metadata_certs_file="${TMP_DIR}/metadata-certs.pem"
  extract_metadata_certificates > "${metadata_certs_file}"

  python3 - <<'PY' "${destination}" "${IDP_ALIAS}" "${IDP_DISPLAY_NAME}" "${metadata_certs_file}"
import json
import os
import pathlib
import sys

def normalize_bool(value: str) -> str:
    return "true" if value.strip().lower() == "true" else "false"

destination = pathlib.Path(sys.argv[1])
alias = sys.argv[2]
display_name = sys.argv[3]
metadata_certs = pathlib.Path(sys.argv[4]).read_text()

payload = {
    "alias": alias,
    "displayName": display_name,
    "providerId": "gel-saml",
    "enabled": True,
    "trustEmail": False,
    "storeToken": False,
    "addReadTokenRoleOnCreate": False,
    "authenticateByDefault": False,
    "firstBrokerLoginFlowAlias": "first broker login",
    "config": {
        "singleSignOnServiceUrl": os.environ["GEL_SSO_URL"],
        "singleLogoutServiceUrl": "",
        "idpEntityId": os.environ["GEL_IDP_ENTITY_ID"],
        "entityId": os.environ["SP_ENTITY_ID"],
        "nameIDPolicyFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        "principalType": os.environ["PRINCIPAL_TYPE"],
        "principalAttribute": os.environ["PRINCIPAL_ATTRIBUTE"],
        "gelAttributeSet": os.environ["ATTRIBUTE_SET"],
        "attributeConsumingServiceIndex": os.environ["ATTRIBUTE_SET"],
        "gelSpidLevel": os.environ["SPID_LEVEL"],
        "gelNameIdSpNameQualifier": os.environ["SP_NAME_QUALIFIER"],
        "gelEnableCie": normalize_bool(os.environ["ENABLE_CIE"]),
        "gelEnableCns": normalize_bool(os.environ["ENABLE_CNS"]),
        "gelCieOnly": normalize_bool(os.environ["CIE_ONLY"]),
        "gelEidas": normalize_bool(os.environ["EIDAS"]),
        "gelUsoProfessionale": normalize_bool(os.environ["USO_PROFESSIONALE"]),
        "gelUsoProfessionaleGiuridico": normalize_bool(os.environ["USO_PROFESSIONALE_GIURIDICO"]),
        "gelCustomExtensions": os.environ["CUSTOM_EXTENSIONS"],
        "gelLogAuthnRequest": normalize_bool(os.environ["LOG_AUTHN_REQUEST"]),
        "wantAuthnRequestsSigned": "true",
        "validateSignature": "true",
        "postBindingAuthnRequest": "true",
        "postBindingResponse": "true",
        "signingCertificate": metadata_certs,
    },
}

destination.write_text(json.dumps(payload, indent=2))
PY
}

write_idp_user_attribute_mapper_payload() {
  local destination="$1"
  local mapper_name="$2"
  local source_attribute="$3"
  local user_attribute="$4"
  local mapper_id="${5:-}"

  python3 - <<'PY' "${destination}" "${IDP_ALIAS}" "${mapper_name}" "${source_attribute}" "${user_attribute}" "${SAML_ATTRIBUTE_NAME_FORMAT}" "${mapper_id}"
import json
import pathlib
import sys

payload = {
    "identityProviderAlias": sys.argv[2],
    "identityProviderMapper": "gel-saml-user-attribute-idp-mapper",
    "name": sys.argv[3],
    "config": {
        "attribute.name": sys.argv[4],
        "attribute.name.format": sys.argv[6],
        "user.attribute": sys.argv[5],
        "syncMode": "INHERIT",
    },
}

if sys.argv[7]:
    payload["id"] = sys.argv[7]

pathlib.Path(sys.argv[1]).write_text(json.dumps(payload, indent=2))
PY
}

write_idp_username_mapper_payload() {
  local destination="$1"
  local mapper_name="$2"
  local source_attribute="$3"
  local mapper_id="${4:-}"

  python3 - <<'PY' "${destination}" "${IDP_ALIAS}" "${mapper_name}" "${source_attribute}" "${USERNAME_TEMPLATE_TARGET}" "${mapper_id}"
import json
import pathlib
import sys

payload = {
    "identityProviderAlias": sys.argv[2],
    "identityProviderMapper": "gel-saml-username-idp-mapper",
    "name": sys.argv[3],
    "config": {
        "template": "${ATTRIBUTE." + sys.argv[4] + "}",
        "target": sys.argv[5],
        "syncMode": "INHERIT",
    },
}

if sys.argv[6]:
    payload["id"] = sys.argv[6]

pathlib.Path(sys.argv[1]).write_text(json.dumps(payload, indent=2))
PY
}

find_first_id_by_field() {
  local response_file="$1"
  local field_name="$2"
  local expected_value="$3"
  python3 - <<'PY' "${response_file}" "${field_name}" "${expected_value}"
import json
import pathlib
import sys

items = json.loads(pathlib.Path(sys.argv[1]).read_text())
field_name = sys.argv[2]
expected_value = sys.argv[3]
for item in items:
    if item.get(field_name) == expected_value:
        print(item.get("id", ""))
        break
PY
}

upsert_idp_mapper() {
  local mapper_name="$1"
  local payload_file="$2"

  local mappers_response="${TMP_DIR}/idp-mappers.json"
  local mappers_code
  mappers_code="$(api_call GET "/admin/realms/${REALM}/identity-provider/instances/${IDP_ALIAS}/mappers" "" "${mappers_response}")"
  assert_http_ok "${mappers_code}" "${mappers_response}" "query identity provider mappers"

  local mapper_id
  mapper_id="$(find_first_id_by_field "${mappers_response}" "name" "${mapper_name}")"

  if [[ -n "${mapper_id}" ]]; then
    local update_payload_file="${TMP_DIR}/idp-mapper-update-payload-${mapper_id}.json"
    python3 - <<'PY' "${payload_file}" "${update_payload_file}" "${mapper_id}"
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
payload = json.loads(source.read_text())
payload["id"] = sys.argv[3]
destination.write_text(json.dumps(payload, indent=2))
PY
    local mapper_update_response="${TMP_DIR}/idp-mapper-update-${mapper_id}.json"
    local mapper_update_code
    mapper_update_code="$(api_call PUT "/admin/realms/${REALM}/identity-provider/instances/${IDP_ALIAS}/mappers/${mapper_id}" "${update_payload_file}" "${mapper_update_response}")"
    assert_http_ok "${mapper_update_code}" "${mapper_update_response}" "update identity provider mapper ${mapper_name}"
  else
    local mapper_create_response
    mapper_create_response="$(mktemp "${TMP_DIR}/idp-mapper-create-XXXXXX")"
    local mapper_create_code
    mapper_create_code="$(api_call POST "/admin/realms/${REALM}/identity-provider/instances/${IDP_ALIAS}/mappers" "${payload_file}" "${mapper_create_response}")"
    assert_http_ok "${mapper_create_code}" "${mapper_create_response}" "create identity provider mapper ${mapper_name}"
  fi
}

build_test_url() {
  python3 - <<'PY' "${KEYCLOAK_URL}" "${REALM}" "${CLIENT_ID}" "${CLIENT_REDIRECT_URI}" "${IDP_ALIAS}"
import sys
import urllib.parse

base = sys.argv[1].rstrip("/")
realm = sys.argv[2]
client_id = sys.argv[3]
redirect_uri = sys.argv[4]
idp_alias = sys.argv[5]

query = urllib.parse.urlencode({
    "client_id": client_id,
    "redirect_uri": redirect_uri,
    "response_type": "code",
    "scope": "openid",
    "kc_idp_hint": idp_alias,
})
print(f"{base}/realms/{realm}/protocol/openid-connect/auth?{query}")
PY
}

GEL_IDP_ENTITY_ID="$(extract_metadata_value entity-id)"
GEL_SSO_URL="$(extract_metadata_value post-sso)"

export GEL_IDP_ENTITY_ID GEL_SSO_URL SP_ENTITY_ID ATTRIBUTE_SET SPID_LEVEL SP_NAME_QUALIFIER
export ENABLE_CIE ENABLE_CNS CIE_ONLY EIDAS USO_PROFESSIONALE USO_PROFESSIONALE_GIURIDICO
export CUSTOM_EXTENSIONS LOG_AUTHN_REQUEST PRINCIPAL_TYPE PRINCIPAL_ATTRIBUTE

REALM_RESPONSE="${TMP_DIR}/realm.json"
REALM_HTTP_CODE="$(api_call GET "/admin/realms/${REALM}" "" "${REALM_RESPONSE}")"
if [[ "${REALM_HTTP_CODE}" == "404" ]]; then
  echo "[1/5] Create realm ${REALM}"
  REALM_PAYLOAD="${TMP_DIR}/realm-create.json"
  write_realm_payload "${REALM_PAYLOAD}"
  REALM_CREATE_RESPONSE="${TMP_DIR}/realm-create-response.json"
  REALM_CREATE_CODE="$(api_call POST "/admin/realms" "${REALM_PAYLOAD}" "${REALM_CREATE_RESPONSE}")"
  assert_http_ok "${REALM_CREATE_CODE}" "${REALM_CREATE_RESPONSE}" "create realm"
fi

REALM_READ_RESPONSE="${TMP_DIR}/realm-read.json"
REALM_READ_CODE="$(api_call GET "/admin/realms/${REALM}" "" "${REALM_READ_RESPONSE}")"
assert_http_ok "${REALM_READ_CODE}" "${REALM_READ_RESPONSE}" "read realm"

REALM_ID="$(
  python3 - <<'PY' "${REALM_READ_RESPONSE}" "${REALM}"
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(payload.get("id", sys.argv[2]))
PY
)"

echo "[2/7] Apply admin theme (${ADMIN_THEME}) to realm ${ADMIN_THEME_REALM}"
THEME_REALM_READ_RESPONSE="${TMP_DIR}/theme-realm-read.json"
THEME_REALM_READ_CODE="$(api_call GET "/admin/realms/${ADMIN_THEME_REALM}" "" "${THEME_REALM_READ_RESPONSE}")"
assert_http_ok "${THEME_REALM_READ_CODE}" "${THEME_REALM_READ_RESPONSE}" "read admin theme realm"
THEME_REALM_UPDATE_PAYLOAD="${TMP_DIR}/theme-realm-update.json"
write_realm_theme_update_payload "${THEME_REALM_READ_RESPONSE}" "${THEME_REALM_UPDATE_PAYLOAD}" "${ADMIN_THEME}"
THEME_REALM_UPDATE_RESPONSE="${TMP_DIR}/theme-realm-update-response.json"
THEME_REALM_UPDATE_CODE="$(api_call PUT "/admin/realms/${ADMIN_THEME_REALM}" "${THEME_REALM_UPDATE_PAYLOAD}" "${THEME_REALM_UPDATE_RESPONSE}")"
assert_http_ok "${THEME_REALM_UPDATE_CODE}" "${THEME_REALM_UPDATE_RESPONSE}" "update admin theme realm"

echo "[3/7] Update realm ${REALM} settings"
REALM_UPDATE_PAYLOAD="${TMP_DIR}/realm-update.json"
write_realm_update_payload "${REALM_READ_RESPONSE}" "${REALM_UPDATE_PAYLOAD}"
REALM_UPDATE_RESPONSE="${TMP_DIR}/realm-update-response.json"
REALM_UPDATE_CODE="$(api_call PUT "/admin/realms/${REALM}" "${REALM_UPDATE_PAYLOAD}" "${REALM_UPDATE_RESPONSE}")"
assert_http_ok "${REALM_UPDATE_CODE}" "${REALM_UPDATE_RESPONSE}" "update realm"

echo "[4/7] Create or update client ${CLIENT_ID}"
CLIENTS_RESPONSE="${TMP_DIR}/clients.json"
CLIENTS_CODE="$(api_call GET "/admin/realms/${REALM}/clients?clientId=${CLIENT_ID}" "" "${CLIENTS_RESPONSE}")"
assert_http_ok "${CLIENTS_CODE}" "${CLIENTS_RESPONSE}" "query clients"
CLIENT_INTERNAL_ID="$(find_first_id_by_field "${CLIENTS_RESPONSE}" "clientId" "${CLIENT_ID}")"
CLIENT_PAYLOAD="${TMP_DIR}/client.json"
write_client_payload "${CLIENT_PAYLOAD}"
if [[ -n "${CLIENT_INTERNAL_ID}" ]]; then
  CLIENT_UPDATE_RESPONSE="${TMP_DIR}/client-update.json"
  CLIENT_UPDATE_CODE="$(api_call PUT "/admin/realms/${REALM}/clients/${CLIENT_INTERNAL_ID}" "${CLIENT_PAYLOAD}" "${CLIENT_UPDATE_RESPONSE}")"
  assert_http_ok "${CLIENT_UPDATE_CODE}" "${CLIENT_UPDATE_RESPONSE}" "update client"
else
  CLIENT_CREATE_RESPONSE="${TMP_DIR}/client-create.json"
  CLIENT_CREATE_CODE="$(api_call POST "/admin/realms/${REALM}/clients" "${CLIENT_PAYLOAD}" "${CLIENT_CREATE_RESPONSE}")"
  assert_http_ok "${CLIENT_CREATE_CODE}" "${CLIENT_CREATE_RESPONSE}" "create client"
fi

echo "[5/7] Create or update realm key provider ${KEY_PROVIDER_NAME}"
COMPONENTS_RESPONSE="${TMP_DIR}/components.json"
COMPONENTS_CODE="$(api_call GET "/admin/realms/${REALM}/components?parent=${REALM_ID}&type=org.keycloak.keys.KeyProvider" "" "${COMPONENTS_RESPONSE}")"
assert_http_ok "${COMPONENTS_CODE}" "${COMPONENTS_RESPONSE}" "query key providers"
KEY_COMPONENT_ID="$(find_first_id_by_field "${COMPONENTS_RESPONSE}" "name" "${KEY_PROVIDER_NAME}")"
KEY_PROVIDER_PAYLOAD="${TMP_DIR}/key-provider.json"
write_key_provider_payload "${KEY_PROVIDER_PAYLOAD}" "${REALM_ID}" "${KEY_COMPONENT_ID}"
if [[ -n "${KEY_COMPONENT_ID}" ]]; then
  KEY_UPDATE_RESPONSE="${TMP_DIR}/key-provider-update.json"
  KEY_UPDATE_CODE="$(api_call PUT "/admin/realms/${REALM}/components/${KEY_COMPONENT_ID}" "${KEY_PROVIDER_PAYLOAD}" "${KEY_UPDATE_RESPONSE}")"
  assert_http_ok "${KEY_UPDATE_CODE}" "${KEY_UPDATE_RESPONSE}" "update key provider"
else
  KEY_CREATE_RESPONSE="${TMP_DIR}/key-provider-create.json"
  KEY_CREATE_CODE="$(api_call POST "/admin/realms/${REALM}/components" "${KEY_PROVIDER_PAYLOAD}" "${KEY_CREATE_RESPONSE}")"
  assert_http_ok "${KEY_CREATE_CODE}" "${KEY_CREATE_RESPONSE}" "create key provider"
fi

echo "[6/7] Create or update identity provider ${IDP_ALIAS} (providerId=gel-saml)"
IDP_PAYLOAD="${TMP_DIR}/identity-provider.json"
write_idp_payload "${IDP_PAYLOAD}"
IDP_RESPONSE="${TMP_DIR}/identity-provider-get.json"
IDP_CODE="$(api_call GET "/admin/realms/${REALM}/identity-provider/instances/${IDP_ALIAS}" "" "${IDP_RESPONSE}")"
if [[ "${IDP_CODE}" == "404" ]]; then
  IDP_CREATE_RESPONSE="${TMP_DIR}/identity-provider-create.json"
  IDP_CREATE_CODE="$(api_call POST "/admin/realms/${REALM}/identity-provider/instances" "${IDP_PAYLOAD}" "${IDP_CREATE_RESPONSE}")"
  assert_http_ok "${IDP_CREATE_CODE}" "${IDP_CREATE_RESPONSE}" "create identity provider"
else
  assert_http_ok "${IDP_CODE}" "${IDP_RESPONSE}" "read identity provider"
  IDP_UPDATE_RESPONSE="${TMP_DIR}/identity-provider-update.json"
  IDP_UPDATE_CODE="$(api_call PUT "/admin/realms/${REALM}/identity-provider/instances/${IDP_ALIAS}" "${IDP_PAYLOAD}" "${IDP_UPDATE_RESPONSE}")"
  assert_http_ok "${IDP_UPDATE_CODE}" "${IDP_UPDATE_RESPONSE}" "update identity provider"
fi

echo "[7/7] Create or update GEL broker mappers"

USERNAME_MAPPER_PAYLOAD="${TMP_DIR}/mapper-username.json"
write_idp_username_mapper_payload "${USERNAME_MAPPER_PAYLOAD}" "gel-username-from-${USERNAME_SOURCE_ATTRIBUTE}" "${USERNAME_SOURCE_ATTRIBUTE}"
upsert_idp_mapper "gel-username-from-${USERNAME_SOURCE_ATTRIBUTE}" "${USERNAME_MAPPER_PAYLOAD}"

FIRST_NAME_MAPPER_PAYLOAD="${TMP_DIR}/mapper-first-name.json"
write_idp_user_attribute_mapper_payload "${FIRST_NAME_MAPPER_PAYLOAD}" "gel-first-name-from-${FIRST_NAME_SOURCE_ATTRIBUTE}" "${FIRST_NAME_SOURCE_ATTRIBUTE}" "firstName"
upsert_idp_mapper "gel-first-name-from-${FIRST_NAME_SOURCE_ATTRIBUTE}" "${FIRST_NAME_MAPPER_PAYLOAD}"

LAST_NAME_MAPPER_PAYLOAD="${TMP_DIR}/mapper-last-name.json"
write_idp_user_attribute_mapper_payload "${LAST_NAME_MAPPER_PAYLOAD}" "gel-last-name-from-${LAST_NAME_SOURCE_ATTRIBUTE}" "${LAST_NAME_SOURCE_ATTRIBUTE}" "lastName"
upsert_idp_mapper "gel-last-name-from-${LAST_NAME_SOURCE_ATTRIBUTE}" "${LAST_NAME_MAPPER_PAYLOAD}"

EMAIL_MAPPER_PAYLOAD="${TMP_DIR}/mapper-email.json"
write_idp_user_attribute_mapper_payload "${EMAIL_MAPPER_PAYLOAD}" "gel-email-from-${EMAIL_SOURCE_ATTRIBUTE}" "${EMAIL_SOURCE_ATTRIBUTE}" "email"
upsert_idp_mapper "gel-email-from-${EMAIL_SOURCE_ATTRIBUTE}" "${EMAIL_MAPPER_PAYLOAD}"

TEST_URL="$(build_test_url)"

cat <<EOF

Configuration completed.

Realm:
  ${REALM}

Admin Theme Realm:
  ${ADMIN_THEME_REALM}

Admin Theme:
  ${ADMIN_THEME}

Client:
  ${CLIENT_ID}

Identity Provider:
  ${IDP_ALIAS}

GEL IdP Entity ID:
  ${GEL_IDP_ENTITY_ID}

GEL SSO URL:
  ${GEL_SSO_URL}

SP Entity ID (Issuer):
  ${SP_ENTITY_ID}

NameID SPNameQualifier:
  ${SP_NAME_QUALIFIER}

Test URL:
  ${TEST_URL}

EOF
