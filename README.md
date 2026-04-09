# GEL Keycloak Provider (PoC)

Plugin Java/Maven per Keycloak `20.0.5` che estende il broker SAML standard con campi e comportamenti specifici GEL.

## Obiettivo

Supportare la configurazione target:

`Keycloak -> GEL -> SPID`

con personalizzazione della `AuthnRequest` per i metadati/estensioni GEL ricavati esclusivamente da:

- `docs/AuthnRequest_valida.xml`
- `docs/idp_metadata.xml`
- `docs/GEL_Kit_Integrazione.zip`
- `docs/Procedure_di_Configurazione_del_GEL_v4_20201109.pdf`

## Funzionalita implementate

Il provider `gel-saml` aggiunge rispetto al SAML standard:

1. Estensioni GEL in `samlp:Extensions` configurabili da UI:
   - `ENABLE_CIE`
   - `CNS`
   - `CIEONLY`
   - `EIDAS`
   - `usoProfessionale`
   - `usoProfessionaleGiuridico`
2. Campo `SPNameQualifier` in `samlp:NameIDPolicy`
3. Selezione semplice livello SPID (`L2`/`L3`) con mapping automatico su:
   - `https://www.spid.gov.it/SpidL2`
   - `https://www.spid.gov.it/SpidL3`
4. Set attributi GEL (`gelAttributeSet`, con override di `AttributeConsumingServiceIndex`, da `0` a `5`)
5. Estensioni custom libere (`TAG=VALORE`, una per riga)
6. Log opzionale della `AuthnRequest` per analisi differenziale PoC
7. Estensione Admin Console con pagina custom `gel-saml` per configurare i parametri GEL aggiuntivi

## Struttura progetto

- `src/main/java/it/rdev/keycloak/gel/broker/saml/GelSamlIdentityProviderFactory.java`
- `src/main/java/it/rdev/keycloak/gel/broker/saml/GelSamlIdentityProvider.java`
- `src/main/java/it/rdev/keycloak/gel/broker/saml/GelSamlIdentityProviderConfig.java`
- `src/main/resources/META-INF/services/org.keycloak.broker.provider.IdentityProviderFactory`
- `src/main/resources/theme/gel/admin/theme.properties`
- `src/main/resources/theme/gel/admin/resources/js/gel-saml-admin-extension.js`
- `src/main/resources/theme/gel/admin/resources/css/gel-saml-admin-extension.css`

## Build

```bash
cd /Users/danilo.dinuzzo/Development/workspaces/codex/poc-gel-keycloak-provider/gel-keycloak-provider
mvn -DskipTests clean package
```

Output:

- `target/gel-keycloak-provider-0.1.0-SNAPSHOT.jar`

## Installazione su Keycloak 20.0.5

1. Copiare il jar in `providers/` della distribuzione Keycloak.
2. Eseguire build Quarkus:

```bash
bin/kc.sh build
```

3. Avviare Keycloak:

```bash
bin/kc.sh start-dev
```

4. Impostare il tema admin del realm su `gel`:
   - `Realm Settings` -> `Themes` -> `Admin theme` -> `gel`
   - Logout/Login in Admin Console dopo la modifica tema

## Pagina custom Admin Console (GEL)

Nota di compatibilita Keycloak `20.0.5`:

- nel template admin standard `keycloak.v2/admin/index.ftl` vengono inclusi i `properties.styles`, ma non i `properties.scripts`;
- per questo motivo la pagina custom GEL usa un override di `index.ftl` nel tema `gel` che include esplicitamente `js/gel-saml-admin-extension.js`.

Con il tema `gel` attivo, quando apri:

- `Identity Providers` -> provider `gel-saml` -> tab `Settings`

viene mostrato un pannello dedicato **Configurazione GEL SAML** con i parametri:

- `GEL Attribute Set` (`attributeConsumingServiceIndex`)
- `SPID Level` (`gelSpidLevel`)
- `NameID SPNameQualifier` (`gelNameIdSpNameQualifier`)
- estensioni booleane GEL (`ENABLE_CIE`, `CNS`, `CIEONLY`, `EIDAS`, `usoProfessionale`, `usoProfessionaleGiuridico`)
- `Custom GEL Extensions`
- `Log AuthnRequest`

Il pulsante `Salva parametri GEL` aggiorna la configurazione `config` dell'Identity Provider via Admin REST.

## Configurazione da Admin Console

1. `Identity Providers` -> `Add provider` -> selezionare `GEL SAML v2.0`.
2. Configurare almeno:
   - `Single Sign-On Service URL`
   - `IdP Entity ID`
   - `SP Entity ID (Issuer)`
   - `Validating X509 Certificates`
   - `Sign AuthnRequest` (tipicamente `ON`)
3. Configurare se necessario campi GEL:
   - `GEL Attribute Set` (0..5)
   - `SPID Level` (`L2` o `L3`)
   - `NameID SPNameQualifier`
   - estensioni booleane (`ENABLE_CIE`, `CNS`, `CIEONLY`, `EIDAS`, `usoProfessionale`, `usoProfessionaleGiuridico`)
   - `Custom GEL Extensions` (es. `MIA_ESTENSIONE=SI`)

## PoC con SimpleSAMLphp (simulazione GEL)

Il plugin non dipende da GEL reale: puoi usarlo con un IdP SAML simulato (SimpleSAMLphp) per confrontare la `AuthnRequest` prodotta con il file `docs/AuthnRequest_valida.xml`.

Workflow consigliato:

1. Configura SimpleSAMLphp come IdP SAML2.
2. Importa metadata/certificato IdP in Keycloak (`gel-saml`).
3. Abilita `Log AuthnRequest` nel provider.
4. Esegui login brokered da Keycloak e cattura la richiesta.
5. Confronta differenze su:
   - `GEL Attribute Set`
   - `RequestedAuthnContext`
   - `NameIDPolicy@SPNameQualifier`
   - contenuto `samlp:Extensions`

## Test reale verso GEL di integrazione

Il kit contiene un metadata IdP remoto di integrazione:

- [`IdpcGelMetadataIntegrazione_locale_PREIT-internet.xml`](/Users/danilo.dinuzzo/Development/workspaces/codex/poc-gel-keycloak-provider/docs/_gel_kit/GEL%20Kit%20Integrazione/IdpcGelMetadataIntegrazione_locale_PREIT-internet.xml)

e una chiave test:

- [`gel-spid.p12`](/Users/danilo.dinuzzo/Development/workspaces/codex/poc-gel-keycloak-provider/docs/_gel_kit/GEL%20Kit%20Integrazione/gel-spid.p12)

Con questi file puoi tentare un test browser-based:

`Keycloak locale -> GEL integrazione remoto -> browser -> Keycloak locale`

Nota importante:

- il browser puo' postare la risposta SAML verso `localhost`, quindi il fatto che Keycloak sia locale non e' di per se' un blocco;
- resta pero' una ambiguita operativa: il tenant GEL remoto potrebbe accettare solo SP/issuer gia' attesi o gia' abilitati da ARIA.

### Script di configurazione

E' disponibile lo script:

- [`tools/configure-keycloak-gel-remote.sh`](/Users/danilo.dinuzzo/Development/workspaces/codex/poc-gel-keycloak-provider/tools/configure-keycloak-gel-remote.sh)

Lo script:

1. crea o aggiorna il realm `gel-poc`
2. imposta `Admin theme = gel`
3. crea un client OIDC pubblico di test
4. importa la chiave di firma test del kit come realm key provider RSA
5. crea o aggiorna l'Identity Provider `gel-saml` verso l'endpoint GEL remoto

Esecuzione standard:

```bash
cd /Users/danilo.dinuzzo/Development/workspaces/codex/poc-gel-keycloak-provider
chmod +x tools/configure-keycloak-gel-remote.sh
./tools/configure-keycloak-gel-remote.sh
```

### Prerequisito GEL: ACS in HTTPS

Il tenant GEL di integrazione rifiuta una `AssertionConsumerServiceURL` in `http`.

Per un test locale browser-based conviene quindi esporre Keycloak anche in HTTPS, ad esempio su:

- `https://localhost:8443`

Nel repository trovi un setup di esempio:

- [docker-compose.yml](/Users/danilo.dinuzzo/Development/workspaces/codex/poc-gel-keycloak-provider/docker-compose.yml)
- [tools/generate-localhost-cert.sh](/Users/danilo.dinuzzo/Development/workspaces/codex/poc-gel-keycloak-provider/tools/generate-localhost-cert.sh)

Passi suggeriti:

```bash
cd /Users/danilo.dinuzzo/Development/workspaces/codex/poc-gel-keycloak-provider
./tools/generate-localhost-cert.sh
docker compose up -d --force-recreate keycloak
```

Poi riconfigura Keycloak usando l'endpoint admin HTTPS locale:

```bash
KEYCLOAK_URL=https://localhost:8443 \
CURL_INSECURE=true \
./tools/configure-keycloak-gel-remote.sh
```

`CURL_INSECURE=true` serve solo per il PoC con certificato self-signed locale.

Nota di compatibilita Keycloak `20.0.5`:

- `--hostname` accetta solo il nome host
- per specificare una URL completa con schema e porta bisogna usare `--hostname-url`

Esempio corretto:

```bash
--hostname-url=https://localhost:8443
```

Esempio errato:

```bash
--hostname=https://localhost:8443
```

Quest'ultima forma porta a URL rotte del tipo `https://https:` nella Admin Console.

Default usati dallo script:

- `IdP Entity ID`: estratto dal metadata remoto
- `Single Sign-On Service URL`: estratto dal metadata remoto
- `SP Entity ID (Issuer)`: `https://idpcgel.integrazione.lispa.it/gelmetadata/test`
- `NameID SPNameQualifier`: uguale all'issuer
- `Principal Type`: `ATTRIBUTE`
- `Principal Attribute`: `codiceFiscale`
- broker mappers created by the helper script:
  - `codiceFiscale` -> `username`
  - `nome` -> `firstName`
  - `cognome` -> `lastName`
  - `emailAddress` -> `email`
- `GEL Attribute Set`: `4`
- `SPID Level`: `L2`
- request firmata con la chiave presente in `gel-spid.p12`

Nota tecnica sui certificati IdP:

- il campo `signingCertificate` del broker SAML di Keycloak 20 non vuole PEM completi
- i certificati vanno salvati come contenuto Base64 X509, separati da virgola
- e' Keycloak ad aggiungere internamente `BEGIN/END CERTIFICATE` durante il parsing

Ho scelto questi default perche' sono i piu' coerenti con il kit di integrazione e con il tenant di test condiviso.

### Modalita confronto con la request di esempio

Se vuoi forzare una configurazione piu' vicina alla request Campania usata per il confronto differenziale:

```bash
SP_ENTITY_ID='https://spidgateway.regione.campania.it/gelmetadata/r_campan' \
SP_NAME_QUALIFIER='https://spidgateway.regione.campania.it/gelmetadata/r_campan' \
ATTRIBUTE_SET=3 \
ENABLE_CIE=true \
ENABLE_CNS=true \
./tools/configure-keycloak-gel-remote.sh
```

Questa modalita e' utile per confrontare la `AuthnRequest`, ma potrebbe ridurre le probabilita di accettazione da parte del tenant GEL remoto.

### Test browser

Al termine, lo script stampa una URL OIDC con `kc_idp_hint=<alias>` da aprire nel browser.

Il risultato atteso puo' essere uno di questi:

1. redirect corretto verso GEL e login completato: buon segnale che il plugin e la firma sono accettati
2. redirect verso GEL ma errore sul servizio remoto: possibile mismatch di issuer/SP abilitato oppure controlli lato tenant
3. errore immediato in Keycloak: problema locale di configurazione, firma o certificati

### Limite noto

Il `p12` del kit contiene una chiave RSA da `1024` bit. Funziona bene come test legacy, ma e' una chiave debole e in alcuni ambienti potrebbe essere rifiutata da policy Java o sicurezza piu' restrittive.

## Ambiguita rilevate nei documenti

1. `docs/idp_metadata.xml` contiene `SPSSODescriptor` (non `IDPSSODescriptor`), quindi non e' un metadata IdP canonico.
2. `docs/AuthnRequest_valida.xml` usa endpoint/issuer ambiente Campania, non Lombardia; i valori sono quindi ambiente-specifici.
3. Le estensioni `ENABLE_CIE`/`CNS` compaiono nell'esempio AuthnRequest ma non sono descritte in modo completo nel PDF rev16, dove sono invece esplicite `CIEONLY`, `EIDAS`, `usoProfessionale`, `usoProfessionaleGiuridico`.

Per questo motivo il plugin espone tutti i campi come configurabili e non hard-coded.
