# GEL Keycloak Provider

Plugin Java/Maven per Keycloak `20.0.5` che estende il broker SAML standard con campi e comportamenti specifici GEL.

## Obiettivo

Supportare la configurazione target:

`Keycloak -> GEL -> SPID`

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
6. Log opzionale della `AuthnRequest` per debug
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
cd gel-keycloak-provider
mvn -DskipTests clean package
```

Output:

- `target/gel-keycloak-provider-20.0.0.jar`

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
   - Logout/Login in Admin Console dopo la modifica tema (oppure svuotare la cache del browser)

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

## Configurazione manuale da Admin Console

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

## Configurazione tramite IdP metadata da Admin Console

1. `Identity Providers` -> `Add provider` -> selezionare `GEL SAML v2.0`.
2. Inserire in `SAML entity descriptor` l'URL che permette di ottenere i metadata dell'IdP o, in alternativa, deselezionare il flag `Use entity descriptor` ed importare il file xml contenente i metadati in `Import config from file`
3. Impostare il valore corretto nel campo `Service provider entity ID` e modificare la gestione del `Principal type`in accordo con le proprie regole di gestione dell'utente
4. Salvare l'IdP appena creato e procedere con le configurazioni nel tab `GEL Params`

## Test verso GEL di integrazione

Il kit di integrazione messo a disposizione da regione Lombardia (in fondo allas seguente [`PAGINA`](https://www.trasformazionedigitale.regione.lombardia.it/wps/portal/site/trasformazionedigitale/api-e-interoperabilita/supporto-agli-enti-locali-per-adesione-a-spid#:~:text=Per%20ulteriori%20informazioni%20o%20supporto,.gel%40ariaspa.it) contiene un metadata IdP remoto di integrazione:

- IdpcGelMetadataIntegrazione_locale_PREIT-internet.xml

e una chiave test:

- gel-spid.p12

Con questi file è possibile effettuare un test browser-based:

`Keycloak locale -> GEL integrazione remoto -> browser -> Keycloak locale`

### Ambiente di test per effettuare il test verso l'istanza di GEL messa a disposizione da Regione Lombardia

Prima di avviare il test è necessario effettaure un build del progetto con

```bash
mvn -DskipTests clean install
```
Tutti i file necessari ad avviare l'ambiente di test sono disponibili all'interno della cartella `test-environment`

### Creazione ambiente di test

1. Assicurarsi che in `GEL Kit Integrazione` sia presente la versione più aggiornata del kit di integrazione rilasciato da regione lombardia
2. Eseguire lo script `scripts\generate-localhost-cert.sh` o generare i certificati che saranno utilizzati da keycloak per la configurazione HTTPS in `scripts\certs`
3. Eseguire `docker compose up -d` in `test-environment` per avviare il container keycloak:20.0.5
4. Eseguire `scripts\configure-keycloak-gel-remote.sh` per configurare keycloak. Lo script effettua le seguenti operazioni:
   - creazione del realm `gel-poc`
   - applicazione del tema `gel` al realm `master`
   - aggiornamento impostazioni realm `gel-poc`
   - creazione client `gel-browser-test`
   - creazione dell'identity provider `gel-saml-remote` di tipo `gel-saml`
   - creazione dei mappers per il nuovo IdP
   - visualizzazione dell'URL di test per verificare il funzionamento

### Esecuzione del test

Una volta creato l'ambiente di test basta incollare l'URL ottenuto dallo script di configurazione di keycloak in un browser web per effettuare il test

