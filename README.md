# GEL Keycloak Provider

Plugin Java/Maven per Keycloak `26.0.0` che estende il broker SAML standard con campi e comportamenti specifici GEL.

## Compatibilita versioni Keycloak

| Versione Keycloak | Stato compatibilita | Note |
| --- | --- | --- |
| `26.0.0` | Testato | Validato in ambiente Docker locale |
| `26.5.6` | Testato | Validato in ambiente Docker locale |

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
7. Firma AuthnRequest per-singolo IdP GEL con chiave privata RSA + certificato X509 configurabili nei campi GEL del tab `Settings` (fallback automatico alla chiave RSA del realm se non valorizzati)
8. Estensione Admin Console minimale per riusare il form SAML nativo in fase di creazione del provider `gel-saml`

## Struttura progetto

- `src/main/java/it/rdev/keycloak/gel/broker/saml/GelSamlIdentityProviderFactory.java`
- `src/main/java/it/rdev/keycloak/gel/broker/saml/GelSamlIdentityProvider.java`
- `src/main/java/it/rdev/keycloak/gel/broker/saml/GelSamlIdentityProviderConfig.java`
- `src/main/resources/META-INF/services/org.keycloak.broker.provider.IdentityProviderFactory`
- `src/main/resources/theme/gel/admin/theme.properties`
- `src/main/resources/theme/gel/admin/resources/js/gel-saml-admin-extension.js`

## Build

```bash
cd gel-keycloak-provider
mvn -DskipTests clean package
```

Output:

- `target/gel-keycloak-provider-<plugin-version>.jar`

## Installazione su Keycloak 26.x

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

## Admin Console (GEL)

Nota di compatibilita Keycloak `26.x`:

- il tema `gel` eredita direttamente da `keycloak.v2`;
- non viene piu' usato un override di `index.ftl`;
- lo script admin serve solo ad aprire il form SAML nativo durante la creazione e salvare il provider come `gel-saml`.

Con il tema `gel` attivo, quando apri:

- `Identity Providers` -> provider `gel-saml` -> tab `Settings`

Keycloak mostra i parametri GEL direttamente nel tab nativo `Settings`:

- `GEL Attribute Set` (`attributeConsumingServiceIndex`)
- `SPID Level` (`gelSpidLevel`)
- `NameID SPNameQualifier` (`gelNameIdSpNameQualifier`)
- `Private RSA Key (PEM)` (`gelSigningPrivateKeyPem`, opzionale)
- `Signing Certificate (PEM)` (`gelSigningCertificatePem`, opzionale)
- estensioni booleane GEL (`ENABLE_CIE`, `CNS`, `CIEONLY`, `EIDAS`, `usoProfessionale`, `usoProfessionaleGiuridico`)
- `Custom GEL Extensions`
- `Log AuthnRequest`

Comportamento firma AuthnRequest:
- se `Private RSA Key (PEM)` e `Signing Certificate (PEM)` sono valorizzati entrambi, il provider `gel-saml` firma con questo materiale solo per quell'IdP;
- se non sono valorizzati, utilizza la chiave RSA attiva del realm.
- il campo `GEL Signing Private Key (PEM)` e' di tipo password/secret e non viene mostrato in chiaro dal form nativo.
- il salvataggio usa il pulsante `Save` standard del tab `Settings`.

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
4. Salvare l'IdP appena creato e completare le configurazioni GEL nel tab `Settings`

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
3. Eseguire `docker compose up -d` in `test-environment` per avviare il container Keycloak 26.x
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

---

## Supporto

Questo è un progetto open source fornito senza alcuna garanzia di supporto.

Per utilizzo in ambienti di produzione:

* è fortemente raccomandato effettuare test approfonditi
* verificare la compatibilità con la versione di Keycloak utilizzata
* validare attentamente la configurazione dei flussi di autenticazione

---

## Disclaimer

Questo software è fornito “così com’è”, senza garanzie di alcun tipo, esplicite o implicite, incluse ma non limitate a:

* idoneità per uno scopo specifico
* assenza di difetti
* non violazione di diritti

L’utilizzo in ambienti di produzione è a proprio rischio.

Gli autori non sono responsabili per:

* interruzioni di servizio
* configurazioni errate
* problemi di sicurezza derivanti da uso improprio
* incompatibilità con versioni di Keycloak

---

## Licenza

Distribuito sotto licenza Apache License 2.0.

Vedi il file LICENSE per i dettagli.

---

## Contributi

I contributi sono benvenuti. È possibile aprire una issue o inviare una pull request.

---

## Note

Questo progetto non è un’implementazione ufficiale di GEL e non deve essere considerato una soluzione certificata o pronta per ambienti di produzione senza adeguata validazione.

---
