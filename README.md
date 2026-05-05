# ToolBEHAVE — Equivocal Behaviours of Goodware

ToolBEHAVE è una CLI Python per automatizzare l'analisi di campioni software tramite VirusTotal e Hybrid Analysis, normalizzare i report prodotti dai provider e derivare indicatori di **Equivocal Behaviour** tramite mapping MITRE ATT&CK.

Il tool non esegue direttamente il campione e non osserva direttamente i comportamenti. La pipeline usa i report prodotti da servizi esterni, estrae le tecniche MITRE ATT&CK riportate dai provider e le mappa su una tassonomia statica di Equivocal Behaviours, identificati dai codici `ESB1..ESB12`.

## Funzionalità principali

- invio di un campione a VirusTotal e Hybrid Analysis;
- polling dello stato di analisi per uno o più SHA256;
- download dei report grezzi dei provider;
- normalizzazione dei report in uno schema uniforme;
- estrazione di osservazioni, verdict, metriche, IoC e tecniche MITRE ATT&CK;
- mapping MITRE ATT&CK → Equivocal Behaviours;
- mapping opzionale MITRE ATT&CK → custom requirements definiti dall'utente;
- generazione di report JSON intermedi e finali;
- produzione di statistiche aggregate, tabelle e grafici.

## Struttura logica della pipeline

```text
sample file
  ↓
submit to VirusTotal + Hybrid Analysis
  ↓
poll provider status
  ↓
fetch raw reports
  ↓
normalize reports
  ↓
extract MITRE ATT&CK techniques
  ↓
map MITRE techniques to Equivocal Behaviours / Requirements
  ↓
produce enriched reports, EB summaries and statistics
```

## Requisiti

- Python 3.10 o superiore;
- una chiave API VirusTotal;
- una chiave API Hybrid Analysis;
- dipendenze Python definite in `pyproject.toml`;
- `matplotlib`, necessario solo per i grafici generati da `eb-stats`.

## Installazione

Creare e attivare un ambiente virtuale:

```bash
python -m venv .venv
```

Su Windows:

```bash
.venv\Scripts\activate
```

Su Linux/macOS:

```bash
source .venv/bin/activate
```

Installare il progetto in modalità editable:

```bash
pip install -e .
```

Se si vogliono usare anche i grafici di `eb-stats`, installare `matplotlib`:

```bash
pip install matplotlib
```

## Configurazione

ToolBEHAVE legge le chiavi API da variabili d'ambiente. È possibile definirle direttamente nel terminale oppure in un file `.env` nella root del progetto.

Esempio di file `.env`:

```bash
VT_API_KEY=your_virustotal_api_key
HA_API_KEY=your_hybridanalysis_api_key
```

Il database SQLite predefinito è:

```text
toolbehave.sqlite3
```

## Output prodotti

Per impostazione predefinita, i report sono salvati nella directory `reports/`.

```text
reports/
  raw/
    raw_<sha256>.json
  normalized/
    normalized_<sha256>.json
  enriched/
    enriched_<sha256>.json
  eb/
    eb_<sha256>.json
  plots/
    aggregate/
    single/
```

I principali livelli di output sono:

- `raw`: report grezzi ottenuti dai provider;
- `normalized`: schema comune indipendente dal provider;
- `enriched`: report normalizzato arricchito con EB e, se forniti, custom requirements;
- `eb`: sintesi compatta degli Equivocal Behaviours e dei requirements attivati;
- `plots`: tabelle e grafici prodotti da `eb-stats`.

## Comandi disponibili

La CLI espone i seguenti comandi:

```bash
toolbehave submit
toolbehave list
toolbehave poll
toolbehave poll-all
toolbehave watch
toolbehave report
toolbehave report-all
toolbehave normalize-all
toolbehave eb-all
toolbehave eb-summary
toolbehave eb-stats
toolbehave run
```

Per visualizzare l'help generale:

```bash
toolbehave --help
```

Per visualizzare l'help di un singolo comando:

```bash
toolbehave <command> --help
```

## Dettaglio dei comandi

### `submit`

Invia un file a VirusTotal e Hybrid Analysis.

```bash
toolbehave submit PATH
```

Esempio:

```bash
toolbehave submit samples/sample.exe
```

Effetti principali:

- calcola lo SHA256 del file;
- registra il campione nel database SQLite;
- invia il file ai due provider;
- registra gli identificativi esterni restituiti dai provider.

### `list`

Mostra le submission salvate nel database locale.

```bash
toolbehave list
```

Output atteso:

```text
<sha256> | <service> | <status> | <external_id>
```

Esempio:

```bash
toolbehave list
```

### `poll`

Esegue un singolo polling dello stato di analisi per uno SHA256.

```bash
toolbehave poll SHA256
```

Esempio:

```bash
toolbehave poll 0123456789abcdef...
```

Effetti principali:

- interroga VirusTotal e Hybrid Analysis per il campione indicato;
- aggiorna lo stato nel database locale.

### `poll-all`

Esegue un singolo polling dello stato di analisi per tutti gli SHA256 presenti nel database.

```bash
toolbehave poll-all
```

Esempio:

```bash
toolbehave poll-all
```

### `watch`

Esegue polling continuo di tutte le submission nel database.

```bash
toolbehave watch [--interval SECONDS]
```

`--interval` è espresso in secondi. Il valore predefinito è `60`.

Esempio:

```bash
toolbehave watch --interval 30
```

Il comando continua finché non viene interrotto con `Ctrl+C`.

### `report`

Scarica i report grezzi disponibili per uno SHA256 e li salva in un file JSON.

```bash
toolbehave report SHA256 [--out FILE]
```

Esempio:

```bash
toolbehave report 0123456789abcdef... --out report.json
```

Output predefinito:

```text
report.json
```

Questo comando lavora su un singolo SHA256 e non usa automaticamente la struttura `reports/raw/`.

### `report-all`

Scarica i report grezzi per tutti gli SHA256 presenti nel database.

```bash
toolbehave report-all [--out-dir DIR] [--force]
```

Opzioni:

- `--out-dir DIR`: directory base dei report. Default: `reports`;
- `--force`: rigenera e sovrascrive i report già presenti.

Esempio:

```bash
toolbehave report-all --out-dir reports
```

Con sovrascrittura:

```bash
toolbehave report-all --out-dir reports --force
```

Output prodotto:

```text
reports/raw/raw_<sha256>.json
```

### `normalize-all`

Normalizza tutti i report grezzi presenti in `reports/raw/`.

```bash
toolbehave normalize-all [--reports-dir DIR] [--force]
```

Opzioni:

- `--reports-dir DIR`: directory base dei report. Default: `reports`;
- `--force`: rigenera e sovrascrive i file normalizzati già presenti.

Esempio:

```bash
toolbehave normalize-all --reports-dir reports
```

Output prodotto:

```text
reports/normalized/normalized_<sha256>.json
```

### `eb-all`

Genera i report arricchiti e le sintesi EB a partire dai file normalizzati.

```bash
toolbehave eb-all [--reports-dir DIR] [--requirements FILE] [--force]
```

Opzioni:

- `--reports-dir DIR`: directory base dei report. Default: `reports`;
- `--requirements FILE`: file JSON opzionale contenente custom requirements;
- `--force`: rigenera e sovrascrive gli output già presenti.

Esempio senza custom requirements:

```bash
toolbehave eb-all --reports-dir reports
```

Esempio con custom requirements:

```bash
toolbehave eb-all --reports-dir reports --requirements src/resources/my_requirements.json
```

Output prodotti:

```text
reports/enriched/enriched_<sha256>.json
reports/eb/eb_<sha256>.json
```

### `eb-summary`

Legge i file `reports/eb/eb_<sha256>.json` e stampa una tabella riassuntiva.

```bash
toolbehave eb-summary [--reports-dir DIR] [--top N] [--csv FILE]
```

Opzioni:

- `--reports-dir DIR`: directory base dei report. Default: `reports`;
- `--top N`: numero massimo di righe mostrate a video. Default: `20`;
- `--csv FILE`: percorso opzionale in cui salvare la tabella in formato CSV.

Esempio:

```bash
toolbehave eb-summary --reports-dir reports --top 20
```

Esempio con esportazione CSV:

```bash
toolbehave eb-summary --reports-dir reports --top 50 --csv reports/eb_summary.csv
```

Campi principali della tabella:

```text
sha256  total_eb  ha_eb  vt_eb  both_eb
```

### `eb-stats`

Genera statistiche, tabelle e grafici a partire dai file EB.

```bash
toolbehave eb-stats [--reports-dir DIR] [--sha SHA256] [--sha-list FILE] [--sha-single SHA256] [--requirements FILE]
```

Opzioni:

- `--reports-dir DIR`: directory base dei report. Default: `reports`;
- `--sha SHA256`: filtra un sottoinsieme specificando uno o più SHA256. L'opzione può essere ripetuta;
- `--sha-list FILE`: file testuale con uno SHA256 per riga;
- `--sha-single SHA256`: modalità singolo campione;
- `--requirements FILE`: file requirements usato per filtrare uno specifico schema in modalità aggregata, oppure per includere i codici requirement in modalità single.

Esempio su tutti i campioni:

```bash
toolbehave eb-stats --reports-dir reports
```

Esempio su un sottoinsieme indicato da riga di comando:

```bash
toolbehave eb-stats --reports-dir reports --sha <sha1> --sha <sha2>
```

Esempio su un sottoinsieme da file:

```bash
toolbehave eb-stats --reports-dir reports --sha-list sha_list.txt
```

Esempio su un singolo campione:

```bash
toolbehave eb-stats --reports-dir reports --sha-single <sha256>
```

Esempio filtrando uno schema di requirements:

```bash
toolbehave eb-stats --reports-dir reports --requirements src/resources/my_requirements.json
```

Output aggregato principale:

```text
reports/plots/aggregate/<scope>/all/eb_hist_pct.png
reports/plots/aggregate/<scope>/all/eb_hist_counts.png
reports/plots/aggregate/<scope>/all/eb_agreement_pct.png
reports/plots/aggregate/<scope>/all/eb_agreement_counts.png
```

In presenza di custom requirements coerenti, il comando genera anche cartelle dedicate allo schema dei requirements.

Output in modalità singolo campione:

```text
reports/plots/single/<sha-prefix>/single_table.txt
reports/plots/single/<sha-prefix>/single_presence_matrix.png
```

### `run`

Esegue la pipeline completa per un singolo file.

```bash
toolbehave run PATH [--reports-dir DIR] [--poll-every SECONDS] [--timeout SECONDS] [--requirements FILE] [--force]
```

Opzioni:

- `--reports-dir DIR`: directory base dei report. Default: `reports`;
- `--poll-every SECONDS`: intervallo di polling. Default: `10`;
- `--timeout SECONDS`: tempo massimo di attesa per il completamento di entrambi i provider. Default: `900`;
- `--requirements FILE`: file JSON opzionale contenente custom requirements;
- `--force`: rigenera e sovrascrive raw, normalized, enriched ed EB per lo SHA256 corrente.

Esempio senza custom requirements:

```bash
toolbehave run samples/sample.exe --reports-dir reports
```

Esempio con custom requirements:

```bash
toolbehave run samples/sample.exe \
  --reports-dir reports \
  --poll-every 15 \
  --timeout 1200 \
  --requirements src/resources/my_requirements.json
```

Output prodotti:

```text
reports/raw/raw_<sha256>.json
reports/normalized/normalized_<sha256>.json
reports/enriched/enriched_<sha256>.json
reports/eb/eb_<sha256>.json
```

## Workflow consigliati

### Pipeline completa per un singolo campione

```bash
toolbehave run samples/sample.exe --reports-dir reports
```

Con requirements custom:

```bash
toolbehave run samples/sample.exe \
  --reports-dir reports \
  --requirements src/resources/my_requirements.json
```

### Pipeline manuale per più campioni

Inviare i campioni:

```bash
toolbehave submit samples/sample1.exe
toolbehave submit samples/sample2.exe
toolbehave submit samples/sample3.exe
```

Controllare lo stato:

```bash
toolbehave list
toolbehave poll-all
```

Oppure usare polling continuo:

```bash
toolbehave watch 60
```

Scaricare i report grezzi:

```bash
toolbehave report-all --out-dir reports
```

Normalizzare:

```bash
toolbehave normalize-all --reports-dir reports
```

Generare EB:

```bash
toolbehave eb-all --reports-dir reports
```

Generare una sintesi:

```bash
toolbehave eb-summary --reports-dir reports --csv reports/eb_summary.csv
```

Generare statistiche e grafici:

```bash
toolbehave eb-stats --reports-dir reports
```

## File di risorse

Le risorse principali sono nella directory:

```text
src/resources/
```

File principali:

```text
Comportamenti_Equivoci.json
code_mappings.json
my_requirements.json
my_requirements_2.json
```

`Comportamenti_Equivoci.json` definisce le regole EB basate su tecniche MITRE ATT&CK.

`code_mappings.json` associa ciascun Equivocal Behaviour a un codice `ESB`.

I file `my_requirements*.json` sono esempi di custom requirements valutabili con la stessa logica di mapping.

## Note metodologiche

Gli Equivocal Behaviours sono derivati dalle tecniche MITRE ATT&CK riportate da VirusTotal e Hybrid Analysis. Quindi l'assenza di un EB non implica necessariamente l'assenza del comportamento reale nel campione: può dipendere dalla copertura del provider, dal tipo di analisi disponibile o dalla granularità del mapping.

La logica di matching corrente è binaria: se almeno una tecnica MITRE associata a un EB viene osservata, l'EB viene considerato attivato per quella sorgente.

## Avvertenze operative

L'invio di campioni a servizi esterni può esporre file, hash, metadati e risultati di analisi secondo le policy dei provider. Usare il tool solo con campioni che si è autorizzati a caricare su VirusTotal e Hybrid Analysis.

Non salvare nel repository pubblico:

```text
.env
toolbehave.sqlite3
reports/
__pycache__/
*.pyc
src/toolbehave.egg-info/
```
