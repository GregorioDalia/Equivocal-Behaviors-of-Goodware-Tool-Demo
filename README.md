# ToolBEHAVE — Equivocal Behaviors of Goodware (Demo)

ToolBEHAVE è un tool da riga di comando (CLI) che automatizza l’analisi di un campione software tramite **VirusTotal** e **HybridAnalysis**, normalizza i risultati in uno schema unificato e calcola:

- **MITRE ATT&CK techniques** osservate per sorgente (VT/HA)
- **Equivocal Behaviours (EB)** (codici **ESB1..ESB12**) derivati da mapping statico
- **Custom Requirements** (codici **R1..Rn**) definiti dall’utente, valutati con la stessa logica di matching MITRE

L’obiettivo è produrre output riproducibili e confrontabili tra provider, oltre a statistiche e grafici per analisi su singoli campioni o su insiemi di campioni.

---

## Requisiti

- Python (consigliato usare un virtualenv)
- Chiavi API valide per:
  - VirusTotal
  - HybridAnalysis
- Dipendenze Python: installate via `pip` (vedi sotto)
- `matplotlib` è necessario solo per la generazione dei grafici (`eb-stats` con plots abilitati)

---

## Installazione

Clona il repository e installa in un virtualenv:

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .
