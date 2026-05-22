# BEHAVE: amBiguous and Equivocal beHAviors Verification Engine

This repository contains the replication package and tool implementation for the paper:

> **BEHAVE: amBiguous and Equivocal beHAviors Verification Engine**

BEHAVE is a command-line tool for collecting, normalizing, enriching, and analyzing behavioural evidence produced by malware-analysis sandboxes and file-reputation services. The tool supports empirical studies on **equivocal behaviours**: behaviours that are not necessarily malicious in isolation, but that may be security-relevant, ambiguous, or context-dependent when observed during software execution or static/dynamic analysis.

The package supports two execution modes:

1. **Replication mode**, starting from already collected raw reports and regenerating normalized reports, enriched reports, EB summaries, plots, and CSV statistics.
2. **Online collection mode**, submitting samples to VirusTotal and Hybrid Analysis and then processing the resulting reports.

For reproducibility, the recommended path is **replication mode**, because it does not require re-submitting binaries to external services and does not depend on API quota availability at execution time.

---

## Requirements

BEHAVE requires:

- **Python 3.10 or newer**;
- a **VirusTotal API key**, required for online collection mode;
- a **Hybrid Analysis API key**, required for online collection mode;
- the Python dependencies declared in `pyproject.toml`;
- `matplotlib`, required by `eb-stats` to generate plots.

The current `pyproject.toml` declares the following dependencies:

```toml
requires-python = ">=3.10"

dependencies = [
  "httpx>=0.27.0",
  "typer>=0.12.0",
  "python-dotenv>=1.0.1",
  "matplotlib>=3.8"
]
```

The declared dependencies are sufficient for the current implementation. Since `matplotlib` is already listed in `pyproject.toml`, installing the project with `pip install -e .` also installs the plotting dependency.

API keys are required only for commands that communicate with VirusTotal or Hybrid Analysis, such as `submit`, `run`, `poll`, `report`, and `report-all`. They are not required to regenerate normalized reports, EB summaries, or aggregate statistics from already collected raw reports.

---

## Installation

The following steps assume a Windows PowerShell environment. Equivalent commands can be used on Linux or macOS.

### 1. Create a Virtual Environment

From the repository root:

```powershell
python -m venv .venv
```

### 2. Activate the Virtual Environment

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, commands can be run directly through the virtual environment Python executable:

```powershell
.\.venv\Scripts\python.exe -m pip --version
```

Alternatively, start PowerShell with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass
```

### 3. Install BEHAVE

Install the tool in editable mode:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
```

This installs BEHAVE and the dependencies declared in `pyproject.toml`, including `matplotlib`.

If plotting commands fail because `matplotlib` is unavailable, install or refresh it explicitly:

```powershell
.\.venv\Scripts\python.exe -m pip install "matplotlib>=3.8"
```

### 4. Configure API Keys

For online collection mode, create a `.env` file in the repository root:

```env
VT_API_KEY=<VirusTotal API key>
HA_API_KEY=<Hybrid Analysis API key>
```

The `.env` file is not required when reproducing the analysis from already collected raw reports.

### 5. Verify the Installation

Recommended invocation:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli --help
```

If the console entry point is available, the following command is equivalent:

```powershell
.\.venv\Scripts\toolbehave.exe --help
```

On some Windows systems, application-control policies may block generated console wrappers such as `toolbehave.exe`. In that case, use the module form:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli --help
```

---

## Artifact Overview

This artifact contains:

- the BEHAVE command-line tool;
- the Equivocal Behaviour mapping rules;
- utilities for submitting samples to external analysis providers;
- utilities for polling and retrieving provider reports;
- a normalization layer for provider-specific report formats;
- utilities for generating per-sample EB summaries;
- utilities for generating aggregate plots, CSV files, and textual summaries;
- a local SQLite-based tracking mechanism for resumable execution.

The artifact supports the following reproducibility tasks:

1. regenerate normalized reports from raw provider reports;
2. regenerate Equivocal Behaviour summaries;
3. regenerate aggregate statistics and plots;
4. inspect source-level implementation details of the analysis pipeline;
5. optionally re-run online analysis using valid API keys.

The artifact does not require online submission if raw reports are already available. Online submission is only needed to collect new reports or extend the dataset.

---

## Recommended Replication Path

For replication, the recommended path is to start from already collected raw reports and regenerate all derived outputs.

This path avoids new submissions to third-party services and focuses on the deterministic part of the pipeline:

```text
raw provider reports
    |
    | normalize-all
    v
normalized reports
    |
    | eb-all
    v
enriched reports + EB summaries
    |
    | eb-stats
    v
plots + CSV statistics
```

Recommended commands:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli normalize-all --reports-dir reports
.\.venv\Scripts\python.exe -m toolbehave.cli eb-all --reports-dir reports
.\.venv\Scripts\python.exe -m toolbehave.cli eb-stats --reports-dir reports --by-os
```

The resulting outputs are written under:

```text
reports/
  normalized/
  enriched/
  eb/
  plots/
```

The aggregate CSV files and plots under `reports/plots/aggregate/` are the main outputs to inspect when reproducing the analysis.

If derived files already exist, commands may skip them by default. Use `--force` only when regenerated outputs should overwrite existing files.

---

## Purpose

BEHAVE supports the automated extraction of ambiguous and equivocal behaviours from software samples by combining evidence from multiple analysis providers.

The tool addresses the following practical needs:

1. submit software samples to external analysis services;
2. track submissions locally to avoid unnecessary re-submissions;
3. poll provider status until reports are available;
4. fetch raw reports from VirusTotal and Hybrid Analysis;
5. normalize heterogeneous reports into a common JSON representation;
6. map MITRE ATT&CK techniques to higher-level Equivocal Behaviour categories;
7. generate per-sample summaries of observed behaviours;
8. compute aggregate statistics over a dataset;
9. compare evidence across sources, for example Hybrid Analysis vs VirusTotal;
10. produce replication-friendly outputs, including JSON files, plots, CSV files, and text summaries.

The tool is not a malware detector. It does not assign definitive maliciousness labels. Instead, it supports the systematic identification and measurement of behaviours that require interpretation in context.

---

## High-Level Workflow

BEHAVE implements the following full workflow:

```text
software sample
    |
    | 1. compute SHA-256
    v
local SQLite database
    |
    | 2. submit/resume analysis
    v
VirusTotal + Hybrid Analysis
    |
    | 3. poll until completed
    v
raw reports
    |
    | 4. normalize provider-specific reports
    v
normalized report
    |
    | 5. map MITRE techniques to Equivocal Behaviours
    v
enriched report + EB summary
    |
    | 6. aggregate statistics
    v
plots + CSV + textual summaries
```

A typical full run for one sample produces:

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
    ...
```

---

## Repository Structure

A typical repository layout is:

```text
.
├── README.md
├── pyproject.toml
├── run_samples_rate_limited.ps1
├── samples/
│   ├── Windows/
│   ├── Linux/
│   └── macOS/
├── reports/
│   ├── raw/
│   ├── normalized/
│   ├── enriched/
│   ├── eb/
│   └── plots/
├── src/
│   ├── resources/
│   │   ├── Equivocal_Behaviours.json
│   │   ├── code_mappings.json
│   │   ├── my_requirements.json
│   │   └── my_requirements_2.json
│   └── toolbehave/
│       ├── cli.py
│       ├── config.py
│       ├── db.py
│       ├── models.py
│       ├── analysis/
│       │   └── normalizer.py
│       ├── mapping/
│       │   └── equivocal_behaviours.py
│       ├── pipeline/
│       │   └── orchestrator.py
│       └── services/
│           ├── virustotal.py
│           └── hybridanalysis.py
└── toolbehave.sqlite3
```

Important components:

| Path | Role |
|---|---|
| `src/toolbehave/cli.py` | Main Typer-based command-line interface |
| `src/toolbehave/config.py` | Loads API keys and DB configuration |
| `src/toolbehave/db.py` | SQLite persistence layer |
| `src/toolbehave/pipeline/orchestrator.py` | Coordinates submission, polling, and report retrieval |
| `src/toolbehave/services/virustotal.py` | VirusTotal API client |
| `src/toolbehave/services/hybridanalysis.py` | Hybrid Analysis API client |
| `src/toolbehave/analysis/normalizer.py` | Converts provider reports into a common normalized format |
| `src/toolbehave/mapping/equivocal_behaviours.py` | Maps MITRE ATT&CK techniques to EB categories |
| `src/resources/Equivocal_Behaviours.json` | Equivocal Behaviour rule definitions |
| `src/resources/code_mappings.json` | EB name to ESB code mapping |
| `toolbehave.sqlite3` | Generated SQLite database; included when reproducing submission metadata or OS-aware statistics |
| `run_samples_rate_limited.ps1` | Auxiliary script used during internal testing; not required for the main replication path |

The `samples/` directory is only required for online collection mode. It is not required when reproducing the analysis from existing raw reports.

The SQLite database is generated automatically by the tool. It is not required to regenerate normalized reports, EB summaries, or global EB statistics from existing raw reports. However, a populated database is required to reproduce OS-aware statistics with `eb-stats --by-os`, because the OS grouping is derived from the Hybrid Analysis `environment_id` stored in the database.

---

## Input Dataset Organization

The recommended layout for online collection is:

```text
samples/
  Windows/
    sample1.exe
    sample2.dll
    ...
  Linux/
    sample1.elf
    sample2.so
    ...
  macOS/
    sample1.macho
    sample2.dmg
    ...
```

The folder structure is useful for human organization. However, the Hybrid Analysis environment is selected by file extension, not by the folder name.

### Hybrid Analysis Environment Mapping

The current mapping is:

| File Type | Extensions | Hybrid Analysis environment ID |
|---|---|---:|
| Windows / PE-like | `.exe`, `.dll`, `.sys`, `.scr`, `.ocx`, `.cpl`, `.drv`, `.efi`, `.msi` | `140` |
| Linux / ELF-like | `.elf`, `.so`, `.bin`, `.run`, `.out` | `330` |
| macOS | `.macho`, `.dylib`, `.app`, `.pkg`, `.dmg` | `430` |

Meaning:

```text
140 -> Windows 11 64 bit
330 -> Linux Ubuntu 24.04 64 bit
430 -> macOS Tahoe ARM64
```

If a sample has an unsupported extension, the tool raises an error before submitting it to Hybrid Analysis.

---

## Core Concepts

### SHA-256 as Primary Identifier

Every sample is identified by its SHA-256 hash.

The hash is used to:

- track files in the SQLite database;
- avoid duplicate submissions;
- associate raw reports, normalized reports, enriched reports, and EB summaries;
- name output files.

Example:

```text
reports/raw/raw_<sha256>.json
reports/normalized/normalized_<sha256>.json
reports/enriched/enriched_<sha256>.json
reports/eb/eb_<sha256>.json
```

### Services

The tool currently supports two services:

```text
virustotal
hybridanalysis
```

The database stores one submission row per SHA-256 and service.

### Status Values

The tool uses the following status values:

```text
SUBMITTED
IN_PROGRESS
COMPLETED
FAILED
ERROR
```

A sample is considered ready for downstream processing only when both VirusTotal and Hybrid Analysis are `COMPLETED`.

### Equivocal Behaviour

An Equivocal Behaviour is a higher-level behavioural category defined by a set of MITRE ATT&CK technique identifiers.

A behaviour is considered triggered if at least one associated MITRE technique is observed in the normalized evidence.

The default EB definitions are stored in:

```text
src/resources/Equivocal_Behaviours.json
```

The mapping from EB names to compact codes is stored in:

```text
src/resources/code_mappings.json
```

Example compact codes:

```text
ESB1
ESB2
...
ESB12
```

---

## Command-Line Interface

The CLI is implemented with Typer.

Recommended invocation:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli <command> [options]
```

If the installed wrapper is available:

```powershell
.\.venv\Scripts\toolbehave.exe <command> [options]
```

### Show Help

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli --help
```

### Available Commands

| Command | Purpose |
|---|---|
| `submit` | Submit or resume submission for one sample |
| `list` | List all submissions stored in the local database |
| `poll` | Poll status once for one SHA-256 |
| `poll-all` | Poll status once for all SHA-256 values in the DB |
| `watch` | Continuously poll all submissions |
| `report` | Fetch raw reports for one SHA-256 |
| `report-all` | Fetch raw reports for all known SHA-256 values |
| `normalize-all` | Normalize all raw reports |
| `eb-all` | Generate enriched reports and EB summaries |
| `eb-summary` | Print compact per-sample EB summary |
| `eb-stats` | Generate aggregate EB statistics and plots |
| `run` | Execute the full online pipeline for one sample |

---

## Reproducing the Analysis from Existing Reports

This is the recommended path for replication.

It assumes that raw provider reports are already available under:

```text
reports/raw/
```

Expected raw report format:

```text
reports/raw/raw_<sha256>.json
```

### 1. Normalize Raw Reports

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli normalize-all --reports-dir reports
```

This reads:

```text
reports/raw/raw_<sha256>.json
```

and writes:

```text
reports/normalized/normalized_<sha256>.json
```

### 2. Generate Enriched Reports and EB Summaries

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-all --reports-dir reports
```

This reads:

```text
reports/normalized/normalized_<sha256>.json
```

and writes:

```text
reports/enriched/enriched_<sha256>.json
reports/eb/eb_<sha256>.json
```

### 3. Generate Aggregate Statistics

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-stats --reports-dir reports
```

### 4. Generate Operating-System-Aware Statistics

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-stats --reports-dir reports --by-os
```

The generated plots, CSV files, and text summaries are written under:

```text
reports/plots/
```

The OS-aware statistics require a populated `toolbehave.sqlite3` database containing Hybrid Analysis `environment_id` values. If the database is not available, global statistics can still be regenerated, but OS grouping may fall back to `unknown`.

This path is the preferred one for reproducing the analysis because it does not require submitting samples to external services.

---

## Running the Full Online Pipeline for One Sample

The `run` command performs online submission and all downstream processing for one sample.

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli run .\samples\Windows\sample.exe `
    --reports-dir reports `
    --poll-every 120 `
    --timeout 7200
```

This command:

1. computes SHA-256;
2. checks whether the final EB report already exists;
3. submits or resumes VirusTotal analysis;
4. submits or resumes Hybrid Analysis;
5. polls both providers until completion;
6. fetches raw reports;
7. normalizes reports;
8. enriches the normalized report with EB mappings;
9. writes the final EB summary.

### Force Reprocessing

To resubmit and regenerate all outputs:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli run .\samples\Windows\sample.exe `
    --reports-dir reports `
    --poll-every 120 `
    --timeout 7200 `
    --force
```

Use `--force` only when re-analysis or output regeneration is intentional.

---

## Generated Outputs

The default output root is:

```text
reports/
```

### Raw Reports

```text
reports/raw/raw_<sha256>.json
```

This file contains provider-specific output collected from VirusTotal and Hybrid Analysis.

A simplified structure is:

```json
{
  "sha256": "...",
  "virustotal": {},
  "hybridanalysis": {}
}
```

### Normalized Reports

```text
reports/normalized/normalized_<sha256>.json
```

The normalized report converts provider-specific structures into a common representation.

It includes, when available:

- verdict information;
- scores and labels;
- observed metrics;
- tags;
- MITRE ATT&CK techniques;
- process evidence;
- file evidence;
- registry evidence;
- network evidence;
- other behavioural observations.

### Enriched Reports

```text
reports/enriched/enriched_<sha256>.json
```

The enriched report contains the normalized report plus EB and optional requirement matches.

### EB Summary Reports

```text
reports/eb/eb_<sha256>.json
```

The EB summary is a compact per-sample representation used by the statistics layer.

It contains:

- SHA-256;
- triggered Equivocal Behaviours;
- sources that triggered each EB;
- matched MITRE techniques;
- counts;
- optional custom requirements;
- optional requirements schema metadata.

---

## Equivocal Behaviour Mapping

Default EB rules are defined in:

```text
src/resources/Equivocal_Behaviours.json
```

This file associates high-level EB categories with MITRE ATT&CK technique IDs.

The compact code mapping is defined in:

```text
src/resources/code_mappings.json
```

Example:

```json
{
  "System Analysis and Resource Discovery": "ESB1",
  "Network Enumeration and Analysis": "ESB2",
  "Network Traffic Manipulation and Covert Communications": "ESB3"
}
```

The current default EB codes are:

| Code | Behaviour |
|---|---|
| ESB1 | System Analysis and Resource Discovery |
| ESB2 | Network Enumeration and Analysis |
| ESB3 | Network Traffic Manipulation and Covert Communications |
| ESB4 | Scripting and Code Execution |
| ESB5 | Task Scheduling and System Automation |
| ESB6 | Advanced OS Utility Exploitation |
| ESB7 | Privilege Manipulation |
| ESB8 | Software Extension and Interaction |
| ESB9 | Control Evasion and Analysis Avoidance |
| ESB10 | Logging Evasion and Indirect Software Execution |
| ESB11 | Encryption Manipulation |
| ESB12 | Media Capture |

A behaviour is triggered if at least one of its associated MITRE techniques appears in the normalized provider evidence.

---

## Custom Requirements

In addition to the default EB taxonomy, BEHAVE can evaluate custom requirement rules.

A custom requirements file is a JSON object or list mapping requirement names to MITRE ATT&CK techniques.

Example:

```json
{
  "REQ - Network Discovery": ["T1016", "T1049"],
  "REQ - Command Execution": ["T1059"]
}
```

Run EB generation with custom requirements:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-all `
    --reports-dir reports `
    --requirements .\src\resources\my_requirements.json
```

Run the full one-sample pipeline with custom requirements:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli run .\samples\Windows\sample.exe `
    --reports-dir reports `
    --poll-every 120 `
    --timeout 7200 `
    --requirements .\src\resources\my_requirements.json
```

The tool stores requirement schema metadata in the generated enriched and EB files. This is important because `R1`, `R2`, etc. are meaningful only with respect to a specific requirements file.

### Requirements Schema Isolation

Aggregate requirements plots/statistics are generated only when the schema is coherent.

In particular:

- for the full dataset, the tool can generate one folder per detected requirements schema;
- for subsets, requirements plots are generated only if all samples in the subset share the same requirements schema;
- if the subset contains mixed or missing schemas, ESB-only outputs are generated and requirements outputs are skipped.

---

## Statistics and Plots

The main aggregate command is:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-stats --reports-dir reports
```

This reads:

```text
reports/eb/eb_<sha256>.json
```

and writes aggregate outputs under:

```text
reports/plots/aggregate/all/all/
```

### Generated Plot Files

```text
eb_hist_pct.png
eb_hist_counts.png
eb_agreement_pct.png
eb_agreement_counts.png
```

Meaning:

| File | Meaning |
|---|---|
| `eb_hist_pct.png` | Percentage of samples triggering each code by source |
| `eb_hist_counts.png` | Absolute count of samples triggering each code by source |
| `eb_agreement_pct.png` | Percentage split into HA-only, VT-only, and Both |
| `eb_agreement_counts.png` | Absolute count split into HA-only, VT-only, and Both |

### Generated Tabular Files

The statistics implementation also writes:

```text
eb_stats_counts.csv
eb_stats_percentages.csv
eb_stats_full.csv
eb_stats_summary.txt
```

Meaning:

| File | Meaning |
|---|---|
| `eb_stats_counts.csv` | Counts per EB/requirement code |
| `eb_stats_percentages.csv` | Percentages per EB/requirement code |
| `eb_stats_full.csv` | Counts and percentages in one file |
| `eb_stats_summary.txt` | Human-readable compact summary |

The CSV columns include:

```text
code
total_samples
ha_count
vt_count
both_count
ha_only_count
vt_only_count
ha_pct
vt_pct
both_pct
ha_only_pct
vt_only_pct
```

The denominator for percentages is the number of samples in the current aggregation scope.

### Single-Sample Statistics

For a single sample:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-stats `
    --reports-dir reports `
    --sha-single <sha256>
```

Outputs:

```text
reports/plots/single/<sha-prefix>/
  single_table.txt
  single_presence_matrix.png
```

The matrix shows whether each EB or requirement was triggered by:

- Hybrid Analysis;
- VirusTotal.

---

## Operating-System-Aware Statistics

BEHAVE can generate statistics grouped by target operating system:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-stats --reports-dir reports --by-os
```

This writes OS-specific aggregates under:

```text
reports/plots/aggregate/by_os/
```

Example:

```text
reports/plots/aggregate/by_os/windows/all/
reports/plots/aggregate/by_os/linux/all/
reports/plots/aggregate/by_os/macos/all/
reports/plots/aggregate/by_os/unknown/all/
```

The OS is inferred from the Hybrid Analysis `environment_id` stored in the SQLite database:

```text
140 -> windows
330 -> linux
430 -> macos
```

This design avoids relying on folder names and instead uses the environment that was actually selected for the sandbox submission.

If a SHA-256 has no corresponding Hybrid Analysis row, or if the row does not include a recognized `environment_id`, the sample is assigned to:

```text
unknown
```

---

## Resume Logic and Reproducibility

BEHAVE is designed to avoid unnecessary API usage and to make interrupted runs recoverable.

### Database

The local database is:

```text
toolbehave.sqlite3
```

It contains two main logical entities:

```text
files
submissions
```

The `files` table stores:

```text
sha256
file_path
```

The `submissions` table stores:

```text
sha256
service
external_id
environment_id
status
error
created_at
updated_at
```

The `environment_id` field is used for Hybrid Analysis OS-aware processing.

### Reusing Existing Submissions

If a sample was already submitted to VirusTotal or Hybrid Analysis, the tool reuses the stored submission unless `--force` is used.

Example:

```text
[RESUME] Reusing existing VirusTotal submission
[RESUME] Reusing existing Hybrid Analysis submission
```

### Skipping Completed Samples

If the final EB summary already exists:

```text
reports/eb/eb_<sha256>.json
```

then `run` exits immediately unless `--force` is used.

### Hybrid Analysis Terminal Failures

If Hybrid Analysis already failed for a sample, the tool does not automatically resubmit it. Instead, it reports a controlled skip unless `--force` is used.

This avoids repeatedly consuming sandbox submissions for samples that systematically fail.

Use `--force` only when a re-analysis is intentional.

---

## Manual Command Reference

### Submit One File

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli submit .\samples\Windows\sample.exe
```

### List Submissions

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli list
```

### Poll One SHA-256

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli poll <sha256>
```

### Poll All Known Submissions

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli poll-all
```

### Continuously Watch Submissions

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli watch --interval 120
```

### Fetch One Raw Report

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli report <sha256> --out report.json
```

### Fetch All Raw Reports

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli report-all --out-dir reports
```

### Normalize All Raw Reports

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli normalize-all --reports-dir reports
```

### Generate EB Reports

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-all --reports-dir reports
```

### Print EB Summary

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-summary --reports-dir reports --top 20
```

Optional CSV:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-summary `
    --reports-dir reports `
    --top 100 `
    --csv reports\eb_summary.csv
```

### Generate Aggregate Statistics

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-stats --reports-dir reports
```

### Generate OS-Specific Aggregate Statistics

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli eb-stats --reports-dir reports --by-os
```

---

## Troubleshooting

### `Missing VT_API_KEY env var`

The `.env` file is missing or does not contain `VT_API_KEY`.

```env
VT_API_KEY=<VirusTotal API key>
```

### `Missing HA_API_KEY env var`

The `.env` file is missing or does not contain `HA_API_KEY`.

```env
HA_API_KEY=<Hybrid Analysis API key>
```

### `toolbehave.exe` is blocked by Windows

Some Windows systems block generated console wrappers.

Use:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli <command>
```

instead of:

```powershell
.\.venv\Scripts\toolbehave.exe <command>
```

### PowerShell activation is blocked

If:

```powershell
.\.venv\Scripts\Activate.ps1
```

fails because script execution is disabled, run commands directly with:

```powershell
.\.venv\Scripts\python.exe
```

or start PowerShell with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass
```

### `Unsupported file extension for Hybrid Analysis environment selection`

The sample extension is not mapped to a Hybrid Analysis environment.

Supported extensions include:

```text
Windows: .exe, .dll, .sys, .scr, .ocx, .cpl, .drv, .efi, .msi
Linux:   .elf, .so, .bin, .run, .out
macOS:   .macho, .dylib, .app, .pkg, .dmg
```

Rename the file with an appropriate extension or extend the mapping in:

```text
src/toolbehave/pipeline/orchestrator.py
```

### VirusTotal `413 Request Entity Too Large`

For files larger than the standard VirusTotal upload size, the tool requests a dedicated VirusTotal upload URL before submitting the file.

If the error persists, verify that the API key has access to the required endpoint and that the file size is within the service limit.

### Provider status remains `IN_PROGRESS`

Increase timeout:

```powershell
--timeout 7200
```

or poll manually later:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli poll <sha256>
```

### Hybrid Analysis status is `FAILED`

A terminal Hybrid Analysis failure is not automatically retried.

To force re-submission:

```powershell
.\.venv\Scripts\python.exe -m toolbehave.cli run .\samples\Windows\sample.exe --force
```

Use this only when re-analysis is intentional.

### `matplotlib` not available

Install dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
```

or install `matplotlib` explicitly:

```powershell
.\.venv\Scripts\python.exe -m pip install "matplotlib>=3.8"
```

---

## Replication Notes

For replication, preserve the following artifacts:

```text
reports/raw/
reports/normalized/
reports/enriched/
reports/eb/
reports/plots/
src/resources/
toolbehave.sqlite3
```

The most important reproducibility files are:

| Artifact | Purpose |
|---|---|
| `reports/raw/` | Raw provider reports |
| `reports/normalized/` | Provider-independent normalized evidence |
| `reports/enriched/` | Normalized evidence enriched with EB mappings |
| `reports/eb/` | Compact EB summaries used for statistics |
| `reports/plots/` | Aggregate figures and CSV outputs |
| `src/resources/Equivocal_Behaviours.json` | EB taxonomy |
| `src/resources/code_mappings.json` | EB code mapping |
| `toolbehave.sqlite3` | Submission metadata, provider IDs, status, HA environment IDs |

The raw reports may be large and may contain provider-specific fields. For archival replication, the EB and normalized outputs are usually more compact and easier to inspect, while raw reports remain necessary for full traceability.

The SQLite database is generated automatically by the tool. It should be included in the replication package if OS-aware statistics must be reproduced exactly, because `eb-stats --by-os` uses the stored Hybrid Analysis `environment_id` values to assign samples to `windows`, `linux`, `macos`, or `unknown`.

---

## Limitations

The current implementation depends on external provider reports when online collection mode is used. Provider availability, quota limits, sandbox failures, and API format changes may affect online data collection.

The analysis is rule-driven and depends on the MITRE ATT&CK techniques exposed by the providers and extracted by the normalization layer. BEHAVE does not provide a definitive maliciousness judgment; it extracts and summarizes behavioural evidence that must be interpreted in context.

---

## Ethical and Safety Notice

This tool may process malware, potentially unwanted programs, or other security-sensitive binaries.

Use it only in controlled research environments.

Do not execute unknown samples on a host system outside an appropriate sandbox. The tool submits files to third-party services in online collection mode; therefore, confidential, proprietary, personal, or otherwise sensitive files should not be submitted unless this is explicitly permitted by the relevant data governance policy.

The replication package does not require executing samples locally. The recommended replication path starts from already collected raw reports.

---

## Citation

```bibtex
@inproceedings{anonymous_behave,
  title     = {BEHAVE: amBiguous and Equivocal beHAviours Verification Engine},
  author    = {Anonymous},
  booktitle = {Anonymous Venue},
  year      = {2026},
  note      = {Replication package}
}
```

---

## Quick Start

### Replication Mode

```powershell
# 1. Create environment
python -m venv .venv

# 2. Install package
.\.venv\Scripts\python.exe -m pip install -e .

# 3. Regenerate normalized reports
.\.venv\Scripts\python.exe -m toolbehave.cli normalize-all --reports-dir reports

# 4. Regenerate EB summaries
.\.venv\Scripts\python.exe -m toolbehave.cli eb-all --reports-dir reports

# 5. Generate aggregate statistics
.\.venv\Scripts\python.exe -m toolbehave.cli eb-stats --reports-dir reports --by-os
```

### Online Collection Mode

```powershell
# 1. Configure API keys in .env
# VT_API_KEY=...
# HA_API_KEY=...

# 2. Run one sample
.\.venv\Scripts\python.exe -m toolbehave.cli run .\samples\Windows\sample.exe `
    --reports-dir reports `
    --poll-every 120 `
    --timeout 7200
```
