# Root del progetto = cartella in cui si trova questo script
$ProjectDir = $PSScriptRoot
Set-Location $ProjectDir

$SamplesDir = Join-Path $ProjectDir "samples"
$ReportsDir = Join-Path $ProjectDir "reports"
$LogsDir = Join-Path $ProjectDir "logs"

# Eseguibile Python dentro il virtual environment del progetto
$PythonExe = Join-Path $ProjectDir ".venv\Scripts\python.exe"
$ToolbehaveModule = "toolbehave.cli"

# Limiti prudenziali per rispettare VirusTotal e Hybrid Analysis
$MaxSamplesToday = 94
$PollEverySeconds = 120
$TimeoutSeconds = 7200
$PauseBetweenSamples = 10

# Generazione statistiche a fine batch
$GenerateStatsAfterRun = $true
$GenerateStatsByOs = $true

# File da escludere
$ExcludedExtensions = @(
    ".json",
    ".txt",
    ".md",
    ".csv",
    ".log"
)

function Invoke-EBStats {
    param (
        [string]$StatsLogFile
    )

    Write-Host "========================================"
    Write-Host "Generating EB statistics"
    Write-Host "Log: $StatsLogFile"
    Write-Host "========================================"

    if ($GenerateStatsByOs) {
        & $PythonExe -m $ToolbehaveModule eb-stats `
            --reports-dir $ReportsDir `
            --by-os `
            2>&1 | Tee-Object -FilePath $StatsLogFile
    }
    else {
        & $PythonExe -m $ToolbehaveModule eb-stats `
            --reports-dir $ReportsDir `
            2>&1 | Tee-Object -FilePath $StatsLogFile
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "EB statistics generation failed. Check log: $StatsLogFile"
    }
    else {
        Write-Host "EB statistics generated successfully."
    }
}

# Crea cartelle di output
New-Item -ItemType Directory -Force -Path $ReportsDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null

# Controlli preliminari
if (-not (Test-Path $SamplesDir)) {
    Write-Error "Samples directory not found: $SamplesDir"
    exit 1
}

if (-not (Test-Path $PythonExe)) {
    Write-Error "Python executable not found: $PythonExe"
    Write-Error "Check that the virtual environment exists in: .venv"
    exit 1
}

& $PythonExe -c "import toolbehave.cli; print('toolbehave import OK')"

if ($LASTEXITCODE -ne 0) {
    Write-Error "Cannot import toolbehave.cli. Install the project first with:"
    Write-Error ".\.venv\Scripts\python.exe -m pip install -e ."
    exit 1
}

Write-Host "Project dir: $ProjectDir"
Write-Host "Samples dir: $SamplesDir"
Write-Host "Reports dir: $ReportsDir"
Write-Host "Logs dir: $LogsDir"
Write-Host "Python: $PythonExe"
Write-Host "Toolbehave module: $ToolbehaveModule"
Write-Host "Max pending samples today: $MaxSamplesToday"
Write-Host "Polling every $PollEverySeconds seconds"
Write-Host "Timeout per sample: $TimeoutSeconds seconds"
Write-Host "Pause between samples: $PauseBetweenSamples seconds"
Write-Host "Generate stats after run: $GenerateStatsAfterRun"
Write-Host "Generate stats by OS: $GenerateStatsByOs"
Write-Host ""

# Verifica compilazione del codice prima del batch
Write-Host "Checking Python code compilation..."

& $PythonExe -m compileall (Join-Path $ProjectDir "src\toolbehave")

if ($LASTEXITCODE -ne 0) {
    Write-Error "Compilation failed. Batch stopped."
    exit 1
}

Write-Host "Compilation OK."
Write-Host ""

# --------------------------------------------------------------------
# Crea helper Python temporaneo per leggere dal DB gli SHA con HA FAILED
# --------------------------------------------------------------------
$HaFailureScriptPath = Join-Path $LogsDir "_ha_failed_lookup.py"

$HaFailurePython = @'
import sqlite3
import sys
from pathlib import Path

project_dir = Path(sys.argv[1])
db_path = project_dir / "toolbehave.sqlite3"

if not db_path.exists():
    raise SystemExit(0)

conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row

try:
    rows = conn.execute(
        """
        SELECT sha256, status, external_id, environment_id
        FROM submissions
        WHERE service = ?
        """,
        ("hybridanalysis",)
    ).fetchall()

    for row in rows:
        status = str(row["status"]).upper()
        if status in {"FAILED", "ERROR"}:
            sha256 = str(row["sha256"])
            env = "" if row["environment_id"] is None else str(row["environment_id"])
            external_id = "" if row["external_id"] is None else str(row["external_id"])
            print(f"{sha256}|{status}|{env}|{external_id}")

finally:
    conn.close()
'@

Set-Content -LiteralPath $HaFailureScriptPath -Value $HaFailurePython -Encoding UTF8

[hashtable]$HaFailureBySha = @{}

$haFailureLines = & $PythonExe $HaFailureScriptPath $ProjectDir 2>$null

if ($LASTEXITCODE -ne 0) {
    Write-Warning "Could not load HA terminal failures from DB. Continuing without this pre-filter."
}
else {
    foreach ($line in @($haFailureLines)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $parts = $line.Split("|", 4)

        if ($parts.Count -ge 2) {
            $sha = $parts[0].Trim().ToLowerInvariant()
            $status = $parts[1].Trim()
            $env = ""
            $externalId = ""

            if ($parts.Count -ge 3) {
                $env = $parts[2].Trim()
            }

            if ($parts.Count -ge 4) {
                $externalId = $parts[3].Trim()
            }

            $HaFailureBySha[$sha] = "$status|$env|$externalId"
        }
    }
}

Write-Host "HA terminal failures loaded from DB:" $HaFailureBySha.Count
Write-Host ""

# Seleziona tutti i candidati ricorsivamente da samples/
$allCandidates = @(
    Get-ChildItem -Path $SamplesDir -File -Recurse |
        Where-Object { $ExcludedExtensions -notcontains $_.Extension.ToLowerInvariant() }
)

$pendingSamples = @()
$alreadyCompleted = @()
$hashFailed = @()
$haFailed = @()

Write-Host "Checking already completed samples..."
Write-Host ""

foreach ($candidate in $allCandidates) {
    if ($null -eq $candidate -or [string]::IsNullOrWhiteSpace($candidate.FullName)) {
        Write-Warning "Skipping null or invalid candidate."
        continue
    }

    try {
        $hashResult = Get-FileHash -Algorithm SHA256 -LiteralPath $candidate.FullName -ErrorAction Stop
    }
    catch {
        $hashFailed += $candidate
        Write-Warning "Cannot compute SHA256 for: $($candidate.FullName)"
        Write-Warning "Reason: $($_.Exception.Message)"
        continue
    }

    if ($null -eq $hashResult -or [string]::IsNullOrWhiteSpace($hashResult.Hash)) {
        $hashFailed += $candidate
        Write-Warning "Empty SHA256 result for: $($candidate.FullName)"
        continue
    }

    $sha256 = $hashResult.Hash.ToLowerInvariant()
    $expectedEbReport = Join-Path $ReportsDir "eb\eb_$sha256.json"

    if (Test-Path $expectedEbReport) {
        $alreadyCompleted += $candidate
        Write-Host "[SKIP BEFORE RUN] Already completed: $($candidate.FullName)"
        Write-Host "                  Existing EB report: $expectedEbReport"
        continue
    }

    if ($HaFailureBySha.ContainsKey($sha256)) {
        $haFailed += $candidate
        Write-Host "[SKIP BEFORE RUN] HA terminal failure already recorded: $($candidate.FullName)"
        Write-Host "                  HA status/env/external_id: $($HaFailureBySha[$sha256])"
        continue
    }

    $pendingSamples += $candidate
}

# Applica il limite giornaliero solo ai campioni realmente da processare
$samples = @($pendingSamples | Select-Object -First $MaxSamplesToday)

Write-Host ""
Write-Host "Candidate summary"
Write-Host "-----------------"
Write-Host "Total candidate files:" $allCandidates.Count
Write-Host "Already completed:" $alreadyCompleted.Count
Write-Host "HA terminal failures:" $haFailed.Count
Write-Host "Hash failed:" $hashFailed.Count
Write-Host "Pending samples:" $pendingSamples.Count
Write-Host "Selected pending samples today:" $samples.Count
Write-Host ""

if ($samples.Count -eq 0) {
    Write-Host "No pending samples to process."

    if ($GenerateStatsAfterRun) {
        $statsTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $statsLogFile = Join-Path $LogsDir "$statsTimestamp`_eb_stats.log"
        Invoke-EBStats -StatsLogFile $statsLogFile
    }

    Write-Host ""
    Write-Host "Batch completed."
    exit 0
}

$count = 0

foreach ($sample in $samples) {
    $count++

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeName = $sample.Name -replace '[^a-zA-Z0-9_.-]', '_'
    $logFile = Join-Path $LogsDir "$timestamp`_$safeName.log"

    Write-Host "========================================"
    Write-Host "[$count/$($samples.Count)] Full pipeline for: $($sample.FullName)"
    Write-Host "Log: $logFile"
    Write-Host "========================================"

    $runFailed = $false

    try {
        & $PythonExe -m $ToolbehaveModule run $sample.FullName `
            --reports-dir $ReportsDir `
            --poll-every $PollEverySeconds `
            --timeout $TimeoutSeconds `
            2>&1 | Tee-Object -FilePath $logFile

        if ($LASTEXITCODE -ne 0) {
            $runFailed = $true
        }
    }
    catch {
        $runFailed = $true
        Write-Warning "PowerShell failed to start or run the pipeline."
        Write-Warning "Reason: $($_.Exception.Message)"
    }

    $logContent = Get-Content -LiteralPath $logFile -Raw -ErrorAction SilentlyContinue

    if ($logContent -match "429|QuotaExceededError|TooManyRequestsError|rate limit|quota") {
        Write-Warning "Rate limit or quota issue detected. Stopping batch to avoid wasting requests."
        Write-Warning "Check log: $logFile"
        exit 2
    }

    if ($runFailed) {
        Write-Warning "Pipeline failed for: $($sample.FullName)"
        Write-Warning "Check log: $logFile"
    }
    else {
        Write-Host "Completed or resumed successfully: $($sample.FullName)"
    }

    if ($count -lt $samples.Count) {
        Write-Host ""
        Write-Host "Pause of $PauseBetweenSamples seconds before next sample..."
        Start-Sleep -Seconds $PauseBetweenSamples
    }
}

if ($GenerateStatsAfterRun) {
    $statsTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $statsLogFile = Join-Path $LogsDir "$statsTimestamp`_eb_stats.log"

    Write-Host ""
    Invoke-EBStats -StatsLogFile $statsLogFile
}

Write-Host ""
Write-Host "Batch completed."