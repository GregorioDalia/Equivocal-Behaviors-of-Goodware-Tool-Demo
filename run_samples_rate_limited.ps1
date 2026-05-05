# Root del progetto = cartella in cui si trova questo script
$ProjectDir = $PSScriptRoot

$SamplesDir = Join-Path $ProjectDir "samples"
$ReportsDir = Join-Path $ProjectDir "reports"
$LogsDir = Join-Path $ProjectDir "logs"

# Limiti prudenziali per rispettare VirusTotal e Hybrid Analysis
$MaxSamplesToday = 50
$PollEverySeconds = 300
$TimeoutSeconds = 7200
$PauseBetweenSamples = 30

# Estensioni considerate campioni software
$AllowedExtensions = @(".exe", ".dll", ".bin")

New-Item -ItemType Directory -Force -Path $ReportsDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null

if (-not (Test-Path $SamplesDir)) {
    Write-Error "Samples directory not found: $SamplesDir"
    exit 1
}

$samples = Get-ChildItem -Path $SamplesDir -File -Recurse |
    Where-Object { $AllowedExtensions -contains $_.Extension.ToLower() } |
    Select-Object -First $MaxSamplesToday

Write-Host "Project dir: $ProjectDir"
Write-Host "Samples dir: $SamplesDir"
Write-Host "Reports dir: $ReportsDir"
Write-Host "Logs dir: $LogsDir"
Write-Host "Selected samples today:" $samples.Count
Write-Host "Polling every $PollEverySeconds seconds"
Write-Host "Timeout per sample: $TimeoutSeconds seconds"
Write-Host ""

if ($samples.Count -eq 0) {
    Write-Warning "No samples found. Check the samples directory or allowed extensions."
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

    & "$ProjectDir\.venv\Scripts\toolbehave.exe" run $sample.FullName `        --reports-dir $ReportsDir `
        --poll-every $PollEverySeconds `
        --timeout $TimeoutSeconds `
        2>&1 | Tee-Object -FilePath $logFile

    Write-Host ""
    Write-Host "Pause of $PauseBetweenSamples seconds before next sample..."
    Start-Sleep -Seconds $PauseBetweenSamples
}