# Re-runs a benchmark until its result file exists. Finished episodes are
# cached under runs/, so every restart resumes where the last one stopped.
#   powershell -File bench/resume.ps1 -Defense provguard
param(
    [string]$Defense = "provguard",
    [string]$Model = "qwen3-8k",
    [int]$MaxAttempts = 20
)
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$py = Join-Path $root ".venv\Scripts\python.exe"
$result = Join-Path $root "results\banking\$Model-nothink\$Defense-r0.json"
$log = Join-Path $root "overnight-$Defense.log"

for ($i = 1; $i -le $MaxAttempts -and -not (Test-Path $result); $i++) {
    Add-Content $log "attempt $i started $(Get-Date -Format 'HH:mm:ss')"
    & $py -m bench.run --suite banking --defense $Defense --no-think --model $Model `
        --injection-tasks injection_task_0 injection_task_1 injection_task_2 *>> $log
    Add-Content $log "attempt $i exited with $LASTEXITCODE at $(Get-Date -Format 'HH:mm:ss')"
}
Add-Content $log "finished: $(Test-Path $result)"
