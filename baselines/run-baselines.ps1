# PowerShell script to run baseline systems
# Usage: .\run-baselines.ps1 [start|stop|benchmark|quick-benchmark]

param(
    [Parameter(Position=0)]
    [ValidateSet("start", "stop", "benchmark", "quick-benchmark", "logs", "status")]
    [string]$Action = "start"
)

$BaselineDir = $PSScriptRoot

function Start-Baselines {
    Write-Host "Starting baseline systems..." -ForegroundColor Green

    Set-Location $BaselineDir
    docker-compose -f docker-compose.baselines.yml up -d

    Write-Host "`nWaiting for services to be ready..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10

    # Check health
    Write-Host "`nChecking service health:" -ForegroundColor Cyan

    $services = @(
        @{Name="OIDC Baseline"; Url="http://localhost:3100/health"},
        @{Name="Centralized Baseline"; Url="http://localhost:3200/health"},
        @{Name="Indy Baseline"; Url="http://localhost:3300/health"},
        @{Name="Keycloak"; Url="http://localhost:8080/health/ready"}
    )

    foreach ($service in $services) {
        try {
            $response = Invoke-RestMethod -Uri $service.Url -Method Get -TimeoutSec 5
            Write-Host "  $($service.Name): " -NoNewline
            Write-Host "Healthy" -ForegroundColor Green
        } catch {
            Write-Host "  $($service.Name): " -NoNewline
            Write-Host "Starting..." -ForegroundColor Yellow
        }
    }

    Write-Host "`nBaseline systems started!" -ForegroundColor Green
    Write-Host "OIDC Baseline: http://localhost:3100"
    Write-Host "Centralized Baseline: http://localhost:3200"
    Write-Host "Indy Baseline: http://localhost:3300"
    Write-Host "Keycloak Admin: http://localhost:8080 (admin/admin)"
}

function Stop-Baselines {
    Write-Host "Stopping baseline systems..." -ForegroundColor Yellow
    Set-Location $BaselineDir
    docker-compose -f docker-compose.baselines.yml down
    Write-Host "Baseline systems stopped." -ForegroundColor Green
}

function Run-Benchmark {
    param([bool]$Quick = $false)

    $mode = if ($Quick) { "--quick" } else { "--full" }
    $modeText = if ($Quick) { "Quick (30 runs)" } else { "Full (100 runs)" }

    Write-Host "Running $modeText benchmark..." -ForegroundColor Green
    Write-Host "This may take several minutes." -ForegroundColor Yellow

    Set-Location $BaselineDir
    docker-compose -f docker-compose.baselines.yml run --rm benchmark-runner node runner.js $mode

    Write-Host "`nBenchmark complete!" -ForegroundColor Green
    Write-Host "Results saved in: $BaselineDir\benchmark\results\" -ForegroundColor Cyan
}

function Show-Logs {
    Set-Location $BaselineDir
    docker-compose -f docker-compose.baselines.yml logs -f --tail=50
}

function Show-Status {
    Set-Location $BaselineDir
    docker-compose -f docker-compose.baselines.yml ps
}

# Main
switch ($Action) {
    "start" { Start-Baselines }
    "stop" { Stop-Baselines }
    "benchmark" { Run-Benchmark -Quick $false }
    "quick-benchmark" { Run-Benchmark -Quick $true }
    "logs" { Show-Logs }
    "status" { Show-Status }
}
