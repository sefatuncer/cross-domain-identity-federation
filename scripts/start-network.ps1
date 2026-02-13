# Cross-Domain Identity Federation Network Startup Script (Windows PowerShell)
# This script starts the complete Hyperledger Fabric + OpenID4VC network

param(
    [Parameter(Position=0)]
    [ValidateSet("start", "stop", "restart", "status", "logs")]
    [string]$Command = "start",

    [Parameter(Position=1)]
    [string]$Service = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Test-Docker {
    Write-Info "Checking Docker..."
    try {
        $null = docker info 2>&1
        Write-Info "Docker is available."
        return $true
    } catch {
        Write-Error "Docker is not available. Please install and start Docker Desktop."
        return $false
    }
}

function Stop-Network {
    Write-Info "Stopping network..."
    Set-Location $ProjectDir
    docker-compose down -v --remove-orphans 2>$null
    docker network rm fabric-network openid-network bridge-network 2>$null
    Write-Info "Network stopped."
}

function Start-Infrastructure {
    Write-Info "Starting infrastructure services..."
    Set-Location $ProjectDir

    docker-compose up -d `
        ca.finance.crossdomain.com `
        ca.healthcare.crossdomain.com `
        ca.education.crossdomain.com `
        couchdb.finance `
        couchdb.healthcare `
        couchdb.education `
        postgres-issuer `
        postgres-holder `
        postgres-verifier

    Write-Info "Waiting for infrastructure services..."
    Start-Sleep -Seconds 10
    Write-Info "Infrastructure services started."
}

function Start-FabricNetwork {
    Write-Info "Starting Hyperledger Fabric network..."
    Set-Location $ProjectDir

    docker-compose up -d orderer.crossdomain.com
    Start-Sleep -Seconds 5

    docker-compose up -d `
        peer0.finance.crossdomain.com `
        peer0.healthcare.crossdomain.com `
        peer0.education.crossdomain.com

    Write-Info "Waiting for Fabric network..."
    Start-Sleep -Seconds 15

    docker-compose up -d cli
    Write-Info "Fabric network started."
}

function Start-OpenIDAgents {
    Write-Info "Starting OpenID4VC agents..."
    Set-Location $ProjectDir

    docker-compose up -d `
        finance-issuer `
        healthcare-issuer `
        education-issuer `
        holder-wallet `
        crossdomain-verifier

    Write-Info "Waiting for agents..."
    Start-Sleep -Seconds 10
    Write-Info "OpenID4VC agents started."
}

function Start-BridgeService {
    Write-Info "Starting Bridge Service..."
    Set-Location $ProjectDir

    docker-compose up -d bridge-service
    Start-Sleep -Seconds 5
    Write-Info "Bridge service started."
}

function Test-Health {
    Write-Info "Running health checks..."

    $services = @(
        @{Name="Bridge Service"; Url="http://localhost:4000/health"},
        @{Name="Finance Issuer"; Url="http://localhost:3001/health"},
        @{Name="Healthcare Issuer"; Url="http://localhost:3002/health"},
        @{Name="Education Issuer"; Url="http://localhost:3003/health"},
        @{Name="Holder Wallet"; Url="http://localhost:3010/health"},
        @{Name="Verifier"; Url="http://localhost:3020/health"}
    )

    foreach ($service in $services) {
        try {
            $response = Invoke-WebRequest -Uri $service.Url -Method Get -TimeoutSec 5 -UseBasicParsing
            Write-Info "$($service.Name): OK"
        } catch {
            Write-Warn "$($service.Name): Not responding"
        }
    }
}

function Show-Urls {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "Service URLs" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Bridge Service:     http://localhost:4000"
    Write-Host "Finance Issuer:     http://localhost:3001"
    Write-Host "Healthcare Issuer:  http://localhost:3002"
    Write-Host "Education Issuer:   http://localhost:3003"
    Write-Host "Holder Wallet:      http://localhost:3010"
    Write-Host "Verifier:           http://localhost:3020"
    Write-Host ""
    Write-Host "CouchDB Finance:    http://localhost:5984/_utils"
    Write-Host "CouchDB Healthcare: http://localhost:6984/_utils"
    Write-Host "CouchDB Education:  http://localhost:7984/_utils"
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "Quick Test Commands" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "# Health check"
    Write-Host "Invoke-WebRequest http://localhost:4000/health"
    Write-Host ""
    Write-Host "# Validate issuer"
    Write-Host 'Invoke-WebRequest -Uri "http://localhost:4000/api/issuer/validate" -Method Post -ContentType "application/json" -Body ''{"issuerDid":"did:web:bank.finance.crossdomain.com","credentialType":"KYCCredential"}'''
    Write-Host ""
}

# Main execution
switch ($Command) {
    "start" {
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "Cross-Domain Identity Federation" -ForegroundColor Cyan
        Write-Host "Network Startup Script (Windows)" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan

        if (-not (Test-Docker)) { exit 1 }
        Stop-Network
        Start-Infrastructure
        Start-FabricNetwork
        Start-OpenIDAgents
        Start-BridgeService
        Test-Health
        Show-Urls
        Write-Info "Network started successfully!"
    }
    "stop" {
        Stop-Network
    }
    "restart" {
        Stop-Network
        & $MyInvocation.MyCommand.Path -Command "start"
    }
    "status" {
        Test-Health
        Show-Urls
    }
    "logs" {
        Set-Location $ProjectDir
        if ($Service) {
            docker-compose logs -f $Service
        } else {
            docker-compose logs -f
        }
    }
}
