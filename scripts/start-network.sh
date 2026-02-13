#!/bin/bash

# Cross-Domain Identity Federation Network Startup Script
# This script starts the complete Hyperledger Fabric + OpenID4VC network

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "============================================"
echo "Cross-Domain Identity Federation"
echo "Network Startup Script"
echo "============================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check Docker
check_docker() {
    log_info "Checking Docker..."
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi

    log_info "Docker is available."
}

# Check Docker Compose
check_docker_compose() {
    log_info "Checking Docker Compose..."
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed."
        exit 1
    fi

    log_info "Docker Compose is available."
}

# Clean up previous deployments
cleanup() {
    log_info "Cleaning up previous deployments..."
    cd "$PROJECT_DIR"

    docker-compose down -v --remove-orphans 2>/dev/null || true
    docker network rm fabric-network openid-network bridge-network 2>/dev/null || true

    log_info "Cleanup complete."
}

# Start infrastructure services (CAs, DBs)
start_infrastructure() {
    log_info "Starting infrastructure services..."
    cd "$PROJECT_DIR"

    docker-compose up -d \
        ca.finance.crossdomain.com \
        ca.healthcare.crossdomain.com \
        ca.education.crossdomain.com \
        couchdb.finance \
        couchdb.healthcare \
        couchdb.education \
        postgres-issuer \
        postgres-holder \
        postgres-verifier

    log_info "Waiting for infrastructure services to be ready..."
    sleep 10

    log_info "Infrastructure services started."
}

# Start Fabric network
start_fabric_network() {
    log_info "Starting Hyperledger Fabric network..."
    cd "$PROJECT_DIR"

    # Start orderer
    docker-compose up -d orderer.crossdomain.com

    sleep 5

    # Start peer nodes
    docker-compose up -d \
        peer0.finance.crossdomain.com \
        peer0.healthcare.crossdomain.com \
        peer0.education.crossdomain.com

    log_info "Waiting for Fabric network to initialize..."
    sleep 15

    # Start CLI
    docker-compose up -d cli

    log_info "Fabric network started."
}

# Start OpenID4VC agents
start_openid_agents() {
    log_info "Starting OpenID4VC agents..."
    cd "$PROJECT_DIR"

    docker-compose up -d \
        finance-issuer \
        healthcare-issuer \
        education-issuer \
        holder-wallet \
        crossdomain-verifier

    log_info "Waiting for agents to initialize..."
    sleep 10

    log_info "OpenID4VC agents started."
}

# Start Bridge Service
start_bridge_service() {
    log_info "Starting Bridge Service..."
    cd "$PROJECT_DIR"

    docker-compose up -d bridge-service

    log_info "Waiting for bridge service to connect..."
    sleep 5

    log_info "Bridge service started."
}

# Health check
health_check() {
    log_info "Running health checks..."

    # Check bridge service
    if curl -s http://localhost:4000/health > /dev/null; then
        log_info "Bridge Service: OK"
    else
        log_warn "Bridge Service: Not responding"
    fi

    # Check Finance Issuer
    if curl -s http://localhost:3001/health > /dev/null; then
        log_info "Finance Issuer: OK"
    else
        log_warn "Finance Issuer: Not responding"
    fi

    # Check Healthcare Issuer
    if curl -s http://localhost:3002/health > /dev/null; then
        log_info "Healthcare Issuer: OK"
    else
        log_warn "Healthcare Issuer: Not responding"
    fi

    # Check Education Issuer
    if curl -s http://localhost:3003/health > /dev/null; then
        log_info "Education Issuer: OK"
    else
        log_warn "Education Issuer: Not responding"
    fi

    # Check Holder Wallet
    if curl -s http://localhost:3010/health > /dev/null; then
        log_info "Holder Wallet: OK"
    else
        log_warn "Holder Wallet: Not responding"
    fi

    # Check Verifier
    if curl -s http://localhost:3020/health > /dev/null; then
        log_info "Verifier: OK"
    else
        log_warn "Verifier: Not responding"
    fi
}

# Print service URLs
print_urls() {
    echo ""
    echo "============================================"
    echo "Service URLs"
    echo "============================================"
    echo ""
    echo "Bridge Service:     http://localhost:4000"
    echo "Finance Issuer:     http://localhost:3001"
    echo "Healthcare Issuer:  http://localhost:3002"
    echo "Education Issuer:   http://localhost:3003"
    echo "Holder Wallet:      http://localhost:3010"
    echo "Verifier:           http://localhost:3020"
    echo ""
    echo "CouchDB Finance:    http://localhost:5984/_utils"
    echo "CouchDB Healthcare: http://localhost:6984/_utils"
    echo "CouchDB Education:  http://localhost:7984/_utils"
    echo ""
    echo "============================================"
    echo "Quick Test Commands"
    echo "============================================"
    echo ""
    echo "# Health check"
    echo "curl http://localhost:4000/health"
    echo ""
    echo "# Validate issuer"
    echo 'curl -X POST http://localhost:4000/api/issuer/validate \'
    echo '  -H "Content-Type: application/json" \'
    echo '  -d '"'"'{"issuerDid":"did:web:bank.finance.crossdomain.com","credentialType":"KYCCredential"}'"'"
    echo ""
    echo "# Cross-domain verification"
    echo 'curl -X POST http://localhost:4000/api/cross-domain/verify \'
    echo '  -H "Content-Type: application/json" \'
    echo '  -d '"'"'{"sourceDomain":"FINANCE","targetDomain":"HEALTHCARE","credentialType":"KYCCredential","issuerDid":"did:web:bank.finance.crossdomain.com"}'"'"
    echo ""
}

# Main execution
main() {
    case "${1:-start}" in
        start)
            check_docker
            check_docker_compose
            cleanup
            start_infrastructure
            start_fabric_network
            start_openid_agents
            start_bridge_service
            health_check
            print_urls
            log_info "Network started successfully!"
            ;;
        stop)
            log_info "Stopping network..."
            cd "$PROJECT_DIR"
            docker-compose down
            log_info "Network stopped."
            ;;
        restart)
            $0 stop
            $0 start
            ;;
        status)
            health_check
            print_urls
            ;;
        logs)
            cd "$PROJECT_DIR"
            docker-compose logs -f ${2:-}
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|status|logs [service]}"
            exit 1
            ;;
    esac
}

main "$@"
