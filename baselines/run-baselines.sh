#!/bin/bash
# Bash script to run baseline systems
# Usage: ./run-baselines.sh [start|stop|benchmark|quick-benchmark]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

start_baselines() {
    echo -e "${GREEN}Starting baseline systems...${NC}"

    docker-compose -f docker-compose.baselines.yml up -d

    echo -e "\n${YELLOW}Waiting for services to be ready...${NC}"
    sleep 10

    echo -e "\n${CYAN}Checking service health:${NC}"

    check_health "OIDC Baseline" "http://localhost:3100/health"
    check_health "Centralized Baseline" "http://localhost:3200/health"
    check_health "Indy Baseline" "http://localhost:3300/health"
    check_health "Keycloak" "http://localhost:8080/health/ready"

    echo -e "\n${GREEN}Baseline systems started!${NC}"
    echo "OIDC Baseline: http://localhost:3100"
    echo "Centralized Baseline: http://localhost:3200"
    echo "Indy Baseline: http://localhost:3300"
    echo "Keycloak Admin: http://localhost:8080 (admin/admin)"
}

check_health() {
    local name="$1"
    local url="$2"

    if curl -s --max-time 5 "$url" > /dev/null 2>&1; then
        echo -e "  $name: ${GREEN}Healthy${NC}"
    else
        echo -e "  $name: ${YELLOW}Starting...${NC}"
    fi
}

stop_baselines() {
    echo -e "${YELLOW}Stopping baseline systems...${NC}"
    docker-compose -f docker-compose.baselines.yml down
    echo -e "${GREEN}Baseline systems stopped.${NC}"
}

run_benchmark() {
    local quick="$1"
    local mode=""
    local mode_text=""

    if [ "$quick" = "true" ]; then
        mode="--quick"
        mode_text="Quick (30 runs)"
    else
        mode="--full"
        mode_text="Full (100 runs)"
    fi

    echo -e "${GREEN}Running $mode_text benchmark...${NC}"
    echo -e "${YELLOW}This may take several minutes.${NC}"

    docker-compose -f docker-compose.baselines.yml run --rm benchmark-runner node runner.js $mode

    echo -e "\n${GREEN}Benchmark complete!${NC}"
    echo -e "${CYAN}Results saved in: $SCRIPT_DIR/benchmark/results/${NC}"
}

show_logs() {
    docker-compose -f docker-compose.baselines.yml logs -f --tail=50
}

show_status() {
    docker-compose -f docker-compose.baselines.yml ps
}

# Main
case "${1:-start}" in
    start)
        start_baselines
        ;;
    stop)
        stop_baselines
        ;;
    benchmark)
        run_benchmark "false"
        ;;
    quick-benchmark)
        run_benchmark "true"
        ;;
    logs)
        show_logs
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 [start|stop|benchmark|quick-benchmark|logs|status]"
        exit 1
        ;;
esac
