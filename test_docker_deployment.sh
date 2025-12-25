#!/bin/bash

# BlkBox Docker Deployment Test Script
# Tests all honeypot services and strike-back functionality

set -e

echo "🐝 BlkBox Docker Deployment Test"
echo "=================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
PASSED=0
FAILED=0

# Function to print test result
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $2"
        ((PASSED++))
    else
        echo -e "${RED}✗${NC} $2"
        ((FAILED++))
    fi
}

# Wait for service to be ready
wait_for_service() {
    local port=$1
    local name=$2
    local max_attempts=30
    local attempt=0

    echo -n "⏳ Waiting for $name (port $port)... "

    while [ $attempt -lt $max_attempts ]; do
        if nc -z localhost $port 2>/dev/null; then
            echo -e "${GREEN}ready${NC}"
            return 0
        fi
        sleep 1
        ((attempt++))
    done

    echo -e "${RED}timeout${NC}"
    return 1
}

echo "📦 Building Docker image..."
docker-compose build
print_result $? "Docker image built"
echo ""

echo "🚀 Starting BlkBox container..."
docker-compose up -d
print_result $? "Container started"
echo ""

# Wait for services to start
sleep 5

echo "🔍 Checking service health..."
echo ""

# Test Management Dashboard
echo "1️⃣  Testing Management Dashboard (HTTP 9000)"
wait_for_service 9000 "Management Dashboard"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9000/api/health 2>/dev/null || echo "000")
if [ "$RESPONSE" = "200" ]; then
    print_result 0 "Management API responding"
else
    print_result 1 "Management API not responding (HTTP $RESPONSE)"
fi
echo ""

# Test HTTP Honeypot
echo "2️⃣  Testing HTTP Honeypot (Port 8080)"
wait_for_service 8080 "HTTP Honeypot"

# Test root
HTTP_RESPONSE=$(curl -s -w "\n%{http_code}" http://localhost:8080/ 2>/dev/null || echo -e "\n000")
HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -1)
print_result $([ "$HTTP_CODE" != "000" ] && echo 0 || echo 1) "HTTP root endpoint (HTTP $HTTP_CODE)"

# Test WordPress admin (common target)
WP_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/wp-admin/ 2>/dev/null || echo "000")
print_result $([ "$WP_RESPONSE" != "000" ] && echo 0 || echo 1) "WordPress admin endpoint (HTTP $WP_RESPONSE)"

# Test phpMyAdmin (common target)
PMA_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/phpmyadmin/ 2>/dev/null || echo "000")
print_result $([ "$PMA_RESPONSE" != "000" ] && echo 0 || echo 1) "phpMyAdmin endpoint (HTTP $PMA_RESPONSE)"

# Test .git exposure (info disclosure)
GIT_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/.git/config 2>/dev/null || echo "000")
print_result $([ "$GIT_RESPONSE" != "000" ] && echo 0 || echo 1) ".git exposure endpoint (HTTP $GIT_RESPONSE)"

echo ""

# Test SSH Honeypot
echo "3️⃣  Testing SSH Honeypot (Port 2222)"
wait_for_service 2222 "SSH Honeypot"

# Try to connect and capture banner
SSH_BANNER=$(timeout 5 ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null localhost 2>&1 | head -1 || true)
if echo "$SSH_BANNER" | grep -q "SSH-2.0"; then
    print_result 0 "SSH banner received: $(echo $SSH_BANNER | grep -o 'SSH-2.0-[^[:space:]]*')"
else
    print_result 1 "SSH banner not received"
fi

# Test authentication attempt (will fail, but should be logged)
timeout 5 sshpass -p "admin" ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@localhost "whoami" 2>/dev/null || true
print_result 0 "SSH authentication attempt sent"

echo ""

# Test PostgreSQL Honeypot
echo "4️⃣  Testing PostgreSQL Honeypot (Port 5432)"
wait_for_service 5432 "PostgreSQL Honeypot"
print_result 0 "PostgreSQL port is listening"

echo ""

# Test MySQL Honeypot
echo "5️⃣  Testing MySQL Honeypot (Port 3306)"
wait_for_service 3306 "MySQL Honeypot"
print_result 0 "MySQL port is listening"

echo ""

# Test FTP Honeypot
echo "6️⃣  Testing FTP Honeypot (Port 21)"
wait_for_service 21 "FTP Honeypot"

# Try to connect and get banner
FTP_BANNER=$(timeout 5 curl -s ftp://localhost:21 2>&1 | head -1 || true)
if echo "$FTP_BANNER" | grep -q "220"; then
    print_result 0 "FTP banner received"
else
    print_result 1 "FTP banner not received"
fi

echo ""

# Wait for events to be processed
echo "⏳ Waiting for events to be processed (5 seconds)..."
sleep 5

# Check if attacks were logged
echo ""
echo "7️⃣  Testing Attack Logging"

# Check database for attacks
ATTACK_COUNT=$(docker exec blkbox-honeypot sqlite3 /opt/blkbox/blkbox.db "SELECT COUNT(*) FROM attacks" 2>/dev/null || echo "0")
if [ "$ATTACK_COUNT" -gt 0 ]; then
    print_result 0 "Attacks logged in database ($ATTACK_COUNT events)"

    # Show attack details
    echo ""
    echo "📊 Recent Attacks:"
    docker exec blkbox-honeypot sqlite3 -header -column /opt/blkbox/blkbox.db \
        "SELECT id, timestamp, source_ip, service_type, threat_level FROM attacks ORDER BY timestamp DESC LIMIT 5" 2>/dev/null || true
else
    print_result 1 "No attacks logged in database"
fi

echo ""

# Check API for attacks
echo "8️⃣  Testing Management API"
ATTACKS_JSON=$(curl -s http://localhost:9000/api/attacks 2>/dev/null || echo "{}")
API_ATTACK_COUNT=$(echo "$ATTACKS_JSON" | grep -o '"id"' | wc -l || echo "0")
print_result $([ "$API_ATTACK_COUNT" -gt 0 ] && echo 0 || echo 1) "Attacks visible via API ($API_ATTACK_COUNT events)"

echo ""

# Generate high-threat attack sequence
echo "9️⃣  Testing Strike-back Trigger"
echo "   Generating high-threat attack sequence..."

# Simulate automated scanning tools (high threat score)
for i in {1..5}; do
    curl -s -A "sqlmap/1.0" http://localhost:8080/phpmyadmin/index.php > /dev/null 2>&1 || true
    curl -s -A "Nmap Scripting Engine" http://localhost:8080/admin/ > /dev/null 2>&1 || true
    sleep 1
done

echo "   Waiting for strike-back decision (10 seconds)..."
sleep 10

# Check for payloads deployed
PAYLOAD_COUNT=$(docker exec blkbox-honeypot sqlite3 /opt/blkbox/blkbox.db "SELECT COUNT(*) FROM payloads" 2>/dev/null || echo "0")
if [ "$PAYLOAD_COUNT" -gt 0 ]; then
    print_result 0 "Strike-back activated - payloads deployed ($PAYLOAD_COUNT payloads)"

    echo ""
    echo "⚡ Deployed Payloads:"
    docker exec blkbox-honeypot sqlite3 -header -column /opt/blkbox/blkbox.db \
        "SELECT payload_id, target_ip, payload_type, status FROM payloads ORDER BY created_at DESC LIMIT 3" 2>/dev/null || true
else
    print_result 1 "No payloads deployed (threat threshold may not be met)"
fi

echo ""

# Check container logs for errors
echo "🔟  Checking for errors in logs"
ERROR_COUNT=$(docker logs blkbox-honeypot 2>&1 | grep -i "error" | wc -l || echo "0")
if [ "$ERROR_COUNT" -eq 0 ]; then
    print_result 0 "No errors in container logs"
else
    print_result 1 "Found $ERROR_COUNT error(s) in logs"
    echo ""
    echo "Recent errors:"
    docker logs blkbox-honeypot 2>&1 | grep -i "error" | tail -5
fi

echo ""
echo "=================================="
echo "📊 Test Summary"
echo "=================================="
echo -e "Passed: ${GREEN}$PASSED${NC}"
echo -e "Failed: ${RED}$FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed!${NC}"
    echo ""
    echo "🎯 Next steps:"
    echo "   - View dashboard: http://localhost:9000/dashboard"
    echo "   - View attacks: curl http://localhost:9000/api/attacks | jq"
    echo "   - View logs: docker logs -f blkbox-honeypot"
    echo "   - Stop container: docker-compose down"
    EXIT_CODE=0
else
    echo -e "${RED}❌ Some tests failed${NC}"
    echo ""
    echo "🔍 Troubleshooting:"
    echo "   - View logs: docker logs blkbox-honeypot"
    echo "   - Check config: docker exec blkbox-honeypot cat /opt/blkbox/config.json"
    echo "   - Restart: docker-compose restart"
    EXIT_CODE=1
fi

echo ""

exit $EXIT_CODE
