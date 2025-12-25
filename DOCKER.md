# BlkBox Docker Deployment

Complete guide for deploying and testing BlkBox honeypot in Docker.

## Quick Start

```bash
# Build and start
docker-compose up -d

# Run comprehensive tests
./test_docker_deployment.sh

# Quick manual test
./quick_test.sh

# View logs
docker logs -f blkbox-honeypot

# Stop
docker-compose down
```

## What Gets Deployed

### Honeypot Services
- **HTTP** on port 8080 - Web application honeypot
- **SSH** on port 2222 - SSH honeypot
- **PostgreSQL** on port 5432 - Database honeypot
- **MySQL** on port 3306 - Database honeypot
- **FTP** on port 21 - File transfer honeypot

### Management Services
- **Dashboard** on port 9000 - Web UI for monitoring
- **C2 Server** on port 8443 - Command & control for payloads

## Testing the Honeypot

### Automated Testing

Run the comprehensive test suite:
```bash
./test_docker_deployment.sh
```

This will:
1. Build the Docker image
2. Start the container
3. Test all honeypot services
4. Generate attack traffic
5. Verify event logging
6. Check if strike-back activated
7. Display results

### Manual Testing

#### Test HTTP Honeypot
```bash
# Basic request
curl http://localhost:8080/

# WordPress admin (common attack target)
curl http://localhost:8080/wp-admin/

# phpMyAdmin (common attack target)
curl http://localhost:8080/phpmyadmin/

# .git exposure (info disclosure)
curl http://localhost:8080/.git/config

# Simulate attack with tool user-agent
curl -A "sqlmap/1.0" http://localhost:8080/admin/
curl -A "Nmap Scripting Engine" http://localhost:8080/
```

#### Test SSH Honeypot
```bash
# Connect and see banner
ssh -p 2222 localhost

# Try authentication (will be logged)
sshpass -p "password" ssh -p 2222 admin@localhost
```

#### Test FTP Honeypot
```bash
# Connect with ftp client
ftp localhost 21

# Or with curl
curl ftp://localhost:21/
```

## Viewing Results

### View Dashboard
Open in browser:
```
http://localhost:9000/dashboard
```

### View Attacks via API
```bash
# Get all attacks
curl http://localhost:9000/api/attacks | jq

# Get attack count
curl http://localhost:9000/api/stats | jq

# Get top attackers
curl http://localhost:9000/api/top-attackers | jq
```

### Query Database Directly
```bash
# Enter container
docker exec -it blkbox-honeypot /bin/bash

# Query attacks
sqlite3 /opt/blkbox/blkbox.db "SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 10"

# Query payloads
sqlite3 /opt/blkbox/blkbox.db "SELECT * FROM payloads"

# Query sessions
sqlite3 /opt/blkbox/blkbox.db "SELECT * FROM sessions"
```

### View Logs
```bash
# Follow logs
docker logs -f blkbox-honeypot

# Search for errors
docker logs blkbox-honeypot 2>&1 | grep -i error

# Search for strike-back activity
docker logs blkbox-honeypot 2>&1 | grep -i stinger

# Search for specific IP
docker logs blkbox-honeypot 2>&1 | grep "1.2.3.4"
```

## Triggering Strike-back

Strike-back will automatically activate when:
1. **Threat threshold met** - Current: 1.0 (very low, triggers easily)
2. **Minimum attacks reached** - Current: 1 attack
3. **IP not whitelisted** - Localhost is whitelisted

### Generate High-Threat Traffic

Run multiple requests with attack tool user-agents:
```bash
# Simulate SQLMap
for i in {1..5}; do
  curl -A "sqlmap/1.0" http://localhost:8080/phpmyadmin/
  sleep 1
done

# Simulate Nmap scan
for i in {1..5}; do
  curl -A "Nmap Scripting Engine" http://localhost:8080/admin/
  sleep 1
done

# Wait 10 seconds, then check for payloads
sleep 10
curl http://localhost:9000/api/payloads | jq
```

### Check Payload Deployment
```bash
# Via API
curl http://localhost:9000/api/strikeback/deployments | jq

# Via database
docker exec blkbox-honeypot sqlite3 /opt/blkbox/blkbox.db \
  "SELECT payload_id, target_ip, payload_type, status, created_at FROM payloads"
```

## Configuration

The container uses the `config.json` from your local directory. Current settings:

- ✅ All honeypots enabled
- ✅ Strike-back enabled (NOT dry-run)
- ✅ Auto-trigger enabled
- ✅ All 14 payload types allowed
- ✅ Localhost whitelisted (127.0.0.0/8)
- ❌ Geofencing disabled
- ❌ Manual approval disabled

To modify configuration:
1. Edit `config.json`
2. Restart container: `docker-compose restart`

## Troubleshooting

### Container won't start
```bash
# Check logs
docker logs blkbox-honeypot

# Check if ports are available
lsof -i :8080
lsof -i :2222
lsof -i :9000

# Rebuild from scratch
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d
```

### No attacks logged
```bash
# Verify services are listening
docker exec blkbox-honeypot netstat -tuln | grep LISTEN

# Check if events are being processed
docker logs blkbox-honeypot | grep "Event processing"

# Verify database is writable
docker exec blkbox-honeypot ls -l /opt/blkbox/blkbox.db
```

### Strike-back not activating
```bash
# Check threat scores
docker exec blkbox-honeypot sqlite3 /opt/blkbox/blkbox.db \
  "SELECT source_ip, threat_level, COUNT(*) FROM attacks GROUP BY source_ip"

# Check stinger logs
docker logs blkbox-honeypot | grep -i stinger

# Verify config
docker exec blkbox-honeypot cat /opt/blkbox/config.json | jq .stinger
```

### FFI errors
```bash
# Check if Rust library was built
docker exec blkbox-honeypot ls -l /opt/blkbox/target/release/libblkbox.so

# Check FFI symbols
docker exec blkbox-honeypot nm -D /opt/blkbox/target/release/libblkbox.so | grep blkbox_
```

## Performance Testing

### Load test HTTP honeypot
```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:8080/

# Using wrk
wrk -t4 -c100 -d30s http://localhost:8080/
```

### Monitor resource usage
```bash
# Container stats
docker stats blkbox-honeypot

# Detailed metrics
docker exec blkbox-honeypot ps aux
docker exec blkbox-honeypot free -h
docker exec blkbox-honeypot df -h
```

## Data Persistence

Data is persisted via Docker volumes:
- `./blkbox.db` - SQLite database (attacks, sessions, payloads)
- `./blkbox.log` - Application logs

To backup:
```bash
# Backup database
cp blkbox.db blkbox.db.backup.$(date +%Y%m%d)

# Or export to SQL
docker exec blkbox-honeypot sqlite3 /opt/blkbox/blkbox.db .dump > backup.sql
```

## Production Deployment

For production deployment:

1. **Change default ports** - Don't use privileged ports without proper setup
2. **Add TLS certificates** - Configure SSL/TLS for C2 and management
3. **Configure Cloudflare** - Add API keys for automatic blocking
4. **Set up monitoring** - Configure notifications and alerts
5. **Secure the dashboard** - Add authentication to port 9000
6. **Review legal compliance** - Ensure authorization and warning banners

## Cleanup

```bash
# Stop and remove container
docker-compose down

# Remove volumes (deletes data!)
docker-compose down -v

# Remove images
docker rmi blkbox-blkbox
```
