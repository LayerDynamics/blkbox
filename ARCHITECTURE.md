# BlkBox - Modern Honeypot Architecture

**Version:** 0.1.0
**Last Updated:** 2025-12-24
**Status:** In Development

---

## Executive Summary

BlkBox is a sophisticated, multi-protocol honeypot system designed for defensive security research and authorized security testing. It combines high-performance Rust FFI core with Deno TypeScript orchestration to provide:

- **Multi-Protocol Emulation**: HTTP/HTTPS, SSH, PostgreSQL, MySQL, MongoDB, FTP/SFTP
- **Advanced Tracking**: IP geolocation, browser fingerprinting, behavioral analysis
- **Strike-Back Capabilities**: Authorized reconnaissance payloads for intelligence gathering
- **Cloud Integration**: Cloudflare DDoS protection, enhanced tracking, dynamic DNS
- **Local-First Storage**: SQLite database for persistence and analytics

**⚠️ LEGAL NOTICE**: This system is designed exclusively for authorized security testing, defensive security research, and educational purposes. All offensive capabilities must be used in strict compliance with applicable laws and only against unauthorized attackers on your own infrastructure. Consult legal counsel before deployment.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Technology Stack](#technology-stack)
3. [Package Structure](#package-structure)
4. [Data Flow](#data-flow)
5. [Implementation Phases](#implementation-phases)
6. [Security Considerations](#security-considerations)
7. [Deployment Guide](#deployment-guide)
8. [Configuration](#configuration)
9. [API Reference](#api-reference)
10. [Legal & Compliance](#legal--compliance)

---

## System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Main Entry (main.ts)                   │
│              Orchestration & Configuration              │
│                                                         │
│  - Initialize FFI bridge                               │
│  - Load configuration                                  │
│  - Start all services                                  │
│  - Event pipeline management                           │
└────────────────────┬────────────────────────────────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
  ┌───────────┐ ┌──────────┐ ┌────────────┐
  │Melittasphex│ │Cookiejar│ │Trackasuarus│
  │ (Honeypot)│ │(Payloads)│ │ (Tracking) │
  │           │ │          │ │            │
  │ Hive      │ │ Dough    │ │ Tracker    │
  │ Stinger   │ │ Oven     │ │ Mask       │
  │           │ │ Bake     │ │            │
  │           │ │ Jar      │ │            │
  └─────┬─────┘ └────┬─────┘ └─────┬──────┘
        │            │              │
        └────────────┼──────────────┘
                     ▼
              ┌────────────┐
              │ lib_deno   │
              │  FFI Layer │
              │            │
              │ - dlopen   │
              │ - Symbols  │
              │ - Types    │
              └──────┬─────┘
                     ▼
              ┌────────────┐      ┌────────────┐
              │ lib_rust   │◄────►│ Cloudflare │
              │   Core     │      │    API     │
              │            │      │            │
              │ - Honeypot │      │ - Headers  │
              │ - Strikeback│      │ - Firewall │
              │ - Storage  │      │ - DNS      │
              │ - Tracking │      └────────────┘
              │ - Cloudflare│
              └──────┬─────┘
                     ▼
              ┌────────────┐
              │   SQLite   │
              │  Database  │
              │            │
              │ - Attacks  │
              │ - Sessions │
              │ - Payloads │
              └────────────┘
```

### Component Responsibilities

#### 1. Main Entry Point (`main.ts`)

- Initialize Rust FFI connection
- Load and validate configuration
- Instantiate all services
- Set up event pipeline
- Coordinate package communication
- Graceful shutdown handling

#### 2. Melittasphex (Honeypot Core)

**Metaphor**: Bee/Wasp - The hive attracts, the stinger defends

- **Hive** (`hive/`): Honeypot service implementations
  - Protocol emulation (HTTP, SSH, databases, FTP)
  - Connection handling
  - Deception logic
  - Event generation

- **Stinger** (`stinger/`): Strike-back capabilities
  - Payload generation
  - Delivery mechanisms
  - Threat evaluation
  - C2 communication

#### 3. Trackasuarus (Tracking & Reconnaissance)

**Purpose**: Track attackers without revealing honeypot nature

- **Tracker** (`tracker/`): Intelligence gathering
  - IP geolocation
  - Browser fingerprinting
  - MAC address collection (passive techniques)
  - Session correlation
  - Threat scoring

- **Mask** (`mask/`): Anti-fingerprinting
  - Polymorphic responses
  - Timing variations
  - Banner rotation
  - Honeypot concealment

#### 4. Cookiejar (Payload Management)

**Metaphor**: Bakery - Raw ingredients → Template → Baking → Serving

- **Dough** (`dough/`): Raw configuration input
- **Oven** (`oven/`): Payload templates
- **Bake** (`bake/`): Compilation & obfuscation
- **Jar** (`jar/`): Storage & serving

#### 5. Rust FFI Core (`lib_rust/`)

High-performance core functionality:

- Protocol implementations
- Async I/O with Tokio
- SQLite persistence
- Cryptography
- Network analysis
- FFI interface

#### 6. Deno FFI Layer (`lib_deno/`)

TypeScript interface to Rust:

- FFI bindings via `dlopen`
- Type-safe wrappers
- Event marshaling
- Error handling

---

## Technology Stack

### Rust Backend

```toml
Runtime:       Tokio (async/await)
HTTP:          Axum, Tower, Hyper
Databases:     tokio-postgres, mysql_async, mongodb
SSH:           ssh2, async-ssh2-tokio
FTP:           async-ftp
Storage:       rusqlite, r2d2
Crypto:        aes-gcm, sha2, rand
Networking:    ipnetwork, mac_address
Cloud:         cloudflare, reqwest
Serialization: serde, serde_json, bincode
FFI:           libc, once_cell
Logging:       tracing, tracing-subscriber
Errors:        anyhow, thiserror
```

### Deno Frontend

```json
Runtime:       Deno 1.x
FFI:           Deno.dlopen
Standard:      @std/assert, @std/http, @std/path, @std/fs
TypeScript:    Strict mode enabled
Configuration: deno.json
```

### Database

```
Type:          SQLite 3
Bundled:       Via rusqlite
Location:      ./blkbox.db (configurable)
Schema:        attacks, sessions, payloads, intelligence
```

### External Services

```
Cloudflare:    DDoS protection, DNS, enhanced headers
GeoIP:         MaxMind GeoLite2 (optional)
```

---

## Package Structure

### Directory Tree

```
blkbox/
├── Cargo.toml                    # Rust workspace
├── deno.json                     # Deno configuration
├── main.ts                       # Application entry
├── config.json                   # Runtime configuration
├── ARCHITECTURE.md               # This file
├── README.md                     # Project overview
│
├── lib_rust/                     # Rust FFI Core
│   ├── lib.rs                    # FFI exports
│   ├── mod.rs                    # Module tree
│   │
│   ├── ffi/                      # FFI infrastructure
│   │   ├── mod.rs
│   │   ├── types.rs              # FFI-safe types
│   │   ├── conversions.rs        # Type conversions
│   │   └── callbacks.rs          # Callback handling
│   │
│   ├── honeypot/                 # Protocol implementations
│   │   ├── mod.rs
│   │   ├── traits.rs             # Common interface
│   │   ├── http.rs               # HTTP/HTTPS
│   │   ├── ssh.rs                # SSH
│   │   ├── postgres.rs           # PostgreSQL
│   │   ├── mysql.rs              # MySQL
│   │   ├── mongodb.rs            # MongoDB
│   │   └── ftp.rs                # FTP/SFTP
│   │
│   ├── strikeback/               # Offensive capabilities
│   │   ├── mod.rs
│   │   ├── payload.rs            # Payload types
│   │   ├── exploits.rs           # Reconnaissance
│   │   ├── delivery.rs           # Delivery methods
│   │   └── crypto.rs             # Encryption
│   │
│   ├── storage/                  # Persistence layer
│   │   ├── mod.rs
│   │   ├── sqlite.rs             # Database wrapper
│   │   ├── schema.rs             # Schema definitions
│   │   └── models.rs             # Data models
│   │
│   ├── tracking/                 # Intelligence gathering
│   │   ├── mod.rs
│   │   ├── session.rs            # Session management
│   │   ├── fingerprint.rs        # Device fingerprinting
│   │   ├── geolocation.rs        # IP geolocation
│   │   └── network.rs            # Network analysis
│   │
│   └── cloudflare/               # Cloud integration
│       ├── mod.rs
│       ├── client.rs             # API client
│       ├── ddos.rs               # DDoS protection
│       └── dns.rs                # Dynamic DNS
│
├── lib_deno/                     # Deno FFI Bindings
│   ├── lib.ts                    # Main FFI wrapper
│   ├── mod.ts                    # Re-exports
│   └── types.ts                  # TypeScript types
│
├── packages/                     # Application Packages
│   │
│   ├── melittasphex/             # Honeypot Package
│   │   ├── hive/
│   │   │   ├── honeypot.ts       # Honeypot wrapper
│   │   │   ├── honeypot_service.ts  # Orchestrator
│   │   │   └── mod.ts
│   │   ├── stinger/
│   │   │   ├── payload.ts        # Payload definitions
│   │   │   ├── modifier.ts       # Dynamic mods
│   │   │   ├── stinger_service.ts   # Delivery
│   │   │   └── mod.ts
│   │   ├── server.ts
│   │   ├── client.ts
│   │   ├── main.ts
│   │   ├── mod.ts
│   │   └── deno.json
│   │
│   ├── trackasuarus/             # Tracking Package
│   │   ├── tracker/
│   │   │   ├── track.ts          # Main tracker
│   │   │   ├── geoping.ts        # Geolocation
│   │   │   ├── mac-address-emit.ts  # MAC collection
│   │   │   ├── emit.ts           # Event emission
│   │   │   └── mod.ts
│   │   ├── mask/
│   │   │   ├── mask.ts           # Anti-fingerprint
│   │   │   └── mod.ts
│   │   ├── server.ts
│   │   ├── client.ts
│   │   ├── mod.ts
│   │   └── deno.json
│   │
│   └── cookiejar/                # Payload Package
│       ├── dough/
│       │   └── mod.ts            # Configuration
│       ├── oven/
│       │   └── mod.ts            # Templates
│       ├── bake/
│       │   └── mod.ts            # Compilation
│       ├── jar/
│       │   └── mod.ts            # Storage/serving
│       ├── server.ts
│       ├── client.ts
│       ├── main.ts
│       ├── mod.ts
│       └── deno.json
│
└── blkbox/                       # Main Application
    ├── config/
    │   ├── config.ts             # Config management
    │   └── mod.ts
    ├── server/
    │   ├── server.ts             # HTTP server
    │   ├── routes/
    │   │   └── mod.ts
    │   ├── schemas/
    │   │   └── mod.ts
    │   └── bx/
    │       └── mod.ts
    ├── client/
    │   ├── app.ts                # Dashboard
    │   └── bx/
    │       └── mod.ts
    └── main.ts
```

---

## Data Flow

### Incoming Attack Flow

```
1. Network Request
   │
   ├─ Protocol: HTTP/SSH/DB/FTP
   ├─ Headers: User-Agent, etc.
   └─ Payload: Commands/queries
   │
   ▼
2. Melittasphex/Hive (TypeScript)
   │
   ├─ Route to appropriate honeypot
   └─ Extract metadata
   │
   ▼
3. lib_deno FFI Call
   │
   ├─ Marshal request data
   └─ Call Rust function
   │
   ▼
4. lib_rust Protocol Handler
   │
   ├─ Parse protocol
   ├─ Generate realistic response
   ├─ Log interaction
   └─ Create attack event
   │
   ▼
5. Event Captured
   │
   ├─ IP address & port
   ├─ HTTP headers / SSH banner
   ├─ Protocol-specific data
   ├─ Timestamp
   └─ Raw payload
   │
   ▼
6. Trackasuarus Processing
   │
   ├─ Fingerprint (JA3, User-Agent, timing)
   ├─ Geolocate (GeoIP, Cloudflare)
   ├─ Session correlation
   └─ Threat scoring
   │
   ▼
7. Cookiejar/Dough
   │
   ├─ Raw event ingestion
   └─ Convert to internal format
   │
   ▼
8. Cookiejar/Oven
   │
   ├─ Threat analysis
   ├─ Pattern matching
   └─ Decision: Store vs Strikeback
   │
   ▼
9a. Store Only               9b. Deploy Stinger
    │                            │
    ▼                            ▼
10. Cookiejar/Jar          10. Melittasphex/Stinger
    │                            │
    ├─ SQLite INSERT             ├─ Select payload type
    └─ attacks table             ├─ Generate payload
                                 ├─ Obfuscate
                                 ├─ Deliver to attacker
                                 └─ Log deployment
```

### Cloudflare Enhanced Flow

```
1. Request → Cloudflare Edge
   │
   ├─ DDoS detection
   ├─ Bot management
   ├─ Geographic routing
   └─ Add headers
   │
   ▼
2. Enhanced Request → Honeypot
   │
   Headers added:
   ├─ CF-Connecting-IP (real IP)
   ├─ CF-IPCountry (country code)
   ├─ CF-Ray (request ID)
   ├─ CF-Visitor (http/https)
   └─ CF-Threat-Score (0-100)
   │
   ▼
3. Trackasuarus Extraction
   │
   ├─ Parse Cloudflare headers
   ├─ Enhanced geolocation
   ├─ Threat intelligence
   └─ Store in database
   │
   ▼
4. Optional: Update CF Rules
   │
   ├─ High threat score → Block
   ├─ Medium → Challenge
   └─ Low → Allow + Monitor
```

### Stringer Payload Deployment

```
1. Trigger Condition Met
   │
   ├─ Threat score > threshold
   ├─ Specific exploit detected
   └─ Manual deployment request
   │
   ▼
2. Stinger Evaluation
   │
   ├─ Verify confirmed attack
   ├─ Check safeguards
   └─ Select payload type
   │
   ▼
3. Cookiejar/Dough
   │
   ├─ Define objectives
   └─ Set constraints
   │
   ▼
4. Cookiejar/Oven
   │
   ├─ Select template
   └─ Fill with parameters
   │
   ▼
5. Cookiejar/Bake
   │
   ├─ Obfuscate code
   ├─ Add anti-debug
   └─ Encrypt if needed
   │
   ▼
6. Cookiejar/Jar
   │
   ├─ Store payload
   └─ Generate delivery URL
   │
   ▼
7. Delivery Method
   │
   ├─ HTTP: Inject in response
   ├─ SSH: Fake script/command
   ├─ DB: Malicious query result
   └─ FTP: Trojan file
   │
   ▼
8. Payload Execution
   │
   ├─ Collect system info
   ├─ Network reconnaissance
   ├─ Geolocation data
   └─ Callback to C2
   │
   ▼
9. Intelligence Collection
   │
   ├─ Store in database
   ├─ Update threat profile
   └─ Generate alerts
```

---

## Implementation Phases

### Phase 1: Foundation (CRITICAL)

**Priority**: P0
**Duration**: ~1 week
**Status**: Not Started

**Goals**:

- Fix Cargo.toml configuration
- Implement basic FFI bridge
- Create SQLite schema
- Verify Rust-Deno communication

**Files**:

1. `Cargo.toml`
2. `lib_rust/lib.rs`
3. `lib_rust/ffi/types.rs`
4. `lib_deno/lib.ts`
5. `lib_rust/storage/schema.rs`

**Success Criteria**:

- [ ] Cargo build succeeds
- [ ] Deno can call `blkbox_init()`
- [ ] Database created with schema
- [ ] Event logging works

---

### Phase 2: HTTP Honeypot (HIGH)

**Priority**: P1
**Duration**: ~1 week
**Status**: Not Started

**Goals**:

- First working protocol implementation
- Serve realistic fake applications
- Log all HTTP requests
- Fingerprint detection

**Files**:

1. `lib_rust/honeypot/http.rs`
2. `lib_rust/honeypot/traits.rs`
3. `packages/melittasphex/hive/honeypot.ts`
4. `packages/melittasphex/hive/honeypot_service.ts`

**Success Criteria**:

- [ ] HTTP server accepts connections
- [ ] Fake WordPress admin panel
- [ ] .git directory accessible
- [ ] nmap detection working
- [ ] All logged to SQLite

---

### Phase 3: SSH Honeypot (HIGH)

**Priority**: P1
**Duration**: ~1 week
**Status**: Not Started

**Goals**:

- Interactive shell emulation
- Command logging
- Fake filesystem
- Credential collection

**Files**:

1. `lib_rust/honeypot/ssh.rs`
2. Fake filesystem data files

**Success Criteria**:

- [ ] SSH authentication works
- [ ] Commands execute in fake shell
- [ ] All commands logged
- [ ] Fake file system navigable

---

### Phase 4: Database Honeypots (MEDIUM)

**Priority**: P2
**Duration**: ~1.5 weeks
**Status**: Not Started

**Goals**:

- PostgreSQL protocol
- MySQL protocol
- MongoDB protocol
- Fake data generation

**Files**:

1. `lib_rust/honeypot/postgres.rs`
2. `lib_rust/honeypot/mysql.rs`
3. `lib_rust/honeypot/mongodb.rs`

**Success Criteria**:

- [ ] Database clients can connect
- [ ] SQL queries return fake data
- [ ] All queries logged
- [ ] Realistic schemas present

---

### Phase 5: Tracking System (HIGH)

**Priority**: P1
**Duration**: ~1 week
**Status**: Not Started

**Goals**:

- IP geolocation
- Browser fingerprinting
- Session correlation
- Threat scoring
- Cloudflare integration

**Files**:

1. `packages/trackasuarus/tracker/track.ts`
2. `packages/trackasuarus/tracker/geoping.ts`
3. `lib_rust/tracking/fingerprint.rs`
4. `lib_rust/cloudflare/client.rs`
5. `packages/trackasuarus/tracker/mac-address-emit.ts`
6. `packages/trackasuarus/mask/mask.ts`

**Success Criteria**:

- [ ] IP geolocation accurate
- [ ] Tool detection working
- [ ] Cloudflare headers extracted
- [ ] Threat scores calculated

---

### Phase 6: Payload System (MEDIUM)

**Priority**: P2
**Duration**: ~1 week
**Status**: Not Started

**Goals**:

- Payload template system
- Bakery metaphor implementation
- Storage and serving
- Tracking callbacks

**Files**:

1. `packages/cookiejar/dough/mod.ts`
2. `packages/cookiejar/oven/mod.ts`
3. `packages/cookiejar/bake/mod.ts`
4. `packages/cookiejar/jar/mod.ts`

**Success Criteria**:

- [ ] Templates created
- [ ] Payloads generated
- [ ] Obfuscation working
- [ ] Callbacks received

---

### Phase 7: Strike-Back (MEDIUM-HIGH)

**Priority**: P1-P2
**Duration**: ~1 week
**Status**: Not Started

**Goals**:

- Reconnaissance payloads
- C2 infrastructure
- Deployment logic
- Safeguards implementation

**Files**:

1. `lib_rust/strikeback/payload.rs`
2. `packages/melittasphex/stinger/payload.ts`
3. `packages/melittasphex/stinger/stinger_service.ts`
4. `packages/melittasphex/stinger/modifier.ts`

**Success Criteria**:

- [ ] Browser recon payload works
- [ ] Network scanner executes
- [ ] C2 receives data
- [ ] Safeguards prevent abuse

---

### Phase 8: Integration (HIGH)

**Priority**: P1
**Duration**: ~1 week
**Status**: Not Started

**Goals**:

- Tie all packages together
- Main application entry
- Configuration system
- Event pipeline

**Files**:

1. `main.ts`
2. `blkbox/config/config.ts`
3. `config.json`
4. `blkbox/server/server.ts`

**Success Criteria**:

- [ ] All packages integrated
- [ ] Config loading works
- [ ] Event pipeline functional
- [ ] System runs stable

---

### Phase 9: FTP Honeypot (LOW)

**Priority**: P3
**Duration**: ~3 days
**Status**: Not Started

**Goals**:

- FTP protocol implementation
- File operations
- Upload quarantine

**Files**:

1. `lib_rust/honeypot/ftp.rs`

---

### Phase 10: Monitoring (MEDIUM)

**Priority**: P2
**Duration**: ~1 week
**Status**: Not Started

**Goals**:

- Web dashboard
- Real-time feed
- Analytics queries
- Export functionality

**Files**:

1. `blkbox/client/app.ts`

---

## Security Considerations

### Legal Safeguards

#### Warning Banner

All services display:

```
╔════════════════════════════════════════════════════════╗
║                      WARNING                           ║
║                                                        ║
║  This system is for AUTHORIZED USE ONLY.               ║
║  Unauthorized access attempts are monitored and        ║
║  logged. By continuing, you consent to monitoring      ║
║  and potential legal action.                           ║
║                                                        ║
║  All activity is recorded and may be reported to       ║
║  law enforcement authorities.                          ║
╚════════════════════════════════════════════════════════╝
```

#### Terms of Service

Implicit by accessing:

1. This is a private system
2. Unauthorized access is forbidden and illegal
3. All activity is logged
4. Defensive measures may be deployed
5. No expectation of privacy

### Technical Security

#### Network Isolation

```
┌─────────────────┐
│  Internet       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Cloudflare     │  ← DDoS, WAF
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Firewall       │  ← Allow inbound, block outbound*
└────────┬────────┘  (*except C2)
         │
         ▼
┌─────────────────┐
│  Honeypot VLAN  │  ← Isolated network
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  IDS/IPS        │  ← Traffic monitoring
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  BlkBox         │
└─────────────────┘
```

#### System Hardening

- Run as non-root user
- Docker containerization
- Resource limits (CPU, memory, connections)
- Automated restart on crash
- Regular database backups
- Log rotation
- Fail2ban for excessive connections

#### Anti-Fingerprinting

- Vary response timing (random 50-500ms)
- Polymorphic responses (not deterministic)
- Rotate banners every 6 hours
- Simulate realistic failures (not always success)
- Avoid honeypot-specific patterns
- Regular updates to signatures

### Strikeback Safeguards

#### Deployment Conditions (ALL must be met)

```typescript
const canDeploy = (
  confirmedAttack &&
  threatScore >= 75 &&
  !isLikelyScanner &&
  !ipWhitelisted &&
  manualApprovalGranted  // For critical deployments
);
```

#### Payload Restrictions

- ✅ Information gathering only
- ✅ Passive network reconnaissance
- ✅ Geolocation data collection
- ❌ No destructive actions
- ❌ No data destruction
- ❌ No lateral movement beyond attacker
- ❌ No persistence mechanisms

#### Logging Requirements

- Log ALL deployment decisions (approved and denied)
- Log ALL payload executions
- Log ALL C2 callbacks
- Retain logs for minimum 1 year
- Immutable log storage

---

## Deployment Guide

### Development Deployment

```bash
# Clone repository
git clone <repo>
cd blkbox

# Build Rust library
cargo build --release

# Verify Deno version
deno --version  # Should be 1.x+

# Run development server
deno task dev
```

### Production Deployment

#### Option 1: Docker (Recommended)

```bash
# Build image
docker build -t blkbox:latest .

# Run container
docker run -d \
  --name blkbox \
  -p 8080:8080 \
  -p 2222:2222 \
  -p 5432:5432 \
  -p 3306:3306 \
  -p 27017:27017 \
  -p 21:21 \
  -v $(pwd)/blkbox.db:/app/blkbox.db \
  -v $(pwd)/config.json:/app/config.json \
  --restart unless-stopped \
  blkbox:latest
```

#### Option 2: Systemd Service

```ini
# /etc/systemd/system/blkbox.service
[Unit]
Description=BlkBox Honeypot System
After=network.target

[Service]
Type=simple
User=blkbox
WorkingDirectory=/opt/blkbox
ExecStart=/usr/local/bin/deno run --allow-all /opt/blkbox/main.ts
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable blkbox
sudo systemctl start blkbox
sudo systemctl status blkbox
```

### Cloudflare Setup

1. **Create Cloudflare Account**
   - Sign up at cloudflare.com
   - Add your domain

2. **Get API Credentials**

   ```bash
   # Navigate to: My Profile → API Tokens
   # Create token with permissions:
   - Zone.DNS (Edit)
   - Zone.Firewall Services (Edit)
   - Zone.Zone Settings (Read)
   ```

3. **Configure DNS**

   ```
   A    honeypot.yourdomain.com → YOUR_SERVER_IP

   # Enable Cloudflare proxy (orange cloud)
   ```

4. **Update config.json**

   ```json
   {
     "cloudflare": {
       "apiKey": "YOUR_API_TOKEN",
       "zoneId": "YOUR_ZONE_ID",
       "enabled": true
     }
   }
   ```

5. **Enable Security Features**
   - Security → Settings → Security Level: High
   - Security → Bots → Enable Bot Fight Mode
   - Firewall → Tools → Rate Limiting

---

## Configuration

### config.json Structure

```json
{
  "honeypots": [
    {
      "type": "HTTP",
      "port": 8080,
      "enabled": true,
      "apps": ["wordpress", "phpmyadmin", "api"],
      "ssl": false
    },
    {
      "type": "SSH",
      "port": 2222,
      "enabled": true,
      "banner": "SSH-2.0-OpenSSH_7.4"
    },
    {
      "type": "PostgreSQL",
      "port": 5432,
      "enabled": true,
      "version": "9.6.2"
    },
    {
      "type": "MySQL",
      "port": 3306,
      "enabled": true,
      "version": "5.5.62"
    },
    {
      "type": "MongoDB",
      "port": 27017,
      "enabled": true,
      "version": "3.4"
    },
    {
      "type": "FTP",
      "port": 21,
      "enabled": false
    }
  ],

  "cloudflare": {
    "enabled": true,
    "apiKey": "YOUR_API_TOKEN",
    "zoneId": "YOUR_ZONE_ID",
    "updateFirewall": true
  },

  "stinger": {
    "enabled": true,
    "autoTrigger": false,
    "threatThreshold": 75,
    "allowedPayloads": ["browser_recon", "network_scan", "system_info"],
    "requireApproval": true,
    "dryRun": false
  },

  "storage": {
    "database": "./blkbox.db",
    "retentionDays": 365,
    "backupInterval": 86400
  },

  "tracking": {
    "geoip": true,
    "fingerprinting": true,
    "sessionCorrelation": true
  },

  "logging": {
    "level": "info",
    "file": "/var/log/blkbox/honeypot.log",
    "maxSize": "100MB",
    "maxFiles": 10
  }
}
```

### Environment Variables

```bash
# Configuration file path
export BLKBOX_CONFIG="/etc/blkbox/config.json"

# Database path
export BLKBOX_DB="/var/lib/blkbox/blkbox.db"

# Cloudflare credentials (alternative to config.json)
export CF_API_KEY="your_key"
export CF_ZONE_ID="your_zone"

# Logging level
export RUST_LOG="info"
```

---

## API Reference

### FFI Interface

```rust
// Initialize runtime
#[no_mangle]
pub extern "C" fn blkbox_init() -> *mut BlkBoxRuntime;

// Start honeypot service
#[no_mangle]
pub extern "C" fn blkbox_start_honeypot(
    runtime: *mut BlkBoxRuntime,
    service_type: u8,  // 0=HTTP, 1=SSH, 2=Postgres, etc.
    port: u16,
    config_json: *const c_char,
) -> i32;  // Returns service ID or -1 on error

// Stop honeypot service
#[no_mangle]
pub extern "C" fn blkbox_stop_honeypot(
    runtime: *mut BlkBoxRuntime,
    service_id: u32,
) -> i32;

// Get attack events (blocking, max 1000 events)
#[no_mangle]
pub extern "C" fn blkbox_get_events(
    runtime: *mut BlkBoxRuntime,
    buffer: *mut c_char,
    buffer_len: usize,
) -> i32;  // Returns bytes written or -1 on error

// Trigger strikeback payload
#[no_mangle]
pub extern "C" fn blkbox_trigger_strikeback(
    runtime: *mut BlkBoxRuntime,
    attacker_ip: *const c_char,
    payload_type: u8,
) -> i32;

// Store event in database
#[no_mangle]
pub extern "C" fn blkbox_store_event(
    runtime: *mut BlkBoxRuntime,
    event_json: *const c_char,
) -> i32;

// Update Cloudflare configuration
#[no_mangle]
pub extern "C" fn blkbox_cloudflare_update(
    runtime: *mut BlkBoxRuntime,
    config_json: *const c_char,
) -> i32;

// Free runtime (cleanup)
#[no_mangle]
pub extern "C" fn blkbox_free(runtime: *mut BlkBoxRuntime);
```

### TypeScript API

```typescript
// Initialize FFI
const ffi = new BlkBoxFFI();

// Start HTTP honeypot
const httpId = ffi.startHoneypot(ServiceType.HTTP, 8080, {
  apps: ["wordpress"],
});

// Poll for events
const events = ffi.getEvents();  // Returns AttackEvent[]

// Deploy stinger
ffi.triggerStrikeback("1.2.3.4", PayloadType.BrowserRecon);

// Store custom event
ffi.storeEvent({
  timestamp: new Date(),
  sourceIp: "1.2.3.4",
  serviceType: "HTTP",
  payload: "...",
});

// Cleanup
ffi.close();
```

---

## Legal & Compliance

### Authorized Use Only

This system is designed **exclusively** for:

- ✅ Defensive security research
- ✅ Authorized penetration testing
- ✅ Educational purposes
- ✅ Threat intelligence gathering on your own infrastructure
- ✅ Protecting your own systems

**Prohibited Uses:**

- ❌ Targeting systems you don't own
- ❌ Unauthorized computer access
- ❌ Violating CFAA or computer crime laws
- ❌ Offensive operations without authorization
- ❌ Compromising innocent third parties

### Legal Requirements

Before deploying:

1. **Consult Legal Counsel** - Verify compliance with local laws
2. **Obtain Authorization** - Written permission for your infrastructure
3. **Display Warning Banners** - Clear notice of monitoring
4. **Implement Logging** - Comprehensive activity logs
5. **Establish Incident Response** - Plan for handling collected intelligence

### Compliance Checklist

- [ ] Legal counsel consulted
- [ ] Authorization documentation in place
- [ ] Warning banners displayed on all services
- [ ] Comprehensive logging enabled
- [ ] Incident response plan documented
- [ ] Data retention policy defined
- [ ] Privacy policy established (if applicable)
- [ ] Terms of service published
- [ ] Safeguards tested and verified
- [ ] Team trained on legal boundaries

### Incident Response

When attack detected:

1. **Document**: Log all activity comprehensively
2. **Assess**: Evaluate threat level and impact
3. **Contain**: Isolate if necessary
4. **Analyze**: Determine attacker intent and capabilities
5. **Report**: Notify authorities if warranted (law enforcement, CERT)
6. **Preserve**: Maintain evidence chain of custody
7. **Review**: Update defenses based on lessons learned

---

## Monitoring & Maintenance

### Health Checks

```bash
# Check service status
systemctl status blkbox

# View logs
tail -f /var/log/blkbox/honeypot.log

# Database stats
sqlite3 blkbox.db "SELECT COUNT(*) FROM attacks"

# Recent attacks
sqlite3 blkbox.db "SELECT * FROM attacks ORDER BY timestamp DESC LIMIT 10"
```

### Database Maintenance

```bash
# Backup
sqlite3 blkbox.db ".backup blkbox_backup_$(date +%Y%m%d).db"

# Optimize
sqlite3 blkbox.db "VACUUM; ANALYZE;"

# Export CSV
sqlite3 -header -csv blkbox.db "SELECT * FROM attacks" > attacks.csv
```

### Performance Monitoring

```bash
# Resource usage
docker stats blkbox

# Connection counts
netstat -an | grep ESTABLISHED | wc -l

# Top attacking IPs
sqlite3 blkbox.db "SELECT source_ip, COUNT(*) as count FROM attacks GROUP BY source_ip ORDER BY count DESC LIMIT 20"
```

---

## Troubleshooting

### Common Issues

**Issue**: Rust library won't compile

```bash
# Solution: Check Rust version
rustc --version  # Should be 1.70+
cargo clean
cargo build --release
```

**Issue**: Deno FFI errors

```bash
# Solution: Verify library path
ls -la target/release/libblkbox.dylib  # macOS
ls -la target/release/libblkbox.so     # Linux

# Check permissions
chmod +x target/release/libblkbox.*
```

**Issue**: Database locked

```bash
# Solution: Check for other processes
lsof blkbox.db
# Kill if necessary, or restart service
```

**Issue**: Port already in use

```bash
# Solution: Find conflicting process
lsof -i :8080
# Kill or change config port
```

---

## Contributing

See `CONTRIBUTING.md` for guidelines.

---

## License

MIT License - See `LICENSE` file

---

## Support

For issues or questions:

- GitHub Issues: [repo]/issues
- Documentation: This file
- Security Issues: security@[domain] (private disclosure)

---

**End of Architecture Documentation**

Last Updated: 2025-12-24
Version: 0.1.0
Status: Living Document - Updated as implementation progresses
