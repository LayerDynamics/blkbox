# BlkBox - Modern Honeypot System

**A multi-protocol honeypot with advanced tracking and authorized strike-back capabilities**

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Deno](https://img.shields.io/badge/deno-1.x-blue.svg)](https://deno.land/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **🚧 Work in Progress**: This project is under active development. Core functionality is operational (HTTP, SSH, FTP honeypots with Docker deployment), but some features are still being implemented. See Development Status section below for details.

## Overview

BlkBox is a next-generation honeypot system combining high-performance Rust FFI with Deno TypeScript orchestration to provide:

- 🕸️ **Multi-Protocol Emulation**: HTTP/HTTPS, SSH, PostgreSQL, MySQL, MongoDB, FTP/SFTP
- 📍 **Advanced Tracking**: IP geolocation, browser fingerprinting, behavioral analysis
- ⚔️ **Strike-Back Capabilities**: Authorized reconnaissance payloads for intelligence gathering
- ☁️ **Cloudflare Integration**: DDoS protection, enhanced tracking, dynamic DNS
- 💾 **SQLite Storage**: Local-first persistence and analytics

**⚠️ LEGAL NOTICE**: This system is designed exclusively for authorized security testing, defensive security research, and educational purposes. All offensive capabilities must be used in strict compliance with applicable laws. Consult legal counsel before deployment.

## Quick Start

```bash
# Build Rust library
cargo build --release

# Run honeypot
deno task start

# Development mode with auto-reload
deno task dev
```

## Architecture

BlkBox uses a layered architecture:

```
┌─────────────┐
│   main.ts   │  ← Orchestration
└──────┬──────┘
       │
   ┌───┴───┬────────┬───────────┐
   ▼       ▼        ▼           ▼
┌──────┐ ┌────┐  ┌──────┐  ┌────────┐
│Melita│ │Cook│  │Tracka│  │lib_deno│
│sphex │ │jar │  │suarus│  │  FFI   │
└──────┘ └────┘  └──────┘  └───┬────┘
                                ▼
                          ┌──────────┐
                          │lib_rust  │
                          │  Core    │
                          └──────────┘
```

For complete architecture documentation, see [ARCHITECTURE.md](ARCHITECTURE.md).

## Components

### Lib Rust (High-Performance Core)

Rust FFI library providing:
- Protocol implementations (HTTP, SSH, databases, FTP)
- SQLite persistence layer
- Fingerprinting and tracking
- Cryptography for payloads
- Cloudflare API integration

**Location**: `lib_rust/`

### Lib Deno (TypeScript Interface)

Deno FFI bindings providing type-safe interface to Rust core:
- FFI symbol definitions
- Type marshaling
- Error handling
- Event management

**Location**: `lib_deno/`

### Packages

#### Melittasphex (Honeypot Core)
*Metaphor: Bee/Wasp - The hive attracts, the stinger defends*

- **Hive**: Honeypot service implementations and orchestration
- **Stinger**: Strike-back payload generation and delivery

**Location**: `packages/melittasphex/`

#### Cookiejar (Payload Management)
*Metaphor: Bakery - Dough → Oven → Bake → Jar*

- **Dough**: Raw configuration input
- **Oven**: Payload templates
- **Bake**: Compilation and obfuscation
- **Jar**: Storage and serving

**Location**: `packages/cookiejar/`

#### Trackasuarus (Tracking & Reconnaissance)
*Purpose: Track attackers without revealing honeypot nature*

- **Tracker**: IP geolocation, fingerprinting, MAC collection, session correlation
- **Mask**: Anti-fingerprinting and concealment

**Location**: `packages/trackasuarus/`

#### blkbox (Main Application)

Deployable application integrating all packages:
- Configuration management
- HTTP server for management API
- Dashboard/client interface

**Location**: `blkbox/`

## How It Works

### Attack Flow

1. **Attacker connects** to honeypot service (HTTP, SSH, DB, FTP)
2. **Protocol handler** (Rust) processes request with realistic responses
3. **Event captured** with IP, headers, payload, timestamp
4. **Trackasuarus** fingerprints attacker (tool detection, geolocation, scoring)
5. **Cookiejar** analyzes threat and makes decision
6. **Action taken**:
   - Store event in SQLite for analysis
   - OR Deploy stinger payload for intelligence gathering

### Cloudflare Enhancement

When proxied through Cloudflare:
- DDoS protection at edge
- Bot detection and management
- Enhanced headers (CF-Connecting-IP, CF-IPCountry, CF-Threat-Score)
- Automatic firewall rule updates for high-threat attackers

## Integrations

### Cloudflare

BlkBox integrates with Cloudflare for:
- **DDoS Protection**: Edge-level attack mitigation
- **Enhanced Tracking**: Real IP, country, threat score via headers
- **Dynamic DNS**: Automatic routing and failover
- **WAF Rules**: Programmatic firewall updates based on threat intelligence

Setup:
1. Create Cloudflare account and add domain
2. Generate API token with Zone.DNS and Zone.Firewall permissions
3. Update `config.json` with credentials
4. Point DNS A record to honeypot server

### GeoIP (Optional)

- MaxMind GeoLite2 for IP geolocation
- Fallback to Cloudflare headers when available
- Provides country, region, city, ASN, ISP data

## Configuration

Edit `config.json`:

```json
{
  "honeypots": [
    { "type": "HTTP", "port": 8080, "enabled": true },
    { "type": "SSH", "port": 2222, "enabled": true },
    { "type": "PostgreSQL", "port": 5432, "enabled": true }
  ],
  "cloudflare": {
    "enabled": true,
    "apiKey": "YOUR_API_TOKEN",
    "zoneId": "YOUR_ZONE_ID"
  },
  "stinger": {
    "enabled": true,
    "autoTrigger": false,
    "threatThreshold": 75
  }
}
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for complete configuration reference.

## Deployment

### Development
```bash
cargo build --release
deno task dev
```

### Production (Docker)
```bash
docker build -t blkbox .
docker run -d -p 8080:8080 -p 2222:2222 -p 5432:5432 blkbox
```

### Production (Systemd)
```bash
sudo cp blkbox.service /etc/systemd/system/
sudo systemctl enable blkbox
sudo systemctl start blkbox
```

## Monitoring

```bash
# View logs
tail -f /var/log/blkbox/honeypot.log

# Database stats
sqlite3 blkbox.db "SELECT COUNT(*) FROM attacks"

# Top attackers
sqlite3 blkbox.db "SELECT source_ip, COUNT(*) FROM attacks GROUP BY source_ip ORDER BY COUNT(*) DESC LIMIT 10"
```

## Legal & Ethics

**This tool is for AUTHORIZED DEFENSIVE USE ONLY.**

Before deployment:
- [ ] Consult legal counsel
- [ ] Obtain written authorization
- [ ] Display warning banners
- [ ] Implement comprehensive logging
- [ ] Establish incident response plan
- [ ] Define data retention policy

See [ARCHITECTURE.md](ARCHITECTURE.md) for complete legal and compliance requirements.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) - Complete system documentation (source of truth)
- [Implementation Plan](/.claude/plans/concurrent-conjuring-elephant.md) - Detailed development roadmap

## Development Status

**Phase 1: Foundation** - Not Started
- Cargo.toml configuration
- FFI infrastructure
- SQLite schema

See [ARCHITECTURE.md](ARCHITECTURE.md) for complete implementation phases.

## Contributing

Contributions welcome! Please:
1. Review [ARCHITECTURE.md](ARCHITECTURE.md)
2. Follow existing code patterns
3. Add tests for new features
4. Update documentation

## License

MIT License - See [LICENSE](LICENSE) file

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/blkbox/issues)
- Documentation: [ARCHITECTURE.md](ARCHITECTURE.md)
- Security: Report privately to security@yourdomain.com

---

**Remember**: This is a defensive security tool. Use responsibly, legally, and ethically.
