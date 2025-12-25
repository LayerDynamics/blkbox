/**
 * BlkBox Honeypot System - Main Application Entry Point
 *
 * This is the main orchestrator that ties together all BlkBox components:
 * - Honeypot services (HTTP, SSH, FTP, databases)
 * - Tracking system (Trackasuarus)
 * - Strike-back capabilities (Stinger)
 * - Payload generation (Cookiejar)
 * - Management dashboard
 *
 * Usage:
 *   deno run --allow-all main.ts
 *   deno run --allow-all main.ts --config /path/to/config.json
 */

import { BlkBoxFFI } from "./lib_deno/lib.ts";
import { loadConfig, type BlkBoxConfiguration } from "./blkbox/config/config.ts";
import { CookiejarServer } from "./packages/cookiejar/server.ts";
import { StingerService } from "./packages/melittasphex/stinger/stinger_service.ts";
import type { AttackEvent } from "./lib_deno/types.ts";

/**
 * BlkBox Main Orchestrator
 *
 * Manages the lifecycle of all BlkBox services and coordinates
 * event processing between components.
 */
class BlkBoxOrchestrator {
  private config!: BlkBoxConfiguration;
  private ffi!: BlkBoxFFI;
  private stingerService?: StingerService;
  private cookiejarServer?: CookiejarServer;
  private running = false;
  private startTime = 0;

  /**
   * Start the BlkBox system
   */
  async start(configPath?: string): Promise<void> {
    this.startTime = Date.now();

    console.log("\n");
    console.log("=".repeat(60));
    console.log("  🐝 BlkBox Honeypot System");
    console.log("  Modern, Resilient, Subversive Honeypot");
    console.log("=".repeat(60));
    console.log("\n");

    // Load configuration
    console.log("📋 Loading configuration...");
    try {
      this.config = await loadConfig(configPath || "./config.json");
      console.log("✓ Configuration loaded successfully\n");
    } catch (error) {
      console.error("❌ Failed to load configuration:", error);
      Deno.exit(1);
    }

    // Initialize FFI
    console.log("🔧 Initializing FFI runtime...");
    try {
      this.ffi = new BlkBoxFFI();
      console.log("✓ FFI runtime initialized\n");
    } catch (error) {
      console.error("❌ Failed to initialize FFI:", error);
      Deno.exit(1);
    }

    // Initialize Cookiejar server (for payload delivery)
    if (this.config.stinger.enabled || this.config.stinger.dryRun) {
      console.log("🍪 Starting Cookiejar server (payload delivery)...");
      try {
        this.cookiejarServer = new CookiejarServer(this.ffi, {
          port: this.config.stinger.c2Port || 8443,
          hostname: "0.0.0.0",
          enableLogging: this.config.logging.level === "debug",
        });
        await this.cookiejarServer.start();
        console.log(`✓ Cookiejar server listening on port ${this.config.stinger.c2Port || 8443}\n`);
      } catch (error) {
        console.error("❌ Failed to start Cookiejar server:", error);
        console.error("   Continuing without strike-back capabilities...\n");
      }
    }

    // Initialize Stinger service (strike-back decision engine)
    if (this.config.stinger.enabled || this.config.stinger.dryRun) {
      console.log("🦂 Initializing Stinger service (strike-back)...");
      try {
        this.stingerService = new StingerService(this.ffi, {
          enabled: this.config.stinger.enabled,
          autoTrigger: this.config.stinger.autoTrigger,
          threatThreshold: this.config.stinger.threatThreshold,
          minAttackCount: 3,
          dryRun: this.config.stinger.dryRun,
          requireApproval: this.config.stinger.requireApproval,
          allowedPayloads: this.config.stinger.allowedPayloads,
          prohibitedPayloads: [],
          whitelistIps: this.config.stinger.whitelistedIps || [],
          whitelistCidrs: [],
          allowedCountries: [],
          prohibitedCountries: this.config.stinger.blacklistedCountries || [],
          payloadExpirationHours: this.config.stinger.payloadExpiration,
          maxCallbacksPerPayload: 100,
          c2Port: this.config.stinger.c2Port || 8443,
          c2UseTls: false,
          legal: {
            counselConsulted: false,
            jurisdiction: "US",
            warningBannerEnabled: true,
          },
        });
        console.log(`✓ Stinger service initialized (${this.config.stinger.dryRun ? "DRY RUN MODE" : "ACTIVE"})\n`);
      } catch (error) {
        console.error("❌ Failed to initialize Stinger service:", error);
        console.error("   Continuing without strike-back capabilities...\n");
      }
    }

    // Start honeypots
    console.log("🍯 Starting honeypots...");
    let honeypotCount = 0;
    for (const honeypot of this.config.honeypots) {
      if (honeypot.enabled) {
        try {
          await this.startHoneypot(honeypot);
          console.log(`  ✓ ${honeypot.type.toUpperCase()} on port ${honeypot.port}`);
          honeypotCount++;
        } catch (error) {
          console.error(`  ❌ Failed to start ${honeypot.type.toUpperCase()} honeypot:`, error);
        }
      }
    }
    console.log(`✓ ${honeypotCount} honeypot(s) running\n`);

    // Setup signal handlers
    this.setupShutdownHandlers();

    // Display system status
    this.displaySystemStatus();

    console.log("✅ BlkBox is running");
    console.log("   Press Ctrl+C to shutdown gracefully\n");
    console.log("=".repeat(60));
    console.log("\n");

    // Enter event processing loop
    this.running = true;
    await this.processEvents();
  }

  /**
   * Start a specific honeypot service
   */
  private async startHoneypot(config: any): Promise<void> {
    console.log(`Starting ${config.type} honeypot on port ${config.port}...`);

    try {
      // Map service type to FFI enum
      const serviceTypeMap: Record<string, number> = {
        http: 0,
        https: 1,
        ssh: 2,
        postgresql: 3,
        mysql: 4,
        mongodb: 5,
        ftp: 6,
        sftp: 7,
      };

      const serviceType = serviceTypeMap[config.type.toLowerCase()];
      if (serviceType === undefined) {
        throw new Error(`Unknown service type: ${config.type}`);
      }

      const serviceId = this.ffi.startHoneypot(
        serviceType,
        config.port,
        config
      );

      if (serviceId < 0) {
        throw new Error(`Failed to start ${config.type} honeypot`);
      }

      console.log(`✓ ${config.type} honeypot started (ID: ${serviceId})`);
    } catch (error) {
      console.error(`Failed to start ${config.type}:`, error);
      throw error;
    }
  }

  /**
   * Process incoming attack events
   */
  private async processEvents(): Promise<void> {
    console.log("🔄 Event processing loop started...\n");

    while (this.running) {
      try {
        // Get events from FFI
        const events = this.ffi.getEvents();

        for (const event of events) {
          await this.processEvent(event);
        }

        // Poll every 100ms
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        console.error("❌ Event processing error:", error);
        // Continue processing even on error
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  }

  /**
   * Process a single attack event
   */
  private async processEvent(event: AttackEvent): Promise<void> {
    try {
      // Log attack
      const timestamp = new Date(event.timestamp).toLocaleString();
      console.log(`[${timestamp}] Attack from ${event.source_ip} on ${event.service_type} (threat: ${event.threat_level})`);

      // Track the attack (would integrate with Trackasuarus)
      // const tracking = await this.trackerService.trackAttack(event);

      // Evaluate for strike-back if enabled
      if (this.stingerService && (this.config.stinger.enabled || this.config.stinger.dryRun)) {
        const decision = await this.stingerService.processAttack(event);

        if (decision) {
          console.log(`  [Stinger] Decision: ${decision.decision} (score: ${decision.threatScore.toFixed(2)})`);
          if (decision.decision === "approve") {
            console.log(`  [Stinger] ⚡ Payload deployed to ${event.source_ip}`);
          } else if (decision.decision === "queue") {
            console.log(`  [Stinger] 📋 Queued for manual approval`);
          }
        }
      }

      // Store event in database (via FFI)
      await this.ffi.storeEvent(event);

    } catch (error) {
      console.error(`❌ Failed to process event from ${event.source_ip}:`, error);
    }
  }

  /**
   * Display system status
   */
  private displaySystemStatus(): void {
    console.log("📊 System Status:");
    console.log(`  Database: ${this.config.storage.database}`);
    console.log(`  Retention: ${this.config.storage.retentionDays} days`);
    console.log(`  Logging: ${this.config.logging.level} to ${this.config.logging.console ? "console" : "file"}`);

    if (this.config.stinger.enabled || this.config.stinger.dryRun) {
      console.log(`  Strike-back: ${this.config.stinger.dryRun ? "DRY RUN" : "ENABLED"}`);
      console.log(`  Threat threshold: ${this.config.stinger.threatThreshold}`);
      if (this.config.stinger.allowedPayloads && Array.isArray(this.config.stinger.allowedPayloads)) {
        console.log(`  Allowed payloads: ${this.config.stinger.allowedPayloads.join(", ")}`);
      }
    } else {
      console.log(`  Strike-back: DISABLED`);
    }

    if (this.config.cloudflare?.enabled) {
      console.log(`  Cloudflare: ENABLED (zone: ${this.config.cloudflare.zoneId.substring(0, 8)}...)`);
    }

    if (this.config.server.enableDashboard) {
      console.log(`  Dashboard: http://localhost:${this.config.server.managementPort}`);
    }

    console.log("");
  }

  /**
   * Stop all services and shutdown gracefully
   */
  async stop(): Promise<void> {
    console.log("\n");
    console.log("=".repeat(60));
    console.log("  🛑 Shutting down BlkBox...");
    console.log("=".repeat(60));
    console.log("");

    this.running = false;

    // Stop Cookiejar server
    if (this.cookiejarServer) {
      console.log("  Stopping Cookiejar server...");
      this.cookiejarServer.stop();
    }

    // Cleanup expired payloads
    if (this.stingerService) {
      console.log("  Cleaning up expired payloads...");
      try {
        const count = await this.stingerService.cleanupExpired();
        console.log(`    ✓ Removed ${count} expired payload(s)`);
      } catch (error) {
        console.error("    ❌ Cleanup failed:", error);
      }
    }

    // Stop honeypots (via FFI)
    console.log("  Stopping honeypots...");
    // await this.ffi.stopAllHoneypots();

    // Close FFI runtime
    console.log("  Closing FFI runtime...");
    try {
      this.ffi.close();
    } catch (error) {
      console.error("    ⚠️  FFI close warning:", error);
    }

    const uptime = Math.floor((Date.now() - this.startTime) / 1000);
    console.log("");
    console.log(`  Uptime: ${uptime}s`);
    console.log("  ✓ Shutdown complete");
    console.log("");
    console.log("=".repeat(60));
    console.log("");

    Deno.exit(0);
  }

  /**
   * Setup signal handlers for graceful shutdown
   */
  private setupShutdownHandlers(): void {
    const shutdown = () => {
      this.stop();
    };

    Deno.addSignalListener("SIGINT", shutdown);
    Deno.addSignalListener("SIGTERM", shutdown);

    // Handle uncaught errors
    globalThis.addEventListener("unhandledrejection", (event) => {
      console.error("❌ Unhandled rejection:", event.reason);
    });

    globalThis.addEventListener("error", (event) => {
      console.error("❌ Uncaught error:", event.error);
    });
  }
}

/**
 * Main entry point
 */
async function main() {
  // Parse command line arguments
  const args = Deno.args;
  let configPath: string | undefined;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--config" || args[i] === "-c") {
      configPath = args[i + 1];
    } else if (args[i] === "--help" || args[i] === "-h") {
      console.log(`
BlkBox Honeypot System

Usage:
  deno run --allow-all main.ts [options]

Options:
  -c, --config <path>   Path to configuration file (default: ./config.json)
  -h, --help           Show this help message

Examples:
  deno run --allow-all main.ts
  deno run --allow-all main.ts --config /etc/blkbox/config.json
      `);
      Deno.exit(0);
    }
  }

  // Create and start orchestrator
  const orchestrator = new BlkBoxOrchestrator();
  await orchestrator.start(configPath);
}

// Run if this is the main module
if (import.meta.main) {
  main().catch((error) => {
    console.error("❌ Fatal error:", error);
    Deno.exit(1);
  });
}

// Export for testing
export { BlkBoxOrchestrator };
