/**
 * Cookiejar Package - Payload Generation System
 *
 * The Cookiejar package implements a complete payload generation pipeline using
 * a "bakery" metaphor:
 *
 * 1. Dough - Raw payload configuration from attack events
 * 2. Oven - Template library for all payload types
 * 3. Bake - Obfuscation and anti-analysis techniques
 * 4. Jar - Storage, serving, and C2 callback handling
 *
 * Usage:
 *
 * ```typescript
 * // Simple usage with client
 * import { CookiejarClient } from "./packages/cookiejar/mod.ts";
 * import { PayloadType } from "./lib_deno/types.ts";
 *
 * const client = new CookiejarClient(ffi, {
 *   c2BaseUrl: "http://localhost:8443",
 *   defaultExpirationHours: 24
 * });
 *
 * const result = await client.generatePayload(attackEvent, PayloadType.SystemInfo);
 * console.log(`Payload ready at: ${result.payloadUrl}`);
 * ```
 *
 * ```typescript
 * // Start standalone server
 * import { startCookiejarServer } from "./packages/cookiejar/mod.ts";
 *
 * const server = await startCookiejarServer(ffi, {
 *   port: 8443,
 *   enableLogging: true
 * });
 * ```
 */

// ========================================
// DOUGH - Configuration
// ========================================
export {
  DoughService,
  type DoughConfig,
  type TargetEnvironment,
  type C2Config,
  type DeliveryConfig
} from "./dough/mod.ts";

// ========================================
// OVEN - Templates
// ========================================
export {
  OvenTemplates
} from "./oven/mod.ts";

// ========================================
// BAKE - Obfuscation
// ========================================
export {
  BakeService,
  bakePayload
} from "./bake/mod.ts";

// ========================================
// JAR - Storage & Serving
// ========================================
export {
  JarService,
  PayloadServer,
  cookiejarWorkflow,
  type StoredPayload,
  type PayloadStatistics
} from "./jar/mod.ts";

// ========================================
// CLIENT - High-level API
// ========================================
export {
  CookiejarClient,
  quickPayload,
  type CookiejarConfig,
  type PayloadResult
} from "./client.ts";

// ========================================
// SERVER - Standalone server
// ========================================
export {
  CookiejarServer,
  startCookiejarServer,
  type CookiejarServerConfig,
  type ServerStatistics
} from "./server.ts";

// ========================================
// Re-export common types
// ========================================
export type { PayloadType } from "../../lib_deno/types.ts";
