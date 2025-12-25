/**
 * Melittasphex - Honeypot and Strike-back Package
 *
 * Package metaphor: Bee/Wasp
 * - HIVE: Honeypots that attract attackers (like bees to flowers)
 * - STINGER: Strike-back capabilities for defense (like a bee's sting)
 *
 * Provides:
 * - Honeypot service management
 * - Strike-back decision engine
 * - Payload generation and delivery
 */

// HIVE - Honeypot Core
export { HoneypotService } from "./hive/honeypot_service.ts";

// STINGER - Strike-back Capabilities
export {
  StingerService,
  createStingerConfig,
  validateStingerConfig,
  isProductionReady,
} from "./stinger/stinger_service.ts";

export type { StingerConfig } from "./stinger/stinger_service.ts";

export type {
  PayloadMetadata,
  PayloadStatus,
  ObfuscationLevel,
  PayloadGenerationConfig,
  PayloadIntelligence,
  C2CallbackData,
} from "./stinger/payload.ts";
