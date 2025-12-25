#!/usr/bin/env -S deno run --allow-read --allow-env

/**
 * Configuration Loading and Validation Test
 *
 * Verifies that:
 * - config.json loads correctly
 * - Strike-back safeguards are validated
 * - Configuration types match
 */

import { loadConfig } from "./blkbox/config/config.ts";

console.log("🧪 Testing configuration loading and validation...\n");

try {
  // Test 1: Load configuration
  console.log("1. Loading config.json...");
  const config = await loadConfig("./config.json");
  console.log("   ✅ Configuration loaded successfully");

  // Test 2: Display stinger configuration
  console.log("\n2. Strike-back configuration:");
  console.log(`   Enabled: ${config.stinger.enabled}`);
  console.log(`   Dry-run: ${config.stinger.dryRun}`);
  console.log(`   Auto-trigger: ${config.stinger.autoTrigger}`);

  if (config.stinger.legal) {
    console.log("\n   Legal compliance:");
    console.log(`     Counsel consulted: ${config.stinger.legal.counselConsulted}`);
    console.log(`     Warning banners: ${config.stinger.legal.warningBannerEnabled}`);
    console.log(`     Audit logging: ${config.stinger.legal.auditLoggingEnabled}`);
  }

  if (config.stinger.safeguards) {
    console.log("\n   Safety safeguards:");
    console.log(`     Threat threshold: ${config.stinger.safeguards.threatThreshold}`);
    console.log(`     Min attack count: ${config.stinger.safeguards.minAttackCount}`);
    console.log(`     Manual approval: ${config.stinger.safeguards.requireManualApproval}`);
    console.log(`     Max active payloads: ${config.stinger.safeguards.maxActivePayloads}`);
  }

  if (config.stinger.geofencing) {
    console.log("\n   Geofencing:");
    console.log(`     Enabled: ${config.stinger.geofencing.enabled}`);
    console.log(`     Mode: ${config.stinger.geofencing.mode}`);
    console.log(`     Prohibited countries: ${config.stinger.geofencing.prohibitedCountries.length} countries`);
  }

  if (config.stinger.payloadRestrictions) {
    console.log("\n   Payload restrictions:");
    console.log(`     Allowed types: ${config.stinger.payloadRestrictions.allowedTypes.join(", ")}`);
    console.log(`     Prohibited types: ${config.stinger.payloadRestrictions.prohibitedTypes.length} types`);
  }

  console.log("\n✅ Configuration test passed!");
  console.log("\nConfiguration loaded:");
  console.log(`  - ${config.honeypots.filter(h => h.enabled).length} honeypots enabled`);
  console.log(`  - Strike-back enabled: ${config.stinger.enabled}`);
  console.log(`  - Dry-run mode: ${config.stinger.dryRun}`);

  Deno.exit(0);
} catch (error) {
  console.error("\n❌ Configuration test failed:");
  console.error(error);
  Deno.exit(1);
}
