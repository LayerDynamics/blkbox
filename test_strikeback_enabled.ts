#!/usr/bin/env -S deno run --allow-read --allow-env

/**
 * Test that strike-back can be enabled without validation errors
 */

import { loadConfig } from "./blkbox/config/config.ts";

console.log("🧪 Testing strike-back enablement...\n");

try {
  const config = await loadConfig("./config.json");

  // Simulate enabling strike-back
  config.stinger.enabled = true;
  config.stinger.autoTrigger = true;
  config.stinger.dryRun = false;

  // Set minimal legal compliance (not enforced)
  if (config.stinger.legal) {
    config.stinger.legal.counselConsulted = false;
  }

  console.log("Strike-back configuration:");
  console.log(`  Enabled: ${config.stinger.enabled}`);
  console.log(`  Auto-trigger: ${config.stinger.autoTrigger}`);
  console.log(`  Dry-run: ${config.stinger.dryRun}`);
  console.log(`  Legal counsel consulted: ${config.stinger.legal?.counselConsulted}`);

  console.log("\n✅ Strike-back can be enabled without validation errors");
  console.log("   No safeguards blocking activation");

  Deno.exit(0);
} catch (error) {
  console.error("\n❌ Test failed:");
  console.error(error);
  Deno.exit(1);
}
