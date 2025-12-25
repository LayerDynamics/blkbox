#!/usr/bin/env -S deno run --allow-read --allow-env

/**
 * Test that all payload types are unrestricted
 */

import { loadConfig } from "./blkbox/config/config.ts";

console.log("🧪 Testing unrestricted payload configuration...\n");

try {
  const config = await loadConfig("./config.json");

  console.log("Payload Restrictions Configuration:");
  console.log(`  Allowed types: ${config.stinger.payloadRestrictions.allowedTypes.length} types`);
  console.log(`  Prohibited types: ${config.stinger.payloadRestrictions.prohibitedTypes.length} types`);
  console.log(`  Max payload size: ${config.stinger.payloadRestrictions.maxPayloadSizeKb} KB`);
  console.log(`  Obfuscation required: ${config.stinger.payloadRestrictions.obfuscationRequired}`);
  console.log(`  Network scanning allowed: ${config.stinger.payloadRestrictions.allowNetworkScanning}`);
  console.log(`  File access allowed: ${config.stinger.payloadRestrictions.allowFileAccess}`);

  console.log("\nAllowed payload types:");
  config.stinger.payloadRestrictions.allowedTypes.forEach(type => {
    console.log(`  ✓ ${type}`);
  });

  console.log("\nVerification:");

  // Check all powerful payload types are allowed
  const powerfulPayloads = [
    "reverse_tcp",
    "reverse_http",
    "command_injection",
    "file_exfiltration",
    "credential_harvester",
    "log_wiper",
    "ransomware_simulator",
    "data_destruction"
  ];

  let allAllowed = true;
  for (const payload of powerfulPayloads) {
    const isAllowed = config.stinger.payloadRestrictions.allowedTypes.includes(payload);
    if (!isAllowed) {
      console.log(`  ✗ ${payload} - NOT ALLOWED`);
      allAllowed = false;
    } else {
      console.log(`  ✓ ${payload} - allowed`);
    }
  }

  // Check no prohibitions
  if (config.stinger.payloadRestrictions.prohibitedTypes.length > 0) {
    console.log(`\n⚠️  WARNING: ${config.stinger.payloadRestrictions.prohibitedTypes.length} types still prohibited:`);
    config.stinger.payloadRestrictions.prohibitedTypes.forEach(type => {
      console.log(`  - ${type}`);
    });
    allAllowed = false;
  }

  // Check capabilities enabled
  if (!config.stinger.payloadRestrictions.allowNetworkScanning) {
    console.log("\n⚠️  Network scanning is disabled");
    allAllowed = false;
  }

  if (!config.stinger.payloadRestrictions.allowFileAccess) {
    console.log("\n⚠️  File access is disabled");
    allAllowed = false;
  }

  if (allAllowed) {
    console.log("\n✅ All payload types are unrestricted!");
    console.log("   No prohibitions in place");
    console.log("   Network scanning enabled");
    console.log("   File access enabled");
    console.log("   All capabilities available");
  } else {
    console.log("\n❌ Some restrictions still exist");
    Deno.exit(1);
  }

  Deno.exit(0);
} catch (error) {
  console.error("\n❌ Test failed:");
  console.error(error);
  Deno.exit(1);
}
