#!/usr/bin/env -S deno run --allow-read --allow-env

/**
 * Check what features are currently disabled in the system
 */

import { loadConfig } from "./blkbox/config/config.ts";

console.log("🔍 Analyzing what is currently DISABLED in BlkBox...\n");
console.log("=".repeat(60));

try {
  const config = await loadConfig("./config.json");

  const disabled: string[] = [];
  const enabled: string[] = [];
  const restrictions: string[] = [];

  // Check honeypots
  console.log("\n📡 HONEYPOTS:");
  config.honeypots.forEach(hp => {
    if (hp.enabled) {
      console.log(`  ✅ ${hp.type.toUpperCase()} - enabled on port ${hp.port}`);
      enabled.push(`${hp.type} honeypot`);
    } else {
      console.log(`  ❌ ${hp.type.toUpperCase()} - DISABLED`);
      disabled.push(`${hp.type} honeypot`);
    }
  });

  // Check Cloudflare
  console.log("\n☁️  CLOUDFLARE INTEGRATION:");
  if (config.cloudflare?.enabled) {
    console.log(`  ✅ Enabled`);
    enabled.push("Cloudflare integration");
  } else {
    console.log(`  ❌ DISABLED`);
    disabled.push("Cloudflare integration");
  }

  // Check Strike-back
  console.log("\n⚡ STRIKE-BACK (STINGER):");
  if (config.stinger.enabled) {
    console.log(`  ✅ Enabled`);
    enabled.push("Strike-back");
  } else {
    console.log(`  ❌ DISABLED`);
    disabled.push("Strike-back (Stinger)");
  }

  if (config.stinger.autoTrigger) {
    console.log(`  ✅ Auto-trigger enabled`);
    enabled.push("Auto-trigger");
  } else {
    console.log(`  ❌ Auto-trigger DISABLED`);
    disabled.push("Auto-trigger");
  }

  if (config.stinger.dryRun) {
    console.log(`  ⚠️  Dry-run mode ENABLED (simulates, doesn't execute)`);
    restrictions.push("Dry-run mode (no real deployments)");
  } else {
    console.log(`  ✅ Dry-run mode disabled (real deployments)`);
  }

  // Check safeguards that act as restrictions
  console.log("\n🛡️  SAFEGUARDS & RESTRICTIONS:");

  if (config.stinger.safeguards.requireManualApproval) {
    console.log(`  ⚠️  Manual approval REQUIRED`);
    restrictions.push("Manual approval required");
  } else {
    console.log(`  ✅ Manual approval disabled (automatic)`);
  }

  if (config.stinger.whitelist.enabled) {
    console.log(`  ⚠️  IP whitelist ENABLED (${config.stinger.whitelist.ips.length} networks blocked)`);
    restrictions.push(`IP whitelist (${config.stinger.whitelist.ips.length} private networks protected)`);
  } else {
    console.log(`  ✅ IP whitelist disabled`);
  }

  if (config.stinger.geofencing.enabled) {
    const blockedCount = config.stinger.geofencing.prohibitedCountries.length;
    console.log(`  ⚠️  Geofencing ENABLED (${blockedCount} countries blocked)`);
    restrictions.push(`Geofencing (${blockedCount} countries blocked)`);
  } else {
    console.log(`  ✅ Geofencing disabled`);
  }

  // Check tracking
  console.log("\n📊 TRACKING:");
  if (config.tracking.trackCookies) {
    console.log(`  ✅ Cookie tracking enabled`);
    enabled.push("Cookie tracking");
  } else {
    console.log(`  ❌ Cookie tracking DISABLED`);
    disabled.push("Cookie tracking");
  }

  // Check notifications
  console.log("\n🔔 NOTIFICATIONS:");
  if (config.stinger.notifications?.enabled) {
    console.log(`  ✅ Enabled`);
    enabled.push("Notifications");
  } else {
    console.log(`  ❌ DISABLED`);
    disabled.push("Notifications");
  }

  // Check SSL/TLS
  console.log("\n🔒 SSL/TLS:");
  if (config.server.enableSSL) {
    console.log(`  ✅ Management server SSL enabled`);
    enabled.push("Management SSL");
  } else {
    console.log(`  ❌ Management server SSL DISABLED`);
    disabled.push("Management SSL");
  }

  if (config.stinger.c2.useTls) {
    console.log(`  ✅ C2 server TLS enabled`);
    enabled.push("C2 TLS");
  } else {
    console.log(`  ❌ C2 server TLS DISABLED`);
    disabled.push("C2 TLS");
  }

  // Check CORS
  console.log("\n🌐 CORS:");
  if (config.server.corsEnabled) {
    console.log(`  ✅ Enabled`);
    enabled.push("CORS");
  } else {
    console.log(`  ❌ DISABLED`);
    disabled.push("CORS");
  }

  // C2 Authentication
  console.log("\n🔐 C2 AUTHENTICATION:");
  if (config.stinger.c2.requireAuthentication) {
    console.log(`  ⚠️  Authentication REQUIRED`);
    restrictions.push("C2 authentication required");
  } else {
    console.log(`  ✅ Authentication disabled (open access)`);
  }

  // Summary
  console.log("\n" + "=".repeat(60));
  console.log("\n📋 SUMMARY:");
  console.log(`\n❌ DISABLED (${disabled.length} features):`);
  disabled.forEach(item => console.log(`   - ${item}`));

  console.log(`\n⚠️  RESTRICTIONS/SAFEGUARDS (${restrictions.length} active):`);
  restrictions.forEach(item => console.log(`   - ${item}`));

  console.log(`\n✅ ENABLED (${enabled.length} features):`);
  enabled.forEach(item => console.log(`   - ${item}`));

  console.log("\n" + "=".repeat(60));
  console.log("\n💡 KEY FINDINGS:");

  if (!config.stinger.enabled) {
    console.log("   🔴 STRIKE-BACK IS DISABLED - Main offensive capability is off");
  } else if (config.stinger.dryRun) {
    console.log("   🟡 STRIKE-BACK IN DRY-RUN MODE - Simulates but doesn't execute");
  } else {
    console.log("   🟢 STRIKE-BACK IS ACTIVE - Can deploy real payloads");
  }

  if (restrictions.length > 0) {
    console.log(`   ⚠️  ${restrictions.length} ACTIVE RESTRICTIONS preventing full operation`);
  } else {
    console.log("   ✅ NO RESTRICTIONS - Full capabilities available");
  }

  console.log("\n");

  Deno.exit(0);
} catch (error) {
  console.error("\n❌ Analysis failed:");
  console.error(error);
  Deno.exit(1);
}
