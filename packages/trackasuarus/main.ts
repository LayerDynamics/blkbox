#!/usr/bin/env -S deno run --allow-all

import { BlkBoxFFI } from "../../lib_deno/lib.ts";
import { TrackerClient, Tracker, Mask } from "./mod.ts";

/**
 * Trackasuarus Test Entry Point
 *
 * Tests the Trackasuarus package functionality:
 * - FFI connectivity
 * - Geolocation
 * - Tracker
 * - Anti-fingerprinting (Mask)
 */
async function main() {
  console.log("🔍 Trackasuarus Package Test\n");

  // Initialize FFI
  console.log("1. Initializing FFI...");
  const ffi = new BlkBoxFFI();
  const client = new TrackerClient(ffi.runtime, ffi.lib);
  console.log("   ✓ FFI initialized");

  // Test geolocation
  console.log("\n2. Testing geolocation:");
  const testIPs = ["8.8.8.8", "1.1.1.1", "208.67.222.222"];
  for (const ip of testIPs) {
    const geo = client.geolocateIp(ip);
    if (geo) {
      console.log(`   ✓ ${ip}: ${geo.city || "Unknown"}, ${geo.country_code || "??"}`);
    } else {
      console.log(`   ✗ ${ip}: No geolocation data`);
    }
  }

  // Test tracker
  console.log("\n3. Testing tracker:");
  const tracker = new Tracker(client);
  const topAttackers = await tracker.getTopAttackers(5);
  console.log(`   ✓ Top attackers query returned ${topAttackers.length} results`);

  // Test mask
  console.log("\n4. Testing anti-fingerprinting mask:");
  const mask = new Mask();

  console.log("   SSH Banner:", mask.getBanner("SSH"));
  console.log("   HTTP Banner:", mask.getBanner("HTTP_SERVER"));
  console.log("   FTP Banner:", mask.getBanner("FTP"));

  console.log("\n   Applying timing jitter...");
  const start = performance.now();
  await mask.applyTimingJitter();
  const elapsed = performance.now() - start;
  console.log(`   ✓ Jitter applied (${Math.round(elapsed)}ms delay)`);

  console.log("\n   Testing error simulation:");
  const errorTests = 20;
  let errorCount = 0;
  for (let i = 0; i < errorTests; i++) {
    if (mask.shouldSimulateError()) {
      errorCount++;
    }
  }
  const errorRate = (errorCount / errorTests) * 100;
  console.log(`   ✓ Error rate: ${errorRate}% (${errorCount}/${errorTests})`);

  console.log("\n   Testing polymorphic transformation:");
  const originalResponse = "HTTP/1.1 200 OK\nContent-Type: text/html\nServer: nginx\n\nHello";
  const transformed = mask.polymorphicResponse(originalResponse);
  console.log(`   ✓ Response transformed (${transformed.length} bytes)`);

  // Cleanup
  ffi.close();
  console.log("\n✅ All tests complete!");
}

if (import.meta.main) {
  await main();
}
