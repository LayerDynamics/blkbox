#!/usr/bin/env -S deno run --allow-all

/**
 * FFI Library Loading Test
 *
 * Verifies that:
 * - Rust library can be loaded
 * - FFI initialization works
 * - No segmentation faults occur
 * - Runtime pointer is valid
 */

import { BlkBoxFFI } from "./lib_deno/lib.ts";

console.log("🧪 Testing FFI library loading...\n");

try {
  // Test 1: Load library
  console.log("1. Loading libblkbox library...");
  const ffi = new BlkBoxFFI();
  console.log("   ✅ FFI loaded successfully");

  // Test 2: Verify runtime pointer
  console.log("\n2. Verifying runtime pointer...");
  console.log("   Runtime pointer:", ffi.runtime);
  if (ffi.runtime === null) {
    throw new Error("Invalid runtime pointer");
  }
  console.log("   ✅ Runtime pointer is valid");

  // Test 3: Test TrackerClient (geolocate_ip)
  console.log("\n3. Testing TrackerClient (geolocate_ip)...");
  const tracker = ffi.getTrackerClient();
  const geo = tracker.geolocateIp("8.8.8.8");
  if (geo) {
    console.log(`   ✅ Geolocation successful: ${geo.country_code || "Unknown"}`);
    console.log(`      City: ${geo.city || "N/A"}, Country: ${geo.country_name || "N/A"}`);
  } else {
    console.log("   ⚠️  Geolocation returned null (database may not be configured)");
  }

  // Test 4: Close FFI cleanly
  console.log("\n4. Testing cleanup...");
  ffi.close();
  console.log("   ✅ FFI closed successfully");

  console.log("\n✅ All FFI tests passed!");
  console.log("\nNext steps:");
  console.log("  - Run main application: deno run --allow-all main.ts");
  console.log("  - Check honeypots start correctly");
  console.log("  - Verify event processing works");

  Deno.exit(0);
} catch (error) {
  console.error("\n❌ FFI test failed:");
  console.error(error);
  console.error("\nTroubleshooting:");
  console.error("  - Verify Rust library compiled: ls -lh target/release/libblkbox.dylib");
  console.error("  - Check FFI symbols: nm -g target/release/libblkbox.dylib | grep blkbox_");
  console.error("  - Ensure Deno has permissions: --allow-all flag");
  Deno.exit(1);
}
