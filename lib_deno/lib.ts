// Deno FFI bindings for BlkBox Rust library

import {
  AttackEvent,
  CloudflareConfig,
  FFIError,
  FFIResult,
  PayloadType,
  ServiceConfig,
  ServiceType,
} from "./types.ts";
import { TrackerClient } from "../packages/trackasuarus/client.ts";

// Define FFI symbols matching Rust exports
const symbols = {
  blkbox_init: {
    parameters: [],
    result: "pointer",
  },
  blkbox_start_honeypot: {
    parameters: ["pointer", "u8", "u16", "buffer"],
    result: "i32",
  },
  blkbox_stop_honeypot: {
    parameters: ["pointer", "u32"],
    result: "i32",
  },
  blkbox_get_events: {
    parameters: ["pointer", "buffer", "usize"],
    result: "i32",
  },
  blkbox_trigger_strikeback: {
    parameters: ["pointer", "buffer", "u8"],
    result: "i32",
  },
  blkbox_store_event: {
    parameters: ["pointer", "buffer"],
    result: "i32",
  },
  blkbox_cloudflare_update: {
    parameters: ["pointer", "buffer"],
    result: "i32",
  },
  blkbox_geolocate_ip: {
    parameters: ["pointer", "buffer", "buffer", "usize"],
    result: "i32",
  },
  blkbox_get_ip_sessions: {
    parameters: ["pointer", "buffer", "buffer", "usize"],
    result: "i32",
  },
  blkbox_get_enriched_attacks: {
    parameters: ["pointer", "usize", "usize", "buffer", "usize"],
    result: "i32",
  },
  blkbox_free: {
    parameters: ["pointer"],
    result: "void",
  },
} as const;

// Determine library path based on platform
const getLibraryPath = (): string => {
  const libPaths: Record<string, string> = {
    darwin: "./target/release/libblkbox.dylib",
    linux: "./target/release/libblkbox.so",
    windows: "./target/release/blkbox.dll",
  };

  const path = libPaths[Deno.build.os];
  if (!path) {
    throw new Error(`Unsupported platform: ${Deno.build.os}`);
  }

  return path;
};

// Load the dynamic library
const libPath = getLibraryPath();
let lib: Deno.DynamicLibrary<typeof symbols>;

try {
  lib = Deno.dlopen(libPath, symbols);
} catch (error) {
  throw new Error(
    `Failed to load BlkBox library from ${libPath}: ${
      error instanceof Error ? error.message : String(error)
    }\n\nMake sure you've built the Rust library with: cargo build --release`,
  );
}

/**
 * Main FFI wrapper class for BlkBox honeypot system
 *
 * Example usage:
 * ```typescript
 * const blkbox = new BlkBoxFFI();
 *
 * // Start HTTP honeypot
 * const serviceId = blkbox.startHoneypot(ServiceType.HTTP, 8080, {
 *   enabled: true,
 * });
 *
 * // Poll for events
 * const events = blkbox.getEvents();
 *
 * // Cleanup
 * blkbox.close();
 * ```
 */
export class BlkBoxFFI {
  [x: string]: any;
  getPayload(payloadId: string): any {
    throw new Error("Method not implemented.");
  }
  private runtime: Deno.PointerValue;
  private closed = false;

  constructor() {
    this.runtime = lib.symbols.blkbox_init();

    if (this.runtime === null) {
      throw new FFIError("Failed to initialize BlkBox runtime");
    }
  }

  /**
   * Start a honeypot service
   *
   * @param serviceType - Type of service to start
   * @param port - Port number to listen on
   * @param config - Service configuration
   * @returns Service ID on success
   * @throws FFIError if service fails to start
   */
  startHoneypot(
    serviceType: ServiceType,
    port: number,
    config: ServiceConfig = { enabled: true },
  ): number {
    this.checkClosed();

    // Convert config to JSON
    const configJson = JSON.stringify(config);
    const encoder = new TextEncoder();
    const configBuffer = encoder.encode(configJson + "\0");

    const result = lib.symbols.blkbox_start_honeypot(
      this.runtime,
      serviceType,
      port,
      configBuffer,
    );

    if (result === FFIResult.Error) {
      throw new FFIError(
        `Failed to start ${ServiceType[serviceType]} honeypot on port ${port}`,
      );
    }

    return result;
  }

  /**
   * Stop a running honeypot service
   *
   * @param serviceId - ID of service to stop
   * @throws FFIError if service fails to stop
   */
  stopHoneypot(serviceId: number): void {
    this.checkClosed();

    const result = lib.symbols.blkbox_stop_honeypot(this.runtime, serviceId);

    if (result === FFIResult.Error) {
      throw new FFIError(`Failed to stop service ${serviceId}`);
    }
  }

  /**
   * Get all pending attack events
   *
   * @returns Array of attack events
   * @throws FFIError if events cannot be retrieved
   */
  getEvents(): AttackEvent[] {
    this.checkClosed();

    // Allocate buffer for JSON response (64KB should be enough for most cases)
    const bufferSize = 65536;
    const buffer = new Uint8Array(bufferSize);

    const bytesWritten = lib.symbols.blkbox_get_events(
      this.runtime,
      buffer,
      bufferSize,
    );

    if (bytesWritten === FFIResult.Error) {
      throw new FFIError("Failed to get events");
    }

    if (bytesWritten === 0) {
      return [];
    }

    // Decode JSON
    const decoder = new TextDecoder();
    const jsonStr = decoder.decode(buffer.slice(0, bytesWritten));

    try {
      return JSON.parse(jsonStr) as AttackEvent[];
    } catch (error) {
      throw new FFIError(
        `Failed to parse events JSON: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  /**
   * Trigger strikeback payload deployment
   *
   * @param attackerIp - IP address of attacker
   * @param payloadType - Type of payload to deploy
   * @throws FFIError if deployment fails
   */
  triggerStrikeback(attackerIp: string, payloadType: PayloadType): void {
    this.checkClosed();

    const encoder = new TextEncoder();
    const ipBuffer = encoder.encode(attackerIp + "\0");

    const result = lib.symbols.blkbox_trigger_strikeback(
      this.runtime,
      ipBuffer,
      payloadType,
    );

    if (result === FFIResult.Error) {
      throw new FFIError(
        `Failed to trigger strikeback to ${attackerIp}`,
      );
    }
  }

  /**
   * Store an attack event in the database
   *
   * @param event - Attack event to store
   * @returns Row ID of stored event
   * @throws FFIError if storage fails
   */
  storeEvent(event: AttackEvent): number {
    this.checkClosed();

    const eventJson = JSON.stringify(event);
    const encoder = new TextEncoder();
    const buffer = encoder.encode(eventJson + "\0");

    const result = lib.symbols.blkbox_store_event(this.runtime, buffer);

    if (result === FFIResult.Error) {
      throw new FFIError("Failed to store event");
    }

    return result;
  }

  /**
   * Update Cloudflare configuration
   *
   * @param config - Cloudflare configuration
   * @throws FFIError if update fails
   */
  updateCloudflare(config: CloudflareConfig): void {
    this.checkClosed();

    const configJson = JSON.stringify(config);
    const encoder = new TextEncoder();
    const buffer = encoder.encode(configJson + "\0");

    const result = lib.symbols.blkbox_cloudflare_update(this.runtime, buffer);

    if (result === FFIResult.Error) {
      throw new FFIError("Failed to update Cloudflare configuration");
    }
  }

  /**
   * Get a TrackerClient for accessing tracking functionality
   *
   * @returns TrackerClient instance
   *
   * Example:
   * ```typescript
   * const blkbox = new BlkBoxFFI();
   * const tracker = blkbox.getTrackerClient();
   *
   * // Geolocate an IP
   * const geo = tracker.geolocateIp("8.8.8.8");
   *
   * // Get attack sessions
   * const sessions = tracker.getIpSessions("1.2.3.4");
   *
   * // Get enriched attacks
   * const enriched = tracker.getEnrichedAttacks(10, 0);
   * ```
   */
  getTrackerClient(): TrackerClient {
    this.checkClosed();
    return new TrackerClient(this.runtime, lib);
  }

  /**
   * Close the runtime and free resources
   *
   * IMPORTANT: Call this when done to prevent memory leaks
   */
  close(): void {
    if (this.closed) {
      return;
    }

    lib.symbols.blkbox_free(this.runtime);
    this.closed = true;
  }

  /**
   * Check if runtime is closed and throw error if it is
   */
  private checkClosed(): void {
    if (this.closed) {
      throw new FFIError("BlkBox runtime has been closed");
    }
  }
}

/**
 * Helper function to create a BlkBox instance with automatic cleanup
 *
 * @param callback - Function to execute with BlkBox instance
 * @returns Result of callback
 *
 * Example:
 * ```typescript
 * await withBlkBox(async (blkbox) => {
 *   const id = blkbox.startHoneypot(ServiceType.HTTP, 8080);
 *   // Use blkbox...
 * }); // Automatically cleaned up
 * ```
 */
export async function withBlkBox<T>(
  callback: (blkbox: BlkBoxFFI) => Promise<T> | T,
): Promise<T> {
  const blkbox = new BlkBoxFFI();
  try {
    return await callback(blkbox);
  } finally {
    blkbox.close();
  }
}
