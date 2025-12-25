// BlkBox Deno FFI Library - Main Module Exports
//
// This module provides the public API for interacting with the BlkBox
// honeypot system from Deno/TypeScript.

// Re-export all types
export type {
  AttackEvent,
  BlkBoxConfig,
  CloudflareConfig,
  HoneypotConfig,
  ServiceConfig,
  ServiceStatus,
} from "./types.ts";

export {
  FFIError,
  FFIResult,
  PayloadType,
  ServiceType,
} from "./types.ts";

// Re-export FFI wrapper and helper functions
export { BlkBoxFFI, withBlkBox } from "./lib.ts";
