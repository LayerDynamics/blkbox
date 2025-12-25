/**
 * Mask Module Exports
 *
 * Anti-fingerprinting and concealment functionality.
 * Makes the honeypot appear more like a real server.
 */

export { Mask, createDefaultMask, maskedResponse } from "./mask.ts";
export type { MaskConfig } from "./mask.ts";
