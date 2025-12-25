/**
 * Tracker Module Exports
 *
 * Intelligence gathering and tracking functionality.
 */

export { Tracker } from "./track.ts";
export { TrackingEmitter, trackAndEmit } from "./emit.ts";
export {
  geoping,
  geopingBatch,
  isHighRiskCountry,
  inferTimezone,
  calculateDistance,
  detectImpossibleTravel,
  getRegion,
  isLikelyVPN,
} from "./geoping.ts";
export {
  collectMacAddress,
  isLocalNetwork,
  extractMacFromIPv6,
  getVendorFromMac,
  isVirtualMachine,
} from "./mac-address-emit.ts";
export type { MacAddressInfo } from "./mac-address-emit.ts";
