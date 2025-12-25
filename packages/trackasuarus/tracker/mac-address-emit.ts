import type { AttackEvent } from "../types.ts";

/**
 * MAC Address Collection
 *
 * IMPORTANT LIMITATION:
 * MAC addresses CANNOT be collected over internet connections.
 * - MAC addresses operate at Layer 2 (data link layer)
 * - Internet traffic operates at Layer 3 (network layer)
 * - MAC addresses don't traverse routers - they change at each hop
 *
 * This module is a placeholder for future capabilities:
 * 1. Local network attacks (when honeypot is deployed on LAN)
 * 2. Payload-based local network scanning (if attacker executes payload)
 * 3. Alternative attribution via TCP/IP fingerprinting
 * 4. IPv6 EUI-64 extraction (MAC embedded in IPv6 address)
 */

export interface MacAddressInfo {
  mac_address: string;
  vendor?: string; // OUI lookup result
  source: "local_arp" | "payload_scan" | "dhcp_log" | "ipv6_eui64";
  confidence: number; // 0.0 - 1.0
  timestamp: string;
}

/**
 * Attempt to collect MAC address (returns null for internet connections)
 *
 * For internet-facing honeypots, this will always return null.
 * For LAN deployments, this could potentially query:
 * - ARP cache (requires system-level permissions)
 * - DHCP logs (requires access to DHCP server)
 * - Network equipment SNMP data
 */
export async function collectMacAddress(
  event: AttackEvent
): Promise<MacAddressInfo | null> {
  // For internet-facing honeypots: always null
  if (!isLocalNetwork(event.source_ip)) {
    return null;
  }

  // TODO: For LAN deployments, could query ARP cache
  // This would require:
  // - Running with elevated privileges (root/admin)
  // - Platform-specific ARP table parsing
  // - Example: `arp -a` on Unix, `arp -a` on Windows

  // Placeholder for future LAN deployment capability
  return null;
}

/**
 * Check if IP is in local network range (RFC 1918 private addresses)
 */
export function isLocalNetwork(ip: string): boolean {
  // RFC 1918 private address spaces
  if (ip.startsWith("10.")) return true;
  if (ip.startsWith("192.168.")) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip)) return true;

  // Loopback
  if (ip.startsWith("127.")) return true;

  // Link-local (APIPA)
  if (ip.startsWith("169.254.")) return true;

  // IPv6 unique local addresses (ULA)
  if (ip.startsWith("fc00:") || ip.startsWith("fd00:")) return true;

  // IPv6 link-local
  if (ip.startsWith("fe80:")) return true;

  return false;
}

/**
 * Extract MAC from IPv6 EUI-64 address (if applicable)
 *
 * IPv6 SLAAC (Stateless Address Autoconfiguration) can embed
 * the MAC address in the interface identifier using EUI-64 format.
 *
 * Format: MAC aa:bb:cc:dd:ee:ff becomes xxxx:xxbb:fffe:ccdd:xxee:xxff
 * where xx includes the flipped U/L bit.
 *
 * Note: This only works if:
 * 1. The IPv6 address uses SLAAC (not DHCPv6 or manually configured)
 * 2. Privacy extensions (RFC 4941) are NOT enabled
 * 3. The address uses EUI-64 format (many modern OSes use random IIDs)
 */
export function extractMacFromIPv6(ipv6: string): string | null {
  // IPv6 EUI-64 format detection
  if (!ipv6.includes(":")) return null;

  const parts = ipv6.split(":");
  if (parts.length < 8) {
    // Expand compressed IPv6 address
    // This is a simplified check - full implementation would expand ::
    return null;
  }

  // Extract interface identifier (last 64 bits)
  const interfaceId = parts.slice(-4);

  // Check for EUI-64 marker (fffe in the middle two octets)
  const combined = interfaceId.join("");
  if (!combined.toLowerCase().includes("fffe")) {
    // Not EUI-64 format
    return null;
  }

  // TODO: Full EUI-64 to MAC conversion
  // This would involve:
  // 1. Extracting the 64-bit interface identifier
  // 2. Checking for the fffe marker at bits 24-39
  // 3. Removing the fffe insertion
  // 4. Flipping the universal/local bit (bit 7 of first octet)
  // 5. Converting back to MAC format

  // Placeholder - requires proper bit manipulation
  return null;
}

/**
 * Parse OUI (Organizationally Unique Identifier) to identify vendor
 *
 * The first 3 octets of a MAC address identify the manufacturer.
 * This function would lookup against the IEEE OUI database.
 */
export function getVendorFromMac(mac: string): string | null {
  // Extract OUI (first 3 octets)
  const ouiMatch = mac.match(/^([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})[:-]([0-9A-Fa-f]{2})/);
  if (!ouiMatch) return null;

  const oui = `${ouiMatch[1]}${ouiMatch[2]}${ouiMatch[3]}`.toUpperCase();

  // Common OUIs (subset for demonstration)
  const vendors: Record<string, string> = {
    "000C29": "VMware",
    "0050": "Realtek",
    "00155D": "Microsoft Hyper-V",
    "001C42": "Parallels",
    "080027": "VirtualBox",
    "00D861": "Cisco",
    "00E04C": "Realtek",
    "5254": "QEMU/KVM",
  };

  // Check exact matches
  for (const [prefix, vendor] of Object.entries(vendors)) {
    if (oui.startsWith(prefix)) {
      return vendor;
    }
  }

  // TODO: Full OUI database lookup
  // Could load IEEE OUI database from:
  // https://standards-oui.ieee.org/oui/oui.txt

  return null;
}

/**
 * Detect if MAC address indicates a virtual machine
 *
 * Useful for identifying attackers using VMs for anonymity.
 */
export function isVirtualMachine(mac: string): boolean {
  const vendor = getVendorFromMac(mac);
  if (!vendor) return false;

  const vmVendors = ["VMware", "VirtualBox", "Hyper-V", "Parallels", "QEMU", "KVM"];
  return vmVendors.some(vm => vendor.includes(vm));
}
