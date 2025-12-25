/**
 * Mask - Anti-Fingerprinting Module
 *
 * Prevents honeypot detection by:
 * - Varying response timing (avoid deterministic patterns)
 * - Rotating banners (avoid static signatures)
 * - Polymorphic responses (randomize formatting)
 * - Simulating realistic errors (not always success)
 *
 * This makes the honeypot appear more like a real server
 * and harder to fingerprint as a trap.
 */

export interface MaskConfig {
  timing: {
    enabled: boolean;
    minDelayMs: number;
    maxDelayMs: number;
  };
  banners: {
    rotationIntervalMs: number;
    pools: Record<string, string[]>;
  };
  errors: {
    enabled: boolean;
    errorRate: number; // 0.0 - 1.0
  };
}

/**
 * Mask class - Anti-fingerprinting engine
 */
export class Mask {
  private config: MaskConfig;
  private currentBannerIndex: number = 0;
  private lastBannerRotation: number = Date.now();

  constructor(config?: Partial<MaskConfig>) {
    this.config = {
      timing: {
        enabled: true,
        minDelayMs: 50,
        maxDelayMs: 500,
        ...config?.timing,
      },
      banners: {
        rotationIntervalMs: 6 * 60 * 60 * 1000, // 6 hours
        pools: {
          SSH: [
            "SSH-2.0-OpenSSH_7.4",
            "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3",
            "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1",
            "SSH-2.0-OpenSSH_9.0p1 Debian-1ubuntu8",
          ],
          HTTP_SERVER: [
            "Apache/2.4.41 (Ubuntu)",
            "nginx/1.18.0 (Ubuntu)",
            "Apache/2.4.52 (Ubuntu)",
            "nginx/1.21.6",
            "Apache/2.4.54 (Debian)",
            "nginx/1.22.0",
          ],
          FTP: [
            "220 ProFTPD 1.3.6 Server",
            "220 vsftpd 3.0.3",
            "220 Welcome to FTP service",
            "220 FTP Server ready",
            "220 ProFTPD 1.3.7 Server",
          ],
          ...config?.banners?.pools,
        },
        rotationIntervalMs: config?.banners?.rotationIntervalMs || 6 * 60 * 60 * 1000,
      },
      errors: {
        enabled: true,
        errorRate: 0.05, // 5% error rate
        ...config?.errors,
      },
    };
  }

  /**
   * Apply random timing jitter to avoid fingerprinting
   *
   * Real servers have variable response times due to:
   * - CPU load
   * - Network latency
   * - Disk I/O
   * - Concurrent connections
   *
   * Honeypots often respond too quickly and consistently,
   * making them detectable. This adds realistic variance.
   */
  async applyTimingJitter(): Promise<void> {
    if (!this.config.timing.enabled) return;

    const delay =
      Math.random() * (this.config.timing.maxDelayMs - this.config.timing.minDelayMs) +
      this.config.timing.minDelayMs;

    await new Promise(resolve => setTimeout(resolve, delay));
  }

  /**
   * Get current banner for service type (rotates periodically)
   *
   * Static banners are easily fingerprinted. Rotation makes
   * scanning and detection harder.
   */
  getBanner(serviceType: string): string {
    // Check if rotation needed
    if (Date.now() - this.lastBannerRotation > this.config.banners.rotationIntervalMs) {
      this.rotateBanner();
    }

    const pool = this.config.banners.pools[serviceType];
    if (!pool || pool.length === 0) {
      return ""; // No banners configured
    }

    return pool[this.currentBannerIndex % pool.length];
  }

  /**
   * Rotate to next banner in pool
   */
  private rotateBanner(): void {
    this.currentBannerIndex++;
    this.lastBannerRotation = Date.now();
    console.log(`[Mask] Rotated to banner index ${this.currentBannerIndex}`);
  }

  /**
   * Manually rotate banner (for testing or forced rotation)
   */
  forceRotation(): void {
    this.rotateBanner();
  }

  /**
   * Apply polymorphic transformation to response
   * (randomize formatting while preserving semantics)
   *
   * Real servers have slight variations in formatting due to:
   * - Different software versions
   * - Configuration differences
   * - Platform differences (Windows vs Linux line endings)
   */
  polymorphicResponse(response: string): string {
    let modified = response;

    // Add random whitespace variations (30% chance)
    if (Math.random() < 0.3) {
      // Vary line endings
      modified = modified.replace(/\n/g, Math.random() < 0.5 ? "\r\n" : "\n");
    }

    // Vary case of headers (HTTP/SMTP/etc)
    if (modified.includes("Content-Type:")) {
      modified = modified.replace(/Content-Type:/g,
        Math.random() < 0.5 ? "content-type:" : "Content-Type:");
    }

    if (modified.includes("Server:")) {
      modified = modified.replace(/Server:/g,
        Math.random() < 0.5 ? "server:" : "Server:");
    }

    // Add or remove trailing whitespace (20% chance)
    if (Math.random() < 0.2) {
      const lines = modified.split("\n");
      modified = lines.map(line =>
        Math.random() < 0.5 ? line.trimEnd() : line + " "
      ).join("\n");
    }

    return modified;
  }

  /**
   * Decide if should simulate an error (realistic failure rate)
   *
   * Real servers occasionally fail due to:
   * - Resource exhaustion
   * - Network issues
   * - Configuration errors
   * - Rate limiting
   *
   * A honeypot that always succeeds is suspicious.
   */
  shouldSimulateError(): boolean {
    if (!this.config.errors.enabled) return false;
    return Math.random() < this.config.errors.errorRate;
  }

  /**
   * Get random error message for service type
   */
  getRandomError(serviceType: string): string {
    const errors: Record<string, string[]> = {
      SSH: [
        "Connection reset by peer",
        "Timeout waiting for authentication",
        "Too many authentication failures",
        "Connection closed by remote host",
        "Network error: Connection timed out",
      ],
      HTTP: [
        "500 Internal Server Error",
        "503 Service Temporarily Unavailable",
        "504 Gateway Timeout",
        "502 Bad Gateway",
        "429 Too Many Requests",
      ],
      FTP: [
        "421 Service not available, closing control connection",
        "530 Login incorrect",
        "550 Permission denied",
        "421 Too many connections from this IP",
        "500 Command not understood",
      ],
      POSTGRESQL: [
        "FATAL: too many connections",
        "FATAL: password authentication failed",
        "FATAL: database \"postgres\" does not exist",
        "ERROR: connection timed out",
      ],
      MYSQL: [
        "ERROR 1040 (HY000): Too many connections",
        "ERROR 1045 (28000): Access denied",
        "ERROR 2002 (HY000): Connection timeout",
        "ERROR 1129 (HY000): Host is blocked",
      ],
    };

    const pool = errors[serviceType] || ["Service error"];
    return pool[Math.floor(Math.random() * pool.length)];
  }

  /**
   * Add realistic variance to numeric values
   *
   * Useful for response times, sequence numbers, etc.
   */
  addNumericVariance(value: number, variancePercent: number): number {
    const variance = value * (variancePercent / 100);
    const offset = (Math.random() * 2 - 1) * variance; // -variance to +variance
    return Math.round(value + offset);
  }

  /**
   * Get configuration for inspection
   */
  getConfig(): MaskConfig {
    return { ...this.config };
  }

  /**
   * Update configuration at runtime
   */
  updateConfig(config: Partial<MaskConfig>): void {
    if (config.timing) {
      this.config.timing = { ...this.config.timing, ...config.timing };
    }
    if (config.banners) {
      this.config.banners = { ...this.config.banners, ...config.banners };
    }
    if (config.errors) {
      this.config.errors = { ...this.config.errors, ...config.errors };
    }
  }
}

/**
 * Create mask with default configuration
 */
export function createDefaultMask(): Mask {
  return new Mask();
}

/**
 * Apply mask to response (convenience function)
 *
 * This is a high-level helper that applies all masking techniques:
 * - Timing jitter
 * - Error simulation
 * - Polymorphic transformation
 */
export async function maskedResponse(
  mask: Mask,
  response: string,
  serviceType: string
): Promise<string> {
  // Apply timing jitter first
  await mask.applyTimingJitter();

  // Simulate errors occasionally
  if (mask.shouldSimulateError()) {
    return mask.getRandomError(serviceType);
  }

  // Apply polymorphic transformation
  return mask.polymorphicResponse(response);
}
