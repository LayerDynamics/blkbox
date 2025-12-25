/**
 * BlkBox Configuration Management System
 *
 * Provides type-safe configuration loading, validation, and environment
 * variable overrides for the entire BlkBox honeypot system.
 */

/**
 * Honeypot configuration for a single protocol instance
 */
export interface HoneypotConfig {
  type: "http" | "https" | "ssh" | "postgresql" | "mysql" | "mongodb" | "ftp" | "sftp";
  port: number;
  enabled: boolean;
  options?: {
    // HTTP/HTTPS options
    fakeApps?: string[];
    serverHeader?: string;

    // SSH options
    banner?: string;
    allowedUsers?: string[];

    // Database options
    databaseName?: string;
    allowedDatabases?: string[];

    // FTP options
    ftpBanner?: string;
    virtualRoot?: string;
  };
}

/**
 * Cloudflare integration configuration
 */
export interface CloudflareConfig {
  enabled: boolean;
  apiKey: string;
  zoneId: string;
  updateFirewall: boolean;
  threatThreshold: number;
  autoBlock: boolean;
  blockDuration: number; // seconds
}

/**
 * Storage and database configuration
 */
export interface StorageConfig {
  database: string;
  retentionDays: number;
  backupInterval: number; // seconds
  geoipDatabase?: string;
  maxDatabaseSize?: number; // MB
  autoVacuum: boolean;
}

/**
 * Stinger (strike-back) configuration with comprehensive safeguards
 */
export interface StingerConfig {
  enabled: boolean;
  autoTrigger: boolean;
  dryRun: boolean;

  legal: {
    counselConsulted: boolean;
    jurisdiction: string;
    warningBannerEnabled: boolean;
    auditLoggingEnabled: boolean;
    retentionPolicyDocumented: boolean;
    incidentResponsePlanExists: boolean;
  };

  safeguards: {
    requireManualApproval: boolean;
    threatThreshold: number;
    minAttackCount: number;
    maxActivePayloads: number;
    payloadExpirationHours: number;
    maxCallbacksPerPayload: number;
    cooldownPeriodMinutes: number;
    maxDeploymentsPerIp: number;
  };

  whitelist: {
    enabled: boolean;
    ips: string[];
    cidrs: string[];
    description?: string;
  };

  geofencing: {
    enabled: boolean;
    mode: "allow" | "prohibit";
    allowedCountries: string[];
    prohibitedCountries: string[];
    description?: string;
  };

  payloadRestrictions: {
    allowedTypes: string[];
    prohibitedTypes: string[];
    maxPayloadSizeKb: number;
    obfuscationRequired: boolean;
    allowNetworkScanning: boolean;
    allowFileAccess: boolean;
  };

  c2: {
    hostname: string;
    port: number;
    useTls: boolean;
    tlsCert?: string;
    tlsKey?: string;
    maxConcurrentConnections: number;
    connectionTimeout: number;
    requireAuthentication: boolean;
  };

  notifications?: {
    enabled: boolean;
    email?: string;
    webhook?: string;
    notifyOnDeploy: boolean;
    notifyOnCallback: boolean;
    notifyOnError: boolean;
  };

  // Legacy fields for backwards compatibility
  threatThreshold?: number;
  allowedPayloads?: string[];
  requireApproval?: boolean;
  c2Server?: string;
  c2Port?: number;
  payloadExpiration?: number;
  maxActivePayloads?: number;
  whitelistedIps?: string[];
  blacklistedCountries?: string[];
}

/**
 * Tracking and fingerprinting configuration
 */
export interface TrackingConfig {
  geoip: boolean;
  fingerprinting: boolean;
  sessionCorrelation: boolean;
  sessionTimeout: number; // seconds
  trackUserAgents: boolean;
  trackHeaders: boolean;
  trackCookies: boolean;
  ipEnrichment: boolean;
}

/**
 * Logging configuration
 */
export interface LoggingConfig {
  level: "debug" | "info" | "warn" | "error";
  file?: string;
  console: boolean;
  maxFileSize?: number; // MB
  maxFiles?: number;
  includeTimestamp: boolean;
  includeLevel: boolean;
  colorize: boolean;
}

/**
 * Management server configuration
 */
export interface ServerConfig {
  managementPort: number;
  enableDashboard: boolean;
  corsEnabled: boolean;
  allowedOrigins?: string[];
  apiRateLimit?: number; // requests per minute
  enableSSL?: boolean;
  sslCert?: string;
  sslKey?: string;
}

/**
 * Complete BlkBox configuration
 */
export interface BlkBoxConfiguration {
  honeypots: HoneypotConfig[];
  cloudflare?: CloudflareConfig;
  storage: StorageConfig;
  stinger: StingerConfig;
  tracking: TrackingConfig;
  logging: LoggingConfig;
  server: ServerConfig;
}

/**
 * Configuration validation errors
 */
export class ConfigurationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigurationError";
  }
}

/**
 * Load configuration from JSON file with environment variable overrides
 */
export async function loadConfig(path = "./config.json"): Promise<BlkBoxConfiguration> {
  try {
    // Read configuration file
    const content = await Deno.readTextFile(path);
    const config = JSON.parse(content) as BlkBoxConfiguration;

    // Apply environment variable overrides
    applyEnvironmentOverrides(config);

    // Validate configuration
    validateConfig(config);

    return config;
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      throw new ConfigurationError(`Configuration file not found: ${path}`);
    } else if (error instanceof SyntaxError) {
      throw new ConfigurationError(`Invalid JSON in configuration file: ${error.message}`);
    } else if (error instanceof ConfigurationError) {
      throw error;
    } else {
      throw new ConfigurationError(`Failed to load configuration: ${error}`);
    }
  }
}

/**
 * Apply environment variable overrides to configuration
 */
function applyEnvironmentOverrides(config: BlkBoxConfiguration): void {
  // Storage overrides
  if (Deno.env.get("BLKBOX_DATABASE")) {
    config.storage.database = Deno.env.get("BLKBOX_DATABASE")!;
  }

  // Stinger overrides
  if (Deno.env.get("BLKBOX_STINGER_ENABLED")) {
    config.stinger.enabled = Deno.env.get("BLKBOX_STINGER_ENABLED") === "true";
  }
  if (Deno.env.get("BLKBOX_STINGER_DRY_RUN")) {
    config.stinger.dryRun = Deno.env.get("BLKBOX_STINGER_DRY_RUN") === "true";
  }
  if (Deno.env.get("BLKBOX_STINGER_THRESHOLD")) {
    config.stinger.threatThreshold = parseFloat(Deno.env.get("BLKBOX_STINGER_THRESHOLD")!);
  }

  // Cloudflare overrides
  if (Deno.env.get("BLKBOX_CLOUDFLARE_ENABLED")) {
    if (!config.cloudflare) {
      config.cloudflare = {
        enabled: false,
        apiKey: "",
        zoneId: "",
        updateFirewall: false,
        threatThreshold: 8.0,
        autoBlock: false,
        blockDuration: 3600
      };
    }
    config.cloudflare.enabled = Deno.env.get("BLKBOX_CLOUDFLARE_ENABLED") === "true";
  }
  if (Deno.env.get("BLKBOX_CLOUDFLARE_API_KEY")) {
    if (config.cloudflare) {
      config.cloudflare.apiKey = Deno.env.get("BLKBOX_CLOUDFLARE_API_KEY")!;
    }
  }
  if (Deno.env.get("BLKBOX_CLOUDFLARE_ZONE_ID")) {
    if (config.cloudflare) {
      config.cloudflare.zoneId = Deno.env.get("BLKBOX_CLOUDFLARE_ZONE_ID")!;
    }
  }

  // Logging overrides
  if (Deno.env.get("BLKBOX_LOG_LEVEL")) {
    const level = Deno.env.get("BLKBOX_LOG_LEVEL")!;
    if (["debug", "info", "warn", "error"].includes(level)) {
      config.logging.level = level as "debug" | "info" | "warn" | "error";
    }
  }
  if (Deno.env.get("BLKBOX_LOG_FILE")) {
    config.logging.file = Deno.env.get("BLKBOX_LOG_FILE")!;
  }

  // Server overrides
  if (Deno.env.get("BLKBOX_MANAGEMENT_PORT")) {
    config.server.managementPort = parseInt(Deno.env.get("BLKBOX_MANAGEMENT_PORT")!);
  }
  if (Deno.env.get("BLKBOX_DASHBOARD_ENABLED")) {
    config.server.enableDashboard = Deno.env.get("BLKBOX_DASHBOARD_ENABLED") === "true";
  }
}

/**
 * Validate configuration for correctness and completeness
 */
function validateConfig(config: BlkBoxConfiguration): void {
  // Validate honeypots
  if (!config.honeypots || config.honeypots.length === 0) {
    throw new ConfigurationError("At least one honeypot must be configured");
  }

  for (const honeypot of config.honeypots) {
    if (!honeypot.type) {
      throw new ConfigurationError("Honeypot type is required");
    }
    if (!honeypot.port || honeypot.port < 1 || honeypot.port > 65535) {
      throw new ConfigurationError(`Invalid port for ${honeypot.type} honeypot: ${honeypot.port}`);
    }
    if (honeypot.enabled === undefined) {
      throw new ConfigurationError(`Enabled flag is required for ${honeypot.type} honeypot`);
    }
  }

  // Check for duplicate ports
  const ports = config.honeypots.filter(h => h.enabled).map(h => h.port);
  const uniquePorts = new Set(ports);
  if (ports.length !== uniquePorts.size) {
    throw new ConfigurationError("Duplicate ports detected in honeypot configuration");
  }

  // Validate storage
  if (!config.storage) {
    throw new ConfigurationError("Storage configuration is required");
  }
  if (!config.storage.database) {
    throw new ConfigurationError("Database path is required");
  }
  if (config.storage.retentionDays < 1) {
    throw new ConfigurationError("Retention days must be at least 1");
  }
  if (config.storage.backupInterval < 0) {
    throw new ConfigurationError("Backup interval must be non-negative");
  }

  // Validate stinger basic structure
  if (!config.stinger) {
    throw new ConfigurationError("Stinger configuration is required");
  }

  // Validate tracking
  if (!config.tracking) {
    throw new ConfigurationError("Tracking configuration is required");
  }
  if (config.tracking.sessionTimeout < 1) {
    throw new ConfigurationError("Session timeout must be at least 1 second");
  }

  // Validate logging
  if (!config.logging) {
    throw new ConfigurationError("Logging configuration is required");
  }
  if (!["debug", "info", "warn", "error"].includes(config.logging.level)) {
    throw new ConfigurationError(`Invalid log level: ${config.logging.level}`);
  }

  // Validate server
  if (!config.server) {
    throw new ConfigurationError("Server configuration is required");
  }
  if (config.server.managementPort < 1 || config.server.managementPort > 65535) {
    throw new ConfigurationError(`Invalid management port: ${config.server.managementPort}`);
  }

  // Check that management port doesn't conflict with honeypot ports
  if (ports.includes(config.server.managementPort)) {
    throw new ConfigurationError("Management port conflicts with honeypot port");
  }

  // Cloudflare validation removed - allow empty API keys
}

/**
 * Get default configuration
 */
export function getDefaultConfig(): BlkBoxConfiguration {
  return {
    honeypots: [
      {
        type: "http",
        port: 8080,
        enabled: true,
        options: {
          fakeApps: ["wordpress", "phpmyadmin"],
          serverHeader: "Apache/2.4.41 (Ubuntu)"
        }
      },
      {
        type: "ssh",
        port: 2222,
        enabled: true,
        options: {
          banner: "SSH-2.0-OpenSSH_9.0",
          allowedUsers: ["root", "admin", "user"]
        }
      },
      {
        type: "ftp",
        port: 21,
        enabled: false,
        options: {
          ftpBanner: "220 FTP Server Ready",
          virtualRoot: "/var/ftp"
        }
      }
    ],
    storage: {
      database: "./blkbox.db",
      retentionDays: 365,
      backupInterval: 86400,
      autoVacuum: true,
      maxDatabaseSize: 10000
    },
    stinger: {
      enabled: false,
      autoTrigger: false,
      threatThreshold: 7.5,
      allowedPayloads: ["system_info", "browser_recon"],
      requireApproval: true,
      dryRun: true,
      payloadExpiration: 24,
      maxActivePayloads: 100,
      c2Port: 8443
    },
    tracking: {
      geoip: true,
      fingerprinting: true,
      sessionCorrelation: true,
      sessionTimeout: 3600,
      trackUserAgents: true,
      trackHeaders: true,
      trackCookies: false,
      ipEnrichment: true
    },
    logging: {
      level: "info",
      console: true,
      includeTimestamp: true,
      includeLevel: true,
      colorize: true,
      maxFileSize: 100,
      maxFiles: 10
    },
    server: {
      managementPort: 9000,
      enableDashboard: true,
      corsEnabled: false,
      apiRateLimit: 100
    }
  };
}

/**
 * Save configuration to JSON file
 */
export async function saveConfig(config: BlkBoxConfiguration, path = "./config.json"): Promise<void> {
  validateConfig(config);
  const content = JSON.stringify(config, null, 2);
  await Deno.writeTextFile(path, content);
}

/**
 * Merge partial configuration with defaults
 */
export function mergeConfig(
  partial: Partial<BlkBoxConfiguration>,
  defaults = getDefaultConfig()
): BlkBoxConfiguration {
  return {
    honeypots: partial.honeypots ?? defaults.honeypots,
    cloudflare: partial.cloudflare ?? defaults.cloudflare,
    storage: { ...defaults.storage, ...partial.storage },
    stinger: { ...defaults.stinger, ...partial.stinger },
    tracking: { ...defaults.tracking, ...partial.tracking },
    logging: { ...defaults.logging, ...partial.logging },
    server: { ...defaults.server, ...partial.server }
  };
}
