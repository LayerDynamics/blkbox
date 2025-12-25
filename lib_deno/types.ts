// TypeScript type definitions for BlkBox FFI

/**
 * Service types supported by BlkBox honeypot
 */
export enum ServiceType {
  HTTP = 0,
  HTTPS = 1,
  SSH = 2,
  PostgreSQL = 3,
  MySQL = 4,
  MongoDB = 5,
  FTP = 6,
  SFTP = 7,
}

/**
 * Payload types for strikeback operations
 */
export enum PayloadType {
  ReverseTCP = 0,
  CommandInjection = 1,
  FileExfiltration = 2,
  LogWiper = 3,
  NetworkScanner = 4,
  BrowserRecon = 5,
  SystemInfo = 6,
  Beacon = 7,
}

/**
 * Attack event captured by honeypot
 */
export interface AttackEvent {
  timestamp: string;
  source_ip: string;
  source_port: number;
  service_type: ServiceType;
  service_id: number;
  user_agent?: string;
  payload: string;
  threat_level: number;
  fingerprint?: string;
}

/**
 * Service configuration
 */
export interface ServiceConfig {
  enabled: boolean;
  custom_responses?: Record<string, string>;
  banner_grabbing?: boolean;
}

/**
 * Cloudflare configuration
 */
export interface CloudflareConfig {
  enabled: boolean;
  apiKey: string;
  zoneId: string;
  updateFirewall?: boolean;
}

/**
 * Honeypot configuration
 */
export interface HoneypotConfig {
  type: keyof typeof ServiceType;
  port: number;
  enabled: boolean;
  config?: ServiceConfig;
}

/**
 * Main BlkBox configuration
 */
export interface BlkBoxConfig {
  honeypots: HoneypotConfig[];
  cloudflare?: CloudflareConfig;
  storage?: {
    database: string;
    retentionDays?: number;
    backupInterval?: number;
  };
  stinger?: {
    enabled: boolean;
    autoTrigger: boolean;
    threatThreshold: number;
    allowedPayloads?: string[];
    requireApproval?: boolean;
    dryRun?: boolean;
  };
}

/**
 * Service status information
 */
export interface ServiceStatus {
  service_id: number;
  service_type: ServiceType;
  port: number;
  active: boolean;
  connections?: number;
  attacks?: number;
}

/**
 * FFI function result codes
 */
export enum FFIResult {
  Success = 0,
  Error = -1,
}

/**
 * Error thrown by FFI operations
 */
export class FFIError extends Error {
  constructor(message: string, public code: number = -1) {
    super(message);
    this.name = "FFIError";
  }
}
