/**
 * Management Server - Dashboard and API
 *
 * Provides:
 * - RESTful API for attack data and analytics
 * - Server-Sent Events (SSE) for real-time attack streaming
 * - Dashboard UI (HTML/CSS/JS)
 * - Export functionality (JSON, CSV)
 * - Honeypot control endpoints
 */

import type { AttackEvent } from "../../lib_deno/types.ts";
import type { EventPipeline } from "./event-pipeline.ts";

/**
 * SSE Client tracking
 */
interface SSEClient {
  id: string;
  controller: ReadableStreamDefaultController;
  lastEventId: number;
  connectedAt: Date;
  filters?: {
    serviceType?: string;
    minThreatLevel?: number;
  };
}

/**
 * Management Server Configuration
 */
export interface ManagementServerConfig {
  port: number;
  host?: string;
  enableCors?: boolean;
  maxConnections?: number;
  eventBufferSize?: number;
}

/**
 * Management Server - Handles dashboard and API requests
 */
export class ManagementServer {
  private port: number;
  private host: string;
  private enableCors: boolean;
  private maxConnections: number;
  private eventBufferSize: number;

  private sseClients: Map<string, SSEClient> = new Map();
  private eventBuffer: AttackEvent[] = [];
  private eventCounter = 0;
  private server?: Deno.HttpServer;
  private startTime: number;

  private eventPipeline?: EventPipeline;
  private ffiHandle?: any; // FFI handle for database queries

  constructor(config: ManagementServerConfig) {
    this.port = config.port;
    this.host = config.host || "0.0.0.0";
    this.enableCors = config.enableCors ?? true;
    this.maxConnections = config.maxConnections || 100;
    this.eventBufferSize = config.eventBufferSize || 1000;
    this.startTime = Date.now();

    console.log(`[ManagementServer] Configured on ${this.host}:${this.port}`);
  }

  /**
   * Set the event pipeline for processing events
   */
  setEventPipeline(pipeline: EventPipeline): void {
    this.eventPipeline = pipeline;
  }

  /**
   * Set FFI handle for database operations
   */
  setFFIHandle(handle: any): void {
    this.ffiHandle = handle;
  }

  /**
   * Start the management server
   */
  async start(): Promise<void> {
    console.log(`[ManagementServer] Starting on ${this.host}:${this.port}`);

    this.server = Deno.serve({
      port: this.port,
      hostname: this.host,
      onListen: ({ hostname, port }) => {
        console.log(`[ManagementServer] 🌐 Listening on http://${hostname}:${port}`);
        console.log(`[ManagementServer] 📊 Dashboard: http://${hostname}:${port}/`);
        console.log(`[ManagementServer] 🔌 SSE Stream: http://${hostname}:${port}/api/events/stream`);
      },
    }, (req) => this.handleRequest(req));
  }

  /**
   * Stop the management server
   */
  async stop(): Promise<void> {
    console.log("[ManagementServer] Stopping server...");

    // Close all SSE connections
    for (const client of this.sseClients.values()) {
      try {
        client.controller.close();
      } catch (_e) {
        // Ignore errors on close
      }
    }
    this.sseClients.clear();

    // Shutdown server
    if (this.server) {
      await this.server.shutdown();
      this.server = undefined;
    }

    console.log("[ManagementServer] Server stopped");
  }

  /**
   * Broadcast an attack event to all SSE clients
   */
  broadcastEvent(event: AttackEvent): void {
    // Add to buffer
    this.eventBuffer.push(event);
    if (this.eventBuffer.length > this.eventBufferSize) {
      this.eventBuffer.shift(); // Remove oldest
    }

    this.eventCounter++;

    // Send to all connected SSE clients
    for (const [clientId, client] of this.sseClients.entries()) {
      try {
        // Apply filters
        if (client.filters) {
          if (client.filters.serviceType && event.service_type !== client.filters.serviceType) {
            continue;
          }
          if (client.filters.minThreatLevel !== undefined && event.threat_level < client.filters.minThreatLevel) {
            continue;
          }
        }

        // Send SSE message
        const data = JSON.stringify(event);
        client.controller.enqueue(
          new TextEncoder().encode(`id: ${this.eventCounter}\ndata: ${data}\n\n`)
        );
      } catch (error) {
        console.error(`[ManagementServer] Failed to send to client ${clientId}:`, error);
        this.sseClients.delete(clientId);
      }
    }
  }

  /**
   * Handle incoming HTTP requests
   */
  private async handleRequest(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;

    // CORS handling
    if (this.enableCors && req.method === "OPTIONS") {
      return this.corsResponse();
    }

    // Route to handlers
    try {
      // Dashboard UI
      if (path === "/" || path === "/index.html") {
        return this.serveDashboard();
      }

      // API endpoints
      if (path.startsWith("/api/")) {
        return await this.handleAPI(req, path);
      }

      // Static assets
      if (path.startsWith("/assets/")) {
        return this.serveAsset(path);
      }

      // 404
      return this.jsonResponse({ error: "Not Found" }, 404);

    } catch (error) {
      console.error("[ManagementServer] Request error:", error);
      return this.jsonResponse({ error: "Internal Server Error", message: String(error) }, 500);
    }
  }

  /**
   * Handle API requests
   */
  private async handleAPI(req: Request, path: string): Promise<Response> {
    const url = new URL(req.url);

    // Health check
    if (path === "/api/health") {
      return this.jsonResponse({
        status: "ok",
        timestamp: new Date().toISOString(),
        sseClients: this.sseClients.size,
        eventBuffer: this.eventBuffer.length
      });
    }

    // Server status
    if (path === "/api/status") {
      return this.jsonResponse({
        server: "blkbox",
        version: "0.1.0",
        uptime: Math.floor((Date.now() - this.startTime) / 1000),
        sseClients: this.sseClients.size,
        eventsPending: this.eventBuffer.length,
        processors: this.eventPipeline?.getProcessors() || []
      });
    }

    // SSE event stream
    if (path === "/api/events/stream") {
      return this.handleSSE(req);
    }

    // Recent attacks
    if (path === "/api/attacks") {
      const limit = parseInt(url.searchParams.get("limit") || "100");
      const offset = parseInt(url.searchParams.get("offset") || "0");

      // For now, return from buffer (in production, query database via FFI)
      const attacks = this.eventBuffer.slice(offset, offset + limit);

      return this.jsonResponse({
        total: this.eventBuffer.length,
        limit,
        offset,
        attacks
      });
    }

    // Analytics - Summary
    if (path === "/api/analytics/summary") {
      const summary = this.calculateSummary();
      return this.jsonResponse(summary);
    }

    // Analytics - Timeline
    if (path === "/api/analytics/timeline") {
      const hours = parseInt(url.searchParams.get("hours") || "24");
      const timeline = this.calculateTimeline(hours);
      return this.jsonResponse(timeline);
    }

    // Analytics - Geography
    if (path === "/api/analytics/geography") {
      const geography = this.calculateGeography();
      return this.jsonResponse(geography);
    }

    // Analytics - Service breakdown
    if (path === "/api/analytics/services") {
      const services = this.calculateServiceBreakdown();
      return this.jsonResponse(services);
    }

    // Analytics - Threat distribution
    if (path === "/api/analytics/threats") {
      const threats = this.calculateThreatDistribution();
      return this.jsonResponse(threats);
    }

    // Export - JSON
    if (path === "/api/export/json") {
      const limit = parseInt(url.searchParams.get("limit") || "1000");
      const attacks = this.eventBuffer.slice(0, limit);

      return new Response(JSON.stringify(attacks, null, 2), {
        headers: {
          "Content-Type": "application/json",
          "Content-Disposition": `attachment; filename="blkbox-export-${Date.now()}.json"`,
          ...this.corsHeaders()
        }
      });
    }

    // Export - CSV
    if (path === "/api/export/csv") {
      const limit = parseInt(url.searchParams.get("limit") || "1000");
      const attacks = this.eventBuffer.slice(0, limit);
      const csv = this.convertToCSV(attacks);

      return new Response(csv, {
        headers: {
          "Content-Type": "text/csv",
          "Content-Disposition": `attachment; filename="blkbox-export-${Date.now()}.csv"`,
          ...this.corsHeaders()
        }
      });
    }

    // Honeypot control - List
    if (path === "/api/honeypots" && req.method === "GET") {
      // In production, query FFI for honeypot status
      return this.jsonResponse({
        honeypots: [
          { id: 1, type: "HTTP", port: 80, status: "running", attacks: 42 },
          { id: 2, type: "SSH", port: 22, status: "running", attacks: 128 },
          { id: 3, type: "FTP", port: 21, status: "running", attacks: 31 }
        ]
      });
    }

    // Honeypot control - Start/Stop/Restart
    if (path.startsWith("/api/honeypots/") && req.method === "POST") {
      const action = path.split("/").pop();

      if (action === "start" || action === "stop" || action === "restart") {
        const body = await req.json();
        const honeypotId = body.honeypot_id;

        // In production, call FFI to control honeypot
        console.log(`[ManagementServer] ${action} honeypot ${honeypotId}`);

        return this.jsonResponse({
          success: true,
          action,
          honeypot_id: honeypotId,
          message: `Honeypot ${action}ed successfully`
        });
      }
    }

    return this.jsonResponse({ error: "Not Found" }, 404);
  }

  /**
   * Handle SSE connections
   */
  private handleSSE(req: Request): Response {
    const url = new URL(req.url);
    const clientId = crypto.randomUUID();

    // Check connection limit
    if (this.sseClients.size >= this.maxConnections) {
      return this.jsonResponse({ error: "Too many connections" }, 503);
    }

    // Parse filters from query params
    const filters: SSEClient["filters"] = {};
    if (url.searchParams.has("serviceType")) {
      filters.serviceType = url.searchParams.get("serviceType")!;
    }
    if (url.searchParams.has("minThreatLevel")) {
      filters.minThreatLevel = parseInt(url.searchParams.get("minThreatLevel")!);
    }

    // Create SSE stream
    const stream = new ReadableStream({
      start: (controller) => {
        const client: SSEClient = {
          id: clientId,
          controller,
          lastEventId: this.eventCounter,
          connectedAt: new Date(),
          filters: Object.keys(filters).length > 0 ? filters : undefined
        };

        this.sseClients.set(clientId, client);
        console.log(`[ManagementServer] SSE client connected: ${clientId} (total: ${this.sseClients.size})`);

        // Send initial connection event
        controller.enqueue(
          new TextEncoder().encode(
            `data: ${JSON.stringify({ type: "connected", clientId, timestamp: new Date().toISOString() })}\n\n`
          )
        );

        // Send recent events from buffer
        const recentEvents = this.eventBuffer.slice(-10);
        for (const event of recentEvents) {
          try {
            const data = JSON.stringify(event);
            controller.enqueue(
              new TextEncoder().encode(`data: ${data}\n\n`)
            );
          } catch (_e) {
            // Ignore
          }
        }
      },
      cancel: () => {
        this.sseClients.delete(clientId);
        console.log(`[ManagementServer] SSE client disconnected: ${clientId} (total: ${this.sseClients.size})`);
      }
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        ...this.corsHeaders()
      }
    });
  }

  /**
   * Serve dashboard HTML
   */
  private serveDashboard(): Response {
    const html = this.getDashboardHTML();
    return new Response(html, {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        ...this.corsHeaders()
      }
    });
  }

  /**
   * Serve static assets
   */
  private serveAsset(path: string): Response {
    // Assets will be served from memory or filesystem
    // For now, return 404
    return this.jsonResponse({ error: "Asset not found" }, 404);
  }

  /**
   * Calculate summary statistics
   */
  private calculateSummary() {
    const total = this.eventBuffer.length;
    const last24h = this.eventBuffer.filter(e =>
      new Date(e.timestamp) > new Date(Date.now() - 24 * 60 * 60 * 1000)
    ).length;

    const uniqueIPs = new Set(this.eventBuffer.map(e => e.source_ip)).size;

    const avgThreat = total > 0
      ? this.eventBuffer.reduce((sum, e) => sum + e.threat_level, 0) / total
      : 0;

    const highThreat = this.eventBuffer.filter(e => e.threat_level >= 8).length;

    return {
      total_attacks: total,
      attacks_24h: last24h,
      unique_ips: uniqueIPs,
      avg_threat_level: Math.round(avgThreat * 10) / 10,
      high_threat_count: highThreat,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Calculate timeline data
   */
  private calculateTimeline(hours: number) {
    const buckets: Map<string, number> = new Map();
    const cutoff = Date.now() - hours * 60 * 60 * 1000;

    for (const event of this.eventBuffer) {
      const timestamp = new Date(event.timestamp).getTime();
      if (timestamp < cutoff) continue;

      // Round to nearest hour
      const hour = new Date(Math.floor(timestamp / 3600000) * 3600000).toISOString();
      buckets.set(hour, (buckets.get(hour) || 0) + 1);
    }

    return Array.from(buckets.entries())
      .map(([time, count]) => ({ time, count }))
      .sort((a, b) => a.time.localeCompare(b.time));
  }

  /**
   * Calculate geography data
   */
  private calculateGeography() {
    const countries: Map<string, number> = new Map();

    for (const event of this.eventBuffer) {
      // In production, would extract from geolocation field
      // For now, mock based on IP
      const country = this.mockCountryFromIP(event.source_ip);
      countries.set(country, (countries.get(country) || 0) + 1);
    }

    return Array.from(countries.entries())
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count);
  }

  /**
   * Calculate service breakdown
   */
  private calculateServiceBreakdown() {
    const services: Map<string, number> = new Map();

    for (const event of this.eventBuffer) {
      const service = event.service_type || "unknown";
      services.set(service, (services.get(service) || 0) + 1);
    }

    return Array.from(services.entries())
      .map(([service, count]) => ({ service, count }))
      .sort((a, b) => b.count - a.count);
  }

  /**
   * Calculate threat distribution
   */
  private calculateThreatDistribution() {
    const distribution = new Array(11).fill(0); // 0-10

    for (const event of this.eventBuffer) {
      const level = Math.min(10, Math.max(0, event.threat_level));
      distribution[level]++;
    }

    return distribution.map((count, level) => ({ level, count }));
  }

  /**
   * Convert attacks to CSV
   */
  private convertToCSV(attacks: AttackEvent[]): string {
    const headers = "timestamp,source_ip,source_port,service_type,threat_level,user_agent,payload\n";

    const rows = attacks.map(a =>
      `"${a.timestamp}","${a.source_ip}",${a.source_port},"${a.service_type}",${a.threat_level},"${a.user_agent || ""}","${(a.payload || "").replace(/"/g, '""')}"`
    );

    return headers + rows.join("\n");
  }

  /**
   * Mock country from IP (for demo)
   */
  private mockCountryFromIP(ip: string): string {
    const hash = ip.split(".").reduce((sum, octet) => sum + parseInt(octet), 0);
    const countries = ["US", "CN", "RU", "DE", "GB", "FR", "IN", "BR", "KR", "JP"];
    return countries[hash % countries.length];
  }

  /**
   * Get dashboard HTML
   */
  private getDashboardHTML(): string {
    // Dashboard HTML will be defined in a separate method
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BlkBox - Honeypot Dashboard</title>
    <style>
        /* Dashboard CSS will be added here */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f0f23; color: #e0e0e0; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: #1a1a2e; padding: 20px; margin-bottom: 30px; border-radius: 8px; }
        h1 { color: #00ff41; font-size: 2em; }
        .subtitle { color: #888; margin-top: 5px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #1a1a2e; padding: 20px; border-radius: 8px; border-left: 4px solid #00ff41; }
        .stat-value { font-size: 2.5em; color: #00ff41; font-weight: bold; }
        .stat-label { color: #888; margin-top: 10px; text-transform: uppercase; font-size: 0.9em; }
        .chart-container { background: #1a1a2e; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .events-feed { background: #1a1a2e; padding: 20px; border-radius: 8px; max-height: 500px; overflow-y: auto; }
        .event-item { padding: 10px; border-left: 3px solid #00ff41; margin-bottom: 10px; background: #252538; }
        .threat-high { border-left-color: #ff4444 !important; }
        .threat-medium { border-left-color: #ffaa00 !important; }
        .threat-low { border-left-color: #00ff41 !important; }
        #status { color: #00ff41; }
        #status.disconnected { color: #ff4444; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ BlkBox Honeypot Dashboard</h1>
            <div class="subtitle">Real-time attack monitoring & intelligence</div>
            <div class="subtitle">Status: <span id="status">Connecting...</span></div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="stat-total">0</div>
                <div class="stat-label">Total Attacks</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="stat-24h">0</div>
                <div class="stat-label">Last 24 Hours</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="stat-ips">0</div>
                <div class="stat-label">Unique IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="stat-threat">0.0</div>
                <div class="stat-label">Avg Threat Level</div>
            </div>
        </div>

        <div class="chart-container">
            <h2>📊 Attack Timeline (24h)</h2>
            <canvas id="timeline-chart"></canvas>
        </div>

        <div class="events-feed">
            <h2>🔴 Live Attack Feed</h2>
            <div id="events-list"></div>
        </div>
    </div>

    <script>
        // Dashboard JavaScript
        const statusEl = document.getElementById('status');
        const eventsListEl = document.getElementById('events-list');
        let eventSource;

        // Connect to SSE stream
        function connectSSE() {
            statusEl.textContent = 'Connecting...';
            statusEl.className = '';

            eventSource = new EventSource('/api/events/stream');

            eventSource.onopen = () => {
                statusEl.textContent = 'Connected';
                statusEl.className = '';
                console.log('SSE connected');
            };

            eventSource.onmessage = (e) => {
                try {
                    const event = JSON.parse(e.data);
                    if (event.type !== 'connected') {
                        addEventToFeed(event);
                    }
                } catch (err) {
                    console.error('Failed to parse event:', err);
                }
            };

            eventSource.onerror = () => {
                statusEl.textContent = 'Disconnected';
                statusEl.className = 'disconnected';
                eventSource.close();
                setTimeout(connectSSE, 5000);
            };
        }

        // Add event to feed
        function addEventToFeed(event) {
            const item = document.createElement('div');
            item.className = 'event-item';

            if (event.threat_level >= 8) item.classList.add('threat-high');
            else if (event.threat_level >= 5) item.classList.add('threat-medium');
            else item.classList.add('threat-low');

            const time = new Date(event.timestamp).toLocaleTimeString();
            item.innerHTML = \`
                <strong>[\${time}]</strong>
                \${event.source_ip} → \${event.service_type || 'unknown'}
                (Threat: \${event.threat_level}/10)
                <br><small>\${event.payload?.substring(0, 100) || 'No payload'}</small>
            \`;

            eventsListEl.insertBefore(item, eventsListEl.firstChild);

            // Keep only last 50 events
            while (eventsListEl.children.length > 50) {
                eventsListEl.removeChild(eventsListEl.lastChild);
            }

            updateStats();
        }

        // Update statistics
        async function updateStats() {
            try {
                const res = await fetch('/api/analytics/summary');
                const data = await res.json();

                document.getElementById('stat-total').textContent = data.total_attacks;
                document.getElementById('stat-24h').textContent = data.attacks_24h;
                document.getElementById('stat-ips').textContent = data.unique_ips;
                document.getElementById('stat-threat').textContent = data.avg_threat_level.toFixed(1);
            } catch (err) {
                console.error('Failed to update stats:', err);
            }
        }

        // Initialize
        connectSSE();
        updateStats();
        setInterval(updateStats, 10000); // Update stats every 10s
    </script>
</body>
</html>`;
  }

  /**
   * JSON response helper
   */
  private jsonResponse(data: any, status = 200): Response {
    return new Response(JSON.stringify(data), {
      status,
      headers: {
        "Content-Type": "application/json",
        ...this.corsHeaders()
      }
    });
  }

  /**
   * CORS headers
   */
  private corsHeaders(): HeadersInit {
    if (!this.enableCors) return {};

    return {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };
  }

  /**
   * CORS preflight response
   */
  private corsResponse(): Response {
    return new Response(null, {
      status: 204,
      headers: this.corsHeaders()
    });
  }
}
