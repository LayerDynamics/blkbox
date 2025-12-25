import { TrackerClient } from "./client.ts";
import { Tracker } from "./tracker/track.ts";

/**
 * TrackasuarusServer
 *
 * Optional stats/monitoring API for Trackasuarus package.
 * Provides endpoints for querying tracking data.
 */
export class TrackasuarusServer {
  private tracker: Tracker;
  private port: number;

  constructor(client: TrackerClient, port = 8081) {
    this.tracker = new Tracker(client);
    this.port = port;
  }

  async start() {
    const handler = async (req: Request): Promise<Response> => {
      const url = new URL(req.url);

      // Top attackers
      if (url.pathname === "/api/top-attackers") {
        const limit = parseInt(url.searchParams.get("limit") || "10");
        try {
          const attackers = await this.tracker.getTopAttackers(limit);
          return Response.json(attackers);
        } catch (error) {
          return Response.json({ error: String(error) }, { status: 500 });
        }
      }

      // Attacker profile
      if (url.pathname.startsWith("/api/profile/")) {
        const ip = url.pathname.substring(13);
        try {
          const profile = await this.tracker.getAttackerProfile(ip);
          return Response.json(profile);
        } catch (error) {
          return Response.json({ error: String(error) }, { status: 500 });
        }
      }

      // Health check
      if (url.pathname === "/health") {
        return Response.json({
          status: "healthy",
          service: "trackasuarus",
          timestamp: new Date().toISOString(),
        });
      }

      return new Response("Not Found", { status: 404 });
    };

    console.log(`Trackasuarus server listening on http://localhost:${this.port}`);
    await Deno.serve({ port: this.port }, handler);
  }
}
