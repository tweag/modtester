import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const apiUrl = process.env.API_URL || "http://localhost:4001";

interface HealthCheck {
  status: "ok" | "error";
  timestamp: string;
  ui: {
    api_url: string;
    node_env: string;
  };
  backend?: {
    reachable: boolean;
    status?: string;
    tools_available?: number;
    error?: string;
    latency_ms?: number;
  };
}

export async function GET(req: NextRequest): Promise<NextResponse<HealthCheck>> {
  const result: HealthCheck = {
    status: "ok",
    timestamp: new Date().toISOString(),
    ui: {
      api_url: apiUrl,
      node_env: process.env.NODE_ENV || "unknown",
    },
  };

  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    
    const res = await fetch(`${apiUrl}/health`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);
    
    const latency = Date.now() - start;
    
    if (res.ok) {
      const data = await res.json();
      result.backend = {
        reachable: true,
        status: data.status,
        tools_available: data.tools_available,
        latency_ms: latency,
      };
    } else {
      result.status = "error";
      result.backend = {
        reachable: false,
        error: `HTTP ${res.status}: ${res.statusText}`,
        latency_ms: latency,
      };
    }
  } catch (err) {
    result.status = "error";
    result.backend = {
      reachable: false,
      error: err instanceof Error ? err.message : String(err),
      latency_ms: Date.now() - start,
    };
  }

  return NextResponse.json(result, {
    status: result.status === "ok" ? 200 : 503,
  });
}