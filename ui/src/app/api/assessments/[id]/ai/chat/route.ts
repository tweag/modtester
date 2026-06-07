import { NextRequest } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 300;

const apiUrl = process.env.API_URL || "http://localhost:4001";

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const body = await req.text();
  const cookie = req.headers.get("cookie") || "";

  let upstream: Response;
  try {
    upstream = await fetch(`${apiUrl}/api/assessments/${id}/ai/chat`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: cookie,
      },
      body,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[chat/route] upstream fetch failed: ${msg}`);
    return new Response(
      JSON.stringify({ error: `upstream unreachable: ${msg}` }),
      { status: 502, headers: { "Content-Type": "application/json" } }
    );
  }

  if (!upstream.ok || !upstream.body) {
    const text = await upstream.text().catch(() => "");
    console.error(`[chat/route] upstream error ${upstream.status}: ${text.slice(0, 200)}`);
    return new Response(
      JSON.stringify({ error: `upstream ${upstream.status}: ${text.slice(0, 200)}` }),
      { status: upstream.status, headers: { "Content-Type": "application/json" } }
    );
  }

  // Stream directly from upstream — no TransformStream wrapper
  return new Response(upstream.body, {
    status: 200,
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "X-Accel-Buffering": "no",
    },
  });
}
