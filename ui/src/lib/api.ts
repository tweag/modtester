// All API calls use relative URLs — Next.js rewrites proxy them to the backend

export interface Assessment {
  id: string;
  name: string;
  target: string;
  scope_type: "web" | "mobile_api" | "public_ip";
  scope: Record<string, unknown>;
  roe: Record<string, unknown>;
  status: "active" | "completed" | "paused";
  findings_count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  created_at: string;
  updated_at: string;
}

export interface ChatMessage {
  assessment_id: string;
  timestamp: string;
  message_id: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  metadata: Record<string, unknown>;
}

export interface Report {
  assessment_id: string;
  created_at: string;
  report_id: string;
  report_type: string;
  content: string;
  findings: Array<{
    severity: string;
    title: string;
    cvss: number;
    cwe?: string;
    owasp?: string;
    cve?: string;
    location?: string;
    description?: string;
    remediation?: string;
  }>;
}

// SSE event types from chat_api.py
export interface SSEStatusEvent {
  phase: string;
  message: string;
}

export interface SSETextEvent {
  content: string;
}

export interface SSEToolStartEvent {
  action: string;
}

export interface SSEToolResultEvent {
  action: string;
  result: string;
  truncated: boolean;
}

export interface SSEDoneEvent {
  tools_used: number;
}

export interface SSEErrorEvent {
  message: string;
}

// API helpers — use relative URLs so Next.js rewrites proxy to backend

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

export const api = {
  assessments: {
    list: (status?: string) =>
      apiFetch<Assessment[]>(`/api/assessments${status ? `?status=${status}` : ""}`),
    get: (id: string) => apiFetch<Assessment>(`/api/assessments/${id}`),
    create: (data: { name: string; target: string; scope_type?: string }) =>
      apiFetch<Assessment>("/api/assessments", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    update: (id: string, data: Partial<Assessment>) =>
      apiFetch<Assessment>(`/api/assessments/${id}`, {
        method: "PATCH",
        body: JSON.stringify(data),
      }),
    delete: (id: string) =>
      apiFetch<{ deleted: string }>(`/api/assessments/${id}`, { method: "DELETE" }),
  },
  chat: {
    list: (assessmentId: string) =>
      apiFetch<ChatMessage[]>(`/api/assessments/${assessmentId}/chat`),
    // AI chat returns SSE stream — use streamChat() instead
  },
  reports: {
    list: (assessmentId: string) =>
      apiFetch<Report[]>(`/api/assessments/${assessmentId}/reports`),
    latest: (assessmentId: string) =>
      apiFetch<Report>(`/api/assessments/${assessmentId}/reports/latest`),
  },
};

export type SSEEvent =
  | { type: "status"; data: SSEStatusEvent }
  | { type: "text"; data: SSETextEvent }
  | { type: "tool_start"; data: SSEToolStartEvent }
  | { type: "tool_result"; data: SSEToolResultEvent }
  | { type: "done"; data: SSEDoneEvent }
  | { type: "error"; data: SSEErrorEvent };

export async function* streamChat(
  assessmentId: string,
  message: string,
  signal?: AbortSignal,
): AsyncGenerator<SSEEvent> {
  const res = await fetch(`/api/assessments/${assessmentId}/ai/chat`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
    signal,
  });

  if (!res.ok || !res.body) {
    const errBody = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error(errBody.error || `HTTP ${res.status}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let currentEvent = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (line.startsWith("event: ")) {
        currentEvent = line.slice(7).trim();
      } else if (line.startsWith("data: ") && currentEvent) {
        try {
          const data = JSON.parse(line.slice(6));
          yield { type: currentEvent, data } as SSEEvent;
        } catch {
          // skip malformed JSON
        }
        currentEvent = "";
      }
    }
  }
}
