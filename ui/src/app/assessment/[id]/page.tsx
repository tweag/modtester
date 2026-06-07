"use client";
import { useEffect, useState, useRef, useCallback } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  Send,
  Loader2,
  Terminal,
  ChevronDown,
  ChevronRight,
  Download,
  FileText,
  Square,
} from "lucide-react";
import { api, streamChat, Assessment, ChatMessage, SSEEvent } from "@/lib/api";
import { StatusBadge, SeverityBadge } from "@/components/Badges";

interface DisplayMessage {
  id: string;
  role: "user" | "assistant" | "system" | "status" | "tool";
  content: string;
  toolAction?: string;
  toolResult?: string;
  toolCollapsed?: boolean;
}

export default function AssessmentPage() {
  const { id } = useParams<{ id: string }>();
  const [assessment, setAssessment] = useState<Assessment | null>(null);
  const [messages, setMessages] = useState<DisplayMessage[]>([]);
  const [input, setInput] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [activeTab, setActiveTab] = useState<"chat" | "report">("chat");
  const chatEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  // Id of the assistant bubble currently being streamed into. Reset to null on
  // each tool step so the next narration starts a fresh bubble below the tool —
  // giving an interleaved narration / action / narration flow like Claude.
  const currentAssistantIdRef = useRef<string | null>(null);

  // Load assessment + chat history
  useEffect(() => {
    if (!id) return;
    api.assessments.get(id).then(setAssessment).catch(console.error);
    api.chat
      .list(id)
      .then((msgs: ChatMessage[]) => {
        const expanded: DisplayMessage[] = [];
        for (const m of msgs) {
          // Prefer the ordered timeline (narration + tool steps in sequence) so
          // the interleaved flow is replayed exactly as it happened live.
          const timeline = m.metadata?.timeline as
            | { type: string; content?: string; action?: string }[]
            | undefined;
          if (Array.isArray(timeline) && timeline.length > 0) {
            let ti = 0;
            for (const entry of timeline) {
              if (entry.type === "tool") {
                expanded.push({
                  id: `${m.message_id}-tl-${ti++}`,
                  role: "tool",
                  content: "",
                  toolAction: entry.action || "",
                  toolResult: "completed",
                  toolCollapsed: true,
                });
              } else if (entry.type === "text" && (entry.content || "").trim()) {
                expanded.push({
                  id: `${m.message_id}-tl-${ti++}`,
                  role: m.role as DisplayMessage["role"],
                  content: (entry.content || "").trim(),
                });
              }
            }
            continue;
          }

          // Legacy fallback: reconstruct tool steps from the flat list FIRST so
          // they survive refresh even when the assistant message is blank.
          const toolActions = (m.metadata?.tool_actions as string[]) || [];
          for (let i = 0; i < toolActions.length; i++) {
            expanded.push({
              id: `${m.message_id}-tool-${i}`,
              role: "tool",
              content: "",
              toolAction: toolActions[i],
              toolResult: "completed",
              toolCollapsed: true,
            });
          }
          const content = (m.content || "").trim();
          if (content && content !== " ") {
            expanded.push({
              id: m.message_id,
              role: m.role as DisplayMessage["role"],
              content,
            });
          }
        }
        setMessages(expanded);
      })
      .catch(console.error);
  }, [id]);

  // Auto-scroll
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Auto-resize textarea
  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${el.scrollHeight}px`;
  }, [input]);

  const sendMessage = useCallback(async () => {
    const msg = input.trim();
    if (!msg || streaming || !id) return;

    setInput("");
    setStreaming(true);

    const controller = new AbortController();
    abortRef.current = controller;

    // Add user message (and remove any previous error-only assistant messages)
    const userMsg: DisplayMessage = {
      id: `user-${Date.now()}`,
      role: "user",
      content: msg,
    };
    const initStatusId = `status-init-${Date.now()}`;
    setMessages((prev) => [
      ...prev.filter((m) => !(m.role === "assistant" && m.content.startsWith("Error:"))),
      userMsg,
      { id: initStatusId, role: "status", content: "Connecting..." },
    ]);

    // Assistant narration is rendered in one or more bubbles, created lazily as
    // text streams in and split around tool steps (see currentAssistantIdRef).
    const assistantId = `assistant-${Date.now()}`;
    currentAssistantIdRef.current = null;
    let firstEvent = true;

    try {
      for await (const event of streamChat(id, msg, controller.signal)) {
        if (firstEvent) {
          // Drop the local "Connecting..." placeholder once real events arrive
          setMessages((prev) => prev.filter((m) => m.id !== initStatusId));
          firstEvent = false;
        }
        handleSSE(event, assistantId);
      }
    } catch (err) {
      if (controller.signal.aborted) {
        setMessages((prev) => {
          const hasMsg = prev.some((m) => m.id === assistantId);
          const stopText = "Stopped. You can ask me to continue or try a different approach.";
          if (hasMsg) {
            return prev.map((m) =>
              m.id === assistantId && !m.content ? { ...m, content: stopText } : m
            );
          }
          return [...prev, { id: assistantId, role: "assistant", content: stopText }];
        });
      } else {
        const errMsg = err instanceof Error ? err.message : String(err);
        setMessages((prev) => {
          const hasMsg = prev.some((m) => m.id === assistantId);
          if (hasMsg) {
            return prev.map((m) =>
              m.id === assistantId ? { ...m, content: m.content || `Error: ${errMsg}` } : m
            );
          }
          return [...prev, { id: assistantId, role: "assistant", content: `Error: ${errMsg}` }];
        });
      }
    } finally {
      abortRef.current = null;
      setStreaming(false);
      // Refresh assessment and show report hint if AI used tools but sent no text
      const updated = await api.assessments.get(id).catch(() => null);
      if (updated) {
        setAssessment(updated);
        if (updated.status === "completed") {
          setMessages((prev) => {
            const hasAssistantText = prev.some(
              (m) => m.role === "assistant" && m.content?.trim()
            );
            if (!hasAssistantText) {
              return [
                ...prev,
                {
                  id: `assistant-complete-${Date.now()}`,
                  role: "assistant",
                  content: `Assessment complete — ${updated.findings_count} finding${updated.findings_count !== 1 ? "s" : ""} recorded. Switch to the **Report** tab for the full report.`,
                },
              ];
            }
            return prev;
          });
        }
      }
    }
  }, [input, streaming, id]);

  const handleSSE = (event: SSEEvent, assistantId: string) => {
    switch (event.type) {
      case "text": {
        // Strip only the phase-tag tokens — never the text that follows them.
        const text = event.data.content.replace(/\[(?:RECON|SCAN|VULN|EXPLOIT|ANALYZE|REPORT|ENUM|POST)\]\s*/g, "");
        if (text) {
          setMessages((prev) => {
            let curId = currentAssistantIdRef.current;
            if (!curId || !prev.some((m) => m.id === curId)) {
              // Start a new narration bubble at the bottom of the thread.
              curId = `assistant-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
              currentAssistantIdRef.current = curId;
              return [...prev, { id: curId, role: "assistant", content: text }];
            }
            const cid = curId;
            return prev.map((m) =>
              m.id === cid ? { ...m, content: m.content + text } : m
            );
          });
        }
        break;
      }
      case "status": {
        const phase = event.data.phase;
        const msg = event.data.message;
        setMessages((prev) => [
          ...prev,
          {
            id: `status-${Date.now()}-${Math.random()}`,
            role: "status",
            content: msg,
          },
        ]);
        break;
      }
      case "tool_start":
        // A new action begins — close the current narration bubble so the next
        // text starts fresh below this tool step.
        currentAssistantIdRef.current = null;
        setMessages((prev) => [
          ...prev,
          {
            id: `tool-${Date.now()}`,
            role: "tool",
            content: "",
            toolAction: event.data.action,
            toolCollapsed: true,
          },
        ]);
        break;
      case "tool_result": {
        // Update the most recent tool message with results
        setMessages((prev) => {
          const idx = [...prev]
            .reverse()
            .findIndex((m) => m.role === "tool" && !m.toolResult);
          if (idx === -1) return prev;
          const realIdx = prev.length - 1 - idx;
          const updated = [...prev];
          updated[realIdx] = {
            ...updated[realIdx],
            toolResult: event.data.result,
          };
          return updated;
        });
        break;
      }
      case "done": {
        // Drop any empty/placeholder assistant bubble so we don't show a blank message
        setMessages((prev) =>
          prev.filter((m) => !(m.role === "assistant" && !m.content?.trim()))
        );
        break;
      }
      case "error":
        // Show throttling/rate limit errors as a gentle status, not in the chat bubble
        if (event.data.message?.includes("ThrottlingException") || event.data.message?.includes("Too many")) {
          setMessages((prev) => [
            ...prev,
            {
              id: `status-${Date.now()}-${Math.random()}`,
              role: "status",
              content: "Rate limited — retrying in a moment...",
            },
          ]);
        } else {
          const errText = `Error: ${event.data.message || "Unknown error — check server logs."}`;
          setMessages((prev) => {
            const hasMsg = prev.some((m) => m.id === assistantId);
            if (hasMsg) {
              return prev.map((m) =>
                m.id === assistantId ? { ...m, content: m.content || errText } : m
              );
            }
            return [...prev, { id: assistantId, role: "assistant", content: errText }];
          });
        }
        break;
    }
  };

  if (!assessment) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full" />
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <header className="border-b border-border bg-surface px-4 py-2.5 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <Link href="/" className="text-muted hover:text-foreground shrink-0">
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="font-medium text-sm truncate">{assessment.name}</h1>
              <StatusBadge status={assessment.status} />
            </div>
            <p className="text-xs text-muted font-mono truncate">{assessment.target}</p>
          </div>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {assessment.findings_count > 0 && (
            <div className="flex gap-1 text-xs">
              {assessment.critical > 0 && <SeverityBadge severity="C" count={assessment.critical} />}
              {assessment.high > 0 && <SeverityBadge severity="H" count={assessment.high} />}
              {assessment.medium > 0 && <SeverityBadge severity="M" count={assessment.medium} />}
            </div>
          )}
          <div className="flex border border-border rounded-md overflow-hidden text-xs">
            <button
              onClick={() => setActiveTab("chat")}
              className={`px-3 py-1.5 font-medium transition-colors ${
                activeTab === "chat"
                  ? "bg-primary text-white"
                  : "text-muted hover:text-foreground hover:bg-background"
              }`}
            >
              Chat
            </button>
            <button
              onClick={() => setActiveTab("report")}
              className={`px-3 py-1.5 font-medium transition-colors ${
                activeTab === "report"
                  ? "bg-primary text-white"
                  : "text-muted hover:text-foreground hover:bg-background"
              }`}
            >
              Report
            </button>
          </div>
        </div>
      </header>

      {activeTab === "chat" ? (
        <>
          {/* Chat messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {messages.length === 0 && (
              <div className="text-center py-16 text-muted">
                <Terminal className="w-10 h-10 mx-auto mb-3 opacity-50" />
                <p className="font-medium">Ready to test</p>
                <p className="text-sm mt-1">
                  Try: &quot;Scan {assessment.target} for vulnerabilities&quot;
                </p>
              </div>
            )}
            {messages.map((msg, i) => (
              <MessageBubble key={msg.id} message={msg} isLast={i === messages.length - 1} streaming={streaming} />
            ))}
            <div ref={chatEndRef} />
          </div>

          {/* Input */}
          <div className="border-t border-border bg-surface px-4 py-3 shrink-0">
            <div className="flex items-end gap-2 max-w-4xl mx-auto">
              <textarea
                ref={inputRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                  }
                }}
                placeholder="Ask ModTester to scan, test, or analyze..."
                rows={1}
                style={{ maxHeight: "200px", overflowY: "auto" }}
                className="flex-1 px-4 py-3 border border-border rounded-lg bg-background text-foreground text-[15px] resize-none focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary"
              />
              <button
                onClick={sendMessage}
                disabled={streaming || !input.trim()}
                className="p-2.5 bg-primary text-white rounded-lg hover:bg-primary-dark disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                {streaming ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
                )}
              </button>
              {streaming && (
                <button
                  onClick={() => {
                    // Cancel backend session first, then abort the SSE stream
                    fetch(`/api/assessments/${id}/ai/cancel`, {
                      method: "POST",
                      credentials: "include",
                    }).catch(() => {});
                    abortRef.current?.abort();
                  }}
                  className="p-2.5 text-red-500 border border-red-500/30 rounded-lg hover:bg-red-500/10 transition-colors"
                  title="Stop"
                >
                  <Square className="w-4 h-4" />
                </button>
              )}
            </div>
          </div>
        </>
      ) : (
        <ReportTab assessmentId={id} />
      )}
    </div>
  );
}

function MessageBubble({ message, isLast, streaming }: { message: DisplayMessage; isLast?: boolean; streaming?: boolean }) {
  const [collapsed, setCollapsed] = useState(message.toolCollapsed ?? true);

  if (message.role === "status") {
    const pulse = streaming && isLast;
    const isDone = message.id.startsWith("status-done-");
    return (
      <div className="flex items-center gap-2 py-2 px-3">
        <div className={`w-2 h-2 rounded-full ${isDone ? "bg-green-500" : `bg-primary ${pulse ? "animate-pulse" : "opacity-40"}`}`} />
        <span className={`text-sm font-medium ${isDone ? "text-green-500" : "text-muted"}`}>{message.content}</span>
      </div>
    );
  }

  if (message.role === "tool") {
    return (
      <div className="ml-4 border border-border rounded-md bg-surface/50 text-sm">
        <div className="flex items-center gap-2 px-3 py-2.5 text-muted font-medium">
          <Terminal className="w-3.5 h-3.5 text-primary" />
          <span className="truncate">{message.toolAction || "Executing..."}</span>
          {message.toolResult !== undefined ? (
            <span className="ml-auto text-green-500 text-xs font-semibold">✓</span>
          ) : (
            <Loader2 className="w-3.5 h-3.5 animate-spin ml-auto text-primary" />
          )}
        </div>
      </div>
    );
  }

  const isUser = message.role === "user";

  if (!isUser && !message.content) {
    return (
      <div className="flex items-center gap-2.5 py-3 px-3">
        <Loader2 className="w-5 h-5 animate-spin text-primary" />
        <span className="text-sm font-medium text-muted">Analyzing target and planning approach...</span>
      </div>
    );
  }

  return (
    <div className={`flex ${isUser ? "justify-end" : "justify-start"}`}>
      <div
        className={`max-w-[80%] px-4 py-3 text-[15px] ${
          isUser
            ? "bg-primary text-white rounded-lg rounded-br-sm"
            : "bg-surface border border-border rounded-lg rounded-bl-sm chat-content"
        }`}
      >
        <div className="whitespace-pre-wrap leading-relaxed" dangerouslySetInnerHTML={{ __html: isUser ? renderChatMarkdown(message.content) : renderMarkdown(message.content) }} />
      </div>
    </div>
  );
}

interface Finding {
  severity: string;
  title: string;
  cvss: number;
  cwe?: string;
  owasp?: string;
  cve?: string;
  location?: string;
  description?: string;
  remediation?: string;
}

interface Report {
  report_id: string;
  report_type: string;
  created_at: string;
  content: string;
  findings?: Finding[];
}

const SEV_CONFIG: Record<string, { bg: string; text: string; border: string; label: string }> = {
  critical: { bg: "bg-red-500/10", text: "text-red-500", border: "border-red-500/30", label: "CRITICAL" },
  high: { bg: "bg-orange-500/10", text: "text-orange-500", border: "border-orange-500/30", label: "HIGH" },
  medium: { bg: "bg-yellow-500/10", text: "text-yellow-500", border: "border-yellow-500/30", label: "MEDIUM" },
  low: { bg: "bg-blue-400/10", text: "text-blue-400", border: "border-blue-400/30", label: "LOW" },
  info: { bg: "bg-gray-400/10", text: "text-gray-400", border: "border-gray-400/30", label: "INFO" },
};

function renderMarkdown(text: string): string {
  const escaped = (text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  const inline = (s: string) =>
    s
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+)`/g, '<code class="px-1 py-0.5 bg-border/50 rounded text-xs font-mono">$1</code>');

  const lines = escaped.split("\n");
  const out: string[] = [];
  let para: string[] = [];
  let i = 0;

  const flushPara = () => {
    if (para.length) {
      out.push(`<p class="my-2 leading-relaxed">${inline(para.join(" "))}</p>`);
      para = [];
    }
  };

  while (i < lines.length) {
    const t = lines[i].trim();

    // Tables
    if (t.startsWith("|") && t.endsWith("|")) {
      flushPara();
      const tbl: string[] = ['<table class="w-full border-collapse my-3 text-sm"><thead>'];
      let firstRow = true;
      while (i < lines.length && lines[i].trim().startsWith("|") && lines[i].trim().endsWith("|")) {
        const row = lines[i].trim();
        if (/^\|[\s\-:|]+\|$/.test(row)) {
          tbl.push("</thead><tbody>");
          firstRow = false;
          i++;
          continue;
        }
        const cells = row.split("|").filter((_, idx, arr) => idx > 0 && idx < arr.length - 1).map((c) => c.trim());
        if (firstRow) {
          tbl.push(`<tr>${cells.map((c) => `<th class="border border-border px-3 py-2 bg-surface font-semibold text-left">${inline(c)}</th>`).join("")}</tr>`);
        } else {
          tbl.push(`<tr>${cells.map((c) => `<td class="border border-border px-3 py-2">${inline(c)}</td>`).join("")}</tr>`);
        }
        i++;
      }
      tbl.push("</tbody></table>");
      out.push(tbl.join(""));
      continue;
    }

    // Headings
    let mh: RegExpExecArray | null;
    if ((mh = /^#### (.+)$/.exec(t))) { flushPara(); out.push(`<h5 class="font-semibold text-foreground mt-3 mb-1">${inline(mh[1])}</h5>`); i++; continue; }
    if ((mh = /^### (.+)$/.exec(t))) { flushPara(); out.push(`<h4 class="font-semibold text-foreground mt-3 mb-1">${inline(mh[1])}</h4>`); i++; continue; }
    if ((mh = /^## (.+)$/.exec(t))) { flushPara(); out.push(`<h3 class="font-bold text-foreground mt-4 mb-2 text-base">${inline(mh[1])}</h3>`); i++; continue; }
    if ((mh = /^# (.+)$/.exec(t))) { flushPara(); out.push(`<h2 class="font-bold text-foreground mt-4 mb-2 text-lg">${inline(mh[1])}</h2>`); i++; continue; }

    // Horizontal rule
    if (/^---+$/.test(t)) { flushPara(); out.push('<hr class="my-3 border-border" />'); i++; continue; }

    // Unordered list
    if (/^[-*] (.+)$/.test(t)) {
      flushPara();
      const items: string[] = [];
      while (i < lines.length && /^[-*] (.+)$/.test(lines[i].trim())) {
        items.push(`<li>${inline(lines[i].trim().replace(/^[-*] /, ""))}</li>`);
        i++;
      }
      out.push(`<ul class="list-disc ml-5 my-2 space-y-1">${items.join("")}</ul>`);
      continue;
    }

    // Ordered list
    if (/^\d+\. (.+)$/.test(t)) {
      flushPara();
      const items: string[] = [];
      while (i < lines.length && /^\d+\. (.+)$/.test(lines[i].trim())) {
        items.push(`<li>${inline(lines[i].trim().replace(/^\d+\. /, ""))}</li>`);
        i++;
      }
      out.push(`<ol class="list-decimal ml-5 my-2 space-y-1">${items.join("")}</ol>`);
      continue;
    }

    // Blank line ends the current paragraph
    if (t === "") { flushPara(); i++; continue; }

    // Regular text — accumulate into the current paragraph
    para.push(t);
    i++;
  }
  flushPara();
  return out.join("");
}

function renderChatMarkdown(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/^### (.+)$/gm, '<strong class="block mt-3 mb-1">$1</strong>')
    .replace(/^## (.+)$/gm, '<strong class="block text-base mt-4 mb-1">$1</strong>')
    .replace(/^# (.+)$/gm, '<strong class="block text-lg mt-4 mb-1">$1</strong>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/^\* (.+)$/gm, '&bull; $1')
    .replace(/`([^`]+)`/g, '<code class="px-1 py-0.5 bg-black/5 dark:bg-white/10 rounded text-xs font-mono">$1</code>')
    .replace(/\n/g, '<br />');
}

function renderMarkdownHtml(text: string): string {
  let escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Parse markdown tables
  const lines = escaped.split('\n');
  const result: string[] = [];
  let inTable = false;
  let isFirstRow = true;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith('|') && line.endsWith('|')) {
      // Check if next line is separator
      const nextLine = (lines[i + 1] || '').trim();
      if (!inTable) {
        inTable = true;
        isFirstRow = true;
        result.push('<table><thead>');
      }
      if (/^\|[\s-:|]+\|$/.test(line)) {
        // separator row - skip it, close thead open tbody
        result.push('</thead><tbody>');
        isFirstRow = false;
        continue;
      }
      const cells = line.split('|').filter((_, idx, arr) => idx > 0 && idx < arr.length - 1).map(c => c.trim());
      const tag = isFirstRow ? 'th' : 'td';
      result.push(`<tr>${cells.map(c => `<${tag}>${c}</${tag}>`).join('')}</tr>`);
    } else {
      if (inTable) {
        result.push('</tbody></table>');
        inTable = false;
        isFirstRow = true;
      }
      result.push(line);
    }
  }
  if (inTable) result.push('</tbody></table>');

  return result.join('\n')
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm, '<h2>$1</h2>')
    .replace(/^# (.+)$/gm, '<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\n/g, '<br />');
}

function ReportTab({ assessmentId }: { assessmentId: string }) {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());

  useEffect(() => {
    api.reports
      .list(assessmentId)
      .then(setReports)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [assessmentId]);

  const toggleFinding = (idx: number) => {
    setExpandedFindings((prev) => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  };

  const downloadHtml = (r: Report) => {
    const findings = r.findings || [];
    const sevColor: Record<string, string> = {
      critical: "#dc2626", high: "#ea580c", medium: "#ca8a04", low: "#60a5fa", info: "#9ca3af",
    };
    const findingsRows = findings.map((f) => `
      <tr>
        <td style="padding:10px 12px;border-bottom:1px solid #e5e7eb">
          <span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff;background:${sevColor[f.severity] || "#9ca3af"}">${f.severity.toUpperCase()}</span>
        </td>
        <td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-weight:600">${f.title}</td>
        <td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;text-align:center">${f.cvss.toFixed(1)}</td>
        <td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:12px">${f.cwe || ""}</td>
        <td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-size:12px">${f.owasp || ""}</td>
        <td style="padding:10px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:12px">${f.location || ""}</td>
      </tr>
      ${f.description || f.remediation ? `<tr><td colspan="6" style="padding:8px 12px 16px 12px;border-bottom:2px solid #e5e7eb;background:#f9fafb">
        ${f.description ? `<p style="margin:0 0 6px;font-size:13px"><strong>Description:</strong> ${f.description}</p>` : ""}
        ${f.remediation ? `<p style="margin:0;font-size:13px"><strong>Remediation:</strong> ${f.remediation}</p>` : ""}
      </td></tr>` : ""}`
    ).join("");

    const critCount = findings.filter((f) => f.severity === "critical").length;
    const highCount = findings.filter((f) => f.severity === "high").length;
    const medCount = findings.filter((f) => f.severity === "medium").length;
    const lowCount = findings.filter((f) => f.severity === "low").length;
    const infoCount = findings.filter((f) => f.severity === "info").length;

    const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${r.report_type} Report - ModTester</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 40px; color: #1a1a2e; background: #fff; line-height: 1.6; }
  .header { border-bottom: 3px solid #2563eb; padding-bottom: 20px; margin-bottom: 30px; }
  .header h1 { margin: 0; font-size: 24px; color: #1a1a2e; }
  .header p { margin: 4px 0 0; color: #6b7280; font-size: 14px; }
  .meta { display: flex; gap: 30px; margin-top: 12px; font-size: 13px; color: #6b7280; }
  .summary-grid { display: flex; gap: 12px; margin-bottom: 30px; }
  .summary-card { flex: 1; text-align: center; padding: 16px; border-radius: 8px; border: 1px solid #e5e7eb; }
  .summary-card .num { font-size: 28px; font-weight: 700; }
  .summary-card .lbl { font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }
  .section { margin-bottom: 30px; }
  .section h2 { font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; color: #1a1a2e; border-bottom: 1px solid #e5e7eb; padding-bottom: 8px; margin-bottom: 16px; }
  .content { font-size: 14px; line-height: 1.7; }
  .content h1 { font-size: 20px; font-weight: 700; color: #1a1a2e; margin: 24px 0 8px; }
  .content h2 { font-size: 16px; font-weight: 700; color: #1a1a2e; margin: 20px 0 8px; }
  .content h3 { font-size: 14px; font-weight: 600; color: #1a1a2e; margin: 16px 0 6px; }
  .content code { padding: 1px 5px; background: #f3f4f6; border-radius: 3px; font-size: 12px; font-family: monospace; }
  .content table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 13px; }
  .content table th, .content table td { border: 1px solid #e5e7eb; padding: 6px 10px; text-align: left; }
  .content table th { background: #f3f4f6; font-weight: 600; }
  table.findings { width: 100%; border-collapse: collapse; font-size: 13px; }
  table.findings thead th { text-align: left; padding: 10px 12px; background: #f3f4f6; border-bottom: 2px solid #e5e7eb; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: #1a1a2e; font-weight: 700; }
  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 12px; color: #9ca3af; text-align: center; }
  @media print { body { padding: 20px; } }
</style>
</head>
<body>
  <div class="header">
    <h1>${r.report_type.charAt(0).toUpperCase() + r.report_type.slice(1)} Security Assessment Report</h1>
    <p>Generated by ModTester - MCP-Powered AI Penetration Testing</p>
    <div class="meta">
      <span>Date: ${new Date(r.created_at).toLocaleDateString()}</span>
      <span>Findings: ${findings.length}</span>
    </div>
  </div>

  ${findings.length > 0 ? `<div class="summary-grid">
    <div class="summary-card"><div class="num">${findings.length}</div><div class="lbl">Total</div></div>
    ${critCount ? `<div class="summary-card" style="border-color:#fca5a5;background:#fef2f2"><div class="num" style="color:#dc2626">${critCount}</div><div class="lbl">Critical</div></div>` : ""}
    ${highCount ? `<div class="summary-card" style="border-color:#fed7aa;background:#fff7ed"><div class="num" style="color:#ea580c">${highCount}</div><div class="lbl">High</div></div>` : ""}
    ${medCount ? `<div class="summary-card" style="border-color:#fde68a;background:#fefce8"><div class="num" style="color:#ca8a04">${medCount}</div><div class="lbl">Medium</div></div>` : ""}
    ${lowCount ? `<div class="summary-card" style="border-color:#bfdbfe;background:#eff6ff"><div class="num" style="color:#2563eb">${lowCount}</div><div class="lbl">Low</div></div>` : ""}
    ${infoCount ? `<div class="summary-card"><div class="num" style="color:#9ca3af">${infoCount}</div><div class="lbl">Info</div></div>` : ""}
  </div>` : ""}

  ${r.content ? `<div class="section"><h2>Executive Summary</h2><div class="content">${renderMarkdownHtml(r.content)}</div></div>` : ""}

  ${findings.length > 0 ? `<div class="section"><h2>Findings Detail</h2>
  <table class="findings">
    <thead><tr><th>Severity</th><th>Finding</th><th>CVSS</th><th>CWE</th><th>OWASP</th><th>Location</th></tr></thead>
    <tbody>${findingsRows}</tbody>
  </table></div>` : ""}

  <div class="footer">ModTester Security Assessment Report &mdash; Confidential</div>
</body>
</html>`;

    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${r.report_type}-report-${new Date(r.created_at).toISOString().slice(0, 10)}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center flex-1">
        <Loader2 className="w-6 h-6 animate-spin text-muted" />
      </div>
    );
  }

  if (reports.length === 0) {
    return (
      <div className="flex items-center justify-center flex-1 text-muted">
        <div className="text-center">
          <FileText className="w-10 h-10 mx-auto mb-3 opacity-50" />
          <p className="font-medium">No reports generated yet</p>
          <p className="text-sm mt-1">Ask the AI to generate a report in the chat.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 overflow-y-auto p-6">
      {reports.map((r) => {
        const findings = r.findings || [];
        const critCount = findings.filter((f) => f.severity === "critical").length;
        const highCount = findings.filter((f) => f.severity === "high").length;
        const medCount = findings.filter((f) => f.severity === "medium").length;
        const lowCount = findings.filter((f) => f.severity === "low").length;
        const infoCount = findings.filter((f) => f.severity === "info").length;
        const maxCvss = findings.length > 0 ? Math.max(...findings.map((f) => f.cvss)) : 0;

        return (
          <div key={r.report_id} className="max-w-5xl mx-auto space-y-6">
            {/* Report Header */}
            <div className="border border-border rounded-xl bg-surface overflow-hidden">
              <div className="bg-primary/5 border-b border-border px-6 py-5">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-xs font-medium text-primary uppercase tracking-wider mb-1">
                      Security Assessment Report
                    </p>
                    <h2 className="text-xl font-bold capitalize">{r.report_type} Report</h2>
                  </div>
                  <div className="text-right flex items-start gap-3">
                    <button
                      onClick={() => downloadHtml(r)}
                      className="inline-flex items-center gap-2 px-4 py-2 text-sm font-bold bg-primary text-white rounded-lg hover:bg-primary-dark transition-colors"
                    >
                      <Download className="w-4 h-4" />
                      Download HTML
                    </button>
                    <div>
                      <p className="text-xs text-muted">Generated</p>
                      <p className="text-sm font-medium">{new Date(r.created_at).toLocaleDateString()}</p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Risk Summary */}
              {findings.length > 0 && (
                <div className="px-6 py-4">
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                    <div className="text-center p-3 rounded-lg bg-background border border-border">
                      <p className="text-2xl font-bold">{findings.length}</p>
                      <p className="text-xs text-muted">Total</p>
                    </div>
                    {critCount > 0 && (
                      <div className="text-center p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                        <p className="text-2xl font-bold text-red-500">{critCount}</p>
                        <p className="text-xs text-red-400">Critical</p>
                      </div>
                    )}
                    {highCount > 0 && (
                      <div className="text-center p-3 rounded-lg bg-orange-500/10 border border-orange-500/20">
                        <p className="text-2xl font-bold text-orange-500">{highCount}</p>
                        <p className="text-xs text-orange-400">High</p>
                      </div>
                    )}
                    {medCount > 0 && (
                      <div className="text-center p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
                        <p className="text-2xl font-bold text-yellow-500">{medCount}</p>
                        <p className="text-xs text-yellow-400">Medium</p>
                      </div>
                    )}
                    {lowCount > 0 && (
                      <div className="text-center p-3 rounded-lg bg-blue-400/10 border border-blue-400/20">
                        <p className="text-2xl font-bold text-blue-400">{lowCount}</p>
                        <p className="text-xs text-blue-300">Low</p>
                      </div>
                    )}
                    {infoCount > 0 && (
                      <div className="text-center p-3 rounded-lg bg-gray-400/10 border border-gray-400/20">
                        <p className="text-2xl font-bold text-gray-400">{infoCount}</p>
                        <p className="text-xs text-gray-400">Info</p>
                      </div>
                    )}
                  </div>
                  {maxCvss > 0 && (
                    <div className="mt-3 flex items-center gap-2 text-sm">
                      <span className="text-muted">Highest CVSS:</span>
                      <span className={`font-bold ${maxCvss >= 9 ? "text-red-500" : maxCvss >= 7 ? "text-orange-500" : maxCvss >= 4 ? "text-yellow-500" : "text-blue-400"}`}>
                        {maxCvss.toFixed(1)}
                      </span>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Executive Summary (content field) */}
            {r.content && (
              <div className="border border-border rounded-xl bg-surface p-6">
                <h3 className="text-sm font-bold uppercase tracking-wider text-foreground mb-4">
                  Executive Summary
                </h3>
                <div className="text-sm leading-relaxed text-foreground report-content" dangerouslySetInnerHTML={{ __html: renderMarkdown(r.content) }} />
              </div>
            )}

            {/* Findings Table */}
            {findings.length > 0 && (
              <div className="border border-border rounded-xl bg-surface overflow-hidden">
                <div className="px-6 py-4 border-b border-border">
                  <h3 className="text-sm font-bold uppercase tracking-wider text-foreground">
                    Findings Detail
                  </h3>
                </div>
                <div className="divide-y divide-border">
                  {findings.map((f, idx) => {
                    const sev = SEV_CONFIG[f.severity] || SEV_CONFIG.info;
                    const expanded = expandedFindings.has(idx);
                    return (
                      <div key={idx} className="hover:bg-background/50 transition-colors">
                        <button
                          onClick={() => toggleFinding(idx)}
                          className="w-full text-left px-6 py-4 flex items-center gap-4"
                        >
                          <span className={`shrink-0 px-2 py-1 rounded text-xs font-bold ${sev.bg} ${sev.text} border ${sev.border}`}>
                            {sev.label}
                          </span>
                          <div className="flex-1 min-w-0">
                            <p className="font-medium text-sm truncate">{f.title}</p>
                            <div className="flex items-center gap-3 mt-1 text-xs text-muted">
                              <span>CVSS {f.cvss.toFixed(1)}</span>
                              {f.cwe && <span>{f.cwe}</span>}
                              {f.owasp && <span>{f.owasp}</span>}
                            </div>
                          </div>
                          {expanded ? (
                            <ChevronDown className="w-4 h-4 text-muted shrink-0" />
                          ) : (
                            <ChevronRight className="w-4 h-4 text-muted shrink-0" />
                          )}
                        </button>
                        {expanded && (
                          <div className="px-6 pb-4 ml-[88px] space-y-3 text-sm">
                            {f.location && (
                              <div>
                                <p className="text-xs font-medium text-muted uppercase mb-1">Location</p>
                                <code className="text-xs bg-background px-2 py-1 rounded border border-border font-mono">
                                  {f.location}
                                </code>
                              </div>
                            )}
                            {f.description && (
                              <div>
                                <p className="text-xs font-medium text-muted uppercase mb-1">Description</p>
                                <p className="text-foreground">{f.description}</p>
                              </div>
                            )}
                            {f.remediation && (
                              <div>
                                <p className="text-xs font-medium text-muted uppercase mb-1">Remediation</p>
                                <p className="text-foreground">{f.remediation}</p>
                              </div>
                            )}
                            <div className="flex flex-wrap gap-2 pt-1">
                              {f.cwe && (
                                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-background border border-border text-muted">
                                  {f.cwe}
                                </span>
                              )}
                              {f.owasp && (
                                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-background border border-border text-muted">
                                  {f.owasp}
                                </span>
                              )}
                              {f.cve && f.cve !== "N/A" && (
                                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-background border border-border text-muted">
                                  {f.cve}
                                </span>
                              )}
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
