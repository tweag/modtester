"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export default function NewAssessment() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [scopeType, setScopeType] = useState("web");
  const [creating, setCreating] = useState(false);

  const handleCreate = async () => {
    if (!name || !target) return;
    setCreating(true);
    try {
      const a = await api.assessments.create({ name, target, scope_type: scopeType });
      router.push(`/assessment/${a.id}`);
    } catch (e) {
      console.error(e);
      setCreating(false);
    }
  };

  return (
    <div className="p-6 max-w-lg mx-auto">
      <h1 className="text-xl font-semibold tracking-tight mb-1">New Assessment</h1>
      <p className="text-muted text-sm mb-6">Configure and launch a security assessment.</p>

      <div className="space-y-4">
        <div>
          <label className="block text-xs font-medium text-muted mb-1.5">Assessment Name</label>
          <input
            placeholder="e.g. OWASP Juice Shop - Full Pentest"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full px-3 py-2 border border-border rounded-lg bg-surface text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary"
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-muted mb-1.5">Target</label>
          <input
            placeholder="URL, IP address, or CIDR range"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="w-full px-3 py-2 border border-border rounded-lg bg-surface text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary"
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-muted mb-1.5">Scope Type</label>
          <select
            value={scopeType}
            onChange={(e) => setScopeType(e.target.value)}
            className="w-full px-3 py-2 border border-border rounded-lg bg-surface text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary"
          >
            <option value="web">Web Application</option>
            <option value="mobile_api">Mobile API</option>
            <option value="public_ip">Public IP / Network</option>
          </select>
        </div>

        <div className="flex gap-3 pt-2">
          <button
            onClick={() => router.push("/")}
            className="px-4 py-2 border border-border text-muted hover:text-foreground rounded-lg text-sm font-medium transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleCreate}
            disabled={!name || !target || creating}
            className="px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-dark text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {creating ? "Creating..." : "Create Assessment"}
          </button>
        </div>
      </div>
    </div>
  );
}
