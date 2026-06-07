"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Target, AlertTriangle, CheckCircle, Clock, ChevronRight, PlusCircle, Trash2 } from "lucide-react";
import { api, Assessment } from "@/lib/api";
import { SeverityBadge, StatusBadge } from "@/components/Badges";

export default function Dashboard() {
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState<string | null>(null);

  useEffect(() => {
    api.assessments.list().then(setAssessments).catch(console.error).finally(() => setLoading(false));
  }, []);

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete "${name}"? This cannot be undone.`)) return;
    setDeleting(id);
    try {
      await api.assessments.delete(id);
      setAssessments((prev) => prev.filter((a) => a.id !== id));
    } catch (e) {
      console.error(e);
      alert("Failed to delete assessment");
    } finally {
      setDeleting(null);
    }
  };

  const active = assessments.filter((a) => a.status === "active").length;
  const completed = assessments.filter((a) => a.status === "completed").length;
  const totalFindings = assessments.reduce((s, a) => s + a.findings_count, 0);
  const totalCritical = assessments.reduce((s, a) => s + a.critical, 0);

  if (loading && assessments.length === 0) {
    return (
      <div className="p-6 max-w-6xl mx-auto space-y-8">
        <div className="flex items-end justify-between">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Assessments</h1>
            <p className="text-muted text-sm mt-0.5">Loading...</p>
          </div>
        </div>
        <div className="grid grid-cols-4 gap-px bg-border rounded-lg overflow-hidden border border-border">
          {[1,2,3,4].map(i => (
            <div key={i} className="bg-surface px-5 py-4 text-center">
              <div className="h-8 w-8 bg-border/50 rounded mx-auto animate-pulse" />
              <div className="h-3 w-16 bg-border/50 rounded mx-auto mt-2 animate-pulse" />
            </div>
          ))}
        </div>
        <div className="border border-border rounded-lg overflow-hidden">
          {[1,2,3].map(i => (
            <div key={i} className="px-4 py-4 border-b border-border last:border-b-0">
              <div className="h-4 w-64 bg-border/50 rounded animate-pulse" />
              <div className="h-3 w-40 bg-border/50 rounded mt-2 animate-pulse" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Assessments</h1>
          <p className="text-muted text-sm mt-0.5">{assessments.length} total &middot; {active} active &middot; {totalFindings} findings</p>
        </div>
        <Link
          href="/new"
          className="inline-flex items-center gap-1.5 px-4 py-2.5 bg-primary text-white text-sm font-semibold rounded-lg hover:bg-primary-dark transition-colors"
        >
          <PlusCircle className="w-4 h-4" />
          New Assessment
        </Link>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-4 gap-px bg-border rounded-lg overflow-hidden border border-border">
        <StatCell label="Active" value={active} color="text-green-500" />
        <StatCell label="Completed" value={completed} color="text-blue-500" />
        <StatCell label="Findings" value={totalFindings} color="text-yellow-500" />
        <StatCell label="Critical" value={totalCritical} color="text-red-500" />
      </div>

      {/* Assessment table */}
      {assessments.length === 0 ? (
        <div className="text-center py-20 text-muted">
          <Target className="w-10 h-10 mx-auto mb-3 opacity-40" />
          <p className="font-semibold">No assessments yet</p>
          <p className="text-sm mt-1">Create your first assessment to get started.</p>
        </div>
      ) : (
        <div className="border border-border rounded-lg overflow-hidden">
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-surface text-xs uppercase tracking-wider">
                <th className="text-left font-bold px-4 py-3 text-foreground border-r border-border">Assessment</th>
                <th className="text-left font-bold px-4 py-3 text-foreground border-r border-border">Target</th>
                <th className="text-left font-bold px-4 py-3 text-foreground border-r border-border">Status</th>
                <th className="text-left font-bold px-4 py-3 text-foreground border-r border-border">Findings</th>
                <th className="text-left font-bold px-4 py-3 text-foreground border-r border-border">Date</th>
                <th className="w-20"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border text-sm">
              {assessments.map((a) => (
                <tr key={a.id} className="hover:bg-surface/50 transition-colors group">
                  <td className="px-4 py-3.5 border-r border-border">
                    <Link href={`/assessment/${a.id}`} className="font-semibold text-foreground hover:text-primary transition-colors">
                      {a.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3.5 text-muted font-mono text-xs border-r border-border truncate">{a.target}</td>
                  <td className="px-4 py-3 border-r border-border"><StatusBadge status={a.status} /></td>
                  <td className="px-4 py-3 border-r border-border">
                    <div className="flex items-center gap-1.5">
                      {a.critical > 0 && <SeverityBadge severity="C" count={a.critical} />}
                      {a.high > 0 && <SeverityBadge severity="H" count={a.high} />}
                      {a.medium > 0 && <SeverityBadge severity="M" count={a.medium} />}
                      {a.low > 0 && <SeverityBadge severity="L" count={a.low} />}
                      {a.findings_count === 0 && <span className="text-xs text-muted">&mdash;</span>}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-muted text-xs border-r border-border">{new Date(a.created_at).toLocaleDateString()}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={(e) => { e.preventDefault(); handleDelete(a.id, a.name); }}
                        disabled={deleting === a.id}
                        className="text-muted hover:text-red-500 transition-colors disabled:opacity-40"
                        title="Delete assessment"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                      <Link href={`/assessment/${a.id}`} className="text-muted group-hover:text-primary transition-colors">
                        <ChevronRight className="w-4 h-4" />
                      </Link>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function StatCell({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-surface px-5 py-4 text-center">
      <p className={`text-2xl font-semibold tabular-nums ${color}`}>{value}</p>
      <p className="text-xs text-muted mt-0.5">{label}</p>
    </div>
  );
}
