"use client";
import { clsx } from "clsx";

interface SeverityBadgeProps {
  severity: string;
  count?: number;
  className?: string;
}

const COLORS: Record<string, string> = {
  critical: "bg-red-600 text-white",
  c: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  h: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  m: "bg-yellow-500 text-black",
  low: "bg-blue-400 text-white",
  l: "bg-blue-400 text-white",
  info: "bg-gray-400 text-white",
  i: "bg-gray-400 text-white",
};

export function SeverityBadge({ severity, count, className }: SeverityBadgeProps) {
  const s = severity.toLowerCase();
  return (
    <span
      className={clsx(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium",
        COLORS[s] || "bg-gray-300 text-black",
        className
      )}
    >
      {count !== undefined ? `${count} ${severity}` : severity}
    </span>
  );
}

interface StatusBadgeProps {
  status: string;
}

const STATUS_COLORS: Record<string, string> = {
  active: "bg-green-600 text-white",
  completed: "bg-blue-600 text-white",
  paused: "bg-yellow-500 text-white",
};

export function StatusBadge({ status }: StatusBadgeProps) {
  return (
    <span
      className={clsx(
        "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-bold capitalize",
        STATUS_COLORS[status] || "bg-gray-500 text-white"
      )}
    >
      {status}
    </span>
  );
}
