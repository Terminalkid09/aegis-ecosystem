import React from 'react';

export function SkeletonLine({ width = '100%', height = '1rem', className = '' }) {
  return (
    <div
      className={`bg-slate-700/50 rounded animate-pulse ${className}`}
      style={{ width, height }}
    />
  );
}

export function SkeletonCard({ lines = 3, className = '' }) {
  return (
    <div className={`bg-slate-800/50 border border-slate-700/50 rounded-xl p-5 space-y-3 ${className}`}>
      <SkeletonLine width="40%" height="1.25rem" />
      {Array.from({ length: lines }).map((_, i) => (
        <SkeletonLine key={i} width={`${60 + Math.random() * 30}%`} />
      ))}
    </div>
  );
}

export function SkeletonTable({ rows = 5, cols = 4, className = '' }) {
  return (
    <div className={`space-y-2 ${className}`}>
      <div className="flex gap-4 pb-2 border-b border-slate-700/50">
        {Array.from({ length: cols }).map((_, i) => (
          <SkeletonLine key={i} width={`${100 / cols}%`} height="0.75rem" />
        ))}
      </div>
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-4 py-2">
          {Array.from({ length: cols }).map((_, c) => (
            <SkeletonLine key={c} width={`${100 / cols}%`} height="0.75rem" />
          ))}
        </div>
      ))}
    </div>
  );
}

export function SkeletonChart({ className = '' }) {
  return (
    <div className={`bg-slate-800/50 border border-slate-700/50 rounded-xl p-5 ${className}`}>
      <SkeletonLine width="30%" height="1rem" className="mb-4" />
      <div className="h-48 flex items-end gap-2">
        {Array.from({ length: 12 }).map((_, i) => (
          <div
            key={i}
            className="flex-1 bg-slate-700/50 rounded-t animate-pulse"
            style={{ height: `${30 + Math.random() * 70}%` }}
          />
        ))}
      </div>
    </div>
  );
}
