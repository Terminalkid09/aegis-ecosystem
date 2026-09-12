import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatBytes(bytes: number): string {
  if (!bytes) return 'n/a'
  if (bytes > 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`
  if (bytes > 1048576) return `${(bytes / 1048576).toFixed(1)} MB`
  if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

export function formatDisk(mb: number): string {
  if (!mb) return 'n/a'
  if (mb > 1024) return `${(mb / 1024).toFixed(1)} GB`
  return `${mb} MB`
}

export function timeAgo(date: string | Date): string {
  const now = new Date()
  const d = new Date(date)
  const diff = Math.floor((now.getTime() - d.getTime()) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export function severityColor(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'text-red-400'
    case 'HIGH': return 'text-orange-400'
    case 'MEDIUM': return 'text-yellow-400'
    case 'LOW': return 'text-blue-400'
    default: return 'text-slate-400'
  }
}

export function severityBadge(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'bg-red-500/15 text-red-400 border-red-500/30'
    case 'HIGH': return 'bg-orange-500/15 text-orange-400 border-orange-500/30'
    case 'MEDIUM': return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
    case 'LOW': return 'bg-blue-500/15 text-blue-400 border-blue-500/30'
    default: return 'bg-slate-500/15 text-slate-400 border-slate-500/30'
  }
}
