import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { severityConfig } from '@/config';
import type { SeverityLevel, Vulnerability, ScanPhase } from '@/types';

// ============================================
// Utility Functions
// ============================================

/**
 * Merge Tailwind classes with conflict resolution
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Get severity level from score
 */
export function getSeverityLevel(score: number): SeverityLevel {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

/**
 * Get severity configuration
 */
export function getSeverityConfig(score: number) {
  const level = getSeverityLevel(score);
  return severityConfig[level];
}

/**
 * Format timestamp
 */
export function formatTimestamp(timestamp: string | Date, options?: Intl.DateTimeFormatOptions): string {
  const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp;
  return date.toLocaleString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    ...options,
  });
}

/**
 * Format date
 */
export function formatDate(timestamp: string | Date): string {
  const date = typeof timestamp === 'string' ? new Date(timestamp) : timestamp;
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/**
 * Format duration in seconds to human readable
 */
export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}m ${secs}s`;
  }
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

/**
 * Format percentage
 */
export function formatPercentage(value: number, decimals = 1): string {
  return `${(value * 100).toFixed(decimals)}%`;
}

/**
 * Generate unique ID
 */
export function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

/**
 * Truncate text
 */
export function truncate(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}

/**
 * Count vulnerabilities by severity
 */
export function countBySeverity(vulnerabilities: Vulnerability[]) {
  return {
    critical: vulnerabilities.filter(v => v.severity >= 9.0).length,
    high: vulnerabilities.filter(v => v.severity >= 7.0 && v.severity < 9.0).length,
    medium: vulnerabilities.filter(v => v.severity >= 4.0 && v.severity < 7.0).length,
    low: vulnerabilities.filter(v => v.severity > 0 && v.severity < 4.0).length,
    info: vulnerabilities.filter(v => v.severity === 0).length,
    total: vulnerabilities.length,
  };
}

/**
 * Get phase index for progress
 */
export function getPhaseIndex(phase: ScanPhase): number {
  const phases: ScanPhase[] = [
    'reconnaissance',
    'scanning',
    'enumeration',
    'exploitation',
    'post_exploitation',
    'reporting',
  ];
  return phases.indexOf(phase);
}

/**
 * Calculate overall risk score
 */
export function calculateRiskScore(vulnerabilities: Vulnerability[]): number {
  if (vulnerabilities.length === 0) return 0;
  
  const weights = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 1,
    info: 0,
  };
  
  const counts = countBySeverity(vulnerabilities);
  const totalWeight = 
    counts.critical * weights.critical +
    counts.high * weights.high +
    counts.medium * weights.medium +
    counts.low * weights.low;
  
  // Normalize to 0-100
  const maxPossible = vulnerabilities.length * weights.critical;
  return Math.min(100, (totalWeight / maxPossible) * 100);
}

/**
 * Parse URL and extract host
 */
export function extractHost(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return url;
  }
}

/**
 * Validate URL
 */
export function isValidUrl(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * Debounce function
 */
export function debounce<T extends (...args: unknown[]) => void>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout | null = null;
  return (...args: Parameters<T>) => {
    if (timeout) clearTimeout(timeout);
    timeout = setTimeout(() => func(...args), wait);
  };
}

/**
 * Throttle function
 */
export function throttle<T extends (...args: unknown[]) => void>(
  func: T,
  limit: number
): (...args: Parameters<T>) => void {
  let inThrottle = false;
  return (...args: Parameters<T>) => {
    if (!inThrottle) {
      func(...args);
      inThrottle = true;
      setTimeout(() => (inThrottle = false), limit);
    }
  };
}

/**
 * Copy to clipboard
 */
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * Download file
 */
export function downloadFile(content: string, filename: string, type = 'application/json') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Sleep utility
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry function with exponential backoff
 */
export async function retry<T>(
  fn: () => Promise<T>,
  maxAttempts = 3,
  delay = 1000
): Promise<T> {
  let lastError: Error | undefined;
  
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;
      if (attempt < maxAttempts - 1) {
        await sleep(delay * Math.pow(2, attempt));
      }
    }
  }
  
  throw lastError;
}
