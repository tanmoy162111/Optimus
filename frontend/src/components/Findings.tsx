import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  Shield,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  Filter,
  Search,
  X,
} from 'lucide-react';
import { cn, getSeverityLevel, getSeverityConfig, formatTimestamp, copyToClipboard } from '@/lib/utils';
import { Card, Badge, Button, Input } from '@/components/ui';
import type { Vulnerability, SeverityLevel } from '@/types';

// ============================================
// Vulnerability Card Component
// ============================================

interface VulnerabilityCardProps {
  vulnerability: Vulnerability;
  isExpanded?: boolean;
  onToggle?: () => void;
  className?: string;
}

export const VulnerabilityCard: React.FC<VulnerabilityCardProps> = ({
  vulnerability: vuln,
  isExpanded = false,
  onToggle,
  className,
}) => {
  const [copied, setCopied] = useState(false);
  const severityLevel = getSeverityLevel(vuln.severity);
  const severityConfig = getSeverityConfig(vuln.severity);

  const handleCopy = async () => {
    await copyToClipboard(JSON.stringify(vuln, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const severityBadgeVariant = {
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    info: 'info',
  } as const;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className={cn('group', className)}
    >
      <Card
        variant="default"
        padding="none"
        className={cn(
          'overflow-hidden transition-all duration-300',
          'hover:border-opacity-50',
          isExpanded && 'ring-1 ring-opacity-30'
        )}
        style={{
          borderColor: severityConfig.borderColor,
          ...(isExpanded && { ringColor: severityConfig.color }),
        }}
      >
        {/* Severity indicator bar */}
        <div
          className="h-1"
          style={{ backgroundColor: severityConfig.color }}
        />

        {/* Header */}
        <div
          className="p-4 cursor-pointer"
          onClick={onToggle}
        >
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-3 mb-2">
                <Badge
                  variant={severityBadgeVariant[severityLevel]}
                  size="sm"
                >
                  {severityLevel.toUpperCase()} ({vuln.severity.toFixed(1)})
                </Badge>
                {vuln.exploitable && (
                  <Badge variant="danger" size="sm">
                    Exploitable
                  </Badge>
                )}
                {vuln.cve && (
                  <Badge variant="purple" size="sm">
                    {vuln.cve}
                  </Badge>
                )}
              </div>

              <h4 className="text-white font-medium truncate mb-1">
                {vuln.name}
              </h4>

              <p className="text-sm text-gray-500 truncate">
                {vuln.location}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-600">
                {vuln.tool}
              </span>
              <button className="text-gray-500 hover:text-white transition-colors">
                {isExpanded ? (
                  <ChevronUp className="w-5 h-5" />
                ) : (
                  <ChevronDown className="w-5 h-5" />
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Expanded Content */}
        <AnimatePresence>
          {isExpanded && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="overflow-hidden"
            >
              <div className="px-4 pb-4 border-t border-cyber-light/20">
                <div className="pt-4 space-y-4">
                  {/* Evidence */}
                  <div>
                    <h5 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">
                      Evidence
                    </h5>
                    <pre className="bg-cyber-black rounded-lg p-3 text-sm text-terminal-text font-mono overflow-x-auto">
                      {vuln.evidence}
                    </pre>
                  </div>

                  {/* Details Grid */}
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <h5 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-1">
                        Type
                      </h5>
                      <p className="text-sm text-white">{vuln.type.replace(/_/g, ' ')}</p>
                    </div>
                    <div>
                      <h5 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-1">
                        Confidence
                      </h5>
                      <p className="text-sm text-white">{(vuln.confidence * 100).toFixed(0)}%</p>
                    </div>
                    {vuln.cwe && (
                      <div>
                        <h5 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-1">
                          CWE
                        </h5>
                        <p className="text-sm text-white">{vuln.cwe}</p>
                      </div>
                    )}
                    <div>
                      <h5 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-1">
                        Discovered
                      </h5>
                      <p className="text-sm text-white">{formatTimestamp(vuln.timestamp)}</p>
                    </div>
                  </div>

                  {/* Remediation */}
                  {vuln.remediation && (
                    <div>
                      <h5 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">
                        Remediation
                      </h5>
                      <p className="text-sm text-gray-300">{vuln.remediation}</p>
                    </div>
                  )}

                  {/* References */}
                  {vuln.references && vuln.references.length > 0 && (
                    <div>
                      <h5 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">
                        References
                      </h5>
                      <div className="flex flex-wrap gap-2">
                        {vuln.references.map((ref, idx) => (
                          <a
                            key={idx}
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-xs text-neon-cyan hover:underline"
                          >
                            <ExternalLink className="w-3 h-3" />
                            {new URL(ref).hostname}
                          </a>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Actions */}
                  <div className="flex items-center gap-2 pt-2 border-t border-cyber-light/20">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={handleCopy}
                    >
                      {copied ? (
                        <>
                          <Check className="w-4 h-4" />
                          Copied
                        </>
                      ) : (
                        <>
                          <Copy className="w-4 h-4" />
                          Copy JSON
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </Card>
    </motion.div>
  );
};

// ============================================
// Findings Panel Component
// ============================================

interface FindingsPanelProps {
  findings: Vulnerability[];
  className?: string;
  title?: string;
  showFilters?: boolean;
  maxHeight?: string;
}

export const FindingsPanel: React.FC<FindingsPanelProps> = ({
  findings,
  className,
  title = 'Findings',
  showFilters = true,
  maxHeight = '600px',
}) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<SeverityLevel | 'all'>('all');
  const [sortBy, setSortBy] = useState<'severity' | 'time'>('severity');

  // Filter and sort findings
  const filteredFindings = useMemo(() => {
    let result = [...findings];

    // Apply search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(
        (f) =>
          f.name.toLowerCase().includes(query) ||
          f.type.toLowerCase().includes(query) ||
          f.location.toLowerCase().includes(query) ||
          (f.cve && f.cve.toLowerCase().includes(query))
      );
    }

    // Apply severity filter
    if (severityFilter !== 'all') {
      result = result.filter((f) => getSeverityLevel(f.severity) === severityFilter);
    }

    // Sort
    result.sort((a, b) => {
      if (sortBy === 'severity') {
        return b.severity - a.severity;
      }
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });

    return result;
  }, [findings, searchQuery, severityFilter, sortBy]);

  // Count by severity
  const counts = useMemo(() => ({
    critical: findings.filter((f) => f.severity >= 9.0).length,
    high: findings.filter((f) => f.severity >= 7.0 && f.severity < 9.0).length,
    medium: findings.filter((f) => f.severity >= 4.0 && f.severity < 7.0).length,
    low: findings.filter((f) => f.severity > 0 && f.severity < 4.0).length,
    info: findings.filter((f) => f.severity === 0).length,
  }), [findings]);

  return (
    <div className={cn('flex flex-col', className)}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5 text-neon-green" />
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          <Badge variant="default" size="sm">
            {findings.length}
          </Badge>
        </div>
      </div>

      {/* Severity Summary */}
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        {counts.critical > 0 && (
          <Badge variant="critical" size="sm">
            {counts.critical} Critical
          </Badge>
        )}
        {counts.high > 0 && (
          <Badge variant="high" size="sm">
            {counts.high} High
          </Badge>
        )}
        {counts.medium > 0 && (
          <Badge variant="medium" size="sm">
            {counts.medium} Medium
          </Badge>
        )}
        {counts.low > 0 && (
          <Badge variant="low" size="sm">
            {counts.low} Low
          </Badge>
        )}
      </div>

      {/* Filters */}
      {showFilters && (
        <div className="flex items-center gap-3 mb-4">
          <div className="flex-1">
            <Input
              placeholder="Search findings..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              icon={<Search className="w-4 h-4" />}
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value as SeverityLevel | 'all')}
            className="bg-cyber-darker border border-cyber-light/50 rounded-lg h-10 px-3 text-sm text-white focus:outline-none focus:border-neon-green"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'severity' | 'time')}
            className="bg-cyber-darker border border-cyber-light/50 rounded-lg h-10 px-3 text-sm text-white focus:outline-none focus:border-neon-green"
          >
            <option value="severity">Sort by Severity</option>
            <option value="time">Sort by Time</option>
          </select>
        </div>
      )}

      {/* Active filters */}
      {(searchQuery || severityFilter !== 'all') && (
        <div className="flex items-center gap-2 mb-4">
          <span className="text-xs text-gray-500">Filters:</span>
          {searchQuery && (
            <Badge variant="outline" size="sm" className="gap-1">
              {searchQuery}
              <button onClick={() => setSearchQuery('')}>
                <X className="w-3 h-3" />
              </button>
            </Badge>
          )}
          {severityFilter !== 'all' && (
            <Badge variant="outline" size="sm" className="gap-1">
              {severityFilter}
              <button onClick={() => setSeverityFilter('all')}>
                <X className="w-3 h-3" />
              </button>
            </Badge>
          )}
        </div>
      )}

      {/* Findings List */}
      <div
        className="space-y-3 overflow-y-auto pr-2"
        style={{ maxHeight }}
      >
        {filteredFindings.length === 0 ? (
          <div className="text-center py-12">
            <AlertTriangle className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-500">
              {findings.length === 0
                ? 'No vulnerabilities found yet'
                : 'No findings match your filters'}
            </p>
          </div>
        ) : (
          <AnimatePresence>
            {filteredFindings.map((finding) => (
              <VulnerabilityCard
                key={finding.id}
                vulnerability={finding}
                isExpanded={expandedId === finding.id}
                onToggle={() =>
                  setExpandedId(expandedId === finding.id ? null : finding.id)
                }
              />
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
};

export default FindingsPanel;
