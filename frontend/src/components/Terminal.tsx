import React, { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Terminal as TerminalIcon, 
  Trash2, 
  Download, 
  Maximize2, 
  Minimize2,
  ChevronDown,
  Filter
} from 'lucide-react';
import { cn, formatTimestamp, downloadFile } from '@/lib/utils';
import { useScanStore } from '@/stores';
import type { TerminalLine } from '@/types';

// ============================================
// Terminal Component
// ============================================

interface TerminalProps {
  className?: string;
  maxHeight?: string;
  showToolbar?: boolean;
  autoScroll?: boolean;
}

export const Terminal: React.FC<TerminalProps> = ({
  className,
  maxHeight = '400px',
  showToolbar = true,
  autoScroll = true,
}) => {
  const { terminalLines, clearTerminal } = useScanStore();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const [filter, setFilter] = useState<string>('all');
  const [isAtBottom, setIsAtBottom] = useState(true);

  // Auto-scroll to bottom when new lines are added
  useEffect(() => {
    if (autoScroll && isAtBottom && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [terminalLines, autoScroll, isAtBottom]);

  // Track scroll position
  const handleScroll = () => {
    if (scrollRef.current) {
      const { scrollTop, scrollHeight, clientHeight } = scrollRef.current;
      setIsAtBottom(scrollHeight - scrollTop - clientHeight < 50);
    }
  };

  // Filter lines
  const filteredLines = terminalLines.filter((line) => {
    if (filter === 'all') return true;
    if (filter === 'errors') return line.type === 'error';
    if (filter === 'tools') return !!line.tool;
    return line.type === filter;
  });

  // Export logs
  const exportLogs = () => {
    const content = terminalLines
      .map((line) => `[${formatTimestamp(line.timestamp)}] ${line.content}`)
      .join('\n');
    downloadFile(content, `optimus-logs-${Date.now()}.txt`, 'text/plain');
  };

  // Scroll to bottom
  const scrollToBottom = () => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  };

  return (
    <div
      className={cn(
        'terminal flex flex-col rounded-lg overflow-hidden',
        isExpanded && 'fixed inset-4 z-50',
        className
      )}
    >
      {/* Header */}
      <div className="terminal-header flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="terminal-dot bg-neon-red" />
            <span className="terminal-dot bg-neon-orange" />
            <span className="terminal-dot bg-neon-green" />
          </div>
          <div className="flex items-center gap-2">
            <TerminalIcon className="w-4 h-4 text-neon-green" />
            <span className="text-sm text-gray-400 font-mono">
              optimus@scanner
            </span>
          </div>
        </div>

        {showToolbar && (
          <div className="flex items-center gap-2">
            {/* Filter dropdown */}
            <div className="relative">
              <select
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="bg-cyber-dark border border-cyber-light/30 rounded px-2 py-1 text-xs text-gray-400 appearance-none pr-6 focus:outline-none focus:border-neon-green"
              >
                <option value="all">All</option>
                <option value="errors">Errors</option>
                <option value="tools">Tools</option>
                <option value="info">Info</option>
              </select>
              <Filter className="absolute right-1.5 top-1/2 -translate-y-1/2 w-3 h-3 text-gray-500 pointer-events-none" />
            </div>

            <button
              onClick={exportLogs}
              className="p-1.5 text-gray-500 hover:text-neon-green transition-colors"
              title="Export logs"
            >
              <Download className="w-4 h-4" />
            </button>

            <button
              onClick={clearTerminal}
              className="p-1.5 text-gray-500 hover:text-neon-red transition-colors"
              title="Clear terminal"
            >
              <Trash2 className="w-4 h-4" />
            </button>

            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="p-1.5 text-gray-500 hover:text-neon-cyan transition-colors"
              title={isExpanded ? 'Minimize' : 'Maximize'}
            >
              {isExpanded ? (
                <Minimize2 className="w-4 h-4" />
              ) : (
                <Maximize2 className="w-4 h-4" />
              )}
            </button>
          </div>
        )}
      </div>

      {/* Terminal Body */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="terminal-body flex-1 overflow-y-auto font-mono text-sm"
        style={{ maxHeight: isExpanded ? 'calc(100vh - 100px)' : maxHeight }}
      >
        {filteredLines.length === 0 ? (
          <div className="text-gray-600 italic">
            Waiting for output...
            <span className="animate-blink ml-1">▌</span>
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {filteredLines.map((line) => (
              <TerminalLineComponent key={line.id} line={line} />
            ))}
          </AnimatePresence>
        )}
      </div>

      {/* Scroll to bottom indicator */}
      {!isAtBottom && (
        <button
          onClick={scrollToBottom}
          className="absolute bottom-4 right-4 bg-cyber-dark border border-neon-green/50 rounded-full p-2 text-neon-green hover:bg-neon-green/10 transition-colors"
        >
          <ChevronDown className="w-4 h-4" />
        </button>
      )}
    </div>
  );
};

// ============================================
// Terminal Line Component
// ============================================

interface TerminalLineProps {
  line: TerminalLine;
}

const TerminalLineComponent: React.FC<TerminalLineProps> = ({ line }) => {
  const typeColors = {
    input: 'text-neon-cyan',
    output: 'text-terminal-text',
    error: 'text-terminal-red',
    info: 'text-terminal-blue',
    success: 'text-terminal-green',
    warning: 'text-terminal-yellow',
  };

  const typePrefix = {
    input: '$ ',
    output: '',
    error: '✗ ',
    info: 'ℹ ',
    success: '✓ ',
    warning: '⚠ ',
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: -10 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.15 }}
      className={cn(
        'py-0.5 break-all whitespace-pre-wrap',
        typeColors[line.type]
      )}
    >
      <span className="text-gray-600 mr-2 text-xs select-none">
        {formatTimestamp(line.timestamp)}
      </span>
      {line.tool && (
        <span className="text-neon-purple mr-1">[{line.tool}]</span>
      )}
      <span className="select-none">{typePrefix[line.type]}</span>
      <span>{line.content}</span>
    </motion.div>
  );
};

// ============================================
// Mini Terminal (Compact Version)
// ============================================

interface MiniTerminalProps {
  lines: string[];
  className?: string;
}

export const MiniTerminal: React.FC<MiniTerminalProps> = ({
  lines,
  className,
}) => {
  return (
    <div
      className={cn(
        'bg-cyber-black rounded-lg border border-cyber-light/20 p-3 font-mono text-xs',
        className
      )}
    >
      {lines.slice(-5).map((line, idx) => (
        <div key={idx} className="text-terminal-text truncate">
          <span className="text-neon-green mr-1">$</span>
          {line}
        </div>
      ))}
    </div>
  );
};

export default Terminal;
