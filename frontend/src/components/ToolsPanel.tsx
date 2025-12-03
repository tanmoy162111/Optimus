import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Wrench,
  Search,
  Play,
  Info,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  ChevronRight,
  Zap,
  Database,
  Globe,
  Lock,
  Radar,
  FileSearch,
  Book,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/services/api';
import { toolCategories } from '@/config';
import { Badge, Button, Input, Spinner } from '@/components/ui';
import type { Tool, ToolResolution } from '@/types';

// ============================================
// Category Icon Map
// ============================================

const categoryIcons: Record<string, React.FC<{ className?: string }>> = {
  recon: Search,
  scanning: Radar,
  enumeration: FileSearch,
  exploitation: Zap,
  post_exploitation: Lock,
  password: Lock,
  web: Globe,
  database: Database,
  utility: Wrench,
};

// ============================================
// Tools Panel Component
// ============================================

interface ToolsPanelProps {
  onSelectTool?: (tool: Tool) => void;
  onExecuteTool?: (tool: string, target: string) => void;
  target?: string;
  className?: string;
}

export const ToolsPanel: React.FC<ToolsPanelProps> = ({
  onSelectTool,
  onExecuteTool,
  target = '',
  className,
}) => {
  const [tools, setTools] = useState<Tool[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedTool, setSelectedTool] = useState<Tool | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  // Load tools on mount
  useEffect(() => {
    loadTools();
  }, []);

  const loadTools = async () => {
    setIsLoading(true);
    try {
      const toolsData = await api.tools.getAvailable();
      setTools(toolsData);
    } catch (error) {
      console.error('Failed to load tools:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const scanForTools = async () => {
    setIsScanning(true);
    try {
      await api.tools.scan();
      await loadTools();
    } catch (error) {
      console.error('Failed to scan for tools:', error);
    } finally {
      setIsScanning(false);
    }
  };

  // Filter tools
  const filteredTools = tools.filter((tool) => {
    const matchesSearch =
      !searchQuery ||
      tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tool.description.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesCategory =
      !selectedCategory || tool.category === selectedCategory;

    return matchesSearch && matchesCategory;
  });

  // Group tools by category
  const groupedTools = filteredTools.reduce((acc, tool) => {
    if (!acc[tool.category]) {
      acc[tool.category] = [];
    }
    acc[tool.category].push(tool);
    return acc;
  }, {} as Record<string, Tool[]>);

  const categories = Object.keys(toolCategories);

  return (
    <div className={cn('flex flex-col h-full', className)}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Wrench className="w-5 h-5 text-neon-green" />
          <h3 className="text-lg font-semibold text-white">Tools</h3>
          <Badge variant="default" size="sm">
            {tools.length}
          </Badge>
        </div>

        <Button
          variant="ghost"
          size="sm"
          onClick={scanForTools}
          disabled={isScanning}
          isLoading={isScanning}
        >
          <RefreshCw className={cn('w-4 h-4', isScanning && 'animate-spin')} />
          Scan
        </Button>
      </div>

      {/* Search */}
      <Input
        placeholder="Search tools..."
        value={searchQuery}
        onChange={(e) => setSearchQuery(e.target.value)}
        icon={<Search className="w-4 h-4" />}
        className="mb-4"
      />

      {/* Category Filter */}
      <div className="flex flex-wrap gap-2 mb-4">
        <button
          onClick={() => setSelectedCategory(null)}
          className={cn(
            'px-3 py-1 rounded-full text-xs font-medium transition-colors',
            !selectedCategory
              ? 'bg-neon-green/20 text-neon-green border border-neon-green/30'
              : 'bg-cyber-light text-gray-400 hover:text-white'
          )}
        >
          All
        </button>
        {categories.slice(0, 6).map((cat) => {
          const config = toolCategories[cat as keyof typeof toolCategories];
          return (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat === selectedCategory ? null : cat)}
              className={cn(
                'px-3 py-1 rounded-full text-xs font-medium transition-colors',
                cat === selectedCategory
                  ? 'border'
                  : 'bg-cyber-light text-gray-400 hover:text-white'
              )}
              style={
                cat === selectedCategory
                  ? {
                      backgroundColor: `${config.color}20`,
                      color: config.color,
                      borderColor: `${config.color}50`,
                    }
                  : undefined
              }
            >
              {config.label}
            </button>
          );
        })}
      </div>

      {/* Tools List */}
      <div className="flex-1 overflow-y-auto space-y-4">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Spinner size="lg" />
          </div>
        ) : Object.keys(groupedTools).length === 0 ? (
          <div className="text-center py-12">
            <Wrench className="w-12 h-12 text-gray-600 mx-auto mb-4" />
            <p className="text-gray-500">No tools found</p>
          </div>
        ) : (
          Object.entries(groupedTools).map(([category, categoryTools]) => {
            const config = toolCategories[category as keyof typeof toolCategories] || {
              label: category,
              color: '#a0a0b0',
            };
            const Icon = categoryIcons[category] || Wrench;

            return (
              <div key={category}>
                <div className="flex items-center gap-2 mb-2">
                  <div
                    className="w-4 h-4"
                    style={{ color: config.color }}
                  >
                    <Icon className="w-full h-full" />
                  </div>
                  <div style={{ color: config.color }}>
                    <span className="text-sm font-medium">
                      {config.label}
                    </span>
                  </div>
                  <span className="text-xs text-gray-600">
                    ({categoryTools.length})
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  {categoryTools.map((tool) => (
                    <ToolCard
                      key={tool.name}
                      tool={tool}
                      isSelected={selectedTool?.name === tool.name}
                      onSelect={() => {
                        setSelectedTool(tool);
                        onSelectTool?.(tool);
                      }}
                      onExecute={() => onExecuteTool?.(tool.name, target)}
                      categoryColor={config.color}
                    />
                  ))}
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* Selected Tool Details */}
      <AnimatePresence>
        {selectedTool && (
          <ToolDetails
            tool={selectedTool}
            target={target}
            onClose={() => setSelectedTool(null)}
            onExecute={() => onExecuteTool?.(selectedTool.name, target)}
          />
        )}
      </AnimatePresence>
    </div>
  );
};

// ============================================
// Tool Card Component
// ============================================

interface ToolCardProps {
  tool: Tool;
  isSelected: boolean;
  onSelect: () => void;
  onExecute: () => void;
  categoryColor: string;
}

const ToolCard: React.FC<ToolCardProps> = ({
  tool,
  isSelected,
  onSelect,
  categoryColor,
}) => {
  const sourceIcons = {
    knowledge_base: Book,
    discovered: Search,
    llm_generated: Zap,
    web_research: Globe,
  };

  const SourceIcon = sourceIcons[tool.source] || Wrench;

  return (
    <motion.div
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      className={cn(
        'p-3 rounded-lg cursor-pointer transition-all duration-200',
        'bg-cyber-dark border border-cyber-light/30',
        isSelected && 'border-neon-green/50 ring-1 ring-neon-green/20',
        !tool.is_available && 'opacity-50'
      )}
      onClick={onSelect}
    >
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-white">
            {tool.name}
          </span>
          {tool.requires_root && (
            <Lock className="w-3 h-3 text-neon-orange" />
          )}
        </div>
        <div
          className="w-3 h-3"
          style={{ color: categoryColor }}
        >
          <SourceIcon className="w-full h-full" />
        </div>
      </div>

      <p className="text-xs text-gray-500 line-clamp-2 mb-2">
        {tool.description}
      </p>

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1">
          {tool.is_available ? (
            <CheckCircle className="w-3 h-3 text-neon-green" />
          ) : (
            <XCircle className="w-3 h-3 text-gray-500" />
          )}
          <span className="text-[10px] text-gray-600">
            {tool.is_available ? 'Available' : 'Not found'}
          </span>
        </div>

        {tool.confidence !== undefined && (
          <Badge variant="default" size="sm">
            {(tool.confidence * 100).toFixed(0)}%
          </Badge>
        )}
      </div>
    </motion.div>
  );
};

// ============================================
// Tool Details Component
// ============================================

interface ToolDetailsProps {
  tool: Tool;
  target: string;
  onClose: () => void;
  onExecute: () => void;
}

const ToolDetails: React.FC<ToolDetailsProps> = ({
  tool,
  target,
  onClose,
  onExecute,
}) => {
  const [resolution, setResolution] = useState<ToolResolution | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    if (target) {
      resolveCommand();
    }
  }, [tool.name, target]);

  const resolveCommand = async () => {
    if (!target) return;
    
    setIsLoading(true);
    try {
      const result = await api.tools.resolve(
        tool.name,
        'general scan',
        target
      );
      setResolution(result);
    } catch (error) {
      console.error('Failed to resolve tool:', error);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 20 }}
      className="mt-4 p-4 bg-cyber-darker rounded-lg border border-cyber-light/30"
    >
      <div className="flex items-start justify-between mb-3">
        <div>
          <h4 className="text-white font-medium">{tool.name}</h4>
          <p className="text-xs text-gray-500">{tool.description}</p>
        </div>
        <button
          onClick={onClose}
          className="text-gray-500 hover:text-white"
        >
          ×
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-4">
          <Spinner size="sm" />
        </div>
      ) : resolution ? (
        <div className="space-y-3">
          {/* Resolution Status */}
          <div className="flex items-center gap-2">
            <Badge
              variant={
                resolution.status === 'resolved'
                  ? 'success'
                  : resolution.status === 'partial'
                  ? 'warning'
                  : 'danger'
              }
              size="sm"
            >
              {resolution.status}
            </Badge>
            <span className="text-xs text-gray-500">
              Source: {resolution.source}
            </span>
            <span className="text-xs text-gray-500">
              Confidence: {(resolution.confidence * 100).toFixed(0)}%
            </span>
          </div>

          {/* Command Preview */}
          {resolution.command && (
            <div>
              <p className="text-xs text-gray-400 mb-1">Command:</p>
              <pre className="bg-cyber-black rounded p-2 text-xs text-terminal-green font-mono overflow-x-auto">
                $ {resolution.command}
              </pre>
            </div>
          )}

          {/* Warnings */}
          {resolution.warnings.length > 0 && (
            <div className="flex items-start gap-2 p-2 bg-neon-orange/10 rounded border border-neon-orange/30">
              <AlertTriangle className="w-4 h-4 text-neon-orange flex-shrink-0 mt-0.5" />
              <div className="text-xs text-neon-orange">
                {resolution.warnings.join('. ')}
              </div>
            </div>
          )}

          {/* Execute Button */}
          <Button
            variant="primary"
            size="sm"
            className="w-full"
            onClick={onExecute}
            disabled={!target || !resolution.command}
          >
            <Play className="w-4 h-4" />
            Execute Tool
            <ChevronRight className="w-4 h-4" />
          </Button>
        </div>
      ) : (
        <div className="text-center py-4">
          <Info className="w-8 h-8 text-gray-600 mx-auto mb-2" />
          <p className="text-xs text-gray-500">
            Enter a target to preview command
          </p>
        </div>
      )}
    </motion.div>
  );
};

export default ToolsPanel;
