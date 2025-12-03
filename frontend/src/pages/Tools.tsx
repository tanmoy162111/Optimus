import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Wrench,
  Search,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Globe,
  Zap,
  Book,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { api } from '@/services/api';
import { toolCategories } from '@/config';
import {
  Card,
  Button,
  Input,
  Badge,
  Spinner,
} from '@/components';
import type { Tool } from '@/types';

// ============================================
// Tools Page
// ============================================

export const ToolsPage: React.FC = () => {
  const [tools, setTools] = useState<Tool[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);


  useEffect(() => {
    loadTools();
  }, []);

  const loadTools = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.tools.getInventory();
      setTools(data.tools);
    } catch (err) {
      setError('Failed to load tools');
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  };

  const scanForTools = async () => {
    setIsScanning(true);
    try {
      await api.tools.scan();
      await loadTools();
    } catch (err) {
      console.error('Scan failed:', err);
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

  // Group by category
  const groupedTools = filteredTools.reduce((acc, tool) => {
    if (!acc[tool.category]) {
      acc[tool.category] = [];
    }
    acc[tool.category].push(tool);
    return acc;
  }, {} as Record<string, Tool[]>);

  const categories = Object.keys(toolCategories);
  const availableCount = tools.filter((t) => t.is_available).length;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-center">
          <Spinner size="lg" />
          <p className="text-gray-400 mt-4">Loading tools...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col md:flex-row md:items-center md:justify-between gap-4"
      >
        <div>
          <h1 className="text-2xl md:text-3xl font-bold text-white display-text mb-2">
            Tool Inventory
          </h1>
          <p className="text-gray-400">
            {availableCount} of {tools.length} tools available
          </p>
        </div>

        <Button
          variant="primary"
          onClick={scanForTools}
          isLoading={isScanning}
        >
          <RefreshCw className={cn('w-4 h-4', isScanning && 'animate-spin')} />
          Scan System
        </Button>
      </motion.div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <ToolStatCard
          label="Total Tools"
          value={tools.length}
          icon={Wrench}
          color="#00ff9d"
        />
        <ToolStatCard
          label="Available"
          value={availableCount}
          icon={CheckCircle}
          color="#00d4ff"
        />
        <ToolStatCard
          label="Knowledge Base"
          value={tools.filter((t) => t.source === 'knowledge_base').length}
          icon={Book}
          color="#9d00ff"
        />
        <ToolStatCard
          label="Discovered"
          value={tools.filter((t) => t.source === 'discovered').length}
          icon={Search}
          color="#ff6600"
        />
      </div>

      {/* Search & Filters */}
      <Card variant="default" className="p-4">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <Input
              placeholder="Search tools..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              icon={<Search className="w-4 h-4" />}
            />
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setSelectedCategory(null)}
              className={cn(
                'px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
                !selectedCategory
                  ? 'bg-neon-green/20 text-neon-green border border-neon-green/30'
                  : 'bg-cyber-light text-gray-400 hover:text-white'
              )}
            >
              All
            </button>
            {categories.map((cat) => {
              const config = toolCategories[cat as keyof typeof toolCategories];
              const count = tools.filter((t) => t.category === cat).length;
              if (count === 0) return null;

              return (
                <button
                  key={cat}
                  onClick={() =>
                    setSelectedCategory(cat === selectedCategory ? null : cat)
                  }
                  className={cn(
                    'px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
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
                  {config.label} ({count})
                </button>
              );
            })}
          </div>
        </div>
      </Card>

      {/* Tools Grid */}
      {error ? (
        <Card variant="default" className="p-6 text-center">
          <AlertTriangle className="w-12 h-12 text-neon-orange mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">Error</h2>
          <p className="text-gray-400 mb-4">{error}</p>
          <Button variant="secondary" onClick={loadTools}>
            Try Again
          </Button>
        </Card>
      ) : filteredTools.length === 0 ? (
        <Card variant="default" className="p-6 text-center">
          <Wrench className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h2 className="text-xl font-bold text-white mb-2">No tools found</h2>
          <p className="text-gray-400">
            {searchQuery
              ? 'Try a different search term'
              : 'Click "Scan System" to discover available tools'}
          </p>
        </Card>
      ) : (
        <div className="space-y-6">
          {Object.entries(groupedTools).map(([category, categoryTools]) => {
            const config = toolCategories[category as keyof typeof toolCategories] || {
              label: category,
              color: '#a0a0b0',
            };

            return (
              <div key={category}>
                <div className="flex items-center gap-2 mb-4">
                  <div
                    className="w-1 h-6 rounded"
                    style={{ backgroundColor: config.color }}
                  />
                  <h2 className="text-lg font-semibold text-white">
                    {config.label}
                  </h2>
                  <Badge variant="default" size="sm">
                    {categoryTools.length}
                  </Badge>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {categoryTools.map((tool) => (
                    <ToolCard key={tool.name} tool={tool} color={config.color} />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// ============================================
// Tool Stat Card Component
// ============================================

interface ToolStatCardProps {
  label: string;
  value: number;
  icon: React.FC<{ className?: string }>;
  color: string;
}

const ToolStatCard: React.FC<ToolStatCardProps> = ({
  label,
  value,
  icon: Icon,
  color,
}) => {
  return (
    <Card variant="default" className="p-4">
      <div className="flex items-center gap-3">
        <div
          className="w-10 h-10 rounded-lg flex items-center justify-center"
          style={{ backgroundColor: `${color}20` }}
        >
          <div className="w-5 h-5" style={{ color }}>
            <Icon className="w-full h-full" />
          </div>
        </div>
        <div>
          <p className="text-2xl font-bold text-white">{value}</p>
          <p className="text-xs text-gray-500">{label}</p>
        </div>
      </div>
    </Card>
  );
};

// ============================================
// Tool Card Component
// ============================================

interface ToolCardProps {
  tool: Tool;
  color: string;
}

const ToolCard: React.FC<ToolCardProps> = ({ tool, color }) => {
  const sourceIcons = {
    knowledge_base: Book,
    discovered: Search,
    llm_generated: Zap,
    web_research: Globe,
  };

  const SourceIcon = sourceIcons[tool.source] || Wrench;

  return (
    <Card variant="default" className="p-4 group hover:border-opacity-50">
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <h3 className="text-white font-medium">{tool.name}</h3>
          {tool.requires_root && (
            <Badge variant="warning" size="sm">
              Root
            </Badge>
          )}
        </div>
        {tool.is_available ? (
          <CheckCircle className="w-4 h-4 text-neon-green" />
        ) : (
          <XCircle className="w-4 h-4 text-gray-500" />
        )}
      </div>

      <p className="text-sm text-gray-400 mb-4 line-clamp-2">
        {tool.description}
      </p>

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3" style={{ color }}>
            <SourceIcon className="w-full h-full" />
          </div>
          <span className="text-xs text-gray-500 capitalize">
            {tool.source.replace(/_/g, ' ')}
          </span>
        </div>

        {tool.version && (
          <span className="text-xs text-gray-600">v{tool.version}</span>
        )}
      </div>
    </Card>
  );
};

export default ToolsPage;
