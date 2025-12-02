// ============================================
// Application Configuration
// ============================================

interface Config {
  apiUrl: string;
  wsUrl: string;
  appName: string;
  version: string;
  maxLogLines: number;
  reconnectAttempts: number;
  reconnectDelay: number;
}

export const config: Config = {
  apiUrl: import.meta.env.VITE_API_URL || 'http://localhost:5000',
  wsUrl: import.meta.env.VITE_WS_URL || 'http://localhost:5000',
  appName: 'Optimus',
  version: '1.0.0',
  maxLogLines: 500,
  reconnectAttempts: 5,
  reconnectDelay: 3000,
};

// Severity configuration
export const severityConfig = {
  critical: {
    min: 9.0,
    max: 10.0,
    color: '#ff0055',
    bgColor: 'rgba(255, 0, 85, 0.1)',
    borderColor: 'rgba(255, 0, 85, 0.3)',
    label: 'Critical',
  },
  high: {
    min: 7.0,
    max: 8.9,
    color: '#ff6600',
    bgColor: 'rgba(255, 102, 0, 0.1)',
    borderColor: 'rgba(255, 102, 0, 0.3)',
    label: 'High',
  },
  medium: {
    min: 4.0,
    max: 6.9,
    color: '#ffcc00',
    bgColor: 'rgba(255, 204, 0, 0.1)',
    borderColor: 'rgba(255, 204, 0, 0.3)',
    label: 'Medium',
  },
  low: {
    min: 0.1,
    max: 3.9,
    color: '#00d4ff',
    bgColor: 'rgba(0, 212, 255, 0.1)',
    borderColor: 'rgba(0, 212, 255, 0.3)',
    label: 'Low',
  },
  info: {
    min: 0,
    max: 0,
    color: '#a0a0b0',
    bgColor: 'rgba(160, 160, 176, 0.1)',
    borderColor: 'rgba(160, 160, 176, 0.3)',
    label: 'Info',
  },
};

// Phase configuration
export const phaseConfig = {
  reconnaissance: {
    label: 'Reconnaissance',
    icon: 'Search',
    color: '#00d4ff',
    description: 'Gathering information about the target',
  },
  scanning: {
    label: 'Scanning',
    icon: 'Radar',
    color: '#00ff9d',
    description: 'Identifying open ports and services',
  },
  enumeration: {
    label: 'Enumeration',
    icon: 'List',
    color: '#9d00ff',
    description: 'Detailed service enumeration',
  },
  exploitation: {
    label: 'Exploitation',
    icon: 'Zap',
    color: '#ff6600',
    description: 'Attempting to exploit vulnerabilities',
  },
  post_exploitation: {
    label: 'Post-Exploitation',
    icon: 'Key',
    color: '#ff0055',
    description: 'Privilege escalation and persistence',
  },
  reporting: {
    label: 'Reporting',
    icon: 'FileText',
    color: '#ffcc00',
    description: 'Generating final report',
  },
};

// Tool category configuration
export const toolCategories = {
  recon: { label: 'Reconnaissance', icon: 'Search', color: '#00d4ff' },
  scanning: { label: 'Scanning', icon: 'Radar', color: '#00ff9d' },
  enumeration: { label: 'Enumeration', icon: 'List', color: '#9d00ff' },
  exploitation: { label: 'Exploitation', icon: 'Zap', color: '#ff6600' },
  post_exploitation: { label: 'Post-Exploitation', icon: 'Key', color: '#ff0055' },
  password: { label: 'Password', icon: 'Lock', color: '#ff00aa' },
  web: { label: 'Web', icon: 'Globe', color: '#00ff9d' },
  database: { label: 'Database', icon: 'Database', color: '#0066ff' },
  utility: { label: 'Utility', icon: 'Wrench', color: '#a0a0b0' },
};

// Default tools for quick execution
export const defaultTools = [
  { name: 'nmap', label: 'Nmap', category: 'scanning' },
  { name: 'nuclei', label: 'Nuclei', category: 'scanning' },
  { name: 'nikto', label: 'Nikto', category: 'web' },
  { name: 'sqlmap', label: 'SQLMap', category: 'exploitation' },
  { name: 'gobuster', label: 'Gobuster', category: 'enumeration' },
  { name: 'ffuf', label: 'FFUF', category: 'enumeration' },
  { name: 'wpscan', label: 'WPScan', category: 'web' },
  { name: 'hydra', label: 'Hydra', category: 'password' },
];

export default config;
