import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Settings,
  User,
  Bell,
  Shield,
  Palette,
  Database,
  Server,
  Key,
  Save,
  RefreshCw,
  Check,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useUIStore } from '@/stores';
import { Card, Button, Input, Badge } from '@/components';

// ============================================
// Settings Page
// ============================================

export const SettingsPage: React.FC = () => {
  const [activeTab, setActiveTab] = useState('general');
  const [isSaving, setIsSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const tabs = [
    { id: 'general', label: 'General', icon: Settings },
    { id: 'scanning', label: 'Scanning', icon: Shield },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'api', label: 'API & Integrations', icon: Key },
  ];

  const handleSave = async () => {
    setIsSaving(true);
    // Simulate save
    await new Promise((resolve) => setTimeout(resolve, 1000));
    setIsSaving(false);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

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
            Settings
          </h1>
          <p className="text-gray-400">Configure your Optimus preferences</p>
        </div>

        <Button
          variant={saved ? 'primary' : 'cyber'}
          onClick={handleSave}
          isLoading={isSaving}
        >
          {saved ? (
            <>
              <Check className="w-4 h-4" />
              Saved
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              Save Changes
            </>
          )}
        </Button>
      </motion.div>

      {/* Tabs & Content */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Tabs Sidebar */}
        <div className="space-y-2">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  'w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors text-left',
                  activeTab === tab.id
                    ? 'bg-neon-green/10 text-neon-green'
                    : 'text-gray-400 hover:bg-cyber-light/30 hover:text-white'
                )}
              >
                <Icon className="w-5 h-5" />
                <span className="font-medium">{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Settings Content */}
        <div className="lg:col-span-3">
          {activeTab === 'general' && <GeneralSettings />}
          {activeTab === 'scanning' && <ScanningSettings />}
          {activeTab === 'notifications' && <NotificationSettings />}
          {activeTab === 'api' && <ApiSettings />}
        </div>
      </div>
    </div>
  );
};

// ============================================
// General Settings
// ============================================

const GeneralSettings: React.FC = () => {
  const { theme, setTheme } = useUIStore();

  return (
    <Card variant="default" padding="lg">
      <h2 className="text-lg font-semibold text-white mb-6">General Settings</h2>

      <div className="space-y-6">
        {/* Theme */}
        <SettingItem
          title="Theme"
          description="Choose your preferred color scheme"
        >
          <div className="flex gap-2">
            <button
              onClick={() => setTheme('dark')}
              className={cn(
                'px-4 py-2 rounded-lg border-2 transition-colors',
                theme === 'dark'
                  ? 'border-neon-green bg-neon-green/10 text-neon-green'
                  : 'border-cyber-light text-gray-400 hover:text-white'
              )}
            >
              Dark
            </button>
            <button
              onClick={() => setTheme('light')}
              className={cn(
                'px-4 py-2 rounded-lg border-2 transition-colors',
                theme === 'light'
                  ? 'border-neon-green bg-neon-green/10 text-neon-green'
                  : 'border-cyber-light text-gray-400 hover:text-white'
              )}
              disabled
            >
              Light (Coming Soon)
            </button>
          </div>
        </SettingItem>

        {/* Language */}
        <SettingItem
          title="Language"
          description="Select your preferred language"
        >
          <select className="bg-cyber-darker border border-cyber-light/50 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-neon-green">
            <option value="en">English</option>
            <option value="es" disabled>
              Spanish (Coming Soon)
            </option>
            <option value="fr" disabled>
              French (Coming Soon)
            </option>
          </select>
        </SettingItem>

        {/* Terminal Lines */}
        <SettingItem
          title="Terminal Buffer Size"
          description="Maximum number of lines to keep in terminal history"
        >
          <Input
            type="number"
            defaultValue={500}
            className="w-32"
          />
        </SettingItem>
      </div>
    </Card>
  );
};

// ============================================
// Scanning Settings
// ============================================

const ScanningSettings: React.FC = () => {
  return (
    <Card variant="default" padding="lg">
      <h2 className="text-lg font-semibold text-white mb-6">Scanning Settings</h2>

      <div className="space-y-6">
        {/* Default Scan Mode */}
        <SettingItem
          title="Default Scan Mode"
          description="Default mode for new scans"
        >
          <select className="bg-cyber-darker border border-cyber-light/50 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-neon-green">
            <option value="quick">Quick Scan</option>
            <option value="standard">Standard</option>
            <option value="full">Full Pentest</option>
          </select>
        </SettingItem>

        {/* AI Settings */}
        <SettingItem
          title="AI-Powered Analysis"
          description="Use machine learning for intelligent vulnerability detection"
        >
          <ToggleSwitch defaultChecked />
        </SettingItem>

        {/* Exploitation */}
        <SettingItem
          title="Enable Exploitation by Default"
          description="Automatically attempt to exploit discovered vulnerabilities"
        >
          <ToggleSwitch />
        </SettingItem>

        {/* Timeout */}
        <SettingItem
          title="Default Scan Timeout"
          description="Maximum scan duration in seconds"
        >
          <Input
            type="number"
            defaultValue={3600}
            className="w-32"
          />
        </SettingItem>

        {/* Concurrent Tools */}
        <SettingItem
          title="Concurrent Tool Execution"
          description="Maximum number of tools to run simultaneously"
        >
          <Input
            type="number"
            defaultValue={3}
            min={1}
            max={10}
            className="w-32"
          />
        </SettingItem>
      </div>
    </Card>
  );
};

// ============================================
// Notification Settings
// ============================================

const NotificationSettings: React.FC = () => {
  return (
    <Card variant="default" padding="lg">
      <h2 className="text-lg font-semibold text-white mb-6">
        Notification Settings
      </h2>

      <div className="space-y-6">
        {/* Scan Notifications */}
        <SettingItem
          title="Scan Complete Notifications"
          description="Show notification when a scan finishes"
        >
          <ToggleSwitch defaultChecked />
        </SettingItem>

        {/* Critical Findings */}
        <SettingItem
          title="Critical Finding Alerts"
          description="Immediate notification for critical vulnerabilities"
        >
          <ToggleSwitch defaultChecked />
        </SettingItem>

        {/* Sound */}
        <SettingItem
          title="Notification Sounds"
          description="Play sound for important notifications"
        >
          <ToggleSwitch />
        </SettingItem>

        {/* Email Notifications */}
        <SettingItem
          title="Email Notifications"
          description="Send scan reports via email"
        >
          <ToggleSwitch />
        </SettingItem>

        {/* Email */}
        <SettingItem
          title="Notification Email"
          description="Email address for notifications"
        >
          <Input
            type="email"
            placeholder="your@email.com"
            className="w-64"
          />
        </SettingItem>
      </div>
    </Card>
  );
};

// ============================================
// API Settings
// ============================================

const ApiSettings: React.FC = () => {
  const [showKey, setShowKey] = useState(false);

  return (
    <Card variant="default" padding="lg">
      <h2 className="text-lg font-semibold text-white mb-6">
        API & Integrations
      </h2>

      <div className="space-y-6">
        {/* API Key */}
        <SettingItem
          title="API Key"
          description="Your Optimus API key for external integrations"
        >
          <div className="flex items-center gap-2">
            <Input
              type={showKey ? 'text' : 'password'}
              value="opt_sk_xxxxxxxxxxxxxxxxxxxx"
              readOnly
              className="w-72 font-mono"
            />
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowKey(!showKey)}
            >
              {showKey ? 'Hide' : 'Show'}
            </Button>
            <Button variant="secondary" size="sm">
              Regenerate
            </Button>
          </div>
        </SettingItem>

        {/* Webhook URL */}
        <SettingItem
          title="Webhook URL"
          description="Receive scan events at this URL"
        >
          <Input
            type="url"
            placeholder="https://your-server.com/webhook"
            className="w-96"
          />
        </SettingItem>

        {/* Integrations */}
        <div className="pt-4 border-t border-cyber-light/20">
          <h3 className="text-sm font-medium text-white mb-4">Integrations</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <IntegrationCard
              name="Slack"
              description="Send notifications to Slack channels"
              connected={false}
            />
            <IntegrationCard
              name="Jira"
              description="Create issues for findings"
              connected={false}
            />
            <IntegrationCard
              name="GitHub"
              description="Create security advisories"
              connected={false}
            />
            <IntegrationCard
              name="Splunk"
              description="Send logs to Splunk SIEM"
              connected={false}
            />
          </div>
        </div>
      </div>
    </Card>
  );
};

// ============================================
// Setting Item Component
// ============================================

interface SettingItemProps {
  title: string;
  description: string;
  children: React.ReactNode;
}

const SettingItem: React.FC<SettingItemProps> = ({
  title,
  description,
  children,
}) => {
  return (
    <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-4 border-b border-cyber-light/20 last:border-0 last:pb-0">
      <div>
        <h4 className="text-white font-medium">{title}</h4>
        <p className="text-sm text-gray-500">{description}</p>
      </div>
      <div>{children}</div>
    </div>
  );
};

// ============================================
// Toggle Switch Component
// ============================================

interface ToggleSwitchProps {
  defaultChecked?: boolean;
  onChange?: (checked: boolean) => void;
}

const ToggleSwitch: React.FC<ToggleSwitchProps> = ({
  defaultChecked = false,
  onChange,
}) => {
  const [checked, setChecked] = useState(defaultChecked);

  const handleToggle = () => {
    const newValue = !checked;
    setChecked(newValue);
    onChange?.(newValue);
  };

  return (
    <button
      onClick={handleToggle}
      className={cn(
        'w-12 h-6 rounded-full transition-colors relative',
        checked ? 'bg-neon-green' : 'bg-cyber-light'
      )}
    >
      <span
        className={cn(
          'absolute top-1 w-4 h-4 rounded-full bg-white transition-transform',
          checked ? 'translate-x-6' : 'translate-x-1'
        )}
      />
    </button>
  );
};

// ============================================
// Integration Card Component
// ============================================

interface IntegrationCardProps {
  name: string;
  description: string;
  connected: boolean;
}

const IntegrationCard: React.FC<IntegrationCardProps> = ({
  name,
  description,
  connected,
}) => {
  return (
    <div className="p-4 rounded-lg bg-cyber-dark/50 border border-cyber-light/20">
      <div className="flex items-start justify-between mb-2">
        <h4 className="text-white font-medium">{name}</h4>
        <Badge variant={connected ? 'success' : 'default'} size="sm">
          {connected ? 'Connected' : 'Not Connected'}
        </Badge>
      </div>
      <p className="text-sm text-gray-500 mb-3">{description}</p>
      <Button variant="secondary" size="sm">
        {connected ? 'Configure' : 'Connect'}
      </Button>
    </div>
  );
};

export default SettingsPage;
