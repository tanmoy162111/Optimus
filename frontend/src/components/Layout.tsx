import React, { useState } from 'react';
import { Link, useLocation, Outlet } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  LayoutDashboard,
  Target,
  Shield,
  Wrench,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Bell,
  Menu,
  X,
  Wifi,
  WifiOff,
  Activity,
  Brain,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useUIStore, useConnectionStore, useScanStore } from '@/stores';
import { Badge, StatusIndicator } from '@/components/ui';

// ============================================
// Navigation Items
// ============================================

const navItems = [
  { path: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/scan', icon: Target, label: 'New Scan' },
  { path: '/findings', icon: Shield, label: 'Findings' },
  { path: '/tools', icon: Wrench, label: 'Tools' },
  { path: '/reports', icon: FileText, label: 'Reports' },
  { path: '/intelligence', icon: Brain, label: 'Intelligence' },
  { path: '/settings', icon: Settings, label: 'Settings' },
];

// ============================================
// Layout Component
// ============================================

export const Layout: React.FC = () => {
  const location = useLocation();
  const { sidebarCollapsed, setSidebarCollapsed, notifications } = useUIStore();
  const { isConnected } = useConnectionStore();
  const { isScanning, currentScan } = useScanStore();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <div className="min-h-screen bg-cyber-black flex">
      {/* Desktop Sidebar */}
      <aside
        className={cn(
          'hidden lg:flex flex-col fixed left-0 top-0 h-full z-40 transition-all duration-300',
          'bg-cyber-darker border-r border-cyber-light/20',
          sidebarCollapsed ? 'w-16' : 'w-64'
        )}
      >
        {/* Logo */}
        <div className="h-16 flex items-center justify-between px-4 border-b border-cyber-light/20">
          <Link to="/" className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-neon-green to-neon-cyan flex items-center justify-center">
              <Activity className="w-5 h-5 text-cyber-black" />
            </div>
            {!sidebarCollapsed && (
              <span className="text-xl font-bold text-white display-text tracking-wider">
                OPTIMUS
              </span>
            )}
          </Link>

          <button
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="text-gray-500 hover:text-white transition-colors"
          >
            {sidebarCollapsed ? (
              <ChevronRight className="w-4 h-4" />
            ) : (
              <ChevronLeft className="w-4 h-4" />
            )}
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const isActive = location.pathname === item.path;
            return (
              <NavItem
                key={item.path}
                to={item.path}
                icon={item.icon}
                label={item.label}
                isActive={isActive}
                collapsed={sidebarCollapsed}
              />
            );
          })}
        </nav>

        {/* Active Scan Indicator */}
        {isScanning && currentScan && (
          <div
            className={cn(
              'mx-2 mb-2 p-3 rounded-lg bg-neon-green/10 border border-neon-green/30',
              sidebarCollapsed && 'p-2'
            )}
          >
            {sidebarCollapsed ? (
              <div className="w-full flex justify-center">
                <span className="w-2 h-2 bg-neon-green rounded-full animate-pulse" />
              </div>
            ) : (
              <>
                <div className="flex items-center gap-2 mb-1">
                  <span className="w-2 h-2 bg-neon-green rounded-full animate-pulse" />
                  <span className="text-xs text-neon-green font-medium">
                    Scan in Progress
                  </span>
                </div>
                <p className="text-xs text-gray-400 truncate">
                  {currentScan.target}
                </p>
              </>
            )}
          </div>
        )}

        {/* Connection Status */}
        <div className="p-4 border-t border-cyber-light/20">
          <div className={cn('flex items-center', sidebarCollapsed ? 'justify-center' : 'gap-2')}>
            {isConnected ? (
              <>
                <Wifi className="w-4 h-4 text-neon-green" />
                {!sidebarCollapsed && (
                  <span className="text-xs text-neon-green">Connected</span>
                )}
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4 text-neon-red" />
                {!sidebarCollapsed && (
                  <span className="text-xs text-neon-red">Disconnected</span>
                )}
              </>
            )}
          </div>
        </div>
      </aside>

      {/* Mobile Header */}
      <header className="lg:hidden fixed top-0 left-0 right-0 h-16 z-50 bg-cyber-darker border-b border-cyber-light/20">
        <div className="flex items-center justify-between h-full px-4">
          <button
            onClick={() => setMobileMenuOpen(true)}
            className="text-gray-400 hover:text-white"
          >
            <Menu className="w-6 h-6" />
          </button>

          <Link to="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-neon-green to-neon-cyan flex items-center justify-center">
              <Activity className="w-5 h-5 text-cyber-black" />
            </div>
            <span className="text-lg font-bold text-white display-text">
              OPTIMUS
            </span>
          </Link>

          <div className="flex items-center gap-2">
            <StatusIndicator
              status={isConnected ? 'online' : 'offline'}
              pulse={isConnected}
            />
            <NotificationButton count={unreadCount} />
          </div>
        </div>
      </header>

      {/* Mobile Menu */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="lg:hidden fixed inset-0 bg-black/50 z-50"
              onClick={() => setMobileMenuOpen(false)}
            />
            <motion.div
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="lg:hidden fixed left-0 top-0 bottom-0 w-64 bg-cyber-darker z-50"
            >
              <div className="h-16 flex items-center justify-between px-4 border-b border-cyber-light/20">
                <span className="text-xl font-bold text-white display-text">
                  OPTIMUS
                </span>
                <button
                  onClick={() => setMobileMenuOpen(false)}
                  className="text-gray-400 hover:text-white"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <nav className="py-4 px-2 space-y-1">
                {navItems.map((item) => {
                  const isActive = location.pathname === item.path;
                  return (
                    <NavItem
                      key={item.path}
                      to={item.path}
                      icon={item.icon}
                      label={item.label}
                      isActive={isActive}
                      collapsed={false}
                      onClick={() => setMobileMenuOpen(false)}
                    />
                  );
                })}
              </nav>
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* Main Content */}
      <main
        className={cn(
          'flex-1 min-h-screen transition-all duration-300',
          'pt-16 lg:pt-0',
          sidebarCollapsed ? 'lg:ml-16' : 'lg:ml-64'
        )}
      >
        {/* Top Bar (Desktop) */}
        <div className="hidden lg:flex h-16 items-center justify-between px-6 border-b border-cyber-light/20 bg-cyber-darker/50 backdrop-blur">
          <div className="flex items-center gap-4">
            <h1 className="text-lg font-medium text-white">
              {navItems.find((item) => item.path === location.pathname)?.label || 'Optimus'}
            </h1>
            {isScanning && (
              <Badge variant="success" size="sm">
                <span className="w-1.5 h-1.5 bg-current rounded-full animate-pulse mr-1" />
                Scanning
              </Badge>
            )}
          </div>

          <div className="flex items-center gap-4">
            <StatusIndicator
              status={isConnected ? 'online' : 'offline'}
              label={isConnected ? 'Connected' : 'Disconnected'}
              pulse={isConnected}
            />
            <NotificationButton count={unreadCount} />
          </div>
        </div>

        {/* Page Content */}
        <div className="p-4 lg:p-6">
          <Outlet />
        </div>
      </main>

      {/* Background Effects */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute inset-0 cyber-grid opacity-30" />
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-neon-green/5 rounded-full blur-[100px]" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-neon-cyan/5 rounded-full blur-[100px]" />
      </div>
    </div>
  );
};

// ============================================
// Nav Item Component
// ============================================

interface NavItemProps {
  to: string;
  icon: React.FC<{ className?: string }>;
  label: string;
  isActive: boolean;
  collapsed: boolean;
  onClick?: () => void;
}

const NavItem: React.FC<NavItemProps> = ({
  to,
  icon: Icon,
  label,
  isActive,
  collapsed,
  onClick,
}) => {
  return (
    <Link
      to={to}
      onClick={onClick}
      className={cn(
        'flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 relative',
        'text-gray-400 hover:text-white hover:bg-cyber-light/30',
        isActive && 'bg-neon-green/10 text-neon-green hover:bg-neon-green/15',
        collapsed && 'justify-center px-2'
      )}
    >
      <Icon className={cn('w-5 h-5 flex-shrink-0', isActive && 'text-neon-green')} />
      {!collapsed && (
        <span className="font-medium text-sm">{label}</span>
      )}
      {isActive && (
        <motion.div
          layoutId="nav-indicator"
          className="absolute left-0 w-1 h-6 bg-neon-green rounded-r"
          transition={{ type: 'spring', stiffness: 500, damping: 30 }}
        />
      )}
    </Link>
  );
};

// ============================================
// Notification Button Component
// ============================================

interface NotificationButtonProps {
  count: number;
}

const NotificationButton: React.FC<NotificationButtonProps> = ({ count }) => {
  return (
    <button className="relative p-2 text-gray-400 hover:text-white transition-colors">
      <Bell className="w-5 h-5" />
      {count > 0 && (
        <span className="absolute -top-0.5 -right-0.5 w-4 h-4 bg-neon-red text-white text-[10px] font-bold flex items-center justify-center rounded-full">
          {count > 9 ? '9+' : count}
        </span>
      )}
    </button>
  );
};

export default Layout;
