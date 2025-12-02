import React, { forwardRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Check, AlertTriangle, Info, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { severityConfig } from '@/config';
import type { SeverityLevel } from '@/types';

// ============================================
// Button Component
// ============================================

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'danger' | 'neon';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'primary', size = 'md', isLoading, children, disabled, ...props }, ref) => {
    const baseStyles = 'inline-flex items-center justify-center font-medium transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed';
    
    const variants = {
      primary: 'bg-neon-green/10 hover:bg-neon-green/20 text-neon-green border border-neon-green/30 hover:border-neon-green/50',
      secondary: 'bg-cyber-light hover:bg-cyber-medium text-white border border-cyber-light',
      ghost: 'hover:bg-cyber-light text-gray-400 hover:text-white',
      danger: 'bg-neon-red/10 hover:bg-neon-red/20 text-neon-red border border-neon-red/30',
      neon: 'btn-neon',
    };
    
    const sizes = {
      sm: 'px-3 py-1.5 text-xs rounded-md gap-1.5',
      md: 'px-4 py-2 text-sm rounded-lg gap-2',
      lg: 'px-6 py-3 text-base rounded-lg gap-2',
    };
    
    return (
      <button
        ref={ref}
        className={cn(baseStyles, variants[variant], sizes[size], className)}
        disabled={disabled || isLoading}
        {...props}
      >
        {isLoading && (
          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
        )}
        {children}
      </button>
    );
  }
);
Button.displayName = 'Button';

// ============================================
// Card Component
// ============================================

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'glow' | 'gradient';
}

export const Card = forwardRef<HTMLDivElement, CardProps>(
  ({ className, variant = 'default', children, ...props }, ref) => {
    const variants = {
      default: 'cyber-card',
      glow: 'cyber-card hover:shadow-neon-green',
      gradient: 'gradient-border',
    };
    
    return (
      <div
        ref={ref}
        className={cn(variants[variant], 'p-6', className)}
        {...props}
      >
        {children}
      </div>
    );
  }
);
Card.displayName = 'Card';

// ============================================
// Input Component
// ============================================

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, label, error, icon, ...props }, ref) => {
    return (
      <div className="space-y-1.5">
        {label && (
          <label className="block text-sm text-gray-400">{label}</label>
        )}
        <div className="relative">
          {icon && (
            <div className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500">
              {icon}
            </div>
          )}
          <input
            ref={ref}
            className={cn(
              'w-full px-4 py-2.5 bg-cyber-darker border border-cyber-light rounded-lg',
              'text-white placeholder-gray-500',
              'focus:outline-none focus:border-neon-green/50 focus:ring-1 focus:ring-neon-green/20',
              'transition-all duration-200',
              icon && 'pl-10',
              error && 'border-neon-red/50',
              className
            )}
            {...props}
          />
        </div>
        {error && (
          <p className="text-xs text-neon-red">{error}</p>
        )}
      </div>
    );
  }
);
Input.displayName = 'Input';

// ============================================
// Badge Component
// ============================================

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info';
  severity?: SeverityLevel;
  size?: 'sm' | 'md';
}

export const Badge = forwardRef<HTMLSpanElement, BadgeProps>(
  ({ className, variant, severity, size = 'md', children, ...props }, ref) => {
    const getStyles = () => {
      if (severity) {
        const config = severityConfig[severity];
        return {
          backgroundColor: config.bgColor,
          color: config.color,
          borderColor: config.borderColor,
        };
      }
      
      const variants = {
        default: 'bg-cyber-light text-gray-300 border-cyber-light',
        success: 'bg-neon-green/10 text-neon-green border-neon-green/30',
        warning: 'bg-neon-orange/10 text-neon-orange border-neon-orange/30',
        danger: 'bg-neon-red/10 text-neon-red border-neon-red/30',
        info: 'bg-neon-cyan/10 text-neon-cyan border-neon-cyan/30',
      };
      
      return variants[variant || 'default'];
    };
    
    const sizes = {
      sm: 'px-2 py-0.5 text-xs',
      md: 'px-2.5 py-1 text-xs',
    };
    
    return (
      <span
        ref={ref}
        className={cn(
          'inline-flex items-center font-medium rounded-md border',
          sizes[size],
          !severity && getStyles(),
          className
        )}
        style={severity ? getStyles() as React.CSSProperties : undefined}
        {...props}
      >
        {children}
      </span>
    );
  }
);
Badge.displayName = 'Badge';

// ============================================
// Progress Component
// ============================================

interface ProgressProps {
  value: number;
  max?: number;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  variant?: 'default' | 'gradient';
  className?: string;
}

export function Progress({ 
  value, 
  max = 100, 
  size = 'md', 
  showLabel = false,
  variant = 'default',
  className 
}: ProgressProps) {
  const percentage = Math.min(100, Math.max(0, (value / max) * 100));
  
  const sizes = {
    sm: 'h-1',
    md: 'h-2',
    lg: 'h-3',
  };
  
  return (
    <div className={cn('w-full', className)}>
      <div className={cn('progress-cyber', sizes[size])}>
        <motion.div
          className={cn(
            'h-full rounded-full',
            variant === 'gradient' 
              ? 'bg-gradient-to-r from-neon-green via-neon-cyan to-neon-purple'
              : 'bg-neon-green'
          )}
          initial={{ width: 0 }}
          animate={{ width: `${percentage}%` }}
          transition={{ duration: 0.5, ease: 'easeOut' }}
          style={{ boxShadow: '0 0 10px currentColor' }}
        />
      </div>
      {showLabel && (
        <span className="text-xs text-gray-400 mt-1 block text-right">
          {percentage.toFixed(0)}%
        </span>
      )}
    </div>
  );
}

// ============================================
// Status Indicator
// ============================================

interface StatusIndicatorProps {
  status: 'online' | 'offline' | 'warning' | 'error' | 'idle';
  label?: string;
  pulse?: boolean;
  className?: string;
}

export function StatusIndicator({ status, label, pulse = true, className }: StatusIndicatorProps) {
  const statusColors = {
    online: 'bg-neon-green',
    offline: 'bg-gray-500',
    warning: 'bg-neon-orange',
    error: 'bg-neon-red',
    idle: 'bg-gray-400',
  };
  
  return (
    <div className={cn('flex items-center gap-2', className)}>
      <div className="relative">
        <div className={cn('w-2 h-2 rounded-full', statusColors[status])} />
        {pulse && status === 'online' && (
          <div className={cn(
            'absolute inset-0 rounded-full animate-ping',
            statusColors[status],
            'opacity-75'
          )} />
        )}
      </div>
      {label && (
        <span className="text-sm text-gray-400 capitalize">{label || status}</span>
      )}
    </div>
  );
}

// ============================================
// Toast/Notification Component
// ============================================

interface ToastProps {
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message?: string;
  onClose?: () => void;
  duration?: number;
}

export function Toast({ type, title, message, onClose, duration = 5000 }: ToastProps) {
  const icons = {
    success: <Check className="w-5 h-5" />,
    error: <AlertCircle className="w-5 h-5" />,
    warning: <AlertTriangle className="w-5 h-5" />,
    info: <Info className="w-5 h-5" />,
  };
  
  const colors = {
    success: 'border-neon-green/30 bg-neon-green/5 text-neon-green',
    error: 'border-neon-red/30 bg-neon-red/5 text-neon-red',
    warning: 'border-neon-orange/30 bg-neon-orange/5 text-neon-orange',
    info: 'border-neon-cyan/30 bg-neon-cyan/5 text-neon-cyan',
  };
  
  React.useEffect(() => {
    if (duration && onClose) {
      const timer = setTimeout(onClose, duration);
      return () => clearTimeout(timer);
    }
  }, [duration, onClose]);
  
  return (
    <motion.div
      initial={{ opacity: 0, y: -20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: -20, scale: 0.95 }}
      className={cn(
        'flex items-start gap-3 p-4 rounded-lg border backdrop-blur-sm',
        colors[type]
      )}
    >
      <div className="flex-shrink-0">{icons[type]}</div>
      <div className="flex-1 min-w-0">
        <p className="font-medium">{title}</p>
        {message && <p className="text-sm opacity-80 mt-0.5">{message}</p>}
      </div>
      {onClose && (
        <button
          onClick={onClose}
          className="flex-shrink-0 hover:opacity-70 transition-opacity"
        >
          <X className="w-4 h-4" />
        </button>
      )}
    </motion.div>
  );
}

// ============================================
// Toast Container
// ============================================

interface ToastContainerProps {
  toasts: Array<ToastProps & { id: string }>;
  onRemove: (id: string) => void;
}

export function ToastContainer({ toasts, onRemove }: ToastContainerProps) {
  return (
    <div className="fixed top-4 right-4 z-50 space-y-2 max-w-sm w-full">
      <AnimatePresence>
        {toasts.map((toast) => (
          <Toast
            key={toast.id}
            {...toast}
            onClose={() => onRemove(toast.id)}
          />
        ))}
      </AnimatePresence>
    </div>
  );
}

// ============================================
// Loading Spinner
// ============================================

interface SpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export function Spinner({ size = 'md', className }: SpinnerProps) {
  const sizes = {
    sm: 'w-4 h-4',
    md: 'w-8 h-8',
    lg: 'w-12 h-12',
  };
  
  return (
    <div className={cn('relative', sizes[size], className)}>
      <div className="absolute inset-0 rounded-full border-2 border-cyber-light" />
      <div className="absolute inset-0 rounded-full border-2 border-neon-green border-t-transparent animate-spin" />
    </div>
  );
}

// ============================================
// Skeleton Loader
// ============================================

interface SkeletonProps {
  className?: string;
  variant?: 'text' | 'circular' | 'rectangular';
}

export function Skeleton({ className, variant = 'rectangular' }: SkeletonProps) {
  const variants = {
    text: 'h-4 rounded',
    circular: 'rounded-full',
    rectangular: 'rounded-lg',
  };
  
  return (
    <div className={cn('skeleton', variants[variant], className)} />
  );
}

// ============================================
// Empty State
// ============================================

interface EmptyStateProps {
  icon?: React.ReactNode;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

export function EmptyState({ icon, title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center py-12 px-4', className)}>
      {icon && (
        <div className="w-16 h-16 rounded-full bg-cyber-light flex items-center justify-center mb-4">
          {icon}
        </div>
      )}
      <h3 className="text-lg font-medium text-white mb-1">{title}</h3>
      {description && (
        <p className="text-sm text-gray-400 text-center max-w-sm mb-4">{description}</p>
      )}
      {action}
    </div>
  );
}

// ============================================
// Divider
// ============================================

interface DividerProps {
  label?: string;
  className?: string;
}

export function Divider({ label, className }: DividerProps) {
  return (
    <div className={cn('flex items-center', className)}>
      <div className="flex-1 h-px bg-cyber-light" />
      {label && (
        <span className="px-4 text-xs text-gray-500 uppercase tracking-wider">{label}</span>
      )}
      <div className="flex-1 h-px bg-cyber-light" />
    </div>
  );
}
