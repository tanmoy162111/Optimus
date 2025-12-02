import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw, Home } from 'lucide-react';
import { Button, Card } from '@/components/ui';

// ============================================
// Error Boundary Component
// ============================================

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
    this.setState({ errorInfo });
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  private handleReload = () => {
    window.location.reload();
  };

  private handleGoHome = () => {
    window.location.href = '/';
  };

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="min-h-screen bg-cyber-black flex items-center justify-center p-4">
          <Card variant="default" padding="lg" className="max-w-lg w-full text-center">
            <div className="w-16 h-16 rounded-full bg-neon-red/20 flex items-center justify-center mx-auto mb-6">
              <AlertTriangle className="w-8 h-8 text-neon-red" />
            </div>

            <h1 className="text-2xl font-bold text-white mb-2">
              Something went wrong
            </h1>
            <p className="text-gray-400 mb-6">
              An unexpected error occurred. Please try refreshing the page.
            </p>

            {this.state.error && (
              <div className="mb-6 p-4 bg-cyber-black rounded-lg text-left">
                <p className="text-sm font-mono text-neon-red mb-2">
                  {this.state.error.message}
                </p>
                {this.state.errorInfo && (
                  <pre className="text-xs text-gray-500 overflow-x-auto max-h-32">
                    {this.state.errorInfo.componentStack}
                  </pre>
                )}
              </div>
            )}

            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <Button variant="outline" onClick={this.handleReset}>
                Try Again
              </Button>
              <Button variant="secondary" onClick={this.handleReload}>
                <RefreshCw className="w-4 h-4" />
                Reload Page
              </Button>
              <Button variant="primary" onClick={this.handleGoHome}>
                <Home className="w-4 h-4" />
                Go Home
              </Button>
            </div>
          </Card>
        </div>
      );
    }

    return this.props.children;
  }
}

// ============================================
// Page Error Fallback Component
// ============================================

interface PageErrorProps {
  error?: Error;
  resetError?: () => void;
}

export const PageError: React.FC<PageErrorProps> = ({ error, resetError }) => {
  return (
    <div className="flex items-center justify-center min-h-[400px]">
      <Card variant="default" padding="lg" className="max-w-md w-full text-center">
        <AlertTriangle className="w-12 h-12 text-neon-orange mx-auto mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">
          Failed to load this page
        </h2>
        <p className="text-gray-400 mb-4">
          {error?.message || 'An error occurred while loading this content.'}
        </p>
        {resetError && (
          <Button variant="outline" onClick={resetError}>
            <RefreshCw className="w-4 h-4" />
            Try Again
          </Button>
        )}
      </Card>
    </div>
  );
};

// ============================================
// Loading Fallback Component
// ============================================

export const LoadingFallback: React.FC = () => {
  return (
    <div className="flex items-center justify-center min-h-[400px]">
      <div className="text-center">
        <div className="w-12 h-12 border-2 border-cyber-light border-t-neon-green rounded-full animate-spin mx-auto mb-4" />
        <p className="text-gray-400">Loading...</p>
      </div>
    </div>
  );
};

export default ErrorBoundary;
