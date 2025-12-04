import React, { Suspense } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Layout, ErrorBoundary, LoadingFallback } from '@/components';
import {
  DashboardPage,
  ScanPage,
  FindingsPage,
  ToolsPage,
  ReportsPage,
  ReportDetailPage,
  SettingsPage,
} from '@/pages';

// Import the useSocket hook
import { useSocket } from '@/hooks';

// Placeholder component since it's not imported
const IntelligencePage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl md:text-3xl font-bold text-white display-text mb-2">
          Intelligence Center
        </h1>
        <p className="text-gray-400">
          AI/ML metrics, threat intelligence, and learning insights
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="p-6 rounded-xl bg-cyber-dark border border-cyber-light/30 text-center">
          <div className="w-16 h-16 rounded-full bg-neon-purple/20 flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-neon-purple" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-white mb-2">ML Models</h3>
          <p className="text-gray-500 text-sm">
            Vulnerability classification and risk prediction models
          </p>
        </div>

        <div className="p-6 rounded-xl bg-cyber-dark border border-cyber-light/30 text-center">
          <div className="w-16 h-16 rounded-full bg-neon-cyan/20 flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-neon-cyan" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-white mb-2">RL Agent</h3>
          <p className="text-gray-500 text-sm">
            Reinforcement learning for adaptive tool selection
          </p>
        </div>

        <div className="p-6 rounded-xl bg-cyber-dark border border-cyber-light/30 text-center">
          <div className="w-16 h-16 rounded-full bg-neon-orange/20 flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-neon-orange" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <h3 className="text-lg font-semibold text-white mb-2">Threat Intel</h3>
          <p className="text-gray-500 text-sm">
            CVE database, exploit feeds, and threat indicators
          </p>
        </div>
      </div>

      <div className="text-center py-12">
        <p className="text-gray-600">
          Full intelligence dashboard coming in the next release
        </p>
      </div>
    </div>
  );
};

// ============================================
// App Component
// ============================================

function App() {
  // Initialize WebSocket connection
  useSocket();

  return (
    <ErrorBoundary>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route
              index
              element={
                <Suspense fallback={<LoadingFallback />}>
                  <DashboardPage />
                </Suspense>
              }
            />
            <Route
              path="scan"
              element={
                <Suspense fallback={<LoadingFallback />}>
                  <ScanPage />
                </Suspense>
              }
            />
            <Route
              path="findings"
              element={
                <Suspense fallback={<LoadingFallback />}>
                  <FindingsPage />
                </Suspense>
              }
            />
            <Route
              path="tools"
              element={
                <Suspense fallback={<LoadingFallback />}>
                  <ToolsPage />
                </Suspense>
              }
            />
            <Route
              path="reports"
              element={
                <Suspense fallback={<LoadingFallback />}>
                  <ReportsPage />
                </Suspense>
              }
            />
            <Route
              path="report/:scanId"
              element={
                <Suspense fallback={<LoadingFallback />}>
                  <ReportDetailPage />
                </Suspense>
              }
            />
            <Route
              path="intelligence"
              element={
                <Suspense fallback={<LoadingFallback />}>
                  <IntelligencePage />
                </Suspense>
              }
            />
            <Route
              path="settings"
              element={
                <Suspense fallback={<LoadingFallback />}>
                  <SettingsPage />
                </Suspense>
              }
            />
            {/* 404 */}
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  );
}

// ============================================
// 404 Page
// ============================================

const NotFoundPage: React.FC = () => {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="text-center">
        <h1 className="text-6xl font-bold text-neon-green display-text mb-4">404</h1>
        <h2 className="text-2xl font-bold text-white mb-4">Page Not Found</h2>
        <p className="text-gray-400 mb-8">
          The page you're looking for doesn't exist or has been moved.
        </p>
        <a
          href="/"
          className="inline-flex items-center gap-2 px-6 py-3 bg-neon-green text-cyber-black font-medium rounded-lg hover:bg-neon-green/90 transition-colors"
        >
          Go to Dashboard
        </a>
      </div>
    </div>
  );
};

export default App;