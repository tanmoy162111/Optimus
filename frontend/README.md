# 🎯 Optimus Frontend

A modern, cyberpunk-themed React frontend for the Optimus AI-driven autonomous penetration testing platform.

## ✨ Features

- **Real-time Dashboard** - Live scan monitoring, vulnerability stats, and system health
- **Scan Management** - Configure and launch penetration tests with customizable options
- **Findings Explorer** - Filter, search, and analyze discovered vulnerabilities
- **Tool Inventory** - Browse available security tools with the hybrid tool system
- **Report Generation** - Export professional reports in multiple formats
- **WebSocket Integration** - Real-time updates for scan progress and findings
- **Responsive Design** - Works on desktop, tablet, and mobile devices

## 🚀 Tech Stack

- **React 18** - UI library
- **TypeScript** - Type safety
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **Zustand** - State management
- **Socket.io** - Real-time communication
- **Framer Motion** - Animations
- **Recharts** - Data visualization
- **Lucide React** - Icons

## 📁 Project Structure

```
src/
├── components/          # Reusable UI components
│   ├── ui/              # Base UI components (Button, Card, Badge, etc.)
│   ├── Terminal.tsx     # Real-time terminal output
│   ├── Findings.tsx     # Vulnerability display components
│   ├── ScanProgress.tsx # Scan phase visualization
│   ├── ToolsPanel.tsx   # Tool selection and resolution
│   ├── StatsCards.tsx   # Dashboard statistics
│   ├── Layout.tsx       # App shell with navigation
│   └── ErrorBoundary.tsx# Error handling
│
├── pages/               # Page components
│   ├── Dashboard.tsx    # Main dashboard
│   ├── Scan.tsx         # New scan configuration
│   ├── Findings.tsx     # Vulnerability explorer
│   ├── Tools.tsx        # Tool inventory
│   ├── Reports.tsx      # Report list and details
│   └── Settings.tsx     # App configuration
│
├── services/            # API and WebSocket services
│   ├── api.ts           # REST API client
│   └── socket.ts        # WebSocket singleton
│
├── stores/              # Zustand state stores
│   └── index.ts         # Global state management
│
├── hooks/               # Custom React hooks
│   └── index.ts         # WebSocket, data fetching hooks
│
├── types/               # TypeScript definitions
│   └── index.ts         # All interfaces and types
│
├── config/              # Configuration
│   └── index.ts         # App settings and constants
│
├── lib/                 # Utilities
│   └── utils.ts         # Helper functions
│
├── App.tsx              # Root component with routing
├── main.tsx             # Entry point
└── index.css            # Global styles
```

## 🛠️ Installation

1. **Clone and navigate to the frontend directory:**
```bash
cd optimus-frontend
```

2. **Install dependencies:**
```bash
npm install
```

3. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your backend URL
```

4. **Start development server:**
```bash
npm run dev
```

5. **Build for production:**
```bash
npm run build
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_URL` | Backend API URL | `http://localhost:5000` |
| `VITE_WS_URL` | WebSocket URL | `http://localhost:5000` |

### Tailwind Theme

The cyber theme is configured in `tailwind.config.js`:

- **Colors**: `cyber-*` (backgrounds), `neon-*` (accents)
- **Fonts**: Orbitron (display), JetBrains Mono (code), Inter (body)
- **Animations**: scan-line, glow, pulse, float

## 🔌 Backend Integration

The frontend expects the backend to provide:

### REST Endpoints

```
POST   /api/scan/start          - Start new scan
GET    /api/scan/status/:id     - Get scan status
POST   /api/scan/stop/:id       - Stop scan
GET    /api/scan/list           - List all scans
GET    /api/tools/available     - List available tools
POST   /api/tools/resolve       - Resolve tool command
GET    /api/dashboard/stats     - Dashboard statistics
POST   /api/reports/generate    - Generate report
```

### WebSocket Events

```javascript
// Client → Server
'join_scan'      - Join scan room
'leave_scan'     - Leave scan room
'execute_tool'   - Execute specific tool

// Server → Client
'scan_started'           - Scan initiated
'scan_complete'          - Scan finished
'scan_update'            - Progress update
'phase_transition'       - Phase changed
'tool_execution_start'   - Tool started
'tool_output'            - Tool output line
'tool_execution_complete'- Tool finished
'finding_discovered'     - New vulnerability found
'tool_resolution'        - Hybrid system resolution
```

## 🎨 Design System

### Color Palette

```css
/* Background colors */
--cyber-black: #0a0a0f;
--cyber-darker: #0d0d14;
--cyber-dark: #12121a;

/* Accent colors */
--neon-green: #00ff9d;
--neon-cyan: #00d4ff;
--neon-purple: #9d00ff;
--neon-red: #ff0055;
--neon-orange: #ff6600;

/* Severity colors */
--critical: #ff0055;
--high: #ff6600;
--medium: #ffcc00;
--low: #00d4ff;
```

### Components

All components are available from `@/components`:

- `Button` - Multiple variants (primary, secondary, outline, cyber, danger)
- `Card` - Container with glass/gradient variants
- `Badge` - Status and severity indicators
- `Input` - Text input with icon support
- `Progress` - Progress bars
- `Spinner` - Loading indicator
- `StatusIndicator` - Online/offline status
- `Terminal` - Real-time log output
- `FindingsPanel` - Vulnerability list
- `ScanProgress` - Phase timeline
- `ToolsPanel` - Tool browser

## 📝 Key Fixes from Previous Version

This redesigned frontend addresses all critical issues:

1. ✅ **Single WebSocket Connection** - Singleton pattern in `socket.ts`
2. ✅ **Memory Leak Prevention** - Proper cleanup of event listeners
3. ✅ **Bounded Log Arrays** - Max 500 lines in terminal
4. ✅ **Error Boundaries** - Graceful error handling
5. ✅ **Type Safety** - Full TypeScript coverage
6. ✅ **Environment Configuration** - Unified config system
7. ✅ **Tool Integration** - Dynamic tool list from API
8. ✅ **Loading States** - Proper loading indicators

## 🚀 Performance Optimizations

- Lazy loading for pages with `Suspense`
- Memoized selectors in Zustand stores
- Debounced search inputs
- Virtual scrolling for large lists
- Optimized WebSocket reconnection

## 📄 License

MIT License - See LICENSE for details

---

Built with 💚 for the Optimus Penetration Testing Platform
