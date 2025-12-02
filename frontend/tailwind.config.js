/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Cyber theme - Matrix/Hacker aesthetic
        cyber: {
          black: '#0a0a0f',
          darker: '#0d0d14',
          dark: '#12121a',
          medium: '#1a1a25',
          light: '#252535',
        },
        neon: {
          green: '#00ff9d',
          cyan: '#00d4ff',
          blue: '#0066ff',
          purple: '#9d00ff',
          pink: '#ff00aa',
          red: '#ff0055',
          orange: '#ff6600',
          yellow: '#ffcc00',
        },
        terminal: {
          bg: '#0c0c10',
          text: '#b4b4b4',
          green: '#4ade80',
          red: '#f87171',
          yellow: '#fbbf24',
          blue: '#60a5fa',
        },
      },
      fontFamily: {
        display: ['Orbitron', 'monospace'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line': 'scanLine 4s linear infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'matrix': 'matrix 20s linear infinite',
        'typing': 'typing 3.5s steps(40, end)',
        'blink': 'blink 1s step-end infinite',
        'float': 'float 6s ease-in-out infinite',
        'border-flow': 'borderFlow 3s linear infinite',
      },
      keyframes: {
        scanLine: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        glow: {
          '0%': { boxShadow: '0 0 5px currentColor, 0 0 10px currentColor' },
          '100%': { boxShadow: '0 0 10px currentColor, 0 0 20px currentColor, 0 0 30px currentColor' },
        },
        matrix: {
          '0%': { backgroundPosition: '0% 0%' },
          '100%': { backgroundPosition: '0% 100%' },
        },
        typing: {
          'from': { width: '0' },
          'to': { width: '100%' },
        },
        blink: {
          'from, to': { borderColor: 'transparent' },
          '50%': { borderColor: '#00ff9d' },
        },
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        borderFlow: {
          '0%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
          '100%': { backgroundPosition: '0% 50%' },
        },
      },
      backgroundImage: {
        'grid-pattern': `linear-gradient(rgba(0, 255, 157, 0.03) 1px, transparent 1px),
                         linear-gradient(90deg, rgba(0, 255, 157, 0.03) 1px, transparent 1px)`,
        'cyber-gradient': 'linear-gradient(135deg, #0a0a0f 0%, #12121a 50%, #0d0d14 100%)',
        'neon-gradient': 'linear-gradient(135deg, #00ff9d 0%, #00d4ff 50%, #9d00ff 100%)',
      },
      backgroundSize: {
        'grid': '50px 50px',
      },
      boxShadow: {
        'neon-green': '0 0 5px #00ff9d, 0 0 10px #00ff9d, 0 0 20px #00ff9d',
        'neon-cyan': '0 0 5px #00d4ff, 0 0 10px #00d4ff, 0 0 20px #00d4ff',
        'neon-red': '0 0 5px #ff0055, 0 0 10px #ff0055, 0 0 20px #ff0055',
        'inner-glow': 'inset 0 0 20px rgba(0, 255, 157, 0.1)',
      },
    },
  },
  plugins: [],
}
