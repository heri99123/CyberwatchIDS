/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{vue,js,ts,jsx,tsx}'
  ],
  theme: {
    extend: {
      colors: {
        // Dark theme palette matching CyberWatch IDS identity
        cyber: {
          bg: '#0a0e14',
          card: '#111824',
          border: '#1e2a3a',
          borderlight: '#2a3a4f',
          accent: '#00d9ff',
          accentdim: '#0099b8',
          danger: '#ff4757',
          critical: '#ff3838',
          high: '#ffa502',
          medium: '#ffd32a',
          low: '#26de81',
          info: '#00d9ff',
          text: '#e0e6ed',
          textdim: '#8a96a8',
          textmuted: '#5a6a7e'
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif']
      },
      animation: {
        'pulse-slow': 'pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'flash': 'flash 0.5s ease-out'
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' }
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' }
        },
        flash: {
          '0%': { backgroundColor: 'rgba(0, 217, 255, 0.15)' },
          '100%': { backgroundColor: 'transparent' }
        }
      }
    }
  },
  plugins: []
}
