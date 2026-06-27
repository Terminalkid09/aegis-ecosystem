module.exports = {
  content: [
    './src/**/*.{js,jsx,ts,tsx}',
    './public/index.html',
  ],
  theme: {
    extend: {
      colors: {
        // Ultra-dark cyber theme (replaces slate)
        slate: {
          950: '#000000', // Pure black
          900: '#07070b', // Deepest violet-black
          800: '#0f0f16', // Dark interface bg
          700: '#1a1a27', // Borders / subtle bg
          600: '#2b2b3b', // Hover states
          500: '#46465c', // Muted text
          400: '#6e6e87', // Secondary text
          300: '#9b9bb2', // Light secondary
          200: '#c5c5d6', // Light text
          100: '#e5e5ef', // Almost white
          50: '#f4f4f8',  // White
        },
        cyan: {
          50: '#ecfdfd',
          100: '#cffafe',
          200: '#a5f3fc',
          300: '#67e8f9',
          400: '#22d3ee',
          500: '#00f0ff', // Cyberpunk Cyan
          600: '#0891b2',
          700: '#0e7490',
          800: '#155e75',
          900: '#164e63',
        },
        purple: {
          400: '#b026ff', // Neon Purple light
          500: '#8e00fa', // Neon Purple base
          600: '#6800cc', // Neon Purple dark
          900: '#1d003b', // Deep glow
        }
      },
      fontFamily: {
        sans: ['Outfit', 'Inter', '-apple-system', 'sans-serif'],
        mono: ['Fira Code', 'JetBrains Mono', 'monospace'],
      },
      boxShadow: {
        'glow': '0 0 20px rgba(6, 182, 212, 0.5)',
        'glow-lg': '0 0 40px rgba(6, 182, 212, 0.3)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
    },
  },
  plugins: [],
};
