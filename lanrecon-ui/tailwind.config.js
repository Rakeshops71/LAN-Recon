/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html"
  ],
  theme: {
    extend: {
      colors: {
        dark: {
          900: '#0B0F19', // Deep dark
          800: '#111827', // Slate
          700: '#1F2937', // Lighter slate
          600: '#374151', // Border color
        },
        neon: {
          cyan: '#06b6d4',
          green: '#10b981',
          red: '#ef4444',
          purple: '#8b5cf6',
          amber: '#f59e0b'
        }
      },
      fontFamily: {
        mono: ['"Fira Code"', '"JetBrains Mono"', 'monospace'],
        sans: ['"Inter"', 'sans-serif']
      }
    },
  },
  plugins: [],
}
