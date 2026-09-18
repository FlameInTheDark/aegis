import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: { DEFAULT: '#0B0C0F', panel: '#101116', raise: '#16181F' },
        line: { DEFAULT: 'rgba(255,255,255,0.08)', strong: 'rgba(255,255,255,0.14)' },
        fg: { DEFAULT: '#E7E8EA', dim: '#8A8F98', faint: '#5C626B' },
        accent: { DEFAULT: '#5E6AD2', hover: '#6E79DB' },
        crit: '#F87171', high: '#FB923C', med: '#FBBF24', low: '#60A5FA', info: '#6B7280',
        ok: '#34D399',
      },
      fontSize: { xs2: ['11px', '14px'] },
      borderRadius: { sm2: '4px', md2: '6px' },
    },
  },
  plugins: [],
} satisfies Config
