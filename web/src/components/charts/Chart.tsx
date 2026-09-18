import { useEffect, useRef } from 'react'
import * as echarts from 'echarts'
import { Spinner } from '@/components/ui'

// Chart theme shared by every chart (spec §64: one theme, no one-offs).
const base = {
  backgroundColor: 'transparent',
  textStyle: { color: '#8A8F98', fontSize: 11 },
  grid: { left: 40, right: 16, top: 24, bottom: 28 },
  tooltip: {
    backgroundColor: '#16181F',
    borderColor: 'rgba(255,255,255,0.14)',
    textStyle: { color: '#E7E8EA', fontSize: 12 },
  },
}

export function Chart({ option, height = 260, loading, onSelect }: {
  option: echarts.EChartsOption
  height?: number
  loading?: boolean
  // onSelect receives clicked elements' params (graph nodes, pie slices…).
  // Undefined marks are harmless — pages filter on what they know.
  onSelect?: (params: { componentType?: string; dataType?: string; data?: unknown }) => void
}) {
  const ref = useRef<HTMLDivElement>(null)
  const onSelectRef = useRef(onSelect)
  onSelectRef.current = onSelect
  useEffect(() => {
    if (!ref.current) return
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' })
    chart.setOption({ ...base, ...option })
    const onResize = () => chart.resize()
    window.addEventListener('resize', onResize)
    if (onSelectRef.current) {
      const handler = (params: echarts.ECElementEvent) => onSelectRef.current?.(params as { componentType?: string; dataType?: string; data?: unknown })
      chart.on('click', handler)
      return () => {
        window.removeEventListener('resize', onResize)
        chart.off('click', handler)
        chart.dispose()
      }
    }
    return () => {
      window.removeEventListener('resize', onResize)
      chart.dispose()
    }
  }, [option])
  return (
    <div>
      {loading ? <Spinner label="Loading chart…" /> : <div ref={ref} style={{ height }} role="img" aria-label="Chart" />}
    </div>
  )
}

// Severity donut (§64 RiskDistributionChart).
export function SeverityDonut({ bySeverity }: { bySeverity: Record<string, number> }) {
  const colors: Record<string, string> = {
    critical: '#F87171', high: '#FB923C', medium: '#FBBF24', low: '#60A5FA', info: '#6B7280',
  }
  const data = Object.entries(bySeverity)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ name: k, value: v, itemStyle: { color: colors[k] ?? '#6B7280' } }))
  return (
    <Chart
      height={220}
      option={{
        tooltip: { trigger: 'item' },
        legend: { bottom: 0, textStyle: { color: '#8A8F98', fontSize: 11 } },
        series: [{
          type: 'pie',
          radius: ['58%', '80%'],
          label: { show: false },
          data: data.length ? data : [{ name: 'none', value: 1, itemStyle: { color: '#2A2D35' } }],
        }],
      }}
    />
  )
}

// Time series area chart (risk/vulns/events trends).
export function TimeSeriesChart({ points, color = '#5E6AD2', label }: {
  points: { ts: string; value: number }[]
  color?: string
  label?: string
}) {
  return (
    <Chart
      option={{
        xAxis: { type: 'category', data: points.map((p) => p.ts.slice(5, 16)), axisLine: { lineStyle: { color: 'rgba(255,255,255,0.1)' } } },
        yAxis: { type: 'value', splitLine: { lineStyle: { color: 'rgba(255,255,255,0.05)' } } },
        series: [{
          type: 'line', data: points.map((p) => p.value),
          smooth: true, symbol: 'none',
          lineStyle: { color }, areaStyle: { color: `${color}22` },
          name: label,
        }],
      }}
    />
  )
}
