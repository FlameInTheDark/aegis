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

type ChartSelectParams = { componentType?: string; dataType?: string; data?: unknown }

export function Chart({ option, height = 260, loading, live, onSelect, onDataZoom }: {
  option: echarts.EChartsOption
  height?: number
  loading?: boolean
  // live marks continuously-polling charts (metric tails). ECharts animation
  // is disabled entirely: with it on, every poll morphs each point from its
  // old value to the new one — the line seems to be reshaped in place — and
  // a replaced category axis replays the entry sweep, so the window never
  // reads as “moving left”. With animation off the refreshed window snaps
  // into its new position and the newest sample simply pushes the line left.
  live?: boolean
  // onSelect receives clicked elements' params (graph nodes, pie slices…).
  // Undefined marks are harmless — pages filter on what they know.
  onSelect?: (params: ChartSelectParams) => void
  // onDataZoom receives the visible [startValue, endValue] window after a
  // zoom interaction (slider drag, brush, resize of the selection). Range
  // timelines use it to drive the date inputs; undefined opts out.
  onDataZoom?: (start: number, end: number) => void
}) {
  const ref = useRef<HTMLDivElement>(null)
  const chartRef = useRef<echarts.ECharts | null>(null)
  const optionRef = useRef(option)
  optionRef.current = option
  const onSelectRef = useRef(onSelect)
  onSelectRef.current = onSelect
  const onDataZoomRef = useRef(onDataZoom)
  onDataZoomRef.current = onDataZoom
  // Polling charts must not animate; see the live prop comment above.
  const withLive = (o: echarts.EChartsOption): echarts.EChartsOption =>
    live ? { ...o, animation: false } : o

  // The chart instance lives as long as the host div does: it is created
  // once when the div enters the DOM and disposed when it leaves (loading
  // toggle or unmount). Re-creating the instance on every data change used
  // to replay the entry animation — lines sweeping left to right on each
  // refresh — instead of morphing the series in place.
  useEffect(() => {
    if (loading || !ref.current) return
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' })
    chartRef.current = chart
    chart.setOption(withLive({ ...base, ...optionRef.current }))
    const onResize = () => chart.resize()
    window.addEventListener('resize', onResize)
    const onClick = (params: echarts.ECElementEvent) => onSelectRef.current?.(params as ChartSelectParams)
    chart.on('click', onClick)
    const onZoom = () => {
      const cb = onDataZoomRef.current
      if (!cb) return
      const raw = (chart.getOption() as echarts.EChartsOption).dataZoom
      const dz = (Array.isArray(raw) ? raw[0] : raw) as
        | { startValue?: number; endValue?: number }
        | undefined
      if (!dz) return
      if (typeof dz.startValue !== 'number' || typeof dz.endValue !== 'number') return
      cb(dz.startValue, dz.endValue)
    }
    chart.on('datazoom', onZoom)
    return () => {
      window.removeEventListener('resize', onResize)
      chart.off('click', onClick)
      chart.off('datazoom', onZoom)
      chart.dispose()
      chartRef.current = null
    }
  }, [loading])

  // Data updates merge into the live instance — ECharts transitions the
  // series between the old and new data instead of redrawing from scratch
  // (unless the chart is marked live, which updates instantly).
  useEffect(() => {
    chartRef.current?.setOption(withLive({ ...base, ...option }))
  }, [option, live])

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

// Time series area chart (risk/vulns/events trends). boundaryGap: false
// pins the first and last point to the plot edges — the newest sample sits
// at the right edge instead of floating half a slot inward.
export function TimeSeriesChart({ points, color = '#5E6AD2', label }: {
  points: { ts: string; value: number }[]
  color?: string
  label?: string
}) {
  return (
    <Chart
      option={{
        xAxis: { type: 'category', boundaryGap: false, data: points.map((p) => p.ts.slice(5, 16)), axisLine: { lineStyle: { color: 'rgba(255,255,255,0.1)' } } },
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
