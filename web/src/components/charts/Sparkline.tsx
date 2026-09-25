import { useEffect, useRef } from 'react'
import * as echarts from 'echarts'

// Sparkline — a tiny inline chart for table cells (interface speed
// history). Deliberately bare: no axes, no legend, minimal padding so a
// fixed-size cell never breaks the row layout. One instance per cell is
// fine at the scale a host reports NICs (single digits).

const RX_COLOR = '#34D399' // matches the throughput chart "in" series
const TX_COLOR = '#FBBF24' // matches the throughput chart "out" series

export function Sparkline({ rx, tx, height = 34, width = 150, loading }: {
  rx: number[]
  tx: number[]
  height?: number
  width?: number
  loading?: boolean
}) {
  const ref = useRef<HTMLDivElement>(null)
  const chartRef = useRef<echarts.ECharts | null>(null)
  const dataRef = useRef({ rx, tx })
  dataRef.current = { rx, tx }

  useEffect(() => {
    if (loading || !ref.current) return
    const chart = echarts.init(ref.current, undefined, { renderer: 'canvas' })
    chartRef.current = chart
    chart.setOption(option(dataRef.current.rx, dataRef.current.tx))
    const onResize = () => chart.resize()
    window.addEventListener('resize', onResize)
    return () => {
      window.removeEventListener('resize', onResize)
      chart.dispose()
      chartRef.current = null
    }
  }, [loading])

  // Data updates redraw instantly — animation is disabled in the option so
  // a refreshed tail snaps to its new position instead of morphing in place.
  useEffect(() => {
    chartRef.current?.setOption(option(rx, tx))
  }, [rx, tx])

  return <div ref={ref} style={{ height, width }} role="img" aria-label="Interface activity sparkline" />
}

function option(rx: number[], tx: number[]): echarts.EChartsOption {
  return {
    backgroundColor: 'transparent',
    // Polling tail: no animation, so new samples push the line left instead
    // of the series morphing between values.
    animation: false,
    grid: { left: 2, right: 2, top: 3, bottom: 3 },
    tooltip: {
      show: rx.length + tx.length > 0,
      trigger: 'axis',
      confine: true,
      backgroundColor: '#16181F',
      borderColor: 'rgba(255,255,255,0.14)',
      textStyle: { color: '#E7E8EA', fontSize: 11 },
      axisPointer: { show: false },
      formatter: (params: unknown) => {
        const rows = params as { seriesName: string; value: number }[]
        return rows
          .filter((p) => Number.isFinite(p.value))
          .map((p) => `${p.seriesName === 'in' ? '↓' : '↑'} ${bps(p.value)}`)
          .join(' · ')
      },
    },
    xAxis: { type: 'category', show: false, boundaryGap: false, data: rx.map((_, i) => i) },
    yAxis: { type: 'value', show: false, scale: true },
    series: [
      {
        name: 'in', type: 'line', data: rx, smooth: true, symbol: 'none',
        lineStyle: { color: RX_COLOR, width: 1.5 }, areaStyle: { color: `${RX_COLOR}33` },
      },
      {
        name: 'out', type: 'line', data: tx, smooth: true, symbol: 'none',
        lineStyle: { color: TX_COLOR, width: 1.5 },
      },
    ],
  }
}

const bps = (v: number): string => {
  if (v >= 1e9) return `${(v / 1e9).toFixed(1)} Gbps`
  if (v >= 1e6) return `${(v / 1e6).toFixed(1)} Mbps`
  if (v >= 1e3) return `${(v / 1e3).toFixed(1)} Kbps`
  return `${Math.round(v)} bps`
}
