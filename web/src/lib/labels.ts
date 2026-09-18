import type { Asset } from '@/types'

export function assetLabel(a: Pick<Asset, 'hostname' | 'fqdn' | 'primary_ip'>): string {
  return a.hostname || a.fqdn || a.primary_ip || 'Unnamed device'
}

export function assetOptionLabel(a: Asset): string {
  const name = assetLabel(a)
  return [name, a.primary_ip !== name ? a.primary_ip : '', a.os_name].filter(Boolean).join(' · ')
}

export const REPORT_TYPE_LABELS: Record<string, string> = {
  executive_security: 'Executive security report',
  technical_vulnerability: 'Technical vulnerability report',
  network_inventory: 'Network inventory report',
  scan_comparison: 'Scan comparison',
  site_detail: 'Site detail report',
  device_detail: 'Device detail report',
}
