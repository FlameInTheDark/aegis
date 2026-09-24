// Aegis streaming socket (v1.13.0): one WebSocket per tab, multiplexing
// channel subscriptions (scan:<id>, notify) with auto-reconnect.
//
// Auth mirrors the REST client (docs/AUTH.md): the access JWT lives in
// module memory, and since a browser WS handshake cannot carry custom
// headers, the token rides the access_token query parameter of the
// upgrade request. The refresh cookie is deliberately NOT usable here —
// a stale tab must never silently re-enter the live event stream.
//
// Resilience: exponential backoff (0.5s → 15s with jitter), automatic
// re-subscription of every channel the app still cares about, and a JSON
// ping every 25s (the server answers with pong and drops idle sockets
// after 90s). Consumers keep their polling fallbacks wired to the
// connection status so a downgraded connection degrades instead of
// breaking.
import { getAccessToken, refreshSession, clearAccessToken } from '@/lib/api'
import { useEffect, useState } from 'react'

export type StreamKind = 'log' | 'state' | 'notification'

export interface StreamEvent {
  channel: string
  kind: StreamKind
  data: Record<string, unknown>
  ts: string
}

type Handler = (ev: StreamEvent) => void
type StatusHandler = (connected: boolean) => void

const MAX_CHANNELS = 32

class AegisSocket {
  private ws: WebSocket | null = null
  private handlers = new Map<string, Set<Handler>>()
  private statusHandlers = new Set<StatusHandler>()
  private retry = 0
  private retryTimer: ReturnType<typeof setTimeout> | undefined
  private pingTimer: ReturnType<typeof setInterval> | undefined
  private userClosed = false
  private connecting = false
  connected = false

  /** Subscribe to a channel; connects lazily on the first subscription. */
  sub(channel: string, handler: Handler): () => void {
    let set = this.handlers.get(channel)
    if (!set) {
      set = new Set()
      this.handlers.set(channel, set)
    }
    set.add(handler)
    this.ensureConnected()
    if (this.ws?.readyState === WebSocket.OPEN) this.send({ type: 'sub', channel })
    return () => {
      const s = this.handlers.get(channel)
      if (!s) return
      s.delete(handler)
      if (s.size === 0) {
        this.handlers.delete(channel)
        if (this.ws?.readyState === WebSocket.OPEN) this.send({ type: 'unsub', channel })
      }
    }
  }

  onStatus(cb: StatusHandler): () => void {
    this.statusHandlers.add(cb)
    cb(this.connected)
    return () => this.statusHandlers.delete(cb)
  }

  private setStatus(c: boolean) {
    this.connected = c
    this.statusHandlers.forEach((h) => h(c))
  }

  private ensureConnected() {
    if (this.userClosed || this.connecting) return
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) return
    this.connecting = true
    this.open()
  }

  private open() {
    // A missing token (page freshly loaded, session not yet restored) is
    // not an error: the auth provider calls refresh after restoring the
    // session; meanwhile we simply stay offline.
    if (!getAccessToken()) {
      void refreshSession().then((r) => {
        this.connecting = false
        if (r === 'ok') this.ensureConnected()
      })
      return
    }
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${location.host}/api/v1/ws?access_token=${encodeURIComponent(getAccessToken())}`)
    this.ws = ws

    ws.onopen = () => {
      this.connecting = false
      this.retry = 0
      this.setStatus(true)
      for (const channel of this.handlers.keys()) this.send({ type: 'sub', channel })
      this.pingTimer = setInterval(() => this.send({ type: 'ping' }), 25_000)
    }

    ws.onmessage = (m) => {
      try {
        const frame = JSON.parse(m.data as string) as { type: string; channel?: string; kind?: StreamKind; data?: Record<string, unknown>; ts?: string }
        if (frame.type === 'event' && frame.channel && frame.kind) {
          const set = this.handlers.get(frame.channel)
          if (!set) return
          const ev: StreamEvent = {
            channel: frame.channel,
            kind: frame.kind,
            data: frame.data ?? {},
            ts: frame.ts ?? new Date().toISOString(),
          }
          set.forEach((h) => h(ev))
        }
        // hello/pong/subscribed/unsubscribed/error frames are informational.
      } catch {
        // malformed frame: ignore
      }
    }

    ws.onclose = (e) => {
      this.connecting = false
      this.setStatus(false)
      if (this.pingTimer) clearInterval(this.pingTimer)
      this.pingTimer = undefined
      this.ws = null
      if (this.userClosed) return
      // 4001 = the server rejected the token (expired/invalid): try one
      // refresh before backing off — the session may simply need renewal.
      if (e.code === 4001) {
        void refreshSession().then((r) => {
          if (r !== 'ok') clearAccessToken()
          this.scheduleReconnect()
        })
        return
      }
      this.scheduleReconnect()
    }

    ws.onerror = () => {
      try { ws.close() } catch { /* already closing */ }
    }
  }

  private scheduleReconnect() {
    if (this.userClosed) return
    if (this.handlers.size === 0) return // nothing to stream; wait for a sub()
    const delay = Math.min(500 * 2 ** this.retry, 15_000) + Math.random() * 300
    this.retry += 1
    this.retryTimer = setTimeout(() => this.ensureConnected(), delay)
  }

  private send(frame: Record<string, unknown>) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      try { this.ws.send(JSON.stringify(frame)) } catch { /* racy close */ }
    }
  }

  /** Force-close (logout); the next sub() reconnects fresh. */
  disconnect() {
    this.userClosed = true
    if (this.retryTimer) clearTimeout(this.retryTimer)
    if (this.pingTimer) clearInterval(this.pingTimer)
    try { this.ws?.close() } catch { /* noop */ }
    this.ws = null
    this.setStatus(false)
    // Allow a future login to reconnect.
    setTimeout(() => { this.userClosed = false }, 0)
  }
}

export const ws = new AegisSocket()

/** Connection status as a React hook (drives polling fallbacks). */
export function useWSStatus(): boolean {
  const [connected, setConnected] = useState(ws.connected)
  useEffect(() => ws.onStatus(setConnected), [])
  return connected
}
