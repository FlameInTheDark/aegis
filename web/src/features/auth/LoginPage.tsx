import { FormEvent, useState } from 'react'
import { Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '@/lib/auth'

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const navigate = useNavigate()
  const { status, login } = useAuth()

  // A session restored through the refresh cookie has no business here.
  if (status === 'authenticated') return <Navigate to="/" replace />

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      // login() establishes the session atomically: access token to memory,
      // refresh cookie set by the server, centralized state flips to
      // authenticated BEFORE navigation happens.
      await login(email, password)
      navigate('/', { replace: true })
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex h-full items-center justify-center">
      <div className="w-[360px]">
        <div className="mb-6 flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-sm2 bg-accent text-[15px] font-bold text-white">Æ</div>
          <div>
            <h1 className="text-[16px] font-semibold">Aegis Security Platform</h1>
            <p className="text-[12px] text-fg-dim">Sign in to your workspace</p>
          </div>
        </div>
        <form onSubmit={submit} className="space-y-3 rounded-md2 border border-line bg-bg-panel p-5">
          <label className="block text-[12px] text-fg-dim" htmlFor="email">Email</label>
          <input id="email" type="email" required autoComplete="username" value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-sm2 border border-line bg-bg-raise px-2.5 py-2 text-[13px] outline-none focus:border-accent" />
          <label className="block text-[12px] text-fg-dim" htmlFor="password">Password</label>
          <input id="password" type="password" required autoComplete="current-password" value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-sm2 border border-line bg-bg-raise px-2.5 py-2 text-[13px] outline-none focus:border-accent" />
          {error && <p className="rounded-sm2 border border-crit/30 bg-crit/10 px-2.5 py-1.5 text-[12.5px] text-crit" role="alert">{error}</p>}
          <button type="submit" disabled={busy}
            className="w-full rounded-sm2 bg-accent py-2 text-[13px] font-medium text-white hover:bg-accent-hover disabled:opacity-50">
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        <p className="mt-4 rounded-sm2 border border-line bg-bg-panel px-3 py-2 text-center text-[11.5px] text-fg-faint">
          Demo deployment: admin@aegis.local / aegis-demo-admin-2026 (see README)
        </p>
      </div>
    </div>
  )
}
