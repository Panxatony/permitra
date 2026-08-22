import { useEffect, useState } from 'react'
import { api, getUser, passkeyRegister } from '../api'
import { useLang } from '../i18n'

/* Account page (all roles): change password, manage 2FA (TOTP) and passkeys. */
export default function Account() {
  const { t } = useLang()
  const user = getUser()
  const [me, setMe] = useState(user)
  const [passkeys, setPasskeys] = useState([])
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const [pw, setPw] = useState({ current: '', next: '' })
  const [setup, setSetup] = useState(null)  // {secret, otpauth_url}
  const [code, setCode] = useState('')

  const load = () => {
    api.me().then(setMe).catch(() => {})
    api.passkeys().then(setPasskeys).catch(() => setPasskeys([]))
  }
  useEffect(() => { load() }, [])

  const act = async (fn, msg = '') => {
    setError('')
    setNotice('')
    try {
      const result = await fn()
      setNotice(result?.detail || msg)
      load()
      return true
    } catch (err) {
      setError(err.message)
      return false
    }
  }

  const changePw = async (e) => {
    e.preventDefault()
    const ok = await act(() => api.changePassword(pw.current, pw.next))
    if (ok) setPw({ current: '', next: '' })
  }

  const startTotp = () => act(async () => {
    const result = await api.totpSetup()
    setSetup(result)
    return { detail: t('Secret generated – add it to your authenticator app and confirm with a code.') }
  })

  const enableTotp = async (e) => {
    e.preventDefault()
    const ok = await act(() => api.totpEnable(code))
    if (ok) {
      setSetup(null)
      setCode('')
    }
  }

  const disableTotp = () => {
    const password = window.prompt(t('Enter your password to disable:'))
    if (!password) return
    act(() => api.totpDisable(password))
  }

  const addPasskey = async () => {
    const name = window.prompt(t('Name for the passkey (e.g. "MacBook Touch ID"):'), 'Passkey')
    if (name === null) return
    try {
      setError('')
      await passkeyRegister(name || 'Passkey')
      setNotice(t('Passkey registered'))
      load()
    } catch (err) {
      setError(`${t('Passkey registration failed')}: ${err.message}`)
    }
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Account & security')}</h1>
        <span className="muted">{me.username} · {me.full_name} {me.email ? `· ${me.email}` : ''}</span>
      </div>

      {error && <div className="error">{error}</div>}
      {notice && <div className="infobox">{notice}</div>}

      <div className="detail-grid">
        <section className="card">
          <h2>{t('Notifications')}</h2>
          <p className="muted small">
            {t('Email on reviews, approvals and recertification (requires a stored email address).')}
          </p>
          <label className="checkbox">
            <input type="checkbox" checked={me.notify_email !== false}
              onChange={(e) => act(() => api.setNotifications(e.target.checked)
                .then((u) => { setMe(u); return { detail: t('Setting saved') } }))()} />
            {t('Email notifications enabled')}
          </label>
        </section>

        <section className="card">
          <h2>{t('Change password')}</h2>
          <form onSubmit={changePw} className="modal-form">
            <label>{t('Current password')}
              <input type="password" value={pw.current} required
                onChange={(e) => setPw({ ...pw, current: e.target.value })} />
            </label>
            <label>{t('New password (min. 8 characters)')}
              <input type="password" value={pw.next} required minLength={8}
                onChange={(e) => setPw({ ...pw, next: e.target.value })} />
            </label>
            <div className="actions">
              <button className="btn btn-primary" type="submit">{t('Update')}</button>
            </div>
          </form>
        </section>

        <section className="card">
          <h2>{t('Two-factor (TOTP)')}</h2>
          {me.totp_enabled ? (
            <>
              <p>✓ {t('2FA is enabled – a code is required at login.')}</p>
              <button className="btn btn-ghost" onClick={disableTotp}>{t('Deactivate')}</button>
            </>
          ) : setup ? (
            <form onSubmit={enableTotp} className="modal-form">
              <p className="muted small">
                {t('Add the secret to your authenticator app (manual entry instead of QR):')}
              </p>
              <p><code style={{ userSelect: 'all' }}>{setup.secret}</code></p>
              <p className="muted small" style={{ wordBreak: 'break-all' }}>
                <code style={{ userSelect: 'all' }}>{setup.otpauth_url}</code>
              </p>
              <label>{t('Code from the app')}
                <input value={code} inputMode="numeric" pattern="[0-9 ]*" required
                  onChange={(e) => setCode(e.target.value)} placeholder="123456" />
              </label>
              <div className="actions">
                <button className="btn btn-primary" type="submit">{t('Activate')}</button>
                <button className="btn btn-ghost" type="button" onClick={() => setSetup(null)}>{t('Cancel')}</button>
              </div>
            </form>
          ) : (
            <>
              <p className="muted small">
                {t('Additional one-time code from an authenticator app (e.g. Google Authenticator, 1Password).')}
              </p>
              <button className="btn btn-primary" onClick={startTotp}>{t('Set up 2FA')}</button>
            </>
          )}
        </section>

        <section className="card">
          <h2>Passkeys</h2>
          <p className="muted small">
            {t('Sign in without a password (Touch ID, Windows Hello, security key). Requires HTTPS.')}
          </p>
          {passkeys.length > 0 && (
            <ul className="plain-list">
              {passkeys.map((p) => (
                <li key={p.id}>
                  🔑 {p.name}
                  <span className="muted small"> · {p.created_at?.slice(0, 10)}</span>{' '}
                  <button className="btn btn-ghost" style={{ padding: '.1rem .4rem' }}
                    onClick={() => act(() => api.deletePasskey(p.id), t('Passkey removed'))}>✕</button>
                </li>
              ))}
            </ul>
          )}
          <button className="btn btn-primary" onClick={addPasskey}
            disabled={!window.PublicKeyCredential}>
            {t('Add passkey')}
          </button>
          {!window.PublicKeyCredential && (
            <p className="muted small">{t('This browser does not support passkeys.')}</p>
          )}
        </section>
      </div>
    </div>
  )
}
