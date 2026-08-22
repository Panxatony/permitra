import { useEffect, useState } from 'react'
import { api, getUser, passkeyRegister } from '../api'
import { useLang } from '../i18n'

/* Konto-Seite (alle Rollen): Passwort ändern, 2FA (TOTP) und Passkeys verwalten. */
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
    return { detail: t('Secret erzeugt – bitte in der Authenticator-App hinterlegen und mit Code bestätigen.') }
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
    const password = window.prompt(t('Zum Deaktivieren bitte das Passwort eingeben:'))
    if (!password) return
    act(() => api.totpDisable(password))
  }

  const addPasskey = async () => {
    const name = window.prompt(t('Name für den Passkey (z.B. "MacBook Touch ID"):'), 'Passkey')
    if (name === null) return
    try {
      setError('')
      await passkeyRegister(name || 'Passkey')
      setNotice(t('Passkey registriert'))
      load()
    } catch (err) {
      setError(`${t('Passkey-Registrierung fehlgeschlagen')}: ${err.message}`)
    }
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Konto & Sicherheit')}</h1>
        <span className="muted">{me.username} · {me.full_name} {me.email ? `· ${me.email}` : ''}</span>
      </div>

      {error && <div className="error">{error}</div>}
      {notice && <div className="infobox">{notice}</div>}

      <div className="detail-grid">
        <section className="card">
          <h2>{t('Benachrichtigungen')}</h2>
          <p className="muted small">
            {t('E-Mail bei Reviews, Freigaben und Rezertifizierung (erfordert eine hinterlegte E-Mail-Adresse).')}
          </p>
          <label className="checkbox">
            <input type="checkbox" checked={me.notify_email !== false}
              onChange={(e) => act(() => api.setNotifications(e.target.checked)
                .then((u) => { setMe(u); return { detail: t('Einstellung gespeichert') } }))()} />
            {t('E-Mail-Benachrichtigungen aktiv')}
          </label>
        </section>

        <section className="card">
          <h2>{t('Passwort ändern')}</h2>
          <form onSubmit={changePw} className="modal-form">
            <label>{t('Aktuelles Passwort')}
              <input type="password" value={pw.current} required
                onChange={(e) => setPw({ ...pw, current: e.target.value })} />
            </label>
            <label>{t('Neues Passwort (min. 8 Zeichen)')}
              <input type="password" value={pw.next} required minLength={8}
                onChange={(e) => setPw({ ...pw, next: e.target.value })} />
            </label>
            <div className="actions">
              <button className="btn btn-primary" type="submit">{t('Ändern')}</button>
            </div>
          </form>
        </section>

        <section className="card">
          <h2>{t('Zwei-Faktor (TOTP)')}</h2>
          {me.totp_enabled ? (
            <>
              <p>✓ {t('2FA ist aktiviert – beim Login wird zusätzlich ein Code abgefragt.')}</p>
              <button className="btn btn-ghost" onClick={disableTotp}>{t('Deaktivieren')}</button>
            </>
          ) : setup ? (
            <form onSubmit={enableTotp} className="modal-form">
              <p className="muted small">
                {t('Secret in der Authenticator-App hinterlegen (QR-Alternative: manuelle Eingabe):')}
              </p>
              <p><code style={{ userSelect: 'all' }}>{setup.secret}</code></p>
              <p className="muted small" style={{ wordBreak: 'break-all' }}>
                <code style={{ userSelect: 'all' }}>{setup.otpauth_url}</code>
              </p>
              <label>{t('Code aus der App')}
                <input value={code} inputMode="numeric" pattern="[0-9 ]*" required
                  onChange={(e) => setCode(e.target.value)} placeholder="123456" />
              </label>
              <div className="actions">
                <button className="btn btn-primary" type="submit">{t('Aktivieren')}</button>
                <button className="btn btn-ghost" type="button" onClick={() => setSetup(null)}>{t('Abbrechen')}</button>
              </div>
            </form>
          ) : (
            <>
              <p className="muted small">
                {t('Zusätzlicher Einmal-Code aus einer Authenticator-App (z.B. Google Authenticator, 1Password).')}
              </p>
              <button className="btn btn-primary" onClick={startTotp}>{t('2FA einrichten')}</button>
            </>
          )}
        </section>

        <section className="card">
          <h2>Passkeys</h2>
          <p className="muted small">
            {t('Anmeldung ohne Passwort (Touch ID, Windows Hello, Sicherheitsschlüssel). Erfordert HTTPS.')}
          </p>
          {passkeys.length > 0 && (
            <ul className="plain-list">
              {passkeys.map((p) => (
                <li key={p.id}>
                  🔑 {p.name}
                  <span className="muted small"> · {p.created_at?.slice(0, 10)}</span>{' '}
                  <button className="btn btn-ghost" style={{ padding: '.1rem .4rem' }}
                    onClick={() => act(() => api.deletePasskey(p.id), t('Passkey entfernt'))}>✕</button>
                </li>
              ))}
            </ul>
          )}
          <button className="btn btn-primary" onClick={addPasskey}
            disabled={!window.PublicKeyCredential}>
            {t('Passkey hinzufügen')}
          </button>
          {!window.PublicKeyCredential && (
            <p className="muted small">{t('Dieser Browser unterstützt keine Passkeys.')}</p>
          )}
        </section>
      </div>
    </div>
  )
}
