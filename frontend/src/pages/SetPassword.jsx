import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { useLang } from '../i18n'

/* Passwort setzen über Aktivierungs- oder Reset-Link (?token=…). */
export default function SetPassword() {
  const { t } = useLang()
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token') || ''
  const [password, setPassword] = useState('')
  const [repeat, setRepeat] = useState('')
  const [error, setError] = useState('')
  const [done, setDone] = useState('')

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    if (password !== repeat) {
      setError(t('Die Passwörter stimmen nicht überein.'))
      return
    }
    try {
      const result = await api.setPassword(token, password)
      setDone(result.detail)
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={submit}>
        <h1>🛡️ Permitra</h1>
        <p className="muted">{t('Passwort setzen')}</p>
        {!token && <div className="error">{t('Kein Token im Link – bitte den Link aus der E-Mail vollständig öffnen.')}</div>}
        {done ? (
          <>
            <div className="infobox">{done}</div>
            <Link className="btn btn-primary" to="/login" style={{ textAlign: 'center' }}>
              {t('Zur Anmeldung')}
            </Link>
          </>
        ) : (
          <>
            <label>{t('Neues Passwort (min. 8 Zeichen)')}
              <input type="password" value={password} required minLength={8} autoFocus
                onChange={(e) => setPassword(e.target.value)} />
            </label>
            <label>{t('Passwort wiederholen')}
              <input type="password" value={repeat} required minLength={8}
                onChange={(e) => setRepeat(e.target.value)} />
            </label>
            {error && <div className="error">{error}</div>}
            <button className="btn btn-primary" type="submit" disabled={!token}>
              {t('Passwort speichern')}
            </button>
          </>
        )}
      </form>
    </div>
  )
}
