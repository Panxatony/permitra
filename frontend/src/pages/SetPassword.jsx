import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import { useLang } from '../i18n'

/* Set a password via an activation or reset link (?token=…). */
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
      setError(t('The passwords do not match.'))
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
        <h1 className="brand-heading">
          <img src="/permitra-logo.svg" alt="Permitra" className="brand-logo" />
        </h1>
        <p className="muted">{t('Set password')}</p>
        {!token && <div className="error">{t('No token in the link – please open the complete link from the email.')}</div>}
        {done ? (
          <>
            <div className="infobox">{done}</div>
            <Link className="btn btn-primary" to="/login" style={{ textAlign: 'center' }}>
              {t('Go to login')}
            </Link>
          </>
        ) : (
          <>
            <label>{t('New password (min. 8 characters)')}
              <input type="password" value={password} required minLength={8} autoFocus
                onChange={(e) => setPassword(e.target.value)} />
            </label>
            <label>{t('Repeat password')}
              <input type="password" value={repeat} required minLength={8}
                onChange={(e) => setRepeat(e.target.value)} />
            </label>
            {error && <div className="error">{error}</div>}
            <button className="btn btn-primary" type="submit" disabled={!token}>
              {t('Save password')}
            </button>
          </>
        )}
      </form>
    </div>
  )
}
