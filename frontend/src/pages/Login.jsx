import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '../api'
import { useLang } from '../i18n'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const navigate = useNavigate()
  const { lang, t, toggle } = useLang()

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await login(username, password)
      navigate('/')
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div className="login-page">
      <form className="login-card" onSubmit={submit}>
        <button type="button" className="btn btn-ghost login-lang" onClick={toggle}
          title={lang === 'de' ? 'Switch to English' : 'Auf Deutsch umstellen'}>
          {lang === 'de' ? 'EN' : 'DE'}
        </button>
        <h1>🛡️ Permitra</h1>
        <p className="muted">{t('Zentrale Verwaltung von Sicherheitsregeln')}</p>
        <label>
          {t('Benutzername')}
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        </label>
        <label>
          {t('Passwort')}
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && <div className="error">{error}</div>}
        <button className="btn btn-primary" type="submit">{t('Anmelden')}</button>
        <p className="muted small">
          Demo: architekt · betrieb · approver · approver2 · admin — Passwort jeweils Name+123
        </p>
      </form>
    </div>
  )
}
