import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, login, passkeyLogin } from '../api'
import { useLang } from '../i18n'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [otpRequired, setOtpRequired] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const navigate = useNavigate()
  const { lang, t, toggle } = useLang()

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    setNotice('')
    try {
      await login(username, password, otp)
      navigate('/')
    } catch (err) {
      if (err.message === 'otp_required') {
        setOtpRequired(true)
        setNotice(t('Bitte den Code aus der Authenticator-App eingeben.'))
      } else if (err.message === 'otp_invalid') {
        setOtpRequired(true)
        setError(t('Der Code ist ungültig – bitte erneut versuchen.'))
      } else {
        setError(err.message)
      }
    }
  }

  const withPasskey = async () => {
    setError('')
    setNotice('')
    if (!username.trim()) {
      setError(t('Bitte zuerst den Benutzernamen eingeben.'))
      return
    }
    try {
      await passkeyLogin(username.trim())
      navigate('/')
    } catch (err) {
      setError(err.message)
    }
  }

  const forgot = async () => {
    setError('')
    setNotice('')
    if (!username.trim()) {
      setError(t('Bitte zuerst den Benutzernamen (oder die E-Mail-Adresse) eingeben.'))
      return
    }
    try {
      const result = await api.forgotPassword(username.trim())
      setNotice(result.detail)
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
        {otpRequired && (
          <label>
            {t('2FA-Code')}
            <input value={otp} inputMode="numeric" autoFocus placeholder="123456"
              onChange={(e) => setOtp(e.target.value)} />
          </label>
        )}
        {notice && <div className="infobox">{notice}</div>}
        {error && <div className="error">{error}</div>}
        <button className="btn btn-primary" type="submit">{t('Anmelden')}</button>
        {window.PublicKeyCredential && (
          <button className="btn btn-ghost" type="button" onClick={withPasskey}>
            🔑 {t('Mit Passkey anmelden')}
          </button>
        )}
        <button className="btn btn-ghost" type="button" onClick={forgot}
          style={{ fontSize: '.85rem' }}>
          {t('Passwort vergessen?')}
        </button>
        <p className="muted small">
          Demo: architekt · betrieb · approver · approver2 · admin — Passwort jeweils Name+123
        </p>
      </form>
    </div>
  )
}
