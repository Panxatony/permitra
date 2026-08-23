import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, login, passkeyLogin } from '../api'
import { useLang } from '../i18n'
import { useTheme } from '../theme'

const THEME_ICONS = { system: '🖥️', light: '☀️', dark: '🌙' }
const THEME_LABELS = { system: 'System', light: 'Hell', dark: 'Dunkel' }

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [otp, setOtp] = useState('')
  const [otpRequired, setOtpRequired] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const navigate = useNavigate()
  const { t } = useLang()
  const { theme, cycle: cycleTheme } = useTheme()

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
        setNotice(t('Please enter the code from your authenticator app.'))
      } else if (err.message === 'otp_invalid') {
        setOtpRequired(true)
        setError(t('The code is invalid – please try again.'))
      } else {
        setError(err.message)
      }
    }
  }

  const withPasskey = async () => {
    setError('')
    setNotice('')
    if (!username.trim()) {
      setError(t('Please enter your username first.'))
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
      setError(t('Please enter your username (or email address) first.'))
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
        <div className="login-controls">
          <button type="button" className="btn btn-ghost" onClick={cycleTheme}
            title={`${t('Colour scheme')}: ${t(THEME_LABELS[theme])}`}
            aria-label={`${t('Colour scheme')}: ${t(THEME_LABELS[theme])}`}>
            {THEME_ICONS[theme]}
          </button>
        </div>
        <h1 className="brand-heading">
          <img src="/permitra-logo.svg" alt="Permitra" className="brand-logo" />
        </h1>
        <p className="muted">{t('Central management of security rules')}</p>
        <label>
          {t('Username')}
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        </label>
        <label>
          {t('Password')}
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {otpRequired && (
          <label>
            {t('2FA code')}
            <input value={otp} inputMode="numeric" autoFocus placeholder="123456"
              onChange={(e) => setOtp(e.target.value)} />
          </label>
        )}
        {notice && <div className="infobox">{notice}</div>}
        {error && <div className="error">{error}</div>}
        <button className="btn btn-primary" type="submit">{t('Sign in')}</button>
        {window.PublicKeyCredential && (
          <button className="btn btn-ghost" type="button" onClick={withPasskey}>
            🔑 {t('Sign in with passkey')}
          </button>
        )}
        <button className="btn btn-ghost" type="button" onClick={forgot}
          style={{ fontSize: '.85rem' }}>
          {t('Forgot password?')}
        </button>
        <p className="muted small">
          Demo: architekt · betrieb · approver · approver2 · admin — Passwort jeweils Name+123
        </p>
      </form>
    </div>
  )
}
