import { useEffect, useState } from 'react'
import { api, getUser } from '../api'
import { useLang } from '../i18n'

const ROLES = ['architect', 'operations', 'change_approver', 'admin']

/* Admin-Bereich: Permitra-Einstellungen – im ersten Schritt die Benutzerverwaltung.
   Neue Benutzer ohne Passwort erhalten einen Aktivierungslink (Mail, falls SMTP
   konfiguriert; der Link wird zusätzlich angezeigt). */
export default function Admin() {
  const { t } = useLang()
  const me = getUser()
  const [users, setUsers] = useState([])
  const [form, setForm] = useState({ username: '', full_name: '', email: '', role: 'architect' })
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [link, setLink] = useState('')
  const [settings, setSettings] = useState({})

  const load = () => {
    api.users().then(setUsers).catch((e) => setError(e.message))
    api.settings().then(setSettings).catch(() => setSettings({}))
  }
  useEffect(() => { load() }, [])

  const act = async (fn, successMsg = '') => {
    setError('')
    setNotice('')
    setLink('')
    try {
      const result = await fn()
      if (result?.detail) setNotice(result.detail)
      else if (successMsg) setNotice(successMsg)
      if (result?.activation_link) setLink(result.activation_link)
      if (result?.reset_link) setLink(result.reset_link)
      load()
      return true
    } catch (err) {
      setError(err.message)
      return false
    }
  }

  const create = async (e) => {
    e.preventDefault()
    const ok = await act(() => api.createUser(form))
    if (ok) setForm({ username: '', full_name: '', email: '', role: form.role })
  }

  const remove = (u) => {
    if (!window.confirm(`${t('Benutzer löschen?')} (${u.username})`)) return
    act(() => api.deleteUser(u.username), t('Benutzer gelöscht'))
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Administration')}</h1>
        <span className="muted">{t('Benutzerverwaltung – weitere Permitra-Einstellungen folgen hier.')}</span>
      </div>

      {error && <div className="error">{error}</div>}
      {notice && <div className="infobox">{notice}</div>}
      {link && (
        <div className="infobox">
          {t('Link (falls keine Mail ankommt, manuell übermitteln):')}{' '}
          <code style={{ userSelect: 'all', wordBreak: 'break-all' }}>{link}</code>
        </div>
      )}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{t('Benutzername')}</th><th>{t('Name')}</th><th>E-Mail</th>
              <th>{t('Rolle')}</th><th>{t('Status')}</th><th>2FA</th><th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td><strong>{u.username}</strong></td>
                <td>{u.full_name}</td>
                <td>{u.email}</td>
                <td>
                  <select value={u.role} disabled={u.username === me.username}
                    onChange={(e) => act(() => api.updateUser(u.username, { role: e.target.value }), t('Rolle geändert'))}>
                    {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </td>
                <td>
                  <span className={`badge ${u.is_active ? 'status-approved' : 'status-deactivated'}`}>
                    {u.is_active ? t('aktiv') : t('inaktiv')}
                  </span>
                </td>
                <td>{u.totp_enabled ? '✓' : '–'}</td>
                <td className="row-actions">
                  {u.username !== me.username && (
                    <>
                      <button className="btn btn-ghost"
                        onClick={() => act(() => api.updateUser(u.username, { is_active: !u.is_active }),
                          u.is_active ? t('Konto deaktiviert') : t('Konto aktiviert'))}>
                        {u.is_active ? t('Deaktivieren') : t('Aktivieren')}
                      </button>
                      <button className="btn btn-ghost" onClick={() => act(() => api.sendReset(u.username))}>
                        {t('Passwort-Reset')}
                      </button>
                      <button className="btn btn-ghost" onClick={() => remove(u)}>{t('Löschen')}</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <section className="card" style={{ margin: '1rem 0' }}>
        <h3>{t('Einstellungen')}</h3>
        <label style={{ maxWidth: '640px' }}>
          {t('Zonen-Matrix: Verhalten für ungepflegte Zonen-Beziehungen')}
          <select value={settings.zone_matrix_default || 'permit'}
            onChange={(e) => act(() => api.updateSettings({ zone_matrix_default: e.target.value })
              .then((s) => { setSettings(s); return { detail: t('Einstellung gespeichert') } }))}>
            <option value="permit">{t('default-permit – erlaubt mit Hinweis (Bestandsverhalten)')}</option>
            <option value="deny">{t('default-deny – Minimalprinzip: Regeln erst nach expliziter Matrix-Freigabe (BSI-Empfehlung)')}</option>
          </select>
        </label>
        <p className="muted small">
          {t('Bei default-deny werden neue Regeln für Zonen-Beziehungen ohne Matrix-Eintrag abgelehnt, bis die Beziehung per Matrixantrag (zwei Freigaben) auf Allow gesetzt ist.')}
        </p>
        <h4 style={{ margin: '1rem 0 .4rem' }}>{t('Pflichtfelder für Regeln')}</h4>
        <p className="muted small">
          {t('Standardmäßig aktiv (BSI-Dokumentationspflichten) – hier lassen sie sich bei Bedarf deaktivieren.')}
        </p>
        {[['require_justification', t('Begründung (Anlass) ist Pflicht')],
          ['require_requestor', t('Requestor (Verantwortlicher) ist Pflicht')],
          ['require_valid_until', t('Ablaufdatum (Gültig-bis) erzwingen')]].map(([key, label]) => (
          <label key={key} className="checkbox">
            <input type="checkbox" checked={settings[key] === 'yes'}
              onChange={(e) => act(() => api.updateSettings({ [key]: e.target.checked ? 'yes' : 'no' })
                .then((s) => { setSettings(s); return { detail: t('Einstellung gespeichert') } }))} />
            {label}
          </label>
        ))}
      </section>

      <form onSubmit={create} className="object-form card">
        <h3>{t('Neuen Benutzer anlegen')}</h3>
        <p className="muted small">
          {t('Ohne Passwort: Der Benutzer erhält einen Aktivierungslink und setzt sein Passwort selbst (empfohlen).')}
        </p>
        <div className="grid-3">
          <label>{t('Benutzername')}
            <input value={form.username} required minLength={2}
              onChange={(e) => setForm({ ...form, username: e.target.value })} />
          </label>
          <label>{t('Name')}
            <input value={form.full_name}
              onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
          </label>
          <label>E-Mail
            <input type="email" value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })} />
          </label>
        </div>
        <label>{t('Rolle')}
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>
        <div className="actions">
          <button className="btn btn-primary" type="submit">{t('Benutzer anlegen')}</button>
        </div>
      </form>
    </div>
  )
}
