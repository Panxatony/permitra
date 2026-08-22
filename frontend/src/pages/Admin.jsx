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
  const [audit, setAudit] = useState([])
  const [integrity, setIntegrity] = useState(null)
  const [siem, setSiem] = useState(null)
  const [tokens, setTokens] = useState([])
  const [tokenName, setTokenName] = useState('')
  const [newToken, setNewToken] = useState('')
  const [netbox, setNetbox] = useState(null)
  const [nbForm, setNbForm] = useState({ url: '', token: '', verify_tls: true, statuses: 'active,reserved' })

  const load = () => {
    api.users().then(setUsers).catch((e) => setError(e.message))
    api.settings().then(setSettings).catch(() => setSettings({}))
    api.auditLog({ limit: 50 }).then(setAudit).catch(() => setAudit([]))
    api.auditSiemStatus().then(setSiem).catch(() => setSiem(null))
    api.apiTokens().then(setTokens).catch(() => setTokens([]))
    api.netboxConfig().then((c) => { setNetbox(c); setNbForm((f) => ({ ...f, url: c.url, verify_tls: c.verify_tls, statuses: c.statuses || 'active,reserved' })) })
      .catch(() => setNetbox(null))
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

      <section className="card" style={{ marginTop: '1rem' }}>
        <h3>NetBox-Import <span className="muted small">{t('(Netzwerk-Prefixe, Status active/planned)')}</span></h3>
        <div className="grid-3">
          <label>NetBox-URL
            <input value={nbForm.url} placeholder="https://netbox.example.org"
              onChange={(e) => setNbForm({ ...nbForm, url: e.target.value })} />
          </label>
          <label>API-Token
            <input type="password" value={nbForm.token}
              placeholder={netbox?.configured ? t('(gespeichert – leer lassen)') : ''}
              onChange={(e) => setNbForm({ ...nbForm, token: e.target.value })} />
          </label>
          <label>{t('Zu importierende Status (kommagetrennt)')}
            <input value={nbForm.statuses}
              onChange={(e) => setNbForm({ ...nbForm, statuses: e.target.value })}
              placeholder="active,reserved" />
          </label>
          <label className="checkbox" style={{ alignSelf: 'end' }}>
            <input type="checkbox" checked={nbForm.verify_tls}
              onChange={(e) => setNbForm({ ...nbForm, verify_tls: e.target.checked })} />
            {t('TLS-Zertifikat prüfen')}
          </label>
        </div>
        <div className="actions" style={{ marginTop: '.5rem' }}>
          <button className="btn btn-primary" onClick={() => act(() => api.setNetboxConfig(nbForm)
            .then((c) => { setNetbox(c); setNbForm((f) => ({ ...f, token: '' })); return { detail: t('NetBox-Konfiguration gespeichert') } }))}>
            {t('Speichern')}
          </button>
          <button className="btn btn-ghost" onClick={() => act(() => api.netboxTest()
            .then((r) => ({ detail: `${t('Verbindung ok')} – ${r.prefix_total} Prefixe in NetBox` })))}>
            {t('Verbindung testen')}
          </button>
          <button className="btn btn-ghost" onClick={() => act(() => api.netboxImport()
            .then((r) => ({ detail: `${t('Import fertig')}: ${r.fetched} geladen, ${r.pending} zur Übernahme bereit`
              + (r.skipped_statuses?.length ? ` (${t('übersprungen')}: ${r.skipped_statuses.join(', ')})` : '') })))}>
            {t('Jetzt importieren')}
          </button>
          {netbox?.last_import_at && (
            <span className="muted small" style={{ alignSelf: 'center' }}>
              {t('Letzter Import')}: {new Date(netbox.last_import_at).toLocaleString('de-DE')}
            </span>
          )}
        </div>
        <p className="muted small" style={{ marginTop: '.4rem' }}>
          {t('Importierte Prefixe werden auf der Seite Netzwerke einer Zone zugeordnet (Freigabe durch zwei Change Approver).')}
        </p>
      </section>

      <section className="card" style={{ marginTop: '1rem' }}>
        <h3>{t('API-Tokens (read-only)')} <span className="muted small">{t('für Ansible/Terraform u.a.')}</span></h3>
        <p className="muted small">
          {t('Nur lesender Zugriff (GET). Als Header verwenden: Authorization: Bearer <token>')}
        </p>
        {newToken && (
          <div className="infobox">
            {t('Neuer Token (wird nur einmal angezeigt):')}{' '}
            <code style={{ userSelect: 'all', wordBreak: 'break-all' }}>{newToken}</code>
          </div>
        )}
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>{t('Name')}</th><th>Prefix</th><th>{t('Zuletzt genutzt')}</th><th>{t('Gültig bis')}</th><th>{t('Status')}</th><th></th></tr>
            </thead>
            <tbody>
              {tokens.map((tok) => (
                <tr key={tok.id}>
                  <td><strong>{tok.name}</strong></td>
                  <td><code>{tok.prefix}…</code></td>
                  <td className="small">{tok.last_used_at ? new Date(tok.last_used_at).toLocaleString('de-DE') : '–'}</td>
                  <td className="small">{tok.expires_at ? tok.expires_at.slice(0, 10) : t('unbefristet')}</td>
                  <td><span className={`badge ${tok.revoked ? 'status-deactivated' : 'status-approved'}`}>
                    {tok.revoked ? t('widerrufen') : t('aktiv')}</span></td>
                  <td className="row-actions">
                    {!tok.revoked && <button className="btn btn-ghost"
                      onClick={() => act(() => api.revokeApiToken(tok.id), t('Token widerrufen'))}>{t('Widerrufen')}</button>}
                  </td>
                </tr>
              ))}
              {!tokens.length && <tr><td colSpan={6} className="muted">{t('Keine Tokens.')}</td></tr>}
            </tbody>
          </table>
        </div>
        <form className="filterbar" style={{ marginTop: '.6rem' }} onSubmit={async (e) => {
          e.preventDefault()
          if (!tokenName.trim()) return
          setNewToken('')
          try {
            const r = await api.createApiToken(tokenName.trim())
            setNewToken(r.token); setTokenName(''); load()
          } catch (err) { setError(err.message) }
        }}>
          <input value={tokenName} onChange={(e) => setTokenName(e.target.value)}
            placeholder={t('Name, z.B. "Ansible-Prod"')} />
          <button className="btn btn-primary" type="submit">{t('Token erzeugen')}</button>
        </form>
      </section>

      <section className="card" style={{ marginTop: '1rem' }}>
        <h3>{t('Audit-Log')} <span className="muted small">{t('(letzte 50 Ereignisse; vollständig über die API /api/audit-log für SIEM)')}</span></h3>
        <div className="row" style={{ display: 'flex', gap: '.6rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '.8rem' }}>
          <button className="btn btn-ghost" onClick={() => act(async () => {
            const r = await api.auditVerify(); setIntegrity(r); return {}
          })}>{t('Integrität prüfen')}</button>
          {integrity && (integrity.ok
            ? <span className="pill" style={{ background: '#e6f4ea', color: '#1e7e34', borderColor: '#bfe3ca' }}>
                ✓ {t('Kette unversehrt')} ({integrity.checked} {t('Einträge')})
              </span>
            : <span className="pill" style={{ background: '#fdecea', color: '#b3261e', borderColor: '#f3c1bc' }}>
                ✗ {t('Kette verletzt')} – ID {integrity.broken_at_id}: {integrity.reason}
              </span>)}
          {siem && (
            <span className="muted small">
              {t('SIEM-Zustellung')}: {siem.enabled ? t('aktiv') : t('nicht konfiguriert')}
              {' · '}{t('ausstehend')}: {siem.pending} · {t('gesendet')}: {siem.sent}
              {siem.skipped ? ` · ${t('ohne Ziel')}: ${siem.skipped}` : ''}
            </span>
          )}
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>{t('Zeitpunkt')}</th><th>{t('Ereignis')}</th><th>{t('Objekt')}</th><th>{t('Von')}</th><th>{t('Quell-IP')}</th><th>{t('Details')}</th></tr>
            </thead>
            <tbody>
              {audit.map((e, i) => (
                <tr key={i}>
                  <td className="small">{e.timestamp ? new Date(e.timestamp).toLocaleString('de-DE') : '–'}</td>
                  <td><code>{e.event}</code></td>
                  <td>{e.object}</td>
                  <td>{e.actor || '–'}</td>
                  <td className="small">{e.source_ip || '–'}</td>
                  <td className="small">{e.detail || (e.status || '')}</td>
                </tr>
              ))}
              {!audit.length && <tr><td colSpan={6} className="muted">{t('Keine Einträge.')}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
