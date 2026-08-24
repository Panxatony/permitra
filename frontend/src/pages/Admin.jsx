import SetupChecklist from '../components/SetupChecklist'
import { useEffect, useState } from 'react'
import { api, getUser } from '../api'
import RiskCriteria from '../components/RiskCriteria'
import { dateLocale, useLang } from '../i18n'

const ROLES = ['architect', 'operations', 'change_approver', 'admin']

/* Admin area: Permitra settings - user management as the first step.
   New users without a password receive an activation link (by email if SMTP is
   configured; the link is also shown on screen). */
export default function Admin() {
  const { lang, t } = useLang()
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
    if (!window.confirm(`${t('Delete user?')} (${u.username})`)) return
    act(() => api.deleteUser(u.username), t('User deleted'))
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Administration')}</h1>
        <span className="muted">{t('User management – more Permitra settings will follow here.')}</span>
      </div>

      <SetupChecklist />

      {error && <div className="error">{error}</div>}
      {notice && <div className="infobox">{notice}</div>}
      {link && (
        <div className="infobox">
          {t('Link (share manually if no mail arrives):')}{' '}
          <code style={{ userSelect: 'all', wordBreak: 'break-all' }}>{link}</code>
        </div>
      )}

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>{t('Username')}</th><th>{t('Name')}</th><th>E-Mail</th>
              <th>{t('Role')}</th><th>{t('Status')}</th><th>2FA</th><th></th>
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
                    onChange={(e) => act(() => api.updateUser(u.username, { role: e.target.value }), t('Role changed'))}>
                    {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
                  </select>
                </td>
                <td>
                  <span className={`badge ${u.is_active ? 'status-approved' : 'status-deactivated'}`}>
                    {u.is_active ? t('active') : t('inactive')}
                  </span>
                </td>
                <td>{u.totp_enabled ? '✓' : '–'}</td>
                <td className="row-actions">
                  {u.username !== me.username && (
                    <>
                      <button className="btn btn-ghost"
                        onClick={() => act(() => api.updateUser(u.username, { is_active: !u.is_active }),
                          u.is_active ? t('Account deactivated') : t('Account activated'))}>
                        {u.is_active ? t('Deactivate') : t('Activate')}
                      </button>
                      <button className="btn btn-ghost" onClick={() => act(() => api.sendReset(u.username))}>
                        {t('Password reset')}
                      </button>
                      <button className="btn btn-ghost" onClick={() => remove(u)}>{t('Delete')}</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <section className="card" style={{ margin: '1rem 0' }}>
        <h3>{t('Settings')}</h3>
        <label style={{ maxWidth: '640px' }}>
          {t('Interface language')}
          <select value={settings.ui_language || 'en'}
            onChange={(e) => act(() => api.updateSettings({ ui_language: e.target.value })
              .then((s) => { setSettings(s); window.location.reload(); return {} }))}>
            <option value="en">English</option>
            <option value="de">Deutsch</option>
          </select>
        </label>
        <p className="muted small">
          {t('Applies to everyone using this instance. The page reloads after the change.')}
        </p>
        <label style={{ maxWidth: '640px', marginTop: '1rem', display: 'block' }}>
          {t('Zone matrix: behaviour for unmaintained zone relationships')}
          <select value={settings.zone_matrix_default || 'permit'}
            onChange={(e) => act(() => api.updateSettings({ zone_matrix_default: e.target.value })
              .then((s) => { setSettings(s); return { detail: t('Setting saved') } }))}>
            <option value="permit">{t('default-permit – allowed with a hint (legacy behaviour)')}</option>
            <option value="deny">{t('default-deny – least privilege: rules only after explicit matrix approval (BSI recommendation)')}</option>
          </select>
        </label>
        <p className="muted small">
          {t('With default-deny, new rules for zone relationships without a matrix entry are rejected until the relationship is set to Allow via a matrix request (two approvals).')}
        </p>
        <label style={{ maxWidth: '640px', marginTop: '1rem', display: 'block' }}>
          {t('Audit log: retention period for personal data')}
          <select value={settings.audit_retention_days || '0'}
            onChange={(e) => act(() => api.updateSettings({ audit_retention_days: e.target.value })
              .then((s) => { setSettings(s); return { detail: t('Setting saved') } }))}>
            <option value="0">{t('Keep forever (no deletion)')}</option>
            <option value="90">90 {t('days')}</option>
            <option value="180">180 {t('days')}</option>
            <option value="365">365 {t('days')}</option>
            <option value="730">730 {t('days')}</option>
            <option value="1095">1095 {t('days')}</option>
          </select>
        </label>
        <p className="muted small">
          {t('Audit events hold usernames and source IPs. Beyond this age, the oldest segment is deleted and replaced by a sealed anchor, so the hash chain stays verifiable while the personal data is removed (GDPR Art. 5(1)(e), BSI CON.6). With a SIEM configured, nothing is deleted until it has been delivered there – retention externalises evidence, it does not destroy it.')}
        </p>
        <h4 style={{ margin: '1rem 0 .4rem' }}>{t('Mandatory fields for rules')}</h4>
        <p className="muted small">
          {t('Active by default (BSI documentation duties) – they can be deactivated here if needed.')}
        </p>
        {[['require_justification', t('Justification (reason) is mandatory')],
          ['require_valid_until', t('Enforce expiry date (valid until)')]].map(([key, label]) => (
          <label key={key} className="checkbox">
            <input type="checkbox" checked={settings[key] === 'yes'}
              onChange={(e) => act(() => api.updateSettings({ [key]: e.target.checked ? 'yes' : 'no' })
                .then((s) => { setSettings(s); return { detail: t('Setting saved') } }))} />
            {label}
          </label>
        ))}
      </section>

      <form onSubmit={create} className="object-form card">
        <h3>{t('Create new user')}</h3>
        <p className="muted small">
          {t('Without a password the user receives an activation link and sets their own password (recommended).')}
        </p>
        <div className="grid-3">
          <label>{t('Username')}
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
        <label>{t('Role')}
          <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </label>
        <div className="actions">
          <button className="btn btn-primary" type="submit">{t('Create user')}</button>
        </div>
      </form>

      <section className="card" style={{ marginTop: '1rem' }}>
        <h3>NetBox-Import <span className="muted small">{t('(network prefixes, status active/planned)')}</span></h3>
        <div className="grid-3">
          <label>NetBox-URL
            <input value={nbForm.url} placeholder="https://netbox.example.org"
              onChange={(e) => setNbForm({ ...nbForm, url: e.target.value })} />
          </label>
          <label>API-Token
            <input type="password" value={nbForm.token}
              placeholder={netbox?.configured ? t('(stored – leave empty)') : ''}
              onChange={(e) => setNbForm({ ...nbForm, token: e.target.value })} />
          </label>
          <label>{t('Statuses to import (comma-separated)')}
            <input value={nbForm.statuses}
              onChange={(e) => setNbForm({ ...nbForm, statuses: e.target.value })}
              placeholder="active,reserved" />
          </label>
          <label className="checkbox" style={{ alignSelf: 'end' }}>
            <input type="checkbox" checked={nbForm.verify_tls}
              onChange={(e) => setNbForm({ ...nbForm, verify_tls: e.target.checked })} />
            {t('Verify TLS certificate')}
          </label>
        </div>
        <div className="actions" style={{ marginTop: '.5rem' }}>
          <button className="btn btn-primary" onClick={() => act(() => api.setNetboxConfig(nbForm)
            .then((c) => { setNetbox(c); setNbForm((f) => ({ ...f, token: '' })); return { detail: t('NetBox configuration saved') } }))}>
            {t('Save')}
          </button>
          <button className="btn btn-ghost" onClick={() => act(() => api.netboxTest()
            .then((r) => ({ detail: `${t('Connection ok')} – ${r.prefix_total} Prefixe in NetBox` })))}>
            {t('Test connection')}
          </button>
          <button className="btn btn-ghost" onClick={() => act(() => api.netboxImport()
            .then((r) => ({ detail: t('Import complete: {fetched} fetched, {pending} ready to adopt')
              .replace('{fetched}', r.fetched).replace('{pending}', r.pending)
              + (r.skipped_statuses?.length ? ` (${t('skipped')}: ${r.skipped_statuses.join(', ')})` : '') })))}>
            {t('Import now')}
          </button>
          {netbox?.last_import_at && (
            <span className="muted small" style={{ alignSelf: 'center' }}>
              {t('Last import')}: {new Date(netbox.last_import_at).toLocaleString(dateLocale(lang))}
            </span>
          )}
        </div>
        <p className="muted small" style={{ marginTop: '.4rem' }}>
          {t('Imported prefixes are assigned to a zone on the Networks page (approval by two change approvers).')}
        </p>
      </section>

      {/* The yardstick behind every risk hint: the criteria live in their own
          component because an approver has to be able to look them up too. */}
      <section className="card" style={{ marginTop: '1rem' }}>
        <h3>{t('Risk criteria')} <span className="muted small">{t('(basis of the automatic assessment)')}</span></h3>
        <RiskCriteria editable={me?.role === 'admin'} />
      </section>

      <section className="card" style={{ marginTop: '1rem' }}>
        <h3>{t('API tokens (read-only)')} <span className="muted small">{t('for Ansible/Terraform and more')}</span></h3>
        <p className="muted small">
          {t('Read-only access (GET). Use as header: Authorization: Bearer <token>')}
        </p>
        {newToken && (
          <div className="infobox">
            {t('New token (shown only once):')}{' '}
            <code style={{ userSelect: 'all', wordBreak: 'break-all' }}>{newToken}</code>
          </div>
        )}
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>{t('Name')}</th><th>Prefix</th><th>{t('Last used')}</th><th>{t('Valid until')}</th><th>{t('Status')}</th><th></th></tr>
            </thead>
            <tbody>
              {tokens.map((tok) => (
                <tr key={tok.id}>
                  <td><strong>{tok.name}</strong></td>
                  <td><code>{tok.prefix}…</code></td>
                  <td className="small">{tok.last_used_at ? new Date(tok.last_used_at).toLocaleString(dateLocale(lang)) : '–'}</td>
                  <td className="small">{tok.expires_at ? tok.expires_at.slice(0, 10) : t('unlimited')}</td>
                  <td><span className={`badge ${tok.revoked ? 'status-deactivated' : 'status-approved'}`}>
                    {tok.revoked ? t('revoked') : t('active')}</span></td>
                  <td className="row-actions">
                    {!tok.revoked && <button className="btn btn-ghost"
                      onClick={() => act(() => api.revokeApiToken(tok.id), t('Token revoked'))}>{t('Revoke')}</button>}
                  </td>
                </tr>
              ))}
              {!tokens.length && <tr><td colSpan={6} className="muted">{t('No tokens.')}</td></tr>}
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
            placeholder={t('Name, e.g. "Ansible-Prod"')} />
          <button className="btn btn-primary" type="submit">{t('Create token')}</button>
        </form>
      </section>

      <section className="card" style={{ marginTop: '1rem' }}>
        <h3>{t('Audit log')} <span className="muted small">{t('(last 50 events; full log via the /api/audit-log API for SIEM)')}</span></h3>
        <div className="row" style={{ display: 'flex', gap: '.6rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '.8rem' }}>
          <button className="btn btn-ghost" onClick={() => act(async () => {
            const r = await api.auditVerify(); setIntegrity(r); return {}
          })}>{t('Verify integrity')}</button>
          {integrity && (integrity.ok
            ? <span className="pill" style={{ background: 'var(--green-bg)', color: 'var(--green)', borderColor: 'var(--green-border)' }}>
                ✓ {t('Chain intact')} ({integrity.checked} {t('entries')})
              </span>
            : <span className="pill" style={{ background: 'var(--red-bg)', color: 'var(--red)', borderColor: 'var(--red-border)' }}>
                ✗ {t('Chain broken')} – ID {integrity.broken_at_id}: {integrity.reason}
              </span>)}
          <button className="btn btn-ghost" onClick={() => act(async () => {
            const r = await api.auditCheckpoint()
            const s = await api.auditSiemStatus(); setSiem(s)
            const v = await api.auditVerify(); setIntegrity(v)
            return { detail: r.event_count
              ? t('Chain end anchored at entry') + ` ${r.event_count}`
              : r.detail }
          })}>{t('Anchor now')}</button>
          {siem && (
            <span className="muted small">
              {t('SIEM delivery')}: {siem.enabled ? t('active') : t('not configured')}
              {' · '}{t('pending')}: {siem.pending} · {t('sent')}: {siem.sent}
              {siem.skipped ? ` · ${t('no sink')}: ${siem.skipped}` : ''}
              {siem.anchor
                ? ` · ${t('anchored at')}: ${siem.anchor.event_count}` +
                  (siem.enabled
                    ? (siem.anchor.delivered ? ` (${t('sent to SIEM')})`
                                             : ` (${t('delivery pending')})`)
                    : '')
                : ` · ${t('not anchored yet')}`}
            </span>
          )}
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>{t('Time')}</th><th>{t('Event')}</th><th>{t('Object')}</th><th>{t('By')}</th><th>{t('Source IP')}</th><th>{t('Details')}</th></tr>
            </thead>
            <tbody>
              {audit.map((e, i) => (
                <tr key={i}>
                  <td className="small">{e.timestamp ? new Date(e.timestamp).toLocaleString(dateLocale(lang)) : '–'}</td>
                  <td><code>{e.event}</code></td>
                  <td>{e.object}</td>
                  <td>{e.actor || '–'}</td>
                  <td className="small">{e.source_ip || '–'}</td>
                  <td className="small">{e.detail || (e.status ? t(e.status) : '')}</td>
                </tr>
              ))}
              {!audit.length && <tr><td colSpan={6} className="muted">{t('No entries.')}</td></tr>}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
