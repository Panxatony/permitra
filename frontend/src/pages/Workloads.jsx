import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api, getUser, hasRole } from '../api'
import { HelpLink } from '../components/shared'
import { useLang } from '../i18n'

/* Workloads, labels and the groups rules refer to by name (#35).

   A micro-segmentation policy names groups ("the web tier may reach the
   database tier"), not addresses. Rules stay address-based - an address is
   what a firewall and a drift comparison can check - so a group is resolved
   to addresses when the rule is written, and again whenever its membership
   moves. This page is the inventory those groups are built on, and the
   groups themselves. */

const EMPTY_WL = { name: '', kind: 'vm', addresses: '', labels: '', description: '' }
const EMPTY_GROUP = { name: '', kind: 'selector', selector: '', members: '', description: '' }
const KINDS = ['host', 'vm', 'container', 'service']

/* "k=v, k2=v2" <-> {k: v}: the labels are typed the way the selector is
   written, so what a group matches reads like what a workload carries. */
function parseLabels(text) {
  const out = {}
  text.split(/[,\n]/).map((s) => s.trim()).filter(Boolean).forEach((term) => {
    const i = term.indexOf('=')
    if (i > 0) out[term.slice(0, i).trim()] = term.slice(i + 1).trim()
    else out[term] = ''
  })
  return out
}
const labelsText = (labels) => Object.entries(labels || {}).map(([k, v]) => `${k}=${v}`).join(', ')
const splitList = (text) => text.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean)

/* Static members are typed one per token: a workload by name, anything that
   looks like an address as an address. */
function parseMembers(text) {
  return splitList(text).map((token) =>
    /^[0-9a-fA-F.:]+(\/\d{1,3})?$/.test(token) ? { ip: token } : { workload: token })
}
const membersText = (members) => (members || []).map((m) => m.workload || m.ip).join(', ')

function LabelChips({ labels }) {
  return (
    <span className="label-chips">
      {Object.entries(labels || {}).map(([k, v]) => (
        <span key={k} className="badge label-chip"><span className="muted">{k}=</span>{v}</span>
      ))}
    </span>
  )
}

export default function Workloads() {
  const { t } = useLang()
  const user = getUser()
  const isAdmin = hasRole(user, 'admin')
  const [workloads, setWorkloads] = useState([])
  const [groups, setGroups] = useState([])
  const [filter, setFilter] = useState({ q: '', label: '' })
  const [wlForm, setWlForm] = useState(EMPTY_WL)
  const [wlEditId, setWlEditId] = useState(null)
  const [groupForm, setGroupForm] = useState(EMPTY_GROUP)
  const [groupEditId, setGroupEditId] = useState(null)
  const [preview, setPreview] = useState(null)   // {group, count, members, rules}
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')

  const load = () => {
    api.workloads(filter).then(setWorkloads).catch((e) => setError(e.message))
    api.groups().then(setGroups).catch(() => {})
  }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load() }, [filter.q, filter.label])

  /* Every write here can move a rule: the response names the rules it
     rewrote, and that is worth a line on the page rather than silence. */
  const report = (res) => {
    const moved = res?.rules_updated || res?.resynced || []
    if (moved.length) {
      setNotice(t('{count} rule(s) follow the new membership: {rules}')
        .replace('{count}', moved.length).replace('{rules}', moved.join(', ')))
    }
  }

  const submitWl = async (e) => {
    e.preventDefault()
    setError(''); setNotice('')
    const payload = {
      name: wlForm.name.trim(), kind: wlForm.kind, description: wlForm.description,
      addresses: splitList(wlForm.addresses), labels: parseLabels(wlForm.labels),
    }
    try {
      const res = wlEditId ? await api.updateWorkload(wlEditId, payload) : await api.createWorkload(payload)
      report(res)
      setWlForm(EMPTY_WL); setWlEditId(null)
      load()
    } catch (err) { setError(err.message) }
  }
  const editWl = (w) => {
    setWlEditId(w.id)
    setWlForm({ name: w.name, kind: w.kind, addresses: (w.addresses || []).join(', '),
      labels: labelsText(w.labels), description: w.description || '' })
  }
  const removeWl = async (w) => {
    if (!window.confirm(t('Delete workload "{name}"?').replace('{name}', w.name))) return
    setError(''); setNotice('')
    try { await api.deleteWorkload(w.id); load() } catch (err) { setError(err.message) }
  }

  const submitGroup = async (e) => {
    e.preventDefault()
    setError(''); setNotice('')
    const payload = {
      name: groupForm.name.trim(), kind: groupForm.kind, description: groupForm.description,
      selector: groupForm.kind === 'selector' ? groupForm.selector : '',
      members: groupForm.kind === 'static' ? parseMembers(groupForm.members) : [],
    }
    try {
      const res = groupEditId ? await api.updateGroup(groupEditId, payload) : await api.createGroup(payload)
      report(res)
      setGroupForm(EMPTY_GROUP); setGroupEditId(null)
      load()
    } catch (err) { setError(err.message) }
  }
  const editGroup = (g) => {
    setGroupEditId(g.id)
    setGroupForm({ name: g.name, kind: g.kind, selector: g.selector || '',
      members: membersText(g.members), description: g.description || '' })
  }
  const removeGroup = async (g) => {
    if (!window.confirm(t('Delete group "{name}"?').replace('{name}', g.name))) return
    setError(''); setNotice('')
    try { await api.deleteGroup(g.id); load() } catch (err) { setError(err.message) }
  }
  const showMembers = async (g) => {
    setError('')
    try { setPreview({ group: g, ...(await api.groupMembers(g.id)) }) } catch (err) { setError(err.message) }
  }

  const importNetbox = async () => {
    setError(''); setNotice('')
    try {
      const res = await api.netboxImportWorkloads()
      setNotice(t('NetBox import: {imported} workload(s) imported, {removed} removed')
        .replace('{imported}', res.imported ?? 0).replace('{removed}', res.removed ?? 0))
      load()
    } catch (err) { setError(err.message) }
  }

  return (
    <div>
      <div className="page-head">
        <h1>{t('Workloads & groups')} <HelpLink topic="segmentation" label={t('How groups and segments work')} /></h1>
        <span className="muted">
          {t('The hosts, VMs and services rules are about, with labels – and the groups rules refer to by name instead of by address')}
        </span>
        {isAdmin && <button className="btn btn-ghost head-action" onClick={importNetbox}>{t('Import from NetBox')}</button>}
      </div>
      {error && <div className="error">{error}</div>}
      {notice && <div className="okbox">{notice}</div>}

      <div className="detail-grid">
        <section className="card">
          <h2>{t('Workloads')} ({workloads.length})</h2>
          <div className="filter-row">
            <input placeholder={t('Search name, address or label')} value={filter.q}
              onChange={(e) => setFilter({ ...filter, q: e.target.value })} />
            <input placeholder={t('Selector, e.g. app=shop, tier=web')} value={filter.label}
              onChange={(e) => setFilter({ ...filter, label: e.target.value })} />
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>{t('Name')}</th><th>{t('Kind')}</th><th>{t('Addresses')}</th><th>{t('Labels')}</th><th></th></tr></thead>
              <tbody>
                {workloads.map((w) => (
                  <tr key={w.id}>
                    <td><strong>{w.name}</strong>
                      {w.source !== 'manual' && <span className="muted small"> · {w.source}</span>}</td>
                    <td>{t(w.kind)}</td>
                    <td>{(w.addresses || []).map((ip) => <div key={ip}><code>{ip}</code></div>)}</td>
                    <td><LabelChips labels={w.labels} /></td>
                    <td className="row-actions">
                      <button className="btn btn-ghost" onClick={() => editWl(w)}>{t('Edit')}</button>
                      <button className="btn btn-ghost" onClick={() => removeWl(w)}>{t('Delete')}</button>
                    </td>
                  </tr>
                ))}
                {!workloads.length && <tr><td colSpan={5} className="muted">{t('No workloads yet')}</td></tr>}
              </tbody>
            </table>
          </div>
          <form onSubmit={submitWl} className="object-form">
            <div className="grid-3">
              <label>{t('Name')}<input value={wlForm.name} required placeholder={t('e.g. web01')}
                onChange={(e) => setWlForm({ ...wlForm, name: e.target.value })} /></label>
              <label>{t('Kind')}
                <select value={wlForm.kind} onChange={(e) => setWlForm({ ...wlForm, kind: e.target.value })}>
                  {KINDS.map((k) => <option key={k} value={k}>{t(k)}</option>)}
                </select>
              </label>
              <label>{t('Addresses')}<input value={wlForm.addresses} required
                placeholder={t('e.g. 10.10.30.11, 10.10.30.12')}
                onChange={(e) => setWlForm({ ...wlForm, addresses: e.target.value })} /></label>
              <label>{t('Labels')}<input value={wlForm.labels}
                placeholder={t('e.g. app=shop, tier=web, env=prod')}
                onChange={(e) => setWlForm({ ...wlForm, labels: e.target.value })} /></label>
              <label>{t('Description')}<input value={wlForm.description}
                onChange={(e) => setWlForm({ ...wlForm, description: e.target.value })} /></label>
            </div>
            <div className="actions">
              <button className="btn btn-primary" type="submit">{wlEditId ? t('Save') : t('Create')}</button>
              {wlEditId && <button type="button" className="btn btn-ghost"
                onClick={() => { setWlEditId(null); setWlForm(EMPTY_WL) }}>{t('Cancel')}</button>}
            </div>
          </form>
        </section>

        <section className="card">
          <h2>{t('Groups')} ({groups.length})</h2>
          <p className="muted small">
            {t('A selector group is every workload whose labels match; a static group lists workloads by name or addresses. A rule names the group, stores its members, and follows the membership when it moves.')}
          </p>
          <div className="table-wrap">
            <table>
              <thead><tr><th>{t('Name')}</th><th>{t('Definition')}</th><th>{t('Members')}</th><th></th></tr></thead>
              <tbody>
                {groups.map((g) => (
                  <tr key={g.id}>
                    <td><strong>{g.name}</strong>
                      {g.description && <div className="muted small">{g.description}</div>}</td>
                    <td>{g.kind === 'selector'
                      ? <code>{g.selector}</code>
                      : <span className="small">{membersText(g.members)}</span>}</td>
                    <td><button className="btn btn-ghost" onClick={() => showMembers(g)}>
                      {g.member_count ?? '…'} {t('members')}</button></td>
                    <td className="row-actions">
                      <button className="btn btn-ghost" onClick={() => editGroup(g)}>{t('Edit')}</button>
                      <button className="btn btn-ghost" onClick={() => removeGroup(g)}>{t('Delete')}</button>
                    </td>
                  </tr>
                ))}
                {!groups.length && <tr><td colSpan={4} className="muted">{t('No groups yet')}</td></tr>}
              </tbody>
            </table>
          </div>
          {preview && (
            <div className="infobox">
              <strong>{preview.group.name}</strong>: {preview.count} {t('members')}
              {preview.rules?.length > 0 && (
                <> · {t('used by')} {preview.rules.map((r, i) => (
                  <span key={r}>{i > 0 && ', '}<Link to={`/rules/${r}`} className="rule-link">{r}</Link></span>
                ))}</>
              )}
              <div className="small">
                {(preview.members || []).map((m) => (
                  <span key={m.ip} className="member-chip"><code>{m.ip}</code>{m.alias ? ` ${m.alias}` : ''}</span>
                ))}
              </div>
              <button type="button" className="btn btn-ghost" onClick={() => setPreview(null)}>{t('Close')}</button>
            </div>
          )}
          <form onSubmit={submitGroup} className="object-form">
            <div className="grid-3">
              <label>{t('Name')}<input value={groupForm.name} required placeholder={t('e.g. shop-web')}
                onChange={(e) => setGroupForm({ ...groupForm, name: e.target.value })} /></label>
              <label>{t('Kind')}
                <select value={groupForm.kind} onChange={(e) => setGroupForm({ ...groupForm, kind: e.target.value })}>
                  <option value="selector">{t('by labels (selector)')}</option>
                  <option value="static">{t('by list (static)')}</option>
                </select>
              </label>
              {groupForm.kind === 'selector'
                ? <label>{t('Selector')}<input value={groupForm.selector} required
                    placeholder={t('e.g. app=shop, tier=web')}
                    onChange={(e) => setGroupForm({ ...groupForm, selector: e.target.value })} /></label>
                : <label>{t('Members')}<input value={groupForm.members} required
                    placeholder={t('workload names or addresses, e.g. web01, 10.10.30.0/28')}
                    onChange={(e) => setGroupForm({ ...groupForm, members: e.target.value })} /></label>}
              <label>{t('Description')}<input value={groupForm.description}
                onChange={(e) => setGroupForm({ ...groupForm, description: e.target.value })} /></label>
            </div>
            <div className="actions">
              <button className="btn btn-primary" type="submit">
                {groupEditId ? t('Save (rules are re-checked)') : t('Create')}</button>
              {groupEditId && <button type="button" className="btn btn-ghost"
                onClick={() => { setGroupEditId(null); setGroupForm(EMPTY_GROUP) }}>{t('Cancel')}</button>}
            </div>
          </form>
        </section>
      </div>
    </div>
  )
}
