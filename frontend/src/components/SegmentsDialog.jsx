import { useCallback, useEffect, useState } from 'react'
import { api, getUser, hasRole } from '../api'
import { Modal } from './shared'
import { useLang } from '../i18n'

/* The segments of one zone and the matrix between them (#36).

   The zone matrix says whether two zones may talk; inside a zone everything
   was allowed. A segment is a group that belongs to the zone, and the matrix
   here is the zone matrix one level down: directed Allow/Block cells, a
   default for what is not maintained, and the same request with two
   approvals to change either. Segments themselves are maintained directly -
   which group is a segment is documentation - but what rules may exist
   between them is a decision, and goes through the batch. */
export default function SegmentsDialog({ zone, groups, changes, onClose, onChanged }) {
  const { t } = useLang()
  const canEdit = hasRole(getUser(), 'architect', 'operations')
  const [matrix, setMatrix] = useState(null)
  const [form, setForm] = useState({ name: '', group: '', description: '' })
  const [draft, setDraft] = useState({})          // "from|to" -> policy
  const [draftDefault, setDraftDefault] = useState(null)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const zref = zone.code || zone.name

  const load = useCallback(() => {
    api.segments(zref).then(setMatrix).catch((e) => setError(e.message))
  }, [zref])
  useEffect(() => { load() }, [load])

  const segments = matrix?.segments || []
  const cells = {}
  for (const p of matrix?.policies || []) cells[`${p.from_segment}|${p.to_segment}`] = p.policy
  const pending = {}
  let pendingDefault = null
  for (const c of changes || []) {
    if (c.status !== 'pending' || c.from_zone !== zref) continue
    if (c.change_type === 'segment_policy') pending[`${c.extra?.from_segment}|${c.extra?.to_segment}`] = c
    if (c.change_type === 'segment_default') pendingDefault = c
  }
  const effectiveDefault = matrix?.intra_zone_default || 'permit'
  // Groups already in use as a segment cannot be a second one
  const taken = new Set(segments.map((s) => s.group))
  const freeGroups = (groups || []).filter((g) => !taken.has(g.name))

  const addSegment = async (e) => {
    e.preventDefault()
    setError(''); setNotice('')
    try {
      await api.createSegment(zref, form)
      setForm({ name: '', group: '', description: '' })
      load(); onChanged?.()
    } catch (err) { setError(err.message) }
  }
  const removeSegment = async (s) => {
    if (!window.confirm(t('Remove segment "{name}"?').replace('{name}', s.name))) return
    setError(''); setNotice('')
    try { await api.deleteSegment(zref, s.id); load(); onChanged?.() } catch (err) { setError(err.message) }
  }

  /* Clicking a cell cycles Allow -> Block -> as stored; the clicks are
     collected and submitted as one request, like the zone matrix. */
  const cycle = (from, to) => {
    if (!canEdit) return
    const key = `${from}|${to}`
    const stored = cells[key]
    const current = draft[key] ?? stored
    const next = current === 'allow_only' ? 'block_all' : 'allow_only'
    const copy = { ...draft }
    if (next === stored) delete copy[key]
    else copy[key] = next
    setDraft(copy)
  }
  const draftCount = Object.keys(draft).length + (draftDefault && draftDefault !== effectiveDefault ? 1 : 0)
  const submit = async () => {
    setError(''); setNotice('')
    const items = Object.entries(draft).map(([key, policy]) => {
      const [from_segment, to_segment] = key.split('|')
      return { type: 'segment_policy', zone: zref, from_segment, to_segment, policy }
    })
    if (draftDefault && draftDefault !== effectiveDefault) {
      items.push({ type: 'segment_default', zone: zref, default: draftDefault })
    }
    try {
      const res = await api.submitMatrixBatch(items, `${t('Segment matrix')} ${zref}`)
      setNotice(res.detail || t('Request submitted'))
      setDraft({}); setDraftDefault(null)
      onChanged?.()
    } catch (err) { setError(err.message) }
  }

  return (
    <Modal title={`${t('Segments')}: ${zone.code ? `${zone.code}-${zone.name}` : zone.name}`} onClose={onClose} wide>
      <p className="muted small">
        {t('Inside a segmented zone only the relations maintained here may carry rules. A segment is a group of this zone; the matrix between the segments is changed by request with two approvals, like the zone matrix.')}
      </p>
      {error && <div className="error">{error}</div>}
      {notice && <div className="okbox">{notice}</div>}

      {segments.length > 0 && (
        <>
          <div className="matrix-legend">
            <span className="badge cell-allow">Allow</span> {t('rules allowed')}
            <span className="badge cell-block">Block</span> {t('no rules admissible')}
            <span className="badge cell-undef">{t('empty')}</span>{' '}
            {effectiveDefault === 'deny' ? t('not maintained – default-deny: rules are rejected') : t('not maintained – allowed with a notice')}
            {canEdit && <em className="muted"> – {t('click a cell to toggle Allow ↔ Block')}</em>}
          </div>
          <div className="table-wrap matrix-wrap">
            <table className="matrix">
              <thead>
                <tr>
                  <th className="corner">{t('From \\ To')}</th>
                  {segments.map((s) => <th key={s.id} className="col-head"><span>{s.name}</span></th>)}
                </tr>
              </thead>
              <tbody>
                {segments.map((from) => (
                  <tr key={from.id}>
                    <th className="row-head">{from.name}</th>
                    {segments.map((to) => {
                      if (from.id === to.id) return <td key={to.id} className="cell-self">–</td>
                      const key = `${from.name}|${to.name}`
                      const stored = cells[key]
                      const shown = draft[key] ?? stored
                      const pend = pending[key]
                      const cls = !shown ? 'cell-undef' : shown === 'allow_only' ? 'cell-allow' : 'cell-block'
                      return (
                        <td key={to.id}
                          className={`${cls}${canEdit ? ' cell-edit' : ''}${pend ? ' cell-pending' : ''}${draft[key] ? ' cell-draft' : ''}`}
                          title={`${from.name} → ${to.name}` + (pend ? ` – ${t('request waiting for approval')} (${pend.requested_by})` : '')}
                          onClick={() => cycle(from.name, to.name)}>
                          {shown ? (shown === 'allow_only' ? 'Allow' : 'Block') : ''}{draft[key] ? ' ✎' : ''}{pend ? ' ⏳' : ''}
                        </td>
                      )
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="segment-default">
            <span>{t('Unmaintained relations:')}</span>
            <select value={draftDefault ?? effectiveDefault} disabled={!canEdit || Boolean(pendingDefault)}
              onChange={(e) => setDraftDefault(e.target.value)}>
              <option value="permit">{t('permit (allowed with a notice)')}</option>
              <option value="deny">{t('deny (default-deny, least privilege)')}</option>
            </select>
            {pendingDefault && <span className="badge status-in_review">⏳ {t('request for')} {pendingDefault.new_policy} {t('waiting for approval')}</span>}
            <a className="btn btn-ghost" href={api.segmentsCsvUrl(zref)} download>CSV</a>
          </div>
          {canEdit && (
            <div className="actions">
              <button className="btn btn-approve" onClick={submit} disabled={!draftCount}>
                {t('Request matrix changes')}{draftCount ? ` (${draftCount})` : ''}
              </button>
              {draftCount > 0 && <button className="btn btn-ghost" onClick={() => { setDraft({}); setDraftDefault(null) }}>{t('Discard')}</button>}
            </div>
          )}
        </>
      )}

      <h3>{t('Segments')} ({segments.length})</h3>
      <div className="table-wrap">
        <table>
          <thead><tr><th>{t('Name')}</th><th>{t('Group')}</th><th>{t('Members')}</th><th>{t('Description')}</th><th></th></tr></thead>
          <tbody>
            {segments.map((s) => (
              <tr key={s.id}>
                <td><strong>{s.name}</strong></td>
                <td>{s.group} <span className="muted small">({t(s.group_kind)})</span></td>
                <td>{s.member_count}</td>
                <td>{s.description}</td>
                <td className="row-actions">
                  {canEdit && <button className="btn btn-ghost" onClick={() => removeSegment(s)}>{t('Remove')}</button>}
                </td>
              </tr>
            ))}
            {!segments.length && <tr><td colSpan={5} className="muted">{t('No segments yet – the zone is not segmented, intra-zone traffic is allowed as before.')}</td></tr>}
          </tbody>
        </table>
      </div>
      {canEdit && (
        <form onSubmit={addSegment} className="object-form">
          <div className="grid-3">
            <label>{t('Name')}<input value={form.name} required placeholder={t('e.g. web')}
              onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
            <label>{t('Group')}
              <select value={form.group} required onChange={(e) => setForm({ ...form, group: e.target.value })}>
                <option value="">{t('– select –')}</option>
                {freeGroups.map((g) => <option key={g.id} value={g.name}>{g.name} ({g.member_count} {t('members')})</option>)}
              </select>
            </label>
            <label>{t('Description')}<input value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })} /></label>
          </div>
          <div className="actions">
            <button className="btn btn-primary" type="submit">{t('Add segment')}</button>
            <span className="muted small">{t('The group has to lie entirely inside the zone.')}</span>
          </div>
        </form>
      )}
    </Modal>
  )
}
