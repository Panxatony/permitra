import { translate } from './i18n'

/* The instance language, cached by main.jsx after loading the public setting.
   This module runs outside the React tree, so it cannot use the context. */
let instanceLanguage = 'en'
export function setInstanceLanguage(lang) {
  instanceLanguage = lang === 'de' ? 'de' : 'en'
}

function uiLanguage() {
  return instanceLanguage
}

// Names of the localStorage slots, not the values kept in them. The secret
// scanner reads any identifier ending in _token as a credential, hence skipcq.
const TOKEN_KEY = 'permitra_token'  // skipcq: SCT-A000
const VRF_KEY = 'permitra_vrf'  // skipcq: SCT-A000

export function getVrfName() {
  return localStorage.getItem(VRF_KEY) || ''
}

export function setVrfName(name) {
  localStorage.setItem(VRF_KEY, name)
}
const USER_KEY = 'permitra_user'  // skipcq: SCT-A000

export function getToken() {
  return localStorage.getItem(TOKEN_KEY)
}

export function getUser() {
  const raw = localStorage.getItem(USER_KEY)
  return raw ? JSON.parse(raw) : null
}

/* Every role the account holds (#78). Falls back to the single `role` so a
   session stored before multi-role - one already in somebody's browser - keeps
   working until the next sign-in instead of reading as an account with none. */
export function rolesOf(user) {
  if (!user) return []
  return user.roles?.length ? user.roles : (user.role ? [user.role] : [])
}

/* True when the account holds any of the named roles - the shape the backend's
   require_roles(...) uses, so both sides ask the same question. */
export function hasRole(user, ...roles) {
  const held = rolesOf(user)
  return roles.some((r) => held.includes(r))
}

export function setSession(token, user) {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

export async function login(username, password, otp = '') {
  const body = new URLSearchParams({ username, password })
  if (otp) body.set('otp', otp)
  const res = await fetch('/api/auth/login', { method: 'POST', body })
  if (!res.ok) throw new Error(translate((await res.json()).detail, uiLanguage()) || 'Login fehlgeschlagen')
  const data = await res.json()
  setSession(data.access_token, data.user)
  return data.user
}

// WebAuthn: base64url <-> ArrayBuffer for the browser credential API
const b64uToBuf = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

export async function passkeyLogin(username) {
  const optRes = await fetch('/api/auth/passkey/login-options', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
  })
  if (!optRes.ok) throw new Error(translate((await optRes.json()).detail, uiLanguage()) || 'Passkey nicht verfügbar')
  const options = await optRes.json()
  options.challenge = b64uToBuf(options.challenge)
  options.allowCredentials = (options.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) }))
  const cred = await navigator.credentials.get({ publicKey: options })
  const credential = {
    id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      authenticatorData: bufToB64u(cred.response.authenticatorData),
      signature: bufToB64u(cred.response.signature),
      userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  }
  const res = await fetch('/api/auth/passkey/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, credential }),
  })
  if (!res.ok) throw new Error(translate((await res.json()).detail, uiLanguage()) || 'Passkey-Anmeldung fehlgeschlagen')
  const data = await res.json()
  setSession(data.access_token, data.user)
  return data.user
}

export async function passkeyRegister(name) {
  const options = await request('/api/auth/passkey/register-options', { method: 'POST' })
  options.challenge = b64uToBuf(options.challenge)
  options.user.id = b64uToBuf(options.user.id)
  options.excludeCredentials = (options.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) }))
  const cred = await navigator.credentials.create({ publicKey: options })
  const credential = {
    id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
    },
    clientExtensionResults: cred.getClientExtensionResults(),
  }
  return request('/api/auth/passkey/register', { method: 'POST', body: { credential, name } })
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (options.body && !(options.body instanceof URLSearchParams)) {
    headers['Content-Type'] = 'application/json'
    options = { ...options, body: JSON.stringify(options.body) }
  }
  const res = await fetch(path, { ...options, headers })
  if (res.status === 401) {
    clearSession()
    window.location.href = '/login'
    throw new Error('Sitzung abgelaufen')
  }
  if (!res.ok) {
    let detail = `HTTP ${res.status}`
    try {
      const data = await res.json()
      detail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail)
    } catch { /* response was not JSON */ }
    // The API speaks English; translate for the German interface (see
    // backendMessages.js). One place covers every caller that shows an error.
    throw new Error(translate(detail, uiLanguage()))
  }
  // Read the body as text first and only then decide: FastAPI stamps
  // application/json even onto a 204 with an empty body, and res.json() on
  // nothing throws - in Safari as the baffling "The string did not match the
  // expected pattern", shown to a user who had just successfully deleted an
  // account. Empty is a valid answer and parses to null, not to an error.
  const contentType = res.headers.get('content-type') || ''
  const text = await res.text()
  if (!text) return null
  return contentType.includes('application/json') ? JSON.parse(text) : text
}

export const api = {
  vrfs: () => request('/api/vrfs'),
  me: () => request('/api/auth/me'),
  settings: () => request('/api/settings'),
  publicSettings: () => request('/api/settings/public'),
  requestorReport: () => request('/api/reports/requestors'),
  architects: () => request('/api/users/architects'),
  proposeHandover: (id, newRequestor) => request(`/api/rules/${id}/requestor-handover`, { method: 'POST', body: { new_requestor: newRequestor } }),
  confirmHandover: (id) => request(`/api/rules/${id}/requestor-handover/confirm`, { method: 'POST', body: {} }),
  cancelHandover: (id) => request(`/api/rules/${id}/requestor-handover/cancel`, { method: 'POST', body: {} }),
  incomingHandovers: () => request('/api/rules/handovers/incoming'),
  setupStatus: () => request('/api/setup/status'),
  updateSettings: (p) => request('/api/settings', { method: 'PUT', body: p }),
  users: () => request('/api/users'),
  auditLog: (params = {}) => request(`/api/audit-log?${new URLSearchParams(params)}`),
  auditVerify: () => request('/api/audit-log/verify'),
  auditSiemStatus: () => request('/api/audit-log/siem-status'),
  auditCheckpoint: () => request('/api/audit-log/checkpoint', { method: 'POST' }),
  netboxConfig: () => request('/api/netbox/config'),
  setNetboxConfig: (p) => request('/api/netbox/config', { method: 'PUT', body: p }),
  netboxTest: () => request('/api/netbox/test', { method: 'POST' }),
  netboxImport: () => request('/api/netbox/import', { method: 'POST' }),
  netboxPrefixes: () => request('/api/netbox/prefixes'),
  netboxAdopt: (items) => request('/api/netbox/adopt', { method: 'POST', body: { items } }),
  riskCriteria: () => request('/api/risk/criteria'),
  setRiskyPort: (port, label) => request(`/api/risk/ports/${encodeURIComponent(port)}`, { method: 'PUT', body: { label } }),
  deleteRiskyPort: (port) => request(`/api/risk/ports/${encodeURIComponent(port)}`, { method: 'DELETE' }),
  apiTokens: () => request('/api/api-tokens'),
  createApiToken: (name, expires_days) => request('/api/api-tokens', { method: 'POST', body: { name, expires_days } }),
  revokeApiToken: (id) => request(`/api/api-tokens/${id}`, { method: 'DELETE' }),
  createUser: (p) => request('/api/users', { method: 'POST', body: p }),
  updateUser: (username, p) => request(`/api/users/${encodeURIComponent(username)}`, { method: 'PUT', body: p }),
  deleteUser: (username) => request(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' }),
  sendReset: (username) => request(`/api/users/${encodeURIComponent(username)}/send-reset`, { method: 'POST' }),
  forgotPassword: (username) => request('/api/auth/forgot', { method: 'POST', body: { username } }),
  setPassword: (token, password) => request('/api/auth/set-password', { method: 'POST', body: { token, password } }),
  changePassword: (current, next) =>
    request('/api/auth/change-password', { method: 'POST', body: { current, new: next } })
      .then((r) => {
        // Changing the password revokes old tokens; adopt the fresh one
        if (r?.access_token) localStorage.setItem(TOKEN_KEY, r.access_token)
        return r
      }),
  setNotifications: (on) => request('/api/auth/notifications', { method: 'PUT', body: { notify_email: on } }),
  totpSetup: () => request('/api/auth/totp/setup', { method: 'POST' }),
  totpEnable: (code) => request('/api/auth/totp/enable', { method: 'POST', body: { code } }),
  totpDisable: (password) => request('/api/auth/totp/disable', { method: 'POST', body: { password } }),
  passkeys: () => request('/api/auth/passkeys'),
  deletePasskey: (id) => request(`/api/auth/passkeys/${id}`, { method: 'DELETE' }),
  rules: (params = {}) => {
    const q = new URLSearchParams(Object.entries({ vrf: getVrfName(), ...params }).filter(([, v]) => v))
    return request(`/api/rules?${q}`)
  },
  rule: (id) => request(`/api/rules/${id}`),
  nextId: () => request('/api/rules/next-id'),
  createRule: (payload) => request('/api/rules', { method: 'POST', body: { vrf: getVrfName(), ...payload } }),
  declareEmergencyRule: (payload) => request('/api/rules/emergency', { method: 'POST', body: { vrf: getVrfName(), ...payload } }),
  updateRule: (id, payload) => request(`/api/rules/${id}`, { method: 'PUT', body: { vrf: getVrfName(), ...payload } }),
  deleteRule: (id) => request(`/api/rules/${id}`, { method: 'DELETE' }),
  restoreRule: (id, version) =>
    request(`/api/rules/${id}/restore/${version}`, { method: 'POST' }),
  submit: (id) => request(`/api/rules/${id}/submit`, { method: 'POST' }),
  approve: (id, comment) => request(`/api/rules/${id}/approve`, { method: 'POST', body: { comment } }),
  reject: (id, comment) => request(`/api/rules/${id}/reject`, { method: 'POST', body: { comment } }),
  deactivate: (id, comment) => request(`/api/rules/${id}/deactivate`, { method: 'POST', body: { comment } }),
  setImplStatus: (id, implStatus) => request(`/api/rules/${id}/impl-status`, { method: 'PUT', body: implStatus }),
  addComment: (id, text) => request(`/api/rules/${id}/comments`, { method: 'POST', body: { text } }),
  conflicts: (id) => request(`/api/rules/${id}/conflicts`),
  risk: (id) => request(`/api/rules/${id}/risk`),
  implementation: (id) => request(`/api/rules/${id}/implementation`),
  ipSearch: (q) => request(`/api/rules/ip-search?${new URLSearchParams({ q, vrf: getVrfName() })}`),
  pathSearch: (src, dst) => request(`/api/rules/path-search?${new URLSearchParams({ src, dst, vrf: getVrfName() })}`),
  pathAnalysis: (params) => { params.set('vrf', getVrfName()); return request(`/api/rules/path-analysis?${params}`) },
  expiring: (days = 30) => request(`/api/rules/expiring?days=${days}`),
  // Recertification campaigns (#35)
  recertCampaigns: () => request('/api/recertification/campaigns'),
  recertCampaign: (id) => request(`/api/recertification/campaigns/${id}`),
  createRecertCampaign: (payload) => request('/api/recertification/campaigns', { method: 'POST', body: payload }),
  closeRecertCampaign: (id) => request(`/api/recertification/campaigns/${id}/close`, { method: 'POST', body: {} }),
  recertDecide: (cid, itemId, decision, payload) =>
    request(`/api/recertification/campaigns/${cid}/items/${itemId}/${decision}`, { method: 'POST', body: payload }),
  extendRule: (id, validUntil, comment = '') =>
    request(`/api/rules/${id}/extend`, { method: 'POST', body: { valid_until: validUntil, comment } }),
  dashboard: () => request('/api/dashboard'),
  resolveComponents: (payload) => request('/api/rules/resolve-components', { method: 'POST', body: { vrf: getVrfName(), ...payload } }),
  saveAddressMap: (payload) => request('/api/address-map', { method: 'POST', body: { vrf: getVrfName(), ...payload } }),
  addressMap: () => request('/api/address-map'),
  components: () => request('/api/components'),
  drift: (id) => request(`/api/components/${id}/drift`),
  componentLinks: () => request('/api/components/links'),
  createComponentLink: (p) => request('/api/components/links', { method: 'POST', body: p }),
  deleteComponentLink: (id) => request(`/api/components/links/${id}`, { method: 'DELETE' }),
  uploadActualConfig: (id, content) =>
    request(`/api/components/${id}/actual-config`, { method: 'PUT', body: { content } }),
  addressObjects: () => request('/api/objects/addresses'),
  createAddressObject: (p) => request('/api/objects/addresses', { method: 'POST', body: p }),
  updateAddressObject: (id, p) => request(`/api/objects/addresses/${id}`, { method: 'PUT', body: p }),
  deleteAddressObject: (id) => request(`/api/objects/addresses/${id}`, { method: 'DELETE' }),
  epgs: () => request('/api/epgs'),
  createEpg: (p) => request('/api/epgs', { method: 'POST', body: p }),
  deleteEpg: (id) => request(`/api/epgs/${id}`, { method: 'DELETE' }),
  epgMap: () => request('/api/epgs/address-map'),
  upsertEpgMap: (p) => request('/api/epgs/address-map', { method: 'POST', body: p }),
  deleteEpgMap: (id) => request(`/api/epgs/address-map/${id}`, { method: 'DELETE' }),
  serviceObjects: () => request('/api/objects/services'),
  createServiceObject: (p) => request('/api/objects/services', { method: 'POST', body: p }),
  deleteServiceObject: (id) => request(`/api/objects/services/${id}`, { method: 'DELETE' }),
  createComponent: (payload) => request('/api/components', { method: 'POST', body: payload }),
  updateComponent: (id, payload) => request(`/api/components/${id}`, { method: 'PUT', body: payload }),
  deleteComponent: (id) => request(`/api/components/${id}`, { method: 'DELETE' }),
  aciGateways: () => request('/api/aci-gateways'),
  createAciGateway: (payload) => request('/api/aci-gateways', { method: 'POST', body: payload }),
  updateAciGateway: (id, payload) => request(`/api/aci-gateways/${id}`, { method: 'PUT', body: payload }),
  deleteAciGateway: (id) => request(`/api/aci-gateways/${id}`, { method: 'DELETE' }),
  zones: () => request('/api/zones'),
  createZone: (payload) => request('/api/zones', { method: 'POST', body: payload }),
  zoneNextCode: () => request('/api/zones/next-code'),
  deleteZone: (name) => request(`/api/zones/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  zoneMatrix: () => request('/api/zones/matrix'),
  zoneOverview: () => request('/api/zones/overview'),
  matrixChanges: () => request('/api/zones/matrix/changes'),
  submitMatrixBatch: (items, comment = '') =>
    request('/api/zones/matrix/changes', { method: 'POST', body: { items, comment } }),
  approveMatrixChange: (id, comment = '') =>
    request(`/api/zones/matrix/changes/${id}/approve`, { method: 'POST', body: { comment } }),
  rejectMatrixChange: (id, comment = '') =>
    request(`/api/zones/matrix/changes/${id}/reject`, { method: 'POST', body: { comment } }),
  zoneNetworks: () => request('/api/zones/networks'),
  updateZoneNetwork: (id, payload) => request(`/api/zones/networks/${id}`, { method: 'PUT', body: payload }),
  addZoneNetwork: (name, cidr, description = '') =>
    request(`/api/zones/${encodeURIComponent(name)}/networks`, { method: 'POST', body: { cidr, description, vrf: getVrfName() } }),
  deleteZoneNetwork: (id) => request(`/api/zones/networks/${id}`, { method: 'DELETE' }),
  setZoneComponents: (name, componentIds) =>
    request(`/api/zones/${encodeURIComponent(name)}/components`, { method: 'PUT', body: { component_ids: componentIds } }),
  setZoneMeta: (name, payload) =>
    request(`/api/zones/${encodeURIComponent(name)}/meta`, { method: 'PUT', body: payload }),
  setZonePapLevel: (name, level) =>
    request(`/api/zones/${encodeURIComponent(name)}/pap-level`, { method: 'PUT', body: { pap_level: level } }),
  setZonePolicy: (from, to, payload) =>
    request(`/api/zones/matrix/${encodeURIComponent(from)}/${encodeURIComponent(to)}`, { method: 'PUT', body: payload }),
  zoneCheck: (source, destination, platforms = []) => {
    const q = new URLSearchParams({ source, destination, platforms: platforms.join(',') })
    return request(`/api/zones/check?${q}`)
  },
  exportPreview: (fmt, params = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== ''))
    return request(`/api/export/${fmt}?${q}`)
  },
}
