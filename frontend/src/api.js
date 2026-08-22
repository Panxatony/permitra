const TOKEN_KEY = 'permitra_token'
const VRF_KEY = 'permitra_vrf'

export function getVrfName() {
  return localStorage.getItem(VRF_KEY) || ''
}

export function setVrfName(name) {
  localStorage.setItem(VRF_KEY, name)
}
const USER_KEY = 'permitra_user'

export function getToken() {
  return localStorage.getItem(TOKEN_KEY)
}

export function getUser() {
  const raw = localStorage.getItem(USER_KEY)
  return raw ? JSON.parse(raw) : null
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
  if (!res.ok) throw new Error((await res.json()).detail || 'Login fehlgeschlagen')
  const data = await res.json()
  setSession(data.access_token, data.user)
  return data.user
}

// WebAuthn: base64url <-> ArrayBuffer für die Browser-Credential-API
const b64uToBuf = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0))
const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b)))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')

export async function passkeyLogin(username) {
  const optRes = await fetch('/api/auth/passkey/login-options', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
  })
  if (!optRes.ok) throw new Error((await optRes.json()).detail || 'Passkey nicht verfügbar')
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
  if (!res.ok) throw new Error((await res.json()).detail || 'Passkey-Anmeldung fehlgeschlagen')
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
    } catch { /* Antwort war kein JSON */ }
    throw new Error(detail)
  }
  const contentType = res.headers.get('content-type') || ''
  return contentType.includes('application/json') ? res.json() : res.text()
}

export const api = {
  vrfs: () => request('/api/vrfs'),
  me: () => request('/api/auth/me'),
  settings: () => request('/api/settings'),
  updateSettings: (p) => request('/api/settings', { method: 'PUT', body: p }),
  users: () => request('/api/users'),
  createUser: (p) => request('/api/users', { method: 'POST', body: p }),
  updateUser: (username, p) => request(`/api/users/${encodeURIComponent(username)}`, { method: 'PUT', body: p }),
  deleteUser: (username) => request(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' }),
  sendReset: (username) => request(`/api/users/${encodeURIComponent(username)}/send-reset`, { method: 'POST' }),
  forgotPassword: (username) => request('/api/auth/forgot', { method: 'POST', body: { username } }),
  setPassword: (token, password) => request('/api/auth/set-password', { method: 'POST', body: { token, password } }),
  changePassword: (current, next) => request('/api/auth/change-password', { method: 'POST', body: { current, new: next } }),
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
  updateRule: (id, payload) => request(`/api/rules/${id}`, { method: 'PUT', body: { vrf: getVrfName(), ...payload } }),
  deleteRule: (id) => request(`/api/rules/${id}`, { method: 'DELETE' }),
  submit: (id) => request(`/api/rules/${id}/submit`, { method: 'POST' }),
  approve: (id, comment) => request(`/api/rules/${id}/approve`, { method: 'POST', body: { comment } }),
  reject: (id, comment) => request(`/api/rules/${id}/reject`, { method: 'POST', body: { comment } }),
  deactivate: (id, comment) => request(`/api/rules/${id}/deactivate`, { method: 'POST', body: { comment } }),
  setImplStatus: (id, implStatus) => request(`/api/rules/${id}/impl-status`, { method: 'PUT', body: implStatus }),
  addComment: (id, text) => request(`/api/rules/${id}/comments`, { method: 'POST', body: { text } }),
  conflicts: (id) => request(`/api/rules/${id}/conflicts`),
  implementation: (id) => request(`/api/rules/${id}/implementation`),
  ipSearch: (q) => request(`/api/rules/ip-search?${new URLSearchParams({ q, vrf: getVrfName() })}`),
  pathSearch: (src, dst) => request(`/api/rules/path-search?${new URLSearchParams({ src, dst, vrf: getVrfName() })}`),
  pathAnalysis: (params) => { params.set('vrf', getVrfName()); return request(`/api/rules/path-analysis?${params}`) },
  expiring: (days = 30) => request(`/api/rules/expiring?days=${days}`),
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
