import { Link, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { api, clearSession, getUser, getVrfName, setVrfName } from './api'
import { useLang } from './i18n'
import { useTheme } from './theme'
import Components from './pages/Components'
import Dashboard from './pages/Dashboard'
import Help from './pages/Help'
import Reports from './pages/Reports'
import Networks from './pages/Networks'
import ObjectCatalog from './pages/ObjectCatalog'
import Recertification from './pages/Recertification'
import ExportPage from './pages/ExportPage'
import Login from './pages/Login'
import Approvals from './pages/Approvals'
import Admin from './pages/Admin'
import Account from './pages/Account'
import SetPassword from './pages/SetPassword'
import RuleDetail from './pages/RuleDetail'
import RuleForm from './pages/RuleForm'
import RuleList from './pages/RuleList'
import Search from './pages/Search'
import ZoneMatrix from './pages/ZoneMatrix'

const THEME_ICONS = { system: '🖥️', light: '☀️', dark: '🌙' }
const THEME_LABELS = { system: 'System', light: 'Light', dark: 'Dark' }

const ROLE_LABELS = { architect: 'Architect', operations: 'Operations', change_approver: 'Change approver', admin: 'Administrator' }

function Layout({ children }) {
  const user = getUser()
  const navigate = useNavigate()
  const location = useLocation()
  const { t } = useLang()
  const { theme, cycle: cycleTheme } = useTheme()
  const [vrfs, setVrfs] = useState([])
  // The backend's version, not the bundle's: the number on screen should be
  // the number of the code that is actually answering.
  const [version, setVersion] = useState('')
  useEffect(() => {
    api.publicSettings().then((s) => setVersion(s.version || '')).catch(() => {})
  }, [])
  useEffect(() => {
    api.vrfs().then(setVrfs).catch(() => setVrfs([]))
  }, [])
  const currentVrf = getVrfName() || (vrfs[0]?.name ?? '')
  const switchVrf = (name) => {
    setVrfName(name)
    window.location.reload()  // load every view in the new environment context
  }
  if (!user) return <Navigate to="/login" state={{ from: location }} />

  const logout = () => {
    clearSession()
    navigate('/login')
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="topbar-row">
          <Link to="/" className="brand">
            {/* A file rather than the shield emoji: an emoji depends on the
                client having an emoji font, and without one it renders as an
                empty box where the product name should be. */}
            <img src="/permitra-mark.svg" alt="" className="brand-mark" />
            Permitra
          </Link>
          <div className="userbox">
            {vrfs.length > 1 && (
              <label className="vrf-select" title={t('Environment/VRF – separate worlds with possibly overlapping IP ranges (e.g. IT and OT)')}>
                <span className="muted-light">{t('Environment')}:</span>
                <select value={currentVrf} onChange={(e) => switchVrf(e.target.value)}>
                  {vrfs.map((v) => <option key={v.id} value={v.name}>{v.name}</option>)}
                </select>
              </label>
            )}
            <Link to="/account" className="account-link" title="Konto & Sicherheit">
              {user.full_name || user.username}
            </Link>
            <span className={`badge role-${user.role}`}>{t(ROLE_LABELS[user.role])}</span>
            <button className="btn btn-topbar btn-theme" onClick={cycleTheme}
              title={`${t('Colour scheme')}: ${t(THEME_LABELS[theme])} – ${t('click to switch')}`}
              aria-label={`${t('Colour scheme')}: ${t(THEME_LABELS[theme])}`}>
              {THEME_ICONS[theme]}
            </button>
            <button className="btn btn-topbar" onClick={logout}>{t('Sign out')}</button>
          </div>
        </div>
        <nav>
          {user.role === 'admin' ? (
            /* Focused view: admins manage Permitra, no rule views */
            <Link to="/admin">{t('Administration')}</Link>
          ) : user.role === 'change_approver' ? (
            <>
              {/* Slimmed-down view: approvers only see what they need to decide */}
              <Link to="/approvals">{t('Approvals')}</Link>
              <Link to="/rules">{t('Rules')}</Link>
              <Link to="/zones">{t('Security zones')}</Link>
              <Link to="/networks">{t('Networks')}</Link>
            </>
          ) : (
            <>
              <Link to="/">{t('Dashboard')}</Link>
              <Link to="/rules">{t('Rules')}</Link>
              {user.role === 'architect' && <Link to="/rules/new">{t('New rule')}</Link>}
              {/* Reachable by operations too - they are the ones at the firewall at
                  three in the morning, and a fast path they cannot find is none.
                  Deliberately not styled as a primary action: it should be
                  available, not inviting. */}
              {['architect', 'operations'].includes(user.role) && (
                <Link to="/rules/new?emergency=1" className="nav-emergency">
                  {t('Emergency change')}
                </Link>
              )}
              <Link to="/search">{t('Analysis')}</Link>
              <Link to="/recertification">{t('Recertification')}</Link>
              <Link to="/zones">{t('Security zones')}</Link>
              <Link to="/networks">{t('Networks')}</Link>
              <Link to="/components">{t('Components')}</Link>
              <Link to="/objects">{t('Objects')}</Link>
              <Link to="/export">{t('Export')}</Link>
              <Link to="/reports">{t('Reports')}</Link>
            </>
          )}
          <Link to="/help" className="nav-help">{t('Help')}</Link>
        </nav>
      </header>
      <main>{children}</main>
      <footer className="app-footer">
        <span>Permitra {version && <code>{version}</code>}</span>
        <span>
          <Link to="/help">{t('Help')}</Link>
          {' · '}
          <a href="https://github.com/Panxatony/permitra" target="_blank"
            rel="noopener noreferrer">GitHub</a>
          {' · '}
          <a href="https://permitra.de" target="_blank" rel="noopener noreferrer">permitra.de</a>
        </span>
        <span className="muted">Apache-2.0 · © 2026 Lars Vonhof-Hunold</span>
      </footer>
    </div>
  )
}

function Home() {
  // Change approvers start focused on the approvals page
  const user = getUser()
  if (user?.role === 'admin') return <Navigate to="/admin" replace />
  if (user?.role === 'change_approver') return <Navigate to="/approvals" replace />
  return <Dashboard />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/set-password" element={<SetPassword />} />
      <Route path="/" element={<Layout><Home /></Layout>} />
      <Route path="/approvals" element={<Layout><Approvals /></Layout>} />
      <Route path="/account" element={<Layout><Account /></Layout>} />
      <Route path="/admin" element={<Layout><Admin /></Layout>} />
      <Route path="/rules" element={<Layout><RuleList /></Layout>} />
      <Route path="/recertification" element={<Layout><Recertification /></Layout>} />
      <Route path="/rules/new" element={<Layout><RuleForm /></Layout>} />
      <Route path="/rules/:id" element={<Layout><RuleDetail /></Layout>} />
      <Route path="/rules/:id/edit" element={<Layout><RuleForm /></Layout>} />
      <Route path="/search" element={<Layout><Search /></Layout>} />
      <Route path="/path" element={<Navigate to="/search" replace />} />
      {/* The gateways moved onto the components page - an ACI gateway is a
          property of the fabric, not a domain of its own. Old links keep working. */}
      <Route path="/gateways" element={<Navigate to="/components" replace />} />
      <Route path="/zones" element={<Layout><ZoneMatrix /></Layout>} />
      <Route path="/networks" element={<Layout><Networks /></Layout>} />
      <Route path="/components" element={<Layout><Components /></Layout>} />
      <Route path="/objects" element={<Layout><ObjectCatalog /></Layout>} />
      <Route path="/export" element={<Layout><ExportPage /></Layout>} />
      <Route path="/help" element={<Layout><Help /></Layout>} />
      <Route path="/reports" element={<Layout><Reports /></Layout>} />
    </Routes>
  )
}
