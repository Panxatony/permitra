/* Color scheme: system (default), light or dark.
 *
 * Three states instead of two: anyone who makes no choice follows the operating
 * system - the right default for most people. An explicit choice sets
 * data-theme on the <html> element and then wins in both directions (even
 * against a dark system). The colors themselves live exclusively as tokens in
 * styles.css.
 */
import { createContext, useCallback, useContext, useEffect, useState } from 'react'

const KEY = 'permitra_theme'
export const THEMES = ['system', 'light', 'dark']

function apply(theme) {
  const root = document.documentElement
  if (theme === 'system') root.removeAttribute('data-theme')
  else root.setAttribute('data-theme', theme)
}

/* Apply before the first render so the page does not briefly flash light.
   Also called from index.html. */
export function applyStoredTheme() {
  let stored = null
  try {
    stored = localStorage.getItem(KEY)
  } catch { /* localStorage may be blocked - fall back to system */ }
  apply(THEMES.includes(stored) ? stored : 'system')
}

const ThemeContext = createContext({ theme: 'system', cycle: () => {}, setTheme: () => {} })

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => {
    try {
      const stored = localStorage.getItem(KEY)
      return THEMES.includes(stored) ? stored : 'system'
    } catch {
      return 'system'
    }
  })

  useEffect(() => {
    apply(theme)
    try {
      localStorage.setItem(KEY, theme)
    } catch { /* no harm done: the choice then only lasts for this session */ }
  }, [theme])

  const setTheme = useCallback((next) => {
    if (THEMES.includes(next)) setThemeState(next)
  }, [])

  const cycle = useCallback(() => {
    setThemeState((cur) => THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length])
  }, [])

  return (
    <ThemeContext.Provider value={{ theme, cycle, setTheme }}>{children}</ThemeContext.Provider>
  )
}

export const useTheme = () => useContext(ThemeContext)
