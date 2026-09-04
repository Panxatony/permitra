import React, { useEffect, useState } from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import { api, setInstanceLanguage } from './api'
import { LangProvider } from './i18n'
import { LegalProvider } from './legal'
import { ThemeProvider } from './theme'
import './styles.css'

/* The interface language is an instance setting made by the administrator, so
   it has to be fetched before anything is rendered - including the login page,
   which is why the endpoint is public. English is the source language and
   therefore also the fallback if the request fails: the interface then reads
   as English rather than breaking. */
function Root() {
  const [lang, setLang] = useState(null)
  // Fetched in the same request as the language, and for the same reason: the
  // sign-in page needs them before anyone has signed in.
  const [legal, setLegal] = useState(null)

  useEffect(() => {
    let cancelled = false
    api.publicSettings()
      .then((s) => {
        const configured = s.ui_language === 'de' ? 'de' : 'en'
        setInstanceLanguage(configured)   // for backend messages outside React
        if (!cancelled) {
          setLang(configured)
          setLegal({ imprint_url: s.imprint_url || '', privacy_url: s.privacy_url || '' })
        }
      })
      .catch(() => { if (!cancelled) setLang('en') })
    return () => { cancelled = true }
  }, [])

  if (lang === null) return null   // avoid a flash of the wrong language

  return (
    <ThemeProvider>
      <LangProvider lang={lang}>
        <LegalProvider links={legal}>
          <BrowserRouter>
            <App />
          </BrowserRouter>
        </LegalProvider>
      </LangProvider>
    </ThemeProvider>
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
)
