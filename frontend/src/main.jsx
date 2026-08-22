import React, { useEffect, useState } from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App'
import { api, setInstanceLanguage } from './api'
import { LangProvider } from './i18n'
import { ThemeProvider } from './theme'
import './styles.css'

/* The interface language is an instance setting made by the administrator, so
   it has to be fetched before anything is rendered - including the login page,
   which is why the endpoint is public. English is the source language and
   therefore also the fallback if the request fails: the interface then reads
   as English rather than breaking. */
function Root() {
  const [lang, setLang] = useState(null)

  useEffect(() => {
    let cancelled = false
    api.publicSettings()
      .then((s) => {
        const configured = s.ui_language === 'de' ? 'de' : 'en'
        setInstanceLanguage(configured)   // for backend messages outside React
        if (!cancelled) setLang(configured)
      })
      .catch(() => { if (!cancelled) setLang('en') })
    return () => { cancelled = true }
  }, [])

  if (lang === null) return null   // avoid a flash of the wrong language

  return (
    <ThemeProvider>
      <LangProvider lang={lang}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </LangProvider>
    </ThemeProvider>
  )
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>,
)
