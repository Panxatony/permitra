/* The imprint and privacy links, where the operator has configured them.

   They are not hard-coded to permitra.de on purpose: a self-hosted Permitra is
   operated by somebody else, and naming us in its footer would name the wrong
   controller. An instance that sets neither URL renders nothing here - a tool
   running inside a company network has no imprint obligation, and an empty
   footer entry is noise. See backend/app/legal.py for the full reasoning. */
import { createContext, useContext } from 'react'
import { useLang } from './i18n'

const LegalContext = createContext({ imprint_url: '', privacy_url: '' })

export function LegalProvider({ children, links }) {
  return (
    <LegalContext.Provider value={links || { imprint_url: '', privacy_url: '' }}>
      {children}
    </LegalContext.Provider>
  )
}

/* Renders nothing at all when neither URL is set, so a caller can drop it into
   a footer without guarding it. The separator only appears between two links
   that both exist. */
export function LegalLinks({ className }) {
  const { t } = useLang()
  const { imprint_url: imprint, privacy_url: privacy } = useContext(LegalContext)
  if (!imprint && !privacy) return null
  return (
    <span className={className}>
      {imprint && (
        <a href={imprint} target="_blank" rel="noopener noreferrer">{t('Legal notice')}</a>
      )}
      {imprint && privacy ? ' · ' : ''}
      {privacy && (
        <a href={privacy} target="_blank" rel="noopener noreferrer">{t('Privacy policy')}</a>
      )}
    </span>
  )
}
