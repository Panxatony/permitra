import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Modal } from '../components/shared'
import { HelpBody, SECTIONS, fmt, teaser } from '../helpContent'
import { useLang } from '../i18n'

/* The help lives in the application, not only in the repository: the person
   with the question is standing in front of a form, not in front of GitHub.
   Content is kept here as one bilingual structure rather than in the i18n
   dictionary - these are pages of prose keyed by topic, not labels keyed by
   English text, and the instance language decides which half renders.

   The page is an overview of topics; the text itself opens as an overlay. One
   wall of nine sections answers none of them well - a reader with a question
   has one, not nine. Pages link here with anchors (/help#recert), which open
   the matching overlay directly, so the "?" next to a feature lands on the
   explanation rather than on a table of contents. */

export default function Help() {
  const { lang, t } = useLang()
  const { hash } = useLocation()
  const navigate = useNavigate()
  const [openId, setOpenId] = useState(null)

  // A deep link (/help#recert) opens its overlay directly - the "?" beside a
  // feature must land on the explanation, not on a table of contents.
  useEffect(() => {
    const id = hash.slice(1)
    setOpenId(SECTIONS.some((s) => s.id === id) ? id : null)
  }, [hash])

  const open = (id) => navigate(`/help#${id}`)
  const close = () => navigate('/help')
  const current = SECTIONS.find((s) => s.id === openId)
  const content = current && (lang === 'de' ? current.de : current.en)

  return (
    <div className="help-page">
      <div className="page-head">
        <h1>{t('Help')}</h1>
        <span className="muted">
          {t('What the interface cannot say in one line – in-depth documentation lives in the repository')}
        </span>
      </div>

      <div className="help-grid">
        {SECTIONS.map((s) => {
          const c = lang === 'de' ? s.de : s.en
          return (
            <button key={s.id} type="button" className="card help-card"
              onClick={() => open(s.id)}>
              <h2>{c.title}</h2>
              <p className="muted">{fmt(teaser(c))}</p>
            </button>
          )
        })}
      </div>

      {content && (
        <Modal title={content.title} onClose={close}>
          <HelpBody section={current} />
        </Modal>
      )}

      <p className="muted small">
        {t('These topics are also on the website, linkable and printable:')}{' '}
        <a href="https://permitra.de/hilfe.html" target="_blank" rel="noopener noreferrer">
          permitra.de/hilfe
        </a>
      </p>
    </div>
  )
}
