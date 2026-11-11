import AuditLog from '../components/AuditLog'
import { useLang } from '../i18n'

/* The auditor's view of the audit log (#41). Reading the log and checking its
   chain used to need the admin account - the one account an audit should not
   have to borrow. */
export default function AuditLogPage() {
  const { t } = useLang()
  return (
    <div>
      <div className="page-head">
        <h1>{t('Audit log')}</h1>
        <span className="muted">
          {t('Who did what and when – every entry is chained to the one before it, so a later change shows')}
        </span>
      </div>
      <AuditLog full />
    </div>
  )
}
