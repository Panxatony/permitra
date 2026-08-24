import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getUser, hasRole } from '../api'
import RuleForm from '../pages/RuleForm'
import { useLang } from '../i18n'
import { Modal } from './shared'

/* Creating a rule starts where the rules are, as an overlay - not on a page you
   have to navigate away to and back from.

   An emergency change is an option inside that form rather than a separate
   entry point: it is the same rule with the same checks, differing only in that
   it is already on the device. Operations can only declare emergencies, so for
   them the button says so plainly instead of offering "new rule" and refusing
   it on submit. */
export default function NewRuleButton() {
  const { t } = useLang()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const user = getUser()
  const architect = hasRole(user, 'architect')
  const operations = hasRole(user, 'operations')

  if (!architect && !operations) return null

  return (
    <>
      <button className={`btn ${architect ? 'btn-primary' : 'nav-emergency'}`}
        onClick={() => setOpen(true)}>
        {architect ? t('New rule') : t('Emergency change')}
      </button>
      {/* Wide: the form has three-column rows, and 640px - right for a page of
          help text - squeezes them into a single column. */}
      {open && (
        <Modal wide title={architect ? t('Create new rule') : t('Document an emergency change')}
          onClose={() => setOpen(false)}>
          <RuleForm embedded onClose={() => setOpen(false)}
            onCreated={(rule) => { setOpen(false); navigate(`/rules/${rule.rule_id}`) }} />
        </Modal>
      )}
    </>
  )
}
