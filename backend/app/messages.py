"""Messages the application sends to its users, and their translations.

English is the source language: every message is written in English at the
place it is raised. German is a translation kept in the catalogue below, keyed
by the English text.

Why the server translates instead of the interface: these messages are
generated here, often with values filled in ("Rule SR00042 not found"). A
dictionary in the browser cannot match a sentence whose middle changes, and
the REST API has consumers other than the interface - Ansible and Terraform
read the same error text. Translating at the source means one place, and every
caller gets the message in the language the instance is configured for.

Usage at the raise site:

    raise HTTPException(404, _("Rule {rule_id} not found", rule_id=rule_id))

The placeholder names are part of the message: German word order differs, so a
translation has to be free to move them. Anything not in the catalogue falls
back to the English text - a missing translation then reads as English rather
than breaking.
"""
from __future__ import annotations

import logging

log = logging.getLogger("permitra.messages")

# The language of this instance, set by the administrator. Cached here because
# messages are raised on every request and the setting changes rarely; it is
# refreshed at startup and whenever the setting is written.
_language = "en"


def set_language(language: str) -> None:
    global _language
    _language = "de" if language == "de" else "en"


def current_language() -> str:
    return _language


def _(template: str, **values) -> str:
    """Translates a message and fills in its values.

    A message must never be the reason a request fails, so a broken template
    falls back to the English text with the values appended rather than
    raising out of the error path."""
    text = CATALOG.get(_language, {}).get(template, template)
    if not values:
        return text
    try:
        return text.format(**values)
    except (KeyError, IndexError):
        log.warning("Message template does not match its values: %r", template)
        try:
            return template.format(**values)
        except (KeyError, IndexError):
            return template


def render(template: str, values: dict | None = None) -> str:
    """Translates a message that was *stored* earlier, at the moment it is read.

    The history and the audit log keep the English template and its values, not
    a finished sentence, so that an entry is shown in the language the instance
    is set to now rather than the one it happened to be set to on the day it was
    written. Switching the instance to German has to translate the past too -
    otherwise the log reads half English forever.

    Text with no values stored alongside it is a person's own words (a change
    note somebody typed). It is looked up all the same, so that entries written
    before this existed still translate, and otherwise passed through unchanged.
    """
    if not isinstance(values, dict) or not values:
        return CATALOG.get(_language, {}).get(template, template)
    return _(template, **{k: _value(v) for k, v in values.items()})


def _value(value):
    """A stored value, made readable.

    A mapping arrives where a message reports something per component - the
    implementation status is the one. Rendering it here rather than at the call
    site keeps the component names untranslated and the status words
    translated, and it keeps a Python dict repr out of the interface.
    """
    if isinstance(value, dict):
        return ", ".join(f"{name} → {_(str(term))}" for name, term in value.items())
    if isinstance(value, list):
        return ", ".join(_(str(term)) for term in value)
    return value


CATALOG: dict[str, dict[str, str]] = {
    "de": {
        "'{port}' is not a valid port (1-65535)": "'{port}' ist kein gültiger Port (1-65535)",
        "A component cannot be linked to itself": "Eine Komponente spricht nicht mit sich selbst",
        "A service from the list below is used": "Ein Dienst aus der Liste unten wird verwendet",
        "A zone transition requires a firewall – Cisco ACI alone is not sufficient (BSI)":
            "Zonenübergang erfordert eine Firewall – Cisco ACI allein genügt nicht (BSI)",
        "Account activated – you can sign in now": "Konto aktiviert – du kannst dich jetzt anmelden",
        "account deactivated": "Konto deaktiviert",
        "account locked": "Konto gesperrt",
        "Account temporarily locked – try again later":
            "Konto vorübergehend gesperrt – bitte später erneut versuchen",
        "ACI gateway not found": "ACI Gateway nicht gefunden",
        "ACI is only used within a single zone – this rule crosses zones, check the ACI platform assignment":
            "ACI wird nur innerhalb einer Zone eingesetzt – diese Regel ist zonenübergreifend, Plattform ACI prüfen",
        "Activation mail sent": "Aktivierungsmail versendet",
        "Address object not found": "Adress-Objekt nicht gefunden",
        "Advisory lock not available": "Advisory-Lock nicht verfügbar",
        "An intra-zone relation is not maintained": "Intra-Zonen-Beziehung wird nicht gepflegt",
        "Anchored entry no longer matches the checkpoint (the chain was recalculated afterwards)":
            "Verankerter Eintrag stimmt nicht mehr mit dem Prüfpunkt überein (Kette wurde nachträglich neu berechnet)",
        "Anycast gateway with prefix, e.g. 10.10.30.1/24": "Anycast-Gateway mit Präfix, z.B. 10.10.30.1/24",
        "API token has expired": "API-Token ist abgelaufen",
        "API token is invalid or revoked": "API-Token ungültig oder widerrufen",
        "API tokens are read-only – only read access is permitted":
            "API-Token sind read-only – nur lesende Zugriffe erlaubt",
        "Assigning a rule ID failed, try again": "Rule-ID-Vergabe fehlgeschlagen, bitte erneut versuchen",
        "At least one service (protocol/port) is required":
            "Mindestens ein Dienst (Protokoll/Port) ist erforderlich",
        "Audit checkpoint failed": "Audit-Prüfpunkt fehlgeschlagen",
        "Central management of security rules for firewalls (Juniper SRX, Check Point) and ACI contracts":
            "Zentrale Verwaltung von Sicherheitsregeln für Firewalls (Juniper SRX, Check Point) und ACI Contracts",
        "Cannot write the initial admin password to {path} ({error}) – startup refused (fail-secure). Set PERMITRA_INITIAL_ADMIN_PASSWORD, or point PERMITRA_INITIAL_ADMIN_PASSWORD_FILE at a writable path.":
            "Das initiale Admin-Passwort kann nicht nach {path} geschrieben werden ({error}) – Start verweigert (fail-secure). Setze PERMITRA_INITIAL_ADMIN_PASSWORD oder richte PERMITRA_INITIAL_ADMIN_PASSWORD_FILE auf einen beschreibbaren Pfad.",
        "Component not found": "Komponente nicht gefunden",
        ". Define it once via the address mapping.": ". Bitte einmalig über die Adress-Zuordnung festlegen.",
        "Demo rule created": "Demo-Regel angelegt",
        "Emergency change declared: {reason}": "Notfall-Änderung erklärt: {reason}",
        "Emergency change not approved in time – deactivated":
            "Notfall-Änderung nicht rechtzeitig freigegeben – deaktiviert",
        "Emergency change, approval due within {hours} h: {reason}":
            "Notfall-Änderung, Freigabe fällig binnen {hours} h: {reason}",
        "Contrary to the zone matrix: {reason}": "Entgegen der Zonen-Matrix: {reason}",
        "The emergency change was not approved within the window. Remove the rule on the components, or submit it again for a proper review.":
            "Die Notfall-Änderung wurde nicht innerhalb des Zeitfensters freigegeben. Bitte die Regel auf den Komponenten entfernen oder erneut regulär zum Review einreichen.",
        "Describe what happened - this is the evidence, and a year from now it is all there will be":
            "Bitte beschreiben, was passiert ist – das ist der Nachweis, und in einem Jahr ist es alles, was übrig bleibt",
        "Recertified in campaign '{campaign}': still required":
            "Rezertifiziert in Kampagne '{campaign}': weiterhin erforderlich",
        "Recertified in campaign '{campaign}': still required, validity extended until {valid_until}":
            "Rezertifiziert in Kampagne '{campaign}': weiterhin erforderlich, Gültigkeit verlängert bis {valid_until}",
        "Recertification '{campaign}': still needed but wrong - back into review: {reason}":
            "Rezertifizierung '{campaign}': weiterhin nötig, aber fehlerhaft – zurück ins Review: {reason}",
        "Recertification '{campaign}': no longer required - deactivated: {reason}":
            "Rezertifizierung '{campaign}': nicht mehr erforderlich – deaktiviert: {reason}",
        "Recertification campaign over {count} rule(s), scope {scope}, due {due}":
            "Rezertifizierungs-Kampagne über {count} Regel(n), Umfang {scope}, fällig {due}",
        "Closed with {open} of {total} item(s) still undecided":
            "Geschlossen mit {open} von {total} Einträgen unentschieden",
        "Campaign '{campaign}'": "Kampagne '{campaign}'",
        "Campaign '{campaign}': {reason}": "Kampagne '{campaign}': {reason}",
        "Campaign not found": "Kampagne nicht gefunden",
        "Item not found": "Eintrag nicht gefunden",
        "The campaign is closed - its record does not change any more":
            "Die Kampagne ist geschlossen – ihr Protokoll ändert sich nicht mehr",
        "The campaign is already closed": "Die Kampagne ist bereits geschlossen",
        "Already decided by {user} ({decision})":
            "Bereits entschieden von {user} ({decision})",
        "The rule is no longer in force - there is nothing to confirm (status '{status}')":
            "Die Regel ist nicht mehr in Kraft – es gibt nichts zu bestätigen (Status '{status}')",
        "The cut-off date must not lie in the past":
            "Der Stichtag darf nicht in der Vergangenheit liegen",
        "'{value}' is not a valid date (YYYY-MM-DD)":
            "'{value}' ist kein gültiges Datum (JJJJ-MM-TT)",
        "The scope covers no rules in force - nothing to recertify":
            "Der Umfang enthält keine Regel in Kraft – nichts zu rezertifizieren",
        "Unknown scope '{scope}' (use 'all', 'zone:<name>' or 'component:<id>')":
            "Unbekannter Umfang '{scope}' (erlaubt: 'all', 'zone:<Name>' oder 'component:<ID>')",
        "Say what is wrong with the rule - the next reviewer starts from this comment":
            "Bitte beschreiben, was an der Regel falsch ist – der nächste Reviewer beginnt mit diesem Kommentar",
        "Say why the rule is no longer needed - retiring it is a decision, and the reason is the evidence":
            "Bitte begründen, warum die Regel nicht mehr benötigt wird – die Stilllegung ist eine Entscheidung, und die Begründung ist der Nachweis",
        "Retired in recertification - remove the rule on the components":
            "In der Rezertifizierung stillgelegt – Regel auf den Komponenten entfernen",
        "confirmed": "bestätigt",
        "rework": "Überarbeitung",
        "retired": "stillgelegt",
        "Requestor handover proposed to {successor} - awaiting confirmation":
            "Requestor-Übergabe an {successor} vorgeschlagen – wartet auf Bestätigung",
        "Requestor handover confirmed: {previous} → {now}":
            "Requestor-Übergabe bestätigt: {previous} → {now}",
        "Requestor handover to {target} cancelled by {who}":
            "Requestor-Übergabe an {target} abgebrochen von {who}",
        "To {successor}": "An {successor}",
        "From {previous}": "Von {previous}",
        "'{username}' is not an active account": "'{username}' ist kein aktives Konto",
        "A requestor is an architect account - '{username}' is {role}":
            "Ein Requestor ist ein Architekten-Konto – '{username}' ist {role}",
        "That is already the requestor": "Das ist bereits der Requestor",
        "An account must hold at least one role": "Ein Konto muss mindestens eine Rolle haben",
        "Dates must be given as YYYY-MM-DD": "Datumsangaben müssen im Format JJJJ-MM-TT erfolgen",
        "The period ends before it starts": "Der Zeitraum endet vor seinem Beginn",
        "A retirement needs a reason - it becomes the removal reason on every rule":
            "Eine Außerbetriebnahme braucht eine Begründung – sie wird zur "
            "Entfernungsbegründung jeder Regel",
        "No rules carry the application '{app_id}'":
            "Keine Regel trägt die Anwendung '{app_id}'",
        "No rule of '{app_id}' is in force":
            "Keine Regel von '{app_id}' ist in Kraft",
        "Application {app_id} retired: {reason} - proposed for removal":
            "Anwendung {app_id} außer Betrieb genommen: {reason} – zur Entfernung vorgeschlagen",
        "{count} rule(s) proposed for removal: {reason}":
            "{count} Regel(n) zur Entfernung vorgeschlagen: {reason}",
        "Only the current requestor may hand a rule over (an admin may, once the requestor's account is gone)":
            "Nur der aktuelle Requestor darf eine Regel übergeben (ein Admin, sobald dessen Konto fort ist)",
        "No handover is pending for this rule":
            "Für diese Regel ist keine Übergabe offen",
        "Only the proposed requestor can confirm the takeover":
            "Nur der vorgeschlagene Requestor kann die Übernahme bestätigen",
        "Only the two sides of the handover, or an admin, can end it":
            "Nur die beiden Seiten der Übergabe oder ein Admin können sie beenden",
        "Permitra: rule {rule_id} handed over to you":
            "Permitra: Regel {rule_id} an dich übergeben",
        "Hello {name},\n\n{rule_line} has been proposed for you to take over as requestor. Confirm the takeover in Permitra - until you do, the requestor does not change.\n\n  {link}\n\nPermitra":
            "Hallo {name},\n\n{rule_line} wurde dir zur Übernahme als Requestor vorgeschlagen. Bitte bestätige die Übernahme in Permitra – bis dahin ändert sich der Requestor nicht.\n\n  {link}\n\nPermitra",
        "The rule logs nothing, into a zone with protection level '{level}' – an access nobody recorded cannot be reconstructed afterwards":
            "Die Regel protokolliert nichts, in eine Zone mit Schutzbedarf '{level}' – ein nicht protokollierter Zugriff lässt sich nachträglich nicht rekonstruieren",
        "The rule logs nothing, into a zone with protection level 'high' or 'very high'":
            "Die Regel protokolliert nichts, in eine Zone mit Schutzbedarf 'hoch' oder 'sehr hoch'",
        "An access nobody recorded cannot be reconstructed afterwards":
            "Ein nicht protokollierter Zugriff lässt sich nachträglich nicht rekonstruieren",
        "Contract {contract}, filter {filter}: the rules behind it disagree about logging – the subject logs, because a missing log entry cannot be reconstructed later":
            "Contract {contract}, Filter {filter}: die dahinterliegenden Regeln sind bei der Protokollierung uneins – das Subject protokolliert, weil ein fehlender Log-Eintrag später nicht rekonstruierbar ist",
        "'{host}' is not an allowed target": "'{host}' ist kein erlaubtes Ziel",
        "NetBox redirected to {url} – not followed":
            "NetBox hat auf {url} umgeleitet – nicht gefolgt",
        "NetBox referred to a different host ({host}) – ignored":
            "NetBox verwies auf einen anderen Host ({host}) – ignoriert",
        "Only http:// and https:// are allowed": "Nur http:// und https:// sind erlaubt",
        "The address has no host": "Die Adresse hat keinen Host",
        "Only {checked} entries accounted for, the checkpoint records {count}":
            "Nur {checked} Einträge nachweisbar, der Prüfpunkt verzeichnet {count}",
        "Description updated": "Beschreibung aktualisiert",
        "Destination": "Ziel",
        "EPG not found": "EPG nicht gefunden",
        "Expired (automatically disabled):": "Abgelaufen (automatisch deaktiviert):",
        "expires_days must be a number": "expires_days muss eine Zahl sein",
        "\nExpiring soon:": "\nLäuft demnächst ab:",
        "First approval granted – a second approval by a different change approver is required":
            "Erste Freigabe erteilt – eine zweite Freigabe durch einen anderen Change Approver ist erforderlich",
        " from an exposed source": " aus exponierter Quelle",
        "FTP (unencrypted)": "FTP (unverschlüsselt)",
        "Full-text search across ID, name, source, destination, justification":
            "Volltextsuche über ID, Name, Quelle, Ziel, Anlass",
        "Hash does not match the content (entry modified)": "Hash passt nicht zum Inhalt (Eintrag verändert)",
        "Identical source, destination and services": "Identische Quelle, Ziel und Dienste",
        "If the account exists and has an e-mail address on file, a reset link has been sent.":
            "Falls das Konto existiert und eine E-Mail-Adresse hinterlegt ist, wurde ein Reset-Link versendet.",
        "Internal (south) – below the P-A-P structure": "Intern (Süd) – unterhalb der P-A-P-Struktur",
        "Intra-zone traffic (same zone)": "Intra-Zonen-Verkehr (gleiche Zone)",
        "Invalid date (expected YYYY-MM-DD)": "Ungültiges Datum (erwartet YYYY-MM-DD)",
        "IP or network is required": "IP/Netz ist erforderlich",
        "ISO timestamp; only rules changed since then (polling)":
            "ISO-Zeitstempel; nur seither geänderte Regeln (Polling)",
        "Justification": "Begründung (Anlass)",
        "Last change": "Letzte Änderung",
        "Link not found": "Beziehung nicht gefunden",
        "Mandatory fields are missing: ": "Pflichtfelder fehlen: ",
        "Mapping not found": "Zuordnung nicht gefunden",
        "MSSQL (direct DB access)": "MSSQL (DB direkt)",
        "MySQL (direct DB access)": "MySQL (DB direkt)",
        "Name is missing": "Name fehlt",
        "Name is required": "Name ist erforderlich",
        "NetBox is not configured": "NetBox ist nicht konfiguriert",
        "Network assignment not found": "Netzwerk-Zuordnung nicht gefunden",
        "New valid-until date (ISO), e.g. 2027-08-20": "Neues Gültig-bis-Datum (ISO), z.B. 2027-08-20",
        "No audit events yet – nothing to anchor.":
            "Noch keine Audit-Ereignisse vorhanden – nichts zu verankern.",
        "No change": "Keine Änderung",
        "No change compared to the current state": "Keine Änderung gegenüber dem aktuellen Stand",
        "No changes included": "Keine Änderungen enthalten",
        "No component mapping is defined yet for these addresses: ":
            "Für folgende Adressen ist noch keine Komponenten-Zuordnung festgelegt: ",
        "No enforcing components could be determined":
            "Es konnten keine Umsetzungs-Komponenten ermittelt werden",
        "No EPG mapping maintained for source/destination – the export falls back to a single contract. Maintain it on the Objects page under ACI EPGs.":
            "Keine EPG-Zuordnung für Quelle/Ziel gepflegt – Export erfolgt als Einzel-Contract (Fallback). EPG-Zuordnung: Seite Objekte → ACI EPGs.",
        "No mail delivery configured – pass on the activation link manually":
            "Kein Mailversand konfiguriert – Aktivierungslink bitte manuell übermitteln",
        "No mail delivery configured – pass on the reset link manually":
            "Kein Mailversand konfiguriert – Reset-Link bitte manuell übermitteln",
        "No matching rules": "Keine passenden Regeln",
        "No matching rules (filters: approved only, matching platform)":
            "Keine passenden Regeln (Filter: nur freigegebene, passende Plattform)",
        "No passkey is registered for this account": "Für dieses Konto ist kein Passkey hinterlegt",
        "No prefixes with a zone selected": "Keine Prefixe mit Zone ausgewählt",
        "No VRF configured": "Kein VRF angelegt",
        "North-south tier: 0 = northmost (closest to the internet)":
            "Nord-Süd-Ebene: 0 = nördlich (Internet-nah)",
        "not permitted by the matrix": "laut Matrix nicht zulässig",
        "One side of the rule spans several zones – the rule has to be split":
            "Regelseite umfasst mehrere Zonen – die Regel muss aufgeteilt werden",
        "Only approved rules can be recertified – submit expired or deactivated ones again":
            "Nur freigegebene Regeln können rezertifiziert werden – abgelaufene/deaktivierte bitte neu einreichen",
        "Oracle (direct DB access)": "Oracle (DB direkt)",
        "Overlapping source/destination networks with the same protocol and overlapping ports":
            "Überlappende Quell-/Zielnetze bei gleichem Protokoll und überlappenden Ports",
        "Passkey not found": "Passkey nicht gefunden",
        "Passkey registered": "Passkey registriert",
        "Password changed": "Passwort geändert",
        "Password must be at least 8 characters long": "Passwort muss mindestens 8 Zeichen haben",
        "PBR enabled: a target firewall (component) is required":
            "PBR aktiviert: Ziel-Firewall (Komponente) ist erforderlich",
        "PBR enabled: the PBR node IP is required": "PBR aktiviert: PBR-Node-IP ist erforderlich",
        "PBR target component not found": "PBR-Ziel-Komponente nicht gefunden",
        "Permitra: activate your account": "Permitra: Konto aktivieren",
        "Permitra: recertification – expired/expiring rules":
            "Permitra: Rezertifizierung – abgelaufene/ablaufende Regeln",
        "Permitra: reset your password": "Permitra: Passwort zurücksetzen",
        "PostgreSQL (direct DB access)": "PostgreSQL (DB direkt)",
        "prev_hash does not match the predecessor (order changed or entry removed)":
            "prev_hash passt nicht zum Vorgänger (Reihenfolge verändert oder Eintrag entfernt)",
        "Protection level for availability": "Schutzbedarf Verfügbarkeit",
        "Protection level for integrity": "Schutzbedarf Integrität",
        "RDP (remote access)": "RDP (Fernzugriff)",
        "Removal approved – remove the rule on the components":
            "Löschung freigegeben – Regel auf den Komponenten entfernen",
        "Request not found": "Antrag nicht gefunden",
        "Requestor (responsible person)": "Requestor (Verantwortlicher)",
        "Reset mail sent": "Reset-Mail versendet",
        "Rule approved": "Regel freigegeben",
        "Rule approved – it has to be implemented on the components":
            "Regel freigegeben – Umsetzung auf den Komponenten erforderlich",
        "Rule changed": "Regel geändert",
        "Rule created": "Regel angelegt",
        "Rule deactivated": "Regel deaktiviert",
        "Rule rejected": "Regel abgelehnt",
        "Rule set to deleted": "Regel auf gelöscht gesetzt",
        "SECRET_KEY is not set – startup refused (fail-secure). Set SECRET_KEY (e.g. `openssl rand -hex 32`) or PERMITRA_DEV=1 for local development.":
            "SECRET_KEY ist nicht gesetzt – Start verweigert (fail-secure). Setze SECRET_KEY (z.B. `openssl rand -hex 32`) oder PERMITRA_DEV=1 für lokale Entwicklung.",
        "Separation of duties: you cannot approve a rule you requested, created or submitted yourself":
            "Vier-Augen-Prinzip: selbst beantragte, angelegte oder eingereichte Regeln "
            "können nicht selbst freigegeben werden",
        "Separation of duties: you cannot approve your own request":
            "Vier-Augen-Prinzip: eigene Anträge können nicht selbst freigegeben werden",
        "Service 'any' on a cross-zone rule": "Dienst 'any' bei zonenübergreifender Regel",
        "Service object not found": "Dienst-Objekt nicht gefunden",
        "Session is no longer valid": "Sitzung ist nicht mehr gültig",
        "Sign-in failed": "Anmeldung fehlgeschlagen",
        "SMB (file sharing)": "SMB (Dateifreigabe)",
        "Source": "Quelle",
        "Source and destination are both 'any' – the rule is too broad":
            "Quelle und Ziel sind beide 'any' – zu breite Regel",
        "Source and destination must be an IP/network or 'any'":
            "Quelle und Ziel müssen IP/Netz oder 'any' sein",
        "Source is 'any' – every address may connect": "Quelle ist 'any' – jede Adresse darf zugreifen",
        "Source or destination contains a very broad network":
            "Quelle oder Ziel enthält ein sehr breites Netz",
        "Source or destination zone not specified": "Quell- oder Ziel-Zone nicht angegeben",
        "Start the setup first": "Bitte zuerst das Setup starten",
        "Submitted for review": "Zum Review eingereicht",
        "Telnet (unencrypted)": "Telnet (unverschlüsselt)",
        "The account is deactivated": "Konto ist deaktiviert",
        "The account is deactivated or not activated yet": "Konto ist deaktiviert bzw. noch nicht aktiviert",
        "The code is invalid": "Code ist ungültig",
        "The current password is wrong": "Aktuelles Passwort ist falsch",
        "The link already exists": "Beziehung existiert bereits",
        "The link is invalid or expired – request a new one":
            "Link ist ungültig oder abgelaufen – bitte neuen anfordern",
        "The matrix allows this relation only temporarily (Temp)":
            "Beziehung ist in der Matrix nur temporär erlaubt (Temp)",
        "The new valid-until date must be in the future": "Neues Gültig-bis muss in der Zukunft liegen",
        "The password is wrong": "Passwort ist falsch",
        "The request has expired – try again": "Anfrage abgelaufen – bitte erneut versuchen",
        "The rule is not in review": "Regel ist nicht im Review",
        "The second approval must come from a different change approver":
            "Die zweite Freigabe muss durch einen anderen Change Approver erfolgen",
        "The token is shown only now – store it somewhere safe.":
            "Token wird nur jetzt angezeigt – bitte sicher hinterlegen.",
        "to change": "zu ändern",
        "to remove": "zu löschen",
        "Token is invalid or expired": "Token ungültig oder abgelaufen",
        "Token not found": "Token nicht gefunden",
        "Two-factor authentication disabled": "Zwei-Faktor-Authentifizierung deaktiviert",
        "Two-factor authentication enabled": "Zwei-Faktor-Authentifizierung aktiviert",
        "Two-factor authentication is already enabled": "2FA ist bereits aktiviert",
        "updated_since must be an ISO timestamp": "updated_since muss ein ISO-Zeitstempel sein",
        "User not found": "Benutzer nicht gefunden",
        "Username is already taken": "Benutzername bereits vergeben",
        "Valid from": "Gültig-ab",
        "Valid until": "Gültig-bis",
        "Valid until (expiry date)": "Gültig-bis (Ablaufdatum)",
        "Valid until is earlier than valid from": "Gültig-bis liegt vor Gültig-ab",
        "Valid until: a date is required (YYYY-MM-DD)": "Gültig-bis: ein Datum ist erforderlich (JJJJ-MM-TT)",
        "Validity job failed": "Gültigkeits-Job fehlgeschlagen",
        "VNC (remote access)": "VNC (Fernzugriff)",
        "VRF not found": "VRF nicht gefunden",
        "wrong 2FA code": "2FA-Code falsch",
        "Wrong username or password": "Benutzername oder Passwort falsch",
        "You cannot deactivate your own account": "Eigener Account nicht deaktivierbar",
        "You cannot delete your own account": "Eigenen Account nicht löschbar",
        "You cannot remove your own admin role": "Eigene Admin-Rolle nicht entziehbar",
        "Zone ID (code) is missing": "Zonen-ID (code) fehlt",
        "Zone ID (code) is required": "Zonen-ID (code) ist erforderlich",
        "Zone matrix: ": "Zonen-Matrix: ",
        "Zone name is missing": "Zonenname fehlt",
        "Zone not found": "Zone nicht gefunden",
        " – default-deny: create the zone and approve the relation":
            " – default-deny: bitte Zone anlegen und Beziehung freigeben",
        " – least privilege (default-deny): set it to allow via a matrix request (two approvals)":
            " – Minimalprinzip (default-deny): bitte per Matrixantrag auf Allow setzen (zwei Freigaben)",
        # --- status values ------------------------------------------
        # Enum values (models.RuleStatus, ZonePolicyChange.status). Translated
        # ONLY where they are inserted into a sentence - what is stored,
        # compared and served through the API stays the English value.
        "approved": "freigegeben",
        "deactivated": "deaktiviert",
        "draft": "Entwurf",
        "in_review": "im Review",
        "pending": "offen",
        "rejected": "abgelehnt",
        # The rollout status per component (domain_values.IMPL_STATUSES);
        # "to change" and "to remove" sit further up in this catalogue.
        "implemented": "umgesetzt",
        "new": "neu",
        "open": "offen",
        # --- messages with placeholders ------------------------------
        # Added together with their call sites; the placeholder names
        # must match so a translation can reorder them.
        "'{cidr}' is not a valid network (CIDR) and not 'any'":
            "'{cidr}' ist kein gültiges Netz (CIDR) und nicht 'any'",
        "'{ip}' is not a valid IP address": "'{ip}' ist keine gültige IP-Adresse",
        "'{ip}' is not a valid IP address or network (CIDR)":
            "'{ip}' ist keine gültige IP-Adresse oder kein gültiges Netz (CIDR)",
        "'{v}' is not a valid gateway address (expected e.g. 10.10.30.1/24)":
            "'{v}' ist keine gültige Gateway-Adresse (erwartet z.B. 10.10.30.1/24)",
        "'{v}' is not a valid MAC address": "'{v}' ist keine gültige MAC-Adresse",
        "  - {rule_line} (until {valid_until})": "  - {rule_line} (bis {valid_until})",
        "A request for {cidr} is already waiting for approval":
            "Für {cidr} wartet bereits ein Antrag auf Freigabe",
        "A request for {from_zone} → {to_zone} is already waiting for approval":
            "Für {from_zone} → {to_zone} wartet bereits ein Antrag auf Freigabe",
        "A zone transition requires a firewall (BSI definition): Cisco ACI alone is not sufficient for {src} → {dst}. Assign a firewall cluster.":
            "Zonenübergang erfordert eine Firewall (BSI-Definition): Cisco ACI allein ist für {src} → {dst} nicht zulässig. Bitte einen Firewall-Cluster zuordnen.",
        "A zone with ID '{code}' or name '{name}' already exists":
            "Zone mit ID '{code}' oder Name '{name}' existiert bereits",
        "Address object '{name}' already exists": "Adress-Objekt '{name}' existiert bereits",
        "Address object '{name}': IP {old_ip} → {new_ip}": "Adress-Objekt '{name}': IP {old_ip} → {new_ip}",
        "Aerleon generation failed: {error}": "Aerleon-Generierung fehlgeschlagen: {error}",
        "Anchored entry {event_id} is missing – the chain was truncated after the checkpoint of {ts:%Y-%m-%d %H:%M}":
            "Verankerter Eintrag {event_id} fehlt – die Kette wurde nach dem Prüfpunkt vom {ts:%d.%m.%Y %H:%M} gekürzt",
        "Automatically deactivated: validity until {valid_until} has expired":
            "Automatisch deaktiviert: Gültigkeit bis {valid_until} abgelaufen",
        "\n\nComment: {comment}": "\n\nKommentar: {comment}",
        "Component '{name}' already exists": "Komponente '{name}' existiert bereits",
        "Component '{name}' does not belong to rule {rule_id}":
            "Komponente '{name}' gehört nicht zur Regel {rule_id}",
        "Component '{name}' is the PBR target of {used} ACI gateway(s)":
            "Komponente '{name}' ist PBR-Ziel von {used} ACI Gateway(s)",
        "Component {component_id} not found": "Komponente {component_id} nicht gefunden",
        "destination {ip}, {count} rule(s)": "Ziel {ip}, {count} Regel(n)",
        "EPG '{name}' already exists": "EPG '{name}' existiert bereits",
        "EPG is used by {used} address mapping(s)": "EPG wird von {used} Adress-Zuordnung(en) verwendet",
        "Gateway '{name}' already exists": "Gateway '{name}' existiert bereits",
        "Hello {g},\n\n{body}\n\nRecertification:\n  {link}\n\nPermitra":
            "Hallo {g},\n\n{body}\n\nRezertifizierung:\n  {link}\n\nPermitra",
        "Hello {g},\n\n{rule_line} has been submitted for review and is waiting for your approval.\n\n  {link}\n\nPermitra":
            "Hallo {g},\n\n{rule_line} wurde zum Review eingereicht und wartet auf deine Freigabe.\n\n  {link}\n\nPermitra",
        "Hello {g},\n\n{rule_line} was {status} by {decided_by}.{extra}\n\n  {link}\n\nPermitra":
            "Hallo {g},\n\n{rule_line} wurde von {decided_by} {status}.{extra}\n\n  {link}\n\nPermitra",
        "Hello {g},\n\n{rule_line}: {reason}\nRoll the rule out on the components or remove it, and update the implementation status.\n\n  {link}\n\nPermitra":
            "Hallo {g},\n\n{rule_line}: {reason}\nBitte auf den Komponenten umsetzen bzw. zurückbauen und den Umsetzungsstatus pflegen.\n\n  {link}\n\nPermitra",
        "Hello {name},\n\na Permitra account has been created for you (username: {username}).\nUse the following link to set your password and activate the account:\n\n  {link}\n\nThe link is valid for 72 hours.\n\nPermitra":
            "Hallo {name},\n\nfür dich wurde ein Permitra-Konto angelegt (Benutzername: {username}).\nBitte setze über folgenden Link dein Passwort und aktiviere damit das Konto:\n\n  {link}\n\nDer Link ist 72 Stunden gültig.\n\nPermitra",
        "Hello {name},\n\nuse the following link to set a new password:\n\n  {link}\n\nThe link is valid for 2 hours. If you did not request this, ignore this mail.\n\nPermitra":
            "Hallo {name},\n\nüber folgenden Link kannst du ein neues Passwort setzen:\n\n  {link}\n\nDer Link ist 2 Stunden gültig. Falls du das nicht angefordert hast, ignoriere diese Mail.\n\nPermitra",
        "Implementation status: {impl_status}": "Umsetzungsstatus: {impl_status}",
        "Implemented on every component – the rule is active":
            "Auf allen Komponenten umgesetzt – die Regel ist aktiv",
        "No longer implemented on every component – the rule is approved again":
            "Nicht mehr auf allen Komponenten umgesetzt – die Regel ist wieder freigegeben",
        "Invalid address: '{ip}'": "Ungültige Adresse: '{ip}'",
        "Invalid implementation status '{value}' (allowed: {allowed})":
            "Ungültiger Umsetzungsstatus '{value}' (erlaubt: {allowed})",
        "Invalid policy '{new_policy}'": "Ungültige Policy '{new_policy}'",
        "Invalid port range: '{part}'": "Ungültiger Port-Bereich: '{part}'",
        "Invalid port: '{part}'": "Ungültiger Port: '{part}'",
        "Invalid protocol '{protocol}'. Allowed: {allowed}":
            "Ungültiges Protokoll '{protocol}'. Erlaubt: {allowed}",
        "Invalid value '{value}' for '{key}' (allowed: {allowed})":
            "Ungültiger Wert '{value}' für '{key}' (erlaubt: {allowed})",
        "Matrix change {from_zone} → {to_zone} to Block (request {request}): the rule has to be reassessed":
            "Matrix-Änderung {from_zone} → {to_zone} auf Block (Antrag {request}): Regel muss neu bewertet werden",
        "NetBox import failed: {error}": "NetBox-Import fehlgeschlagen: {error}",
        "NetBox is not reachable: {error}": "NetBox nicht erreichbar: {error}",
        "Network {cidr} moved to {zone} (request {short_id}): zones re-derived, {old_src} → {old_dst} becomes {new_src} → {new_dst}; still permitted":
            "Netz {cidr} nach {zone} umgehängt (Antrag {short_id}): Zonen neu abgeleitet, {old_src} → {old_dst} wird {new_src} → {new_dst}; weiterhin zulässig",
        "Network {cidr} moved to {zone} (request {short_id}): {old_src} → {old_dst} is now {new_src} → {new_dst} and no longer permitted – {reasons}":
            "Netz {cidr} nach {zone} umgehängt (Antrag {short_id}): {old_src} → {old_dst} ist jetzt {new_src} → {new_dst} und nicht mehr zulässig – {reasons}",
        "No approved permit rule has {ip} as its destination":
            "Keine freigegebene permit-Regel hat {ip} als Ziel",
        "Not approved and therefore not exported: {listed}. For a preview, turn off 'approved only' (only_approved=false).":
            "Nicht freigegeben und deshalb nicht exportiert: {listed}. Für eine Vorschau 'nur freigegebene' abwählen (only_approved=false).",
        "Only {checked} entries present, the checkpoint records {count} – entries have been removed":
            "Nur {checked} Einträge vorhanden, der Prüfpunkt belegt {count} – es wurden Einträge entfernt",
        "Overlapping networks/ports with opposite action ({action} vs. {other_action})":
            "Überlappende Netze/Ports mit entgegengesetzter Aktion ({action} vs. {other_action})",
        "pap_level must be one of {levels}": "pap_level muss einer von {levels} sein",
        "Passkey registration failed: {error}": "Passkey-Registrierung fehlgeschlagen: {error}",
        "PBR attaches to Check Point firewalls – '{name}' is of type {component_type}":
            "PBR-Anbindung erfolgt an Check Point Firewalls – '{name}' ist vom Typ {component_type}",
        "# Permitra host firewall for {target_ip} (Debian/nftables)":
            "# Permitra Host-Firewall für {target_ip} (Debian/nftables)",
        "# Permitra host firewall for {target_ip} (RHEL/firewalld, rich rules)":
            "# Permitra Host-Firewall für {target_ip} (RHEL/firewalld, Rich Rules)",
        "# Permitra host firewall for {target_ip} (SLES/iptables)":
            "# Permitra Host-Firewall für {target_ip} (SLES/iptables)",
        "Permitra: rule {rule_id} is waiting for approval": "Permitra: Regel {rule_id} wartet auf Freigabe",
        "Permitra: rule {rule_id} needs to be implemented": "Permitra: Regel {rule_id} umzusetzen",
        "Permitra: rule {rule_id} {status}": "Permitra: Regel {rule_id} {status}",
        "Port outside 1-65535: '{part}'": "Port außerhalb 1-65535: '{part}'",
        "Port {hit_port} in {port}": "Port {hit_port} in {port}",
        "Port {port}": "Port {port}",
        "Port {port} is not on the list": "Port {port} steht nicht auf der Liste",
        "Protection level must be one of {levels}": "Schutzbedarf muss einer von {levels} sein",
        "Raised to high when the source zone is exposed":
            "Wird auf hoch angehoben, wenn die Quellzone exponiert ist",
        "Recertified: validity extended until {valid_until}":
            "Rezertifiziert: Gültigkeit verlängert bis {valid_until}",
        "Relation {from_zone} → {to_zone} is not maintained in the matrix":
            "Beziehung {from_zone} → {to_zone} ist in der Matrix nicht gepflegt",
        "Removal approved: {reason} – remove the rule on the components ('to remove')":
            "Löschung freigegeben: {reason} – Regel auf den Komponenten entfernen ('zu löschen')",
        "Removal approved: the zone relation {from_zone} → {to_zone} is Block – remove the rule on the components ('to remove')":
            "Löschung freigegeben: die Zonenbeziehung {from_zone} → {to_zone} ist Block – Regel auf den Komponenten entfernen ('zu löschen')",
        "Risky service {label} ({where})": "Riskanter Dienst {label} ({where})",
        "Role '{role}' is not permitted to perform this action":
            "Rolle '{role}' ist für diese Aktion nicht berechtigt",
        "Role {role}": "Rolle {role}",
        "Rolled back to version {version}": "Rollback auf Version {version}",
        "Rule automatically deactivated – validity until {valid_until} has expired. If it is still needed, recertify it (submit it again).":
            "Regel automatisch deaktiviert – Gültigkeit bis {valid_until} abgelaufen. Bei weiterem Bedarf bitte rezertifizieren (neu einreichen).",
        "Rule deleted (soft delete): {name}": "Regel gelöscht (Soft-Delete): {name}",
        "Rule {rule_id} not found": "Regel {rule_id} nicht gefunden",
        "Service object '{name}' already exists": "Dienst-Objekt '{name}' existiert bereits",
        "The matrix forbids security rules from {from_zone} to {to_zone} (Block)":
            "Matrix verbietet Sicherheitsregeln von {from_zone} nach {to_zone} (Block)",
        "The request is already '{status}'": "Antrag ist bereits '{status}'",
        "The rule is in status '{status}'": "Regel ist im Status '{status}'",
        "The rule is in status '{status}' – the preview shows the future implementation":
            "Regel ist im Status '{status}' – Vorschau zeigt die künftige Umsetzung",
        "The zone for {from_zone} → {to_zone} no longer exists":
            "Zone für {from_zone} → {to_zone} existiert nicht mehr",
        "Unknown component(s): {components}": "Unbekannte Komponente(n): {components}",
        "Unknown format '{fmt}'": "Unbekanntes Format '{fmt}'",
        "Unknown host OS '{os_name}'. Allowed: {allowed}":
            "Unbekanntes Host-OS '{os_name}'. Erlaubt: {allowed}",
        "Unknown setting '{key}'": "Unbekannte Einstellung '{key}'",
        "Unknown target '{target}'. Allowed: policy, {allowed}":
            "Unbekanntes Ziel '{target}'. Erlaubt: policy, {allowed}",
        "Version {version} has no restorable snapshot":
            "Version {version} hat keinen wiederherstellbaren Snapshot",
        "VRF '{name}' already exists": "VRF '{name}' existiert bereits",
        "VRF '{name}' not found": "VRF '{name}' nicht gefunden",
        "VRF '{name}' still contains {rules} rule(s) and {nets} network(s)":
            "VRF '{name}' enthält noch {rules} Regel(n) und {nets} Netz(e)",
        "Zone '{name}' is still in use ({used} rule(s), {nets} network assignment(s)) – deletion aborted":
            "Zone '{name}' wird noch verwendet ({used} Regel(n), {nets} Netz-Zuordnung(en)) – Löschung abgebrochen",
        "Zone '{name}' is used by {used} rule(s)": "Zone '{name}' wird von {used} Regel(n) verwendet",
        "Zone '{name}' no longer exists": "Zone '{name}' existiert nicht mehr",
        "Zone '{name}' not found": "Zone '{name}' nicht gefunden",
        "Zone '{name}' still has {nets} network assignment(s) – move or remove them first":
            "Zone '{name}' hat noch {nets} Netz-Zuordnung(en) – bitte zuerst umhängen oder entfernen",
        "Zone(s) not maintained in the zone administration: {zones}":
            "Zone(n) nicht in der Zonenverwaltung gepflegt: {zones}",
        "Zones attach to firewall clusters – ACI is not a zone transition: {components}":
            "Zonen werden an Firewall-Cluster angebunden – ACI ist kein Zonenübergang: {components}",
        "{cidr} is already assigned to zone '{zone}'": "{cidr} ist bereits der Zone '{zone}' zugeordnet",
        "{cidr} is already assigned to zone '{zone}' in environment '{vrf}'":
            "{cidr} ist in Umgebung '{vrf}' bereits der Zone '{zone}' zugeordnet",
        "{count} approved rule(s) of this relation were sent back into review: {rule_ids}":
            "{count} freigegebene Regel(n) der Beziehung wurden in den Review zurückgesetzt: {rule_ids}",
        "{count} change(s) requested – waiting for approval by two change approvers":
            "{count} Änderung(en) beantragt – warten auf Freigabe durch zwei Change Approver",
        "{count} further rule(s) were carried over to the new zones":
            "{count} weitere Regel(n) wurden auf die neuen Zonen nachgezogen",
        "{count} prefixes": "{count} Prefixe",
        "{count} rule(s)": "{count} Regel(n)",
        "{count} rule(s), app_id={app_id}": "{count} Regel(n), app_id={app_id}",
        "{count} rule(s), app_id={app_id}, NOT approved: {rule_ids}":
            "{count} Regel(n), app_id={app_id}, NICHT freigegeben: {rule_ids}",
        "{count} rule(s), NOT approved: {rule_ids}":
            "{count} Regel(n), NICHT freigegeben: {rule_ids}",
        "{count} rule(s) became inadmissible through the move and are in review for removal: {rule_ids}":
            "{count} Regel(n) sind durch die Umhängung unzulässig geworden und stehen zur Löschung im Review: {rule_ids}",
        "{description} [{changed} rule(s) updated]": "{description} [{changed} Regel(n) aktualisiert]",
        "{field}: '{entry}' is neither a CIDR/IP nor a hostname nor 'any'":
            "{field}: '{entry}' ist weder CIDR/IP noch Hostname noch 'any'",
        "{field}: at least one address entry is required":
            "{field}: mindestens ein Adress-Eintrag erforderlich",
        "{field}: at least one entry is required": "{field}: mindestens ein Eintrag erforderlich",
        "{label} contains a very broad network (/{pfx})": "{label} enthält ein sehr breites Netz (/{pfx})",
        "{label} spans several zones ({zones}) – split the rule":
            "{label} umfasst mehrere Zonen ({zones}) – bitte aufteilen",
        "{label} spans several zones: {zones}": "{label} umfasst mehrere Zonen: {zones}",
        "{label}: '{text}' is not a valid date – expected YYYY-MM-DD, e.g. 2027-03-31":
            "{label}: '{text}' ist kein gültiges Datum – erwartet wird JJJJ-MM-TT, z.B. 2027-03-31",
        "{label}: network(s) not assigned to any security zone: {networks} – create the network on the Networks page first and assign it to a security zone":
            "{label}: Netz(e) keiner Sicherheitszone zugeordnet: {networks} – bitte das Netzwerk zuerst auf der Seite „Netzwerke“ anlegen und einer Sicherheitszone zuordnen",
        "{proto} requires a port specification": "Für {proto} ist eine Port-Angabe erforderlich",
    },
}
