#!/usr/bin/env python3
"""Generates the website's help page from the in-app help.

The application is the source of truth: frontend/src/helpContent.jsx holds the
bilingual sections, and this script renders them as the website's bilingual
source src/hilfe.html. Two hand-maintained copies of a dozen sections of prose
drift the week after somebody edits one of them - so the website copy is
generated, never edited.

The website splits the languages itself: run its build.py afterwards to write
hilfe.html and en/help.html from the source this produces.

Usage:  python3 scripts/export_help.py [path-to-website-repo]
"""
import html
import pathlib
import re
import sys

APP = pathlib.Path(__file__).resolve().parent.parent
HELP_JSX = APP / "frontend" / "src" / "helpContent.jsx"


def parse_sections(text: str) -> list[dict]:
    start = text.index("const SECTIONS = [")
    block = text[start:text.index("\n]\n", start)]
    # Ids carry hyphens ('ping-baseline'), so \w+ is not enough - and a
    # section it silently skipped would simply be missing from the website.
    chunks = re.split(r"\n  \{\n    id: '([\w-]+)',", block)
    sections = []
    for i in range(1, len(chunks), 2):
        sid, body = chunks[i], chunks[i + 1]
        entry = {"id": sid}
        for lang in ("de", "en"):
            m = re.search(
                lang + r": \{\n      title: '((?:[^'\\]|\\.)*)',\n      body: \[(.*?)\n      \],\n    \}",
                body, re.S)
            if not m:
                raise SystemExit(f"help section '{sid}' ({lang}) does not match - "
                                 "the helpContent.jsx structure changed; adjust this parser")
            items = []
            for item in re.finditer(
                    r"\n\s+(?:'((?:[^'\\]|\\.)*)',|\{ (ol|ul): \[(.*?)\n\s+\] \})",
                    m.group(2), re.S):
                if item.group(1) is not None:
                    items.append(("p", item.group(1).replace("\\'", "'")))
                else:
                    items.append((item.group(2),
                                  [li.group(1).replace("\\'", "'")
                                   for li in re.finditer(r"'((?:[^'\\]|\\.)*)',",
                                                         item.group(3))]))
            entry[lang] = {"title": m.group(1).replace("\\'", "'"), "body": items}
        sections.append(entry)
    return sections


def fmt(text: str) -> str:
    """**bold** and `code`, matching the in-app renderer."""
    out = html.escape(text, quote=False)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    return out


def render_body(items) -> str:
    parts = []
    for kind, content in items:
        if kind == "p":
            parts.append(f"      <p>{fmt(content)}</p>")
        else:
            lis = "\n".join(f"        <li>{fmt(li)}</li>" for li in content)
            parts.append(f"      <{kind}>\n{lis}\n      </{kind}>")
    return "\n".join(parts)


def build(sections: list[dict]) -> str:
    toc, blocks = [], []
    for s in sections:
        toc.append(
            f'      <a href="#{s["id"]}">'
            f'<span class="lang-de">{html.escape(s["de"]["title"])}</span>'
            f'<span class="lang-en">{html.escape(s["en"]["title"])}</span></a>')
        for lang in ("de", "en"):
            blocks.append(
                f'    <section class="help-topic lang-{lang}" id="{s["id"] if lang == "de" else s["id"] + "-en"}">\n'
                f'      <h2>{html.escape(s[lang]["title"])}</h2>\n'
                f'{render_body(s[lang]["body"])}\n'
                f'    </section>')
    # The anchor an app deep-link uses must land on the visible section in
    # either language, so the German section carries the bare id and a small
    # script re-points anchors when English is active.
    return f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Permitra – Hilfe</title>
<link rel="icon" type="image/svg+xml" href="permitra-mark.svg">
<meta name="description" content="Hilfe zu Permitra: Regel-Workflow, Rezertifizierungs-Kampagnen, Notfall-Änderungen, Zonen-Matrix, Soll-Ist-Abgleich, Exporte.">
<link rel="stylesheet" href="styles.css">
<style>
  /* GENERATED FILE - edit frontend/src/helpContent.jsx in the application
     repository and re-run scripts/export_help.py. Changes made here are lost. */
  .help-head {{ background: linear-gradient(160deg, var(--brand) 0%, var(--brand-2) 100%); color: var(--on-brand); padding: 1.6rem 0; }}
  .help-head .topline {{ margin-bottom: 0; }}
  .help-head a.back {{ color: var(--hero-sub); font-size: .9rem; }}
  .help-toc {{ display: flex; flex-wrap: wrap; gap: .4rem 1rem; margin: 1.6rem 0; font-size: .92rem; }}
  .help-topic {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem 1.4rem; margin-bottom: 1rem; scroll-margin-top: 1rem; }}
  .help-topic h2 {{ font-size: 1.15rem; margin-bottom: .7rem; }}
  .help-topic p, .help-topic li {{ font-size: .94rem; color: var(--ink); max-width: 75ch; margin-bottom: .6rem; }}
  .help-topic ol, .help-topic ul {{ padding-left: 1.3rem; }}
  .help-topic code {{ background: var(--panel-2); border: 1px solid var(--border); border-radius: 4px; padding: .05rem .3rem; font-size: .88em; }}
  main.wrap {{ padding-bottom: 2rem; }}
</style>
</head>
<body>

<header class="help-head">
  <div class="wrap">
    <div class="topline">
      <div class="logo">
        <img src="permitra-mark.svg" alt="" width="34" height="34">
        Permitra
        <span class="lang-de" style="font-weight:400">&nbsp;Hilfe</span>
        <span class="lang-en" style="font-weight:400">&nbsp;Help</span>
      </div>
      <div>
        <a class="back" href="index.html"><span class="lang-de">← permitra.de</span><span class="lang-en">← permitra.de</span></a>
        &nbsp;&nbsp;
        <button class="lang-toggle" id="langToggle" type="button" aria-label="Sprache wechseln / switch language">
          <span class="lang-de">EN</span><span class="lang-en">DE</span>
        </button>
      </div>
    </div>
  </div>
</header>

<main class="wrap">
  <nav class="help-toc">
{chr(10).join(toc)}
  </nav>

{chr(10).join(blocks)}
</main>

<footer>
  <div class="wrap">
    <span>© 2026 Permitra</span>
    <span><a href="index.html">permitra.de</a> · <a href="https://demo.permitra.de">Demo</a> · <a href="impressum.html"><span class="lang-de">Impressum</span><span class="lang-en">Legal notice</span></a> · <a href="datenschutz.html"><span class="lang-de">Datenschutz</span><span class="lang-en">Privacy</span></a></span>
  </div>
</footer>

<script>
  (function () {{
    function apply(lang) {{
      document.body.classList.toggle('en', lang === 'en');
      document.documentElement.lang = lang;
      try {{ localStorage.setItem('permitra_www_lang', lang); }} catch (e) {{}}
      // Deep links from the application use the bare ids, which sit on the
      // German sections; in English, land on the English twin instead.
      if (lang === 'en' && location.hash && !location.hash.endsWith('-en')) {{
        var el = document.getElementById(location.hash.slice(1) + '-en');
        if (el) el.scrollIntoView();
      }}
    }}
    var saved = null;
    try {{ saved = localStorage.getItem('permitra_www_lang'); }} catch (e) {{}}
    apply(saved || ((navigator.language || 'de').toLowerCase().indexOf('de') === 0 ? 'de' : 'en'));
    document.getElementById('langToggle').addEventListener('click', function () {{
      apply(document.body.classList.contains('en') ? 'de' : 'en');
    }});
  }})();
</script>

</body>
</html>
"""


def main() -> None:
    website = pathlib.Path(sys.argv[1] if len(sys.argv) > 1
                           else APP.parent / "permitra-website")
    # src/, not the root: since the language split the root pages are generated
    # from these bilingual sources. Writing the root file directly would be
    # undone by the very next build.py run, which is a quiet way to publish
    # nothing.
    source = website / "src" / "hilfe.html"
    if not (website / "src" / "index.html").exists():
        raise SystemExit(f"{website} does not look like the website repository")
    sections = parse_sections(HELP_JSX.read_text())
    source.write_text(build(sections))
    print(f"{len(sections)} sections -> {source}")
    print("now run the website's build.py to write hilfe.html and en/help.html")


if __name__ == "__main__":
    main()
