"""One-off migration: switch the interface dictionary to English keys.

Until now German was the source language: `t('Sicherheitsregeln')` looked up an
English translation. With English as the code language that direction is wrong,
so this script turns it around - English becomes the key, German the
translation - and rewrites every call site accordingly.

The existing dictionary already holds the German-to-English mapping, so the
conversion is derived from it rather than typed by hand. Three things need
judgement and are therefore listed explicitly below:

  OVERRIDES  German terms whose English translation collides with another
             entry. Inverting them blindly would merge two distinct meanings
             into one and silently lose a German wording.
  ADDITIONS  Strings passed to t() that never had a dictionary entry.
  FIXUPS     Call sites that build a word by appending to a translation, which
             only works in German.

Run from the repository root:  python3 scripts/invert_i18n.py [--check]
"""
import argparse
import glob
import re
import sys
from collections import Counter

I18N = "frontend/src/i18n.jsx"

# German term -> English key to use instead of the current translation.
OVERRIDES = {
    # "Ändern" is the button on the account page, "Änderung" the table column.
    # Both translated to "Change", which would merge them on inversion.
    "Ändern": "Update",
    # "Herkunft" is where a network entry came from (manual, NetBox);
    # "Quelle" is the source address of a rule. Both were "Source".
    "Herkunft": "Origin",
}

# German variants that mean the same thing as another entry: their call sites
# are rewritten to the shared English key, but they get no dictionary entry of
# their own. The form labels carried a German-only clarification in brackets
# ("Quell-Zone (Source SZ)") that the English wording does not need.
ALIASES = {
    "Quell-Zone (Source SZ)": "Source zone",
    "Ziel-Zone (Destination SZ)": "Destination zone",
}

# Strings used via t() that had no entry at all.
ADDITIONS = {
    "Schutzbedarf": "Protection level",
    "Zonen-Zuordnung auf der Seite Netzwerke pflegen":
        "Maintain the zone mapping on the Networks page",
    # Needed by the FIXUPS below.
    "Änderungen": "Changes",
}

# (file, search, replace) - call sites that append to a translated word.
# `{t('Änderung')}en` yields "Änderungen" in German and "Changeen" in English.
FIXUPS = [
    ("frontend/src/pages/ZoneMatrix.jsx", "{t('Änderung')}en", "{t('Änderungen')}"),
]


def read_pairs(source: str) -> dict[str, str]:
    start = source.index("const EN = {")
    end = source.index("\n}\n", start)
    body = source[start:end]
    pairs = re.findall(r"\n\s*'((?:[^'\\]|\\.)*)':\s*\n?\s*'((?:[^'\\]|\\.)*)'", body)
    return pairs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true",
                        help="only report what would change")
    args = parser.parse_args()

    source = open(I18N, encoding="utf-8").read()
    pairs = read_pairs(source)

    mapping: dict[str, str] = {}
    for german, english in pairs:
        mapping[german] = OVERRIDES.get(german, english)
    mapping.update({de: en for de, en in ADDITIONS.items()})
    # Aliases steer the call sites but must not become dictionary entries,
    # otherwise they would collide with the term they point at.
    for german in ALIASES:
        mapping.pop(german, None)

    collisions = {en: [de for de, e in mapping.items() if e == en]
                  for en, count in Counter(mapping.values()).items() if count > 1}
    real = {en: des for en, des in collisions.items() if len(set(des)) > 1}
    if real:
        print("Collisions left - two German terms would share one English key:")
        for en, des in real.items():
            print(f"  {en!r} <- {des}")
        print("Add an entry to OVERRIDES for each and run again.")
        return 1

    files = sorted(set(glob.glob("frontend/src/**/*.jsx", recursive=True)
                       + glob.glob("frontend/src/**/*.js", recursive=True)))
    replaced = 0
    for path in files:
        if path.endswith("i18n.jsx"):
            continue
        text = original = open(path, encoding="utf-8").read()
        for file_name, search, replace in FIXUPS:
            if path == file_name and search in text:
                text = text.replace(search, replace)
        def swap(match):
            nonlocal replaced
            german = match.group(1)
            english = ALIASES.get(german) or mapping.get(german)
            if not english:
                return match.group(0)
            replaced += 1
            return f"t('{english}')"
        text = re.sub(r"\bt\('((?:[^'\\]|\\.)*)'\)", swap, text)
        if text != original and not args.check:
            open(path, "w", encoding="utf-8").write(text)

    print(f"call sites rewritten: {replaced}")
    print(f"dictionary entries:   {len(mapping)}")

    if args.check:
        return 0

    # Rebuild the dictionary with English keys and German values.
    lines = ["const DE = {"]
    for german, english in sorted(mapping.items(), key=lambda kv: kv[1].lower()):
        key = english.replace("\\", "\\\\").replace("'", "\\'")
        value = german.replace("\\", "\\\\").replace("'", "\\'")
        lines.append(f"  '{key}': '{value}',")
    lines.append("}")
    new_dict = "\n".join(lines)

    start = source.index("const EN = {")
    end = source.index("\n}\n", start) + 2
    source = source[:start] + new_dict + source[end:]
    open(I18N, "w", encoding="utf-8").write(source)
    print("dictionary inverted (English keys, German values)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
