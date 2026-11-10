#!/usr/bin/env python3
"""Anonymiseur local.

Masque les données personnelles (e-mails, téléphones, IBAN, cartes, IP et
termes que vous indiquez : noms, entreprises...) avant d'envoyer un texte à
un assistant IA, puis restaure les vraies valeurs dans la réponse.

Aucune dépendance externe. Le serveur écoute uniquement sur 127.0.0.1.
Lancement : python3 app.py  puis ouvrir http://127.0.0.1:8765
"""
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST, PORT = "127.0.0.1", 8765

# Ordre important : les motifs les plus spécifiques passent en premier.
PATTERNS = [
    ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){3,7}\s?[A-Z0-9]{1,3}\b")),
    ("CARTE", re.compile(r"(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)")),
    ("TEL", re.compile(
        r"(?<![\w+])(?:(?:\+|00)33\s?|0)[1-9](?:[\s.-]?\d{2}){4}(?!\w)"   # France
        r"|(?<![\w+])\+\d{1,3}[\s.-]?\d{1,4}(?:[\s.-]?\d{2,4}){2,4}(?!\w)"  # international
    )),
    ("IP", re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")),
]

# Mémoire de la session : placeholder -> valeur originale, et l'inverse.
MAPPING = {}
REVERSE = {}
COUNTERS = {}


def _placeholder(label, original):
    key = (label, original)
    if key in REVERSE:
        return REVERSE[key]
    COUNTERS[label] = COUNTERS.get(label, 0) + 1
    token = f"[{label}_{COUNTERS[label]}]"
    MAPPING[token] = original
    REVERSE[key] = token
    return token


def anonymize(text, terms=None):
    count = 0

    def repl_factory(label):
        def repl(match):
            nonlocal count
            count += 1
            return _placeholder(label, match.group(0))
        return repl

    for label, pattern in PATTERNS:
        text = pattern.sub(repl_factory(label), text)

    # Termes personnalisés (noms, entreprises...), du plus long au plus court.
    for term in sorted({t.strip() for t in (terms or []) if t.strip()}, key=len, reverse=True):
        pattern = re.compile(r"(?<!\w)" + re.escape(term) + r"(?!\w)", re.IGNORECASE)
        text = pattern.sub(repl_factory("NOM"), text)

    return text, count


def restore(text):
    # Crochets inclus dans le token : [NOM_1] ne touche pas [NOM_10].
    for token in sorted(MAPPING, key=len, reverse=True):
        text = text.replace(token, MAPPING[token])
    return text


PAGE = """<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Anonymiseur</title>
<style>
 body{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#222}
 h1{font-size:1.4rem} h2{font-size:1.05rem;margin-top:1.8rem}
 textarea{width:100%;min-height:160px;font:14px/1.4 monospace;box-sizing:border-box;padding:.5rem}
 button{margin-top:.5rem;padding:.5rem 1rem;cursor:pointer}
 .row{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
 .note{color:#666;font-size:.9rem}
</style></head><body>
<h1>Anonymiseur</h1>
<p class="note">Collez votre texte, copiez la version masquée, envoyez-la à Claude.
Quand vous recevez la réponse, collez-la dans la section « Restaurer » pour remettre les vraies valeurs.</p>

<h2>1. Texte original</h2>
<textarea id="src" placeholder="Votre texte ici..."></textarea>
<h2>Termes à masquer (un par ligne : noms, entreprises, adresses...)</h2>
<textarea id="terms" style="min-height:70px" placeholder="Jean Dupont&#10;Acme SAS&#10;12 rue des Lilas"></textarea>
<div class="row"><button id="go">Anonymiser</button><span id="stat" class="note"></span></div>

<h2>2. Version anonymisée (à envoyer à Claude)</h2>
<textarea id="out" readonly></textarea>
<div class="row"><button id="copy">Copier</button></div>

<h2>3. Restaurer la réponse de Claude</h2>
<textarea id="back" placeholder="Collez ici la réponse de Claude..."></textarea>
<div class="row"><button id="restore">Restaurer</button><button id="copy2">Copier le résultat</button></div>
<h2>Résultat restauré</h2>
<textarea id="res" readonly></textarea>

<script>
const $ = id => document.getElementById(id);
$('go').onclick = async () => {
  const terms = $('terms').value.split('\\n').filter(s => s.trim());
  const r = await fetch('/anonymize', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({text: $('src').value, terms})});
  const d = await r.json();
  $('out').value = d.text;
  $('stat').textContent = d.count + ' élément(s) masqué(s)';
};
$('copy').onclick = () => navigator.clipboard.writeText($('out').value);
$('restore').onclick = async () => {
  const r = await fetch('/restore', {method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({text: $('back').value})});
  $('res').value = (await r.json()).text;
};
$('copy2').onclick = () => navigator.clipboard.writeText($('res').value);
</script></body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, ctype="application/json; charset=utf-8"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            self._send(200, PAGE, "text/html; charset=utf-8")
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, json.dumps({"error": "JSON invalide"}))

        if self.path == "/anonymize":
            text, count = anonymize(payload.get("text", ""), payload.get("terms", []))
            return self._send(200, json.dumps({"text": text, "count": count}, ensure_ascii=False))
        if self.path == "/restore":
            return self._send(200, json.dumps({"text": restore(payload.get("text", ""))}, ensure_ascii=False))
        self._send(404, json.dumps({"error": "not found"}))

    def log_message(self, fmt, *args):
        pass  # ne jamais journaliser le contenu


if __name__ == "__main__":
    print(f"Anonymiseur sur http://{HOST}:{PORT}  (Ctrl+C pour arrêter)")
    HTTPServer((HOST, PORT), Handler).serve_forever()
