#!/usr/bin/env python3
"""Anonymiseur de presse-papiers (Windows / macOS / Linux, sans dépendance).

- « Anonymiser » : remplace les données personnelles du presse-papiers.
- « Restaurer »  : remet les vraies valeurs dans un texte copié depuis Claude.
- Mode automatique (case à cocher) : anonymise tout texte copié qui ne contient
  pas encore de jetons, et restaure tout texte qui en contient.

Les correspondances restent en mémoire tant que la fenêtre est ouverte.
"""
import re
import tkinter as tk
from tkinter import messagebox

from app import anonymize, restore, MAPPING

TOKEN_RE = re.compile(r"\[(?:NOM|EMAIL|TEL|CARTE|IBAN|IP)_\d+\]")
POLL_MS = 700


class App:
    def __init__(self, root):
        self.root = root
        root.title("Anonymiseur")
        root.geometry("460x420")

        tk.Label(root, text="Termes à masquer (un par ligne) :", anchor="w").pack(fill="x", padx=10, pady=(10, 0))
        self.terms = tk.Text(root, height=6)
        self.terms.pack(fill="x", padx=10)

        row = tk.Frame(root)
        row.pack(fill="x", padx=10, pady=10)
        tk.Button(row, text="Anonymiser le presse-papiers", command=self.do_anonymize).pack(side="left", expand=True, fill="x")
        tk.Button(row, text="Restaurer le presse-papiers", command=self.do_restore).pack(side="left", expand=True, fill="x", padx=(6, 0))

        self.auto = tk.BooleanVar(value=False)
        tk.Checkbutton(root, text="Mode automatique", variable=self.auto).pack(anchor="w", padx=10)

        self.status = tk.Label(root, text="Prêt.", anchor="w", fg="#555")
        self.status.pack(fill="x", padx=10, pady=(10, 0))

        self.last_seen = None
        self.poll()

    def _terms(self):
        return self.terms.get("1.0", "end").splitlines()

    def _read_clipboard(self):
        try:
            return self.root.clipboard_get()
        except tk.TclError:
            return None

    def _write_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()  # nécessaire pour que le texte persiste après fermeture

    def do_anonymize(self):
        text = self._read_clipboard()
        if not text:
            self.status.config(text="Presse-papiers vide.")
            return
        new, count = anonymize(text, self._terms())
        self._write_clipboard(new)
        self.last_seen = new
        self.status.config(text=f"{count} élément(s) masqué(s). Collez dans Claude.")

    def do_restore(self):
        text = self._read_clipboard()
        if not text:
            self.status.config(text="Presse-papiers vide.")
            return
        new = restore(text)
        self._write_clipboard(new)
        self.last_seen = new
        if MAPPING:
            self.status.config(text="Texte restauré.")
        else:
            self.status.config(text="Aucune correspondance en mémoire.")

    def poll(self):
        if self.auto.get():
            text = self._read_clipboard()
            if text and text != self.last_seen:
                if TOKEN_RE.search(text):
                    new = restore(text)
                    action = "restauré"
                else:
                    new, count = anonymize(text, self._terms())
                    action = f"{count} élément(s) masqué(s)"
                if new != text:
                    self._write_clipboard(new)
                    self.status.config(text=f"Automatique : {action}.")
                self.last_seen = new
        self.root.after(POLL_MS, self.poll)


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
