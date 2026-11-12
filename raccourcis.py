"""Raccourcis clavier globaux (Windows) : actifs même quand IA-Anonymiser n'a pas le focus.

RegisterHotKey enregistre les combinaisons pour un fil dédié, qui attend les messages WM_HOTKEY.
Les appuis sont transmis au fil de l'interface par une file, lue régulièrement (Tkinter n'est pas
prévu pour être appelé depuis un autre fil).
"""
import queue
import sys
import threading

MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_NOREPEAT = 0x0001, 0x0002, 0x0004, 0x4000
WM_HOTKEY, WM_QUIT = 0x0312, 0x0012

ANONYMISER, RESTAURER = 1, 2

# Jeux de raccourcis proposés dans les options : identifiant -> (libellé, [(action, modificateurs, touche)])
JEUX = {
    "ctrl_alt": ("Ctrl+Alt+A / Ctrl+Alt+R", [(ANONYMISER, MOD_CONTROL | MOD_ALT, 0x41),
                                            (RESTAURER, MOD_CONTROL | MOD_ALT, 0x52)]),
    "ctrl_maj_f": ("Ctrl+Maj+F9 / Ctrl+Maj+F10", [(ANONYMISER, MOD_CONTROL | MOD_SHIFT, 0x78),
                                                 (RESTAURER, MOD_CONTROL | MOD_SHIFT, 0x79)]),
    "aucun": ("", []),
}


class Raccourcis:
    def __init__(self):
        self.appuis = queue.Queue()
        self._fil = None
        self._id_fil = None

    def disponible(self):
        return sys.platform == "win32"

    def demarrer(self, jeu):
        """Enregistre le jeu de raccourcis. Renvoie {action: True si enregistré, False si déjà pris}."""
        self.arreter()
        combinaisons = JEUX.get(jeu, JEUX["aucun"])[1]
        if not self.disponible() or not combinaisons:
            return {}
        resultat, pret = {}, threading.Event()

        def boucle():
            import ctypes
            from ctypes import wintypes
            user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
            self._id_fil = kernel32.GetCurrentThreadId()
            for action, modificateurs, touche in combinaisons:
                resultat[action] = bool(user32.RegisterHotKey(None, action, modificateurs | MOD_NOREPEAT, touche))
            pret.set()
            message = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
                if message.message == WM_HOTKEY:
                    self.appuis.put(int(message.wParam))
            for action, _, _ in combinaisons:
                user32.UnregisterHotKey(None, action)

        self._fil = threading.Thread(target=boucle, name="raccourcis", daemon=True)
        self._fil.start()
        pret.wait(2)
        return resultat

    def arreter(self):
        if self._fil and self._fil.is_alive() and self._id_fil:
            import ctypes
            ctypes.windll.user32.PostThreadMessageW(self._id_fil, WM_QUIT, 0, 0)
            self._fil.join(1)
        self._fil = self._id_fil = None

    def lire(self):
        """Appuis reçus depuis la dernière lecture (à appeler depuis le fil de l'interface)."""
        appuis = []
        while True:
            try:
                appuis.append(self.appuis.get_nowait())
            except queue.Empty:
                return appuis
