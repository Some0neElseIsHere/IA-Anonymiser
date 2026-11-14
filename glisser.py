"""Glisser-déposer de fichiers depuis l'Explorateur Windows, sans dépendance (message WM_DROPFILES).

Tkinter ne sait pas recevoir des fichiers déposés : on demande à Windows d'envoyer WM_DROPFILES à la fenêtre
et on intercepte ce message dans sa procédure de fenêtre. Sur un autre système, ou en cas d'échec, rien ne
change : le bouton « Ouvrir… » reste disponible.
"""
import ctypes
import sys

WM_DROPFILES = 0x0233
WM_COPYDATA = 0x004A
WM_COPYGLOBALDATA = 0x0049
GWLP_WNDPROC = -4
MSGFLT_ALLOW = 1


def fenetre(widget):
    """Handle Windows de la fenêtre principale (le cadre autour de la zone Tk)."""
    return ctypes.windll.user32.GetParent(widget.winfo_id()) or widget.winfo_id()


def activer(racine, rappel):
    """Appelle rappel(liste_de_chemins) quand des fichiers sont déposés sur la fenêtre. Renvoie True si actif."""
    if sys.platform != "win32":
        return False
    try:
        from ctypes import wintypes as w
        user32, shell32 = ctypes.windll.user32, ctypes.windll.shell32
        hwnd = fenetre(racine)
        procedure = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
        user32.SetWindowLongPtrW.argtypes = [w.HWND, ctypes.c_int, ctypes.c_void_p]
        user32.SetWindowLongPtrW.restype = ctypes.c_void_p
        user32.CallWindowProcW.argtypes = [ctypes.c_void_p, w.HWND, w.UINT, w.WPARAM, w.LPARAM]
        user32.CallWindowProcW.restype = ctypes.c_ssize_t
        shell32.DragQueryFileW.argtypes = [ctypes.c_void_p, w.UINT, w.LPWSTR, w.UINT]
        shell32.DragQueryFileW.restype = w.UINT
        shell32.DragFinish.argtypes = [ctypes.c_void_p]
        etat = {}

        def recevoir(h, message, wparam, lparam):
            if message == WM_DROPFILES:
                chemins = []
                for i in range(shell32.DragQueryFileW(wparam, 0xFFFFFFFF, None, 0)):
                    longueur = shell32.DragQueryFileW(wparam, i, None, 0)
                    tampon = ctypes.create_unicode_buffer(longueur + 1)
                    shell32.DragQueryFileW(wparam, i, tampon, longueur + 1)
                    chemins.append(tampon.value)
                shell32.DragFinish(wparam)
                racine.after(0, rappel, chemins)  # hors de la procédure de fenêtre
                return 0
            return user32.CallWindowProcW(etat["ancienne"], h, message, wparam, lparam)

        rappel_c = procedure(recevoir)
        # Application lancée en administrateur : autoriser quand même les dépôts venant de l'Explorateur
        for message in (WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA):
            try:
                user32.ChangeWindowMessageFilterEx(hwnd, message, MSGFLT_ALLOW, None)
            except Exception:
                pass
        shell32.DragAcceptFiles(hwnd, True)
        etat["ancienne"] = user32.SetWindowLongPtrW(hwnd, GWLP_WNDPROC, ctypes.cast(rappel_c, ctypes.c_void_p))
        racine._glisser = (rappel_c, etat)  # garder la fonction en vie tant que la fenêtre existe
        return bool(etat["ancienne"])
    except Exception:
        return False


def simuler_depot(racine, chemins):
    """Pour les tests : envoie à la fenêtre un vrai WM_DROPFILES, comme le ferait l'Explorateur."""
    from ctypes import wintypes as w
    kernel32, user32 = ctypes.windll.kernel32, ctypes.windll.user32
    kernel32.GlobalAlloc.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    user32.SendMessageW.argtypes = [w.HWND, w.UINT, ctypes.c_void_p, w.LPARAM]
    liste = ("\0".join(chemins) + "\0\0").encode("utf-16-le")
    entete = (ctypes.c_uint32 * 5)(20, 0, 0, 0, 1)  # DROPFILES : pFiles=20, pt=(0,0), fNC=0, fWide=1
    memoire = kernel32.GlobalAlloc(0x0042, 20 + len(liste))
    pointeur = kernel32.GlobalLock(memoire)
    ctypes.memmove(pointeur, entete, 20)
    ctypes.memmove(pointeur + 20, liste, len(liste))
    kernel32.GlobalUnlock(memoire)
    user32.SendMessageW(fenetre(racine), WM_DROPFILES, memoire, 0)
