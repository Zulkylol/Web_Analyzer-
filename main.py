import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import threading
import time

# ------------------ Fonctions ------------------

def start_scan():
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Attention", "Veuillez entrer une URL")
        return

    # Désactiver boutons pendant le scan
    go_button.config(state="disabled")
    open_report_button.config(state="disabled")

    progress_bar["value"] = 0
    root.update_idletasks()

    # Simulation du scan
    def run_scan():
        for i in range(101):
            time.sleep(0.03)  # Remplacer par le vrai code d'analyse
            progress_bar["value"] = i
            root.update_idletasks()
        messagebox.showinfo("Terminé", "Scan terminé !")
        open_report_button.config(state="normal")
        go_button.config(state="normal")

    threading.Thread(target=run_scan).start()

def open_settings():
    messagebox.showinfo("Settings", "Ici tu peux ajouter des paramètres supplémentaires.")

def open_report():
    messagebox.showinfo("Report", "Ici tu pourrais ouvrir le rapport généré.")

# ------------------ Fenêtre principale ------------------

root = ttk.Window(themename="cosmo")  # thème moderne
root.title("Scanner de sécurité Web")
root.geometry("550x420")

# Titre
title_label = ttk.Label(root, text="Scanner de configuration de sécurité Web", font=("Helvetica", 16, "bold"))
title_label.pack(pady=10)

# Champ URL
url_frame = ttk.Frame(root)
url_frame.pack(pady=5)
ttk.Label(url_frame, text="URL du site:", font=("Helvetica", 12)).pack(side="left", padx=5)
url_entry = ttk.Entry(url_frame, width=35)
url_entry.pack(side="left", padx=5)

# Checkboxes
checkbox_frame = ttk.LabelFrame(root, text="Sélection des vérifications")
checkbox_frame.pack(padx=10, pady=10, fill="x")

https_var = ttk.IntVar(value=1)
ssl_var = ttk.IntVar(value=1)
headers_var = ttk.IntVar(value=1)
cookies_var = ttk.IntVar(value=1)

ttk.Checkbutton(checkbox_frame, text="Vérifier HTTPS", variable=https_var).pack(anchor="w", pady=2, padx=5)
ttk.Checkbutton(checkbox_frame, text="Vérifier SSL/TLS", variable=ssl_var).pack(anchor="w", pady=2, padx=5)
ttk.Checkbutton(checkbox_frame, text="Vérifier headers HTTP", variable=headers_var).pack(anchor="w", pady=2, padx=5)
ttk.Checkbutton(checkbox_frame, text="Vérifier cookies", variable=cookies_var).pack(anchor="w", pady=2, padx=5)

# Boutons GO et Settings
button_frame = ttk.Frame(root)
button_frame.pack(pady=15)
go_button = ttk.Button(button_frame, text="GO", bootstyle=SUCCESS, width=12, command=start_scan)
go_button.pack(side="left", padx=10)
settings_button = ttk.Button(button_frame, text="Settings", bootstyle=INFO, width=12, command=open_settings)
settings_button.pack(side="left", padx=10)

# Barre de chargement
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate", bootstyle="success-striped")
progress_bar.pack(pady=20)

# Bouton Open Report (désactivé par défaut)
open_report_button = ttk.Button(root, text="Open Report", bootstyle=WARNING, width=25, state="disabled", command=open_report)
open_report_button.pack(pady=10)

root.mainloop()
