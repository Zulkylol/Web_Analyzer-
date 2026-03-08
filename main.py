# main.py

# ===============================================================
# IMPORTS
# ===============================================================
import threading
import time
import tkinter as tk
import ttkbootstrap as ttk
from ttkbootstrap.constants import SUCCESS, INFO, WARNING
from tkinter import messagebox

from core.http.scan_http import scan_http_config
from core.tls.scan_tls import scan_tls_config
from core.cookies.scan_cookies import scan_cookies_config
from ui.tables import create_result_table, clear_tables
from ui.display_http import display_http
from ui.display_tls import display_ssl_tls
from ui.display_cookies import display_cookies
from constants import STATUS_ICON


_detached_by_tree = {}
selected_language = "fr"


# ===============================================================
# FUNCTION : start_scan()
# ===============================================================
def start_scan():
    _detached_by_tree.clear()
    clear_tables(http_table,ssl_table,cookies_table)
    url = url_entry.get().strip()
    if not url:
        messagebox.showwarning("Attention", "Veuillez entrer une URL")
        return
    
    # Disable buttons
    go_button.config(state="disabled")
    open_report_button.config(state="disabled")
    progress_bar["value"] = 0
    root.update_idletasks()

    def run_scan():
        result = {}

        def update_progress(value, steps=12, delay=0.008):
            current = float(progress_bar["value"])
            target = float(value)
            if steps <= 1:
                progress_bar["value"] = target
                root.update_idletasks()
                return

            delta = (target - current) / steps
            for _ in range(steps):
                current += delta
                progress_bar["value"] = current
                root.update_idletasks()
                time.sleep(delay)
            progress_bar["value"] = target
            root.update_idletasks()

        try:
            # Step 1 : normalize URL
            update_progress(5, steps=8)

            # Step 2 : HTTP request
            update_progress(20, steps=14)
            result_http = scan_http_config(url)

            
            # Step 3 SSL / TLS 
            update_progress(40, steps=16)
            result_ssl = scan_tls_config(url)

            # Step 4 Cookies
            result_cookies = None
            if cookies_var.get():
                update_progress(60, steps=14)
                result_cookies = scan_cookies_config(url)

            # Step 5 : Display results
            update_progress(80, steps=14)
            display_http(result_http, http_table)
            display_ssl_tls(result_ssl, ssl_table)
            if cookies_var.get():
                display_cookies(result_cookies, cookies_table)
            apply_filter_state()
            refresh_summary_cards()
            update_progress(90, steps=10)

            # Final step
            update_progress(100, steps=12)

        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur pendant le scan : {e}")

        finally:
            messagebox.showinfo("Terminé", "Scan terminé !")
            open_report_button.config(state="normal")
            go_button.config(state="normal")

    threading.Thread(target=run_scan, daemon=True).start()


# ===============================================================
# FUNCTION : open_settings()
# ===============================================================
def open_settings():
    settings_win = ttk.Toplevel(root)
    settings_win.title("Paramètres")
    settings_win.geometry("360x180")
    settings_win.resizable(False, False)

    container = ttk.Frame(settings_win, padding=14)
    container.pack(fill="both", expand=True)

    ttk.Label(container, text="Langue de l'interface", font=("Helvetica", 11, "bold")).pack(anchor="w", pady=(0, 8))

    lang_choices = {"Français": "fr", "English": "en"}
    reverse_choices = {v: k for k, v in lang_choices.items()}
    lang_var = ttk.StringVar(value=reverse_choices.get(selected_language, "Français"))
    lang_combo = ttk.Combobox(
        container,
        textvariable=lang_var,
        values=("Français", "English"),
        state="readonly",
        width=20,
    )
    lang_combo.pack(anchor="w")
    lang_combo.set(reverse_choices.get(selected_language, "Français"))

    ttk.Label(
        container,
        text="Français est la langue par défaut.",
    ).pack(anchor="w", pady=(8, 14))

    def save_settings():
        global selected_language
        selected_language = lang_choices.get(lang_var.get(), "fr")
        messagebox.showinfo("Paramètres", f"Langue enregistrée: {reverse_choices.get(selected_language, 'Français')}")
        settings_win.destroy()

    actions = ttk.Frame(container)
    actions.pack(fill="x")
    ttk.Button(actions, text="Enregistrer", bootstyle=SUCCESS, command=save_settings).pack(side="left")
    ttk.Button(actions, text="Annuler", bootstyle="secondary", command=settings_win.destroy).pack(side="left", padx=8)


# ===============================================================
# FUNCTION : open_report()
# ===============================================================
def open_report():
    messagebox.showinfo("Report")


def _is_alert_icon(icon: str) -> bool:
    return icon not in ("", STATUS_ICON["ok"], STATUS_ICON["info"])


def apply_alert_filter_to_tree(tree, only_alerts: bool):
    tree_id = str(tree)
    detached = _detached_by_tree.setdefault(tree_id, [])

    if only_alerts:
        for item in tree.get_children():
            values = tree.item(item, "values") or ()
            icon = values[2] if len(values) >= 3 else ""
            if not _is_alert_icon(icon):
                detached.append(item)
                tree.detach(item)
    else:
        while detached:
            item = detached.pop(0)
            tree.move(item, "", "end")


def apply_filter_state():
    only_alerts = bool(alerts_only_var.get())
    apply_alert_filter_to_tree(http_table, only_alerts)
    apply_alert_filter_to_tree(ssl_table, only_alerts)
    apply_alert_filter_to_tree(cookies_table, only_alerts)


def _all_items_for_tree(tree):
    tree_id = str(tree)
    return list(tree.get_children()) + list(_detached_by_tree.get(tree_id, []))


def refresh_summary_cards():
    total_rows = 0
    total_alerts = 0
    high_alerts = 0

    for tree in (http_table, ssl_table, cookies_table):
        for item in _all_items_for_tree(tree):
            values = tree.item(item, "values") or ()
            if len(values) < 3:
                continue
            total_rows += 1
            icon = values[2]
            if _is_alert_icon(icon):
                total_alerts += 1
                if icon in (STATUS_ICON["high"], STATUS_ICON["missing"], STATUS_ICON["ko"], "âœ–"):
                    high_alerts += 1

    if high_alerts > 0:
        risk = "ELEVE"
    elif total_alerts > 0:
        risk = "MODERE"
    else:
        risk = "FAIBLE"

    summary_scan_rows_var.set(str(total_rows))
    summary_alerts_var.set(str(total_alerts))
    summary_high_var.set(str(high_alerts))
    summary_risk_var.set(risk)


def on_table_select(event):
    tree = event.widget
    selected = tree.selection()
    if not selected:
        return
    values = tree.item(selected[0], "values") or ("", "", "", "")
    param = values[0] if len(values) > 0 else ""
    value = values[1] if len(values) > 1 else ""
    check = values[2] if len(values) > 2 else ""
    comment = values[3] if len(values) > 3 else ""

    details_text.config(state="normal")
    details_text.delete("1.0", "end")
    details_text.insert(
        "end",
        f"Parametre: {param}\n"
        f"Valeur: {value}\n"
        f"Check: {check}\n"
        f"Commentaire:\n{comment}",
    )
    details_text.config(state="disabled")


# ===============================================================
# -------------------------- UI ---------------------------------
# ===============================================================
root = ttk.Window(themename="cosmo")  
root.title("Web Analyzer")
root.geometry("1580x920")
root.iconbitmap("ressources/title_bar.ico")  # Windows .ico




# Title
title_label = ttk.Label(root, text="Scanner de configuration de sécurité Web", font=("Helvetica", 16, "bold"))
title_label.pack(pady=10)

# URL textbox
url_frame = ttk.Frame(root)
url_frame.pack(pady=5)
ttk.Label(url_frame, text="URL du site:", font=("Helvetica", 12)).pack(side="left", padx=5)
url_entry = ttk.Entry(url_frame, width=35)
url_entry.pack(side="left", padx=5)

# Top controls row (left: checks / right: actions)
controls_row = ttk.Frame(root)
controls_row.pack(padx=10, pady=10, fill="x")

# Checkboxes (left half)
checkbox_frame = ttk.LabelFrame(controls_row, text="Sélection des vérifications")
checkbox_frame.pack(side="left", fill="both", expand=False, padx=(0, 8))
checkbox_frame.configure(width=760)
checkbox_frame.pack_propagate(False)

https_var = ttk.IntVar(value=1)
ssl_var = ttk.IntVar(value=1)
headers_var = ttk.IntVar(value=1)
cookies_var = ttk.IntVar(value=1)

ttk.Checkbutton(checkbox_frame, text="Vérifier HTTPS", variable=https_var).pack(anchor="w", pady=2, padx=5)
ttk.Checkbutton(checkbox_frame, text="Vérifier SSL/TLS", variable=ssl_var).pack(anchor="w", pady=2, padx=5)
ttk.Checkbutton(checkbox_frame, text="Vérifier headers HTTP", variable=headers_var).pack(anchor="w", pady=2, padx=5)
ttk.Checkbutton(checkbox_frame, text="Vérifier cookies", variable=cookies_var).pack(anchor="w", pady=2, padx=5)

# Actions (right side)
actions_frame = ttk.LabelFrame(controls_row, text="Actions")
actions_frame.pack(side="left", fill="both", expand=True, padx=(8, 0))

# Buttons GO and Settings
button_frame = ttk.Frame(actions_frame)
button_frame.pack(anchor="n", pady=(12, 8))
go_button = ttk.Button(button_frame, text="GO", bootstyle=SUCCESS, width=12, command=start_scan)
go_button.pack(side="left", padx=10)
settings_button = ttk.Button(button_frame, text="Settings", bootstyle=INFO, width=12, command=open_settings)
settings_button.pack(side="left", padx=10)
alerts_only_var = ttk.IntVar(value=0)
ttk.Checkbutton(
    button_frame,
    text="Afficher seulement les alertes",
    variable=alerts_only_var,
    command=lambda: (apply_filter_state(), refresh_summary_cards()),
).pack(side="left", padx=10)

# Loading bar
progress_bar = ttk.Progressbar(actions_frame, orient="horizontal", length=420, mode="determinate", bootstyle="success-striped")
progress_bar.pack(anchor="n", pady=(6, 10), padx=12)

# Button Open Report
open_report_button = ttk.Button(actions_frame, text="Open Report", bootstyle=WARNING, width=25, state="disabled", command=open_report)
open_report_button.pack(anchor="n", pady=(2, 12))
# ------------------ Results ------------------
tables_frame = ttk.Frame(root)
tables_frame.pack(padx=10, pady=10, fill="both", expand=True)

# Notebook + tabs
results_notebook = ttk.Notebook(tables_frame)
results_notebook.pack(fill="both", expand=True)

tab_summary = ttk.Frame(results_notebook)
tab_http = ttk.Frame(results_notebook)
tab_tls = ttk.Frame(results_notebook)
tab_cookies = ttk.Frame(results_notebook)

results_notebook.add(tab_summary, text="Vue globale")
results_notebook.add(tab_http, text="HTTP")
results_notebook.add(tab_tls, text="SSL/TLS")
results_notebook.add(tab_cookies, text="Cookies")

# Summary cards
summary_scan_rows_var = ttk.StringVar(value="0")
summary_alerts_var = ttk.StringVar(value="0")
summary_high_var = ttk.StringVar(value="0")
summary_risk_var = ttk.StringVar(value="-")

summary_box = ttk.LabelFrame(tab_summary, text="Synthese")
summary_box.pack(fill="x", padx=14, pady=14)

ttk.Label(summary_box, text="Lignes analysees", font=("Helvetica", 11, "bold")).grid(row=0, column=0, padx=18, pady=8, sticky="w")
ttk.Label(summary_box, textvariable=summary_scan_rows_var, font=("Helvetica", 16, "bold")).grid(row=1, column=0, padx=18, pady=8, sticky="w")
ttk.Label(summary_box, text="Alertes totales", font=("Helvetica", 11, "bold")).grid(row=0, column=1, padx=18, pady=8, sticky="w")
ttk.Label(summary_box, textvariable=summary_alerts_var, font=("Helvetica", 16, "bold")).grid(row=1, column=1, padx=18, pady=8, sticky="w")
ttk.Label(summary_box, text="Alertes critiques", font=("Helvetica", 11, "bold")).grid(row=0, column=2, padx=18, pady=8, sticky="w")
ttk.Label(summary_box, textvariable=summary_high_var, font=("Helvetica", 16, "bold")).grid(row=1, column=2, padx=18, pady=8, sticky="w")
ttk.Label(summary_box, text="Risque global", font=("Helvetica", 11, "bold")).grid(row=0, column=3, padx=18, pady=8, sticky="w")
ttk.Label(summary_box, textvariable=summary_risk_var, font=("Helvetica", 16, "bold")).grid(row=1, column=3, padx=18, pady=8, sticky="w")

ttk.Label(
    tab_summary,
    text="Astuce: sélectionne une ligne dans HTTP/SSL-TLS/Cookies pour voir le détail complet ci-dessous.",
).pack(anchor="w", padx=14, pady=(0, 10))

# Tables creation
http_table = create_result_table(tab_http, "HTTP")
ssl_table = create_result_table(tab_tls, "SSL/TLS")
cookies_table = create_result_table(tab_cookies, "Cookies")

http_table.bind("<<TreeviewSelect>>", on_table_select)
ssl_table.bind("<<TreeviewSelect>>", on_table_select)
cookies_table.bind("<<TreeviewSelect>>", on_table_select)

# Details panel
details_frame = ttk.LabelFrame(root, text="Détail de la ligne sélectionnée")
details_frame.pack(fill="x", padx=10, pady=(0, 10))
details_text = tk.Text(details_frame, height=5, wrap="word")
details_text.pack(fill="x", padx=8, pady=8)
details_text.insert("end", "Sélectionne une ligne pour afficher son commentaire complet.")
details_text.config(state="disabled")

style = ttk.Style()
style.configure("Treeview", rowheight=22)
style.configure("Treeview.Heading",font=("Helvetica", 11, "bold"))

refresh_summary_cards()

root.mainloop()
