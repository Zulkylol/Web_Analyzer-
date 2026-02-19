import threading
import time
import ttkbootstrap as ttk
from ttkbootstrap.constants import SUCCESS, INFO, WARNING
from tkinter import messagebox

from core.http.scan_http import scan_http_config
from core.tls.scan_tls import scan_tls_config
from ui.tables import create_result_table, clear_tables
from ui.display_http import display_http
from ui.display_tls import display_ssl_tls
from ui.display_cookies import display_cookies



# ===============================================================
# FUNCTION : start_scan()
# ===============================================================
def start_scan():
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

        def update_progress(value):
            progress_bar["value"] = value
            root.update_idletasks()

        try:
            # Step 1 : normalize URL
            time.sleep(0.05) 
            update_progress(5)

            # Step 2 : HTTP request
            update_progress(20)
            result_http = scan_http_config(url)

            
            # Step 3 SSL / TLS 
            update_progress(40)
            result_ssl = scan_tls_config(url)

            # Step 3 : Display results
            update_progress(80)
            display_http(result_http, http_table)
            display_ssl_tls(result_ssl, ssl_table)
            update_progress(90)

            # Final step
            time.sleep(0.1)  # petite pause pour montrer la barre à 100%
            update_progress(100)

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
    messagebox.showinfo("Settings")


# ===============================================================
# FUNCTION : open_report()
# ===============================================================
def open_report():
    messagebox.showinfo("Report")


# ===============================================================
# -------------------------- UI ---------------------------------
# ===============================================================
root = ttk.Window(themename="cosmo")  
root.title("Scanner de sécurité Web")
root.geometry("1600x800")

# Title
title_label = ttk.Label(root, text="Scanner de configuration de sécurité Web", font=("Helvetica", 16, "bold"))
title_label.pack(pady=10)

# URL textbox
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

# Buttons GO and Settings
button_frame = ttk.Frame(root)
button_frame.pack(pady=15)
go_button = ttk.Button(button_frame, text="GO", bootstyle=SUCCESS, width=12, command=start_scan)
go_button.pack(side="left", padx=10)
settings_button = ttk.Button(button_frame, text="Settings", bootstyle=INFO, width=12, command=open_settings)
settings_button.pack(side="left", padx=10)

# Loading bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate", bootstyle="success-striped")
progress_bar.pack(pady=20)

# Button Open Report 
open_report_button = ttk.Button(root, text="Open Report", bootstyle=WARNING, width=25, state="disabled", command=open_report)
open_report_button.pack(pady=10)

# ------------------ Results ------------------
tables_frame = ttk.Frame(root)
tables_frame.pack(padx=10, pady=10, fill="both", expand=True)

# Tables creation
http_table = create_result_table(tables_frame, "HTTP")
ssl_table = create_result_table(tables_frame, "SSL/TLS")
cookies_table = create_result_table(tables_frame, "Cookies")

style = ttk.Style()
style.configure("Treeview", rowheight=18)
style.configure("Treeview.Heading",font=("Helvetica", 11, "bold"))

root.mainloop()
