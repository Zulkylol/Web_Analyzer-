import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import threading
import time
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import ipaddress



# ------------------ Functions ------------------

def check_http_config(url : str) -> dict:
    """
    Analyse complète des headers et protocoles de sécurité :
    - HTTPS
    - Headers de sécurité classiques (HSTS, CSP, X-Frame-Options, etc.)
    - Mixed Content (si HTTPS)
    
    Args:
        url (str): URL à analyser
    
    Returns:
        dict: résultats détaillés avec score et commentaires
    """

    result = {
        "original_url": url,
        "final_url": None,
        "uses_https": False,
        "time" : 0.0,
        "score": 0,
        "comment": "",
        "missing_headers": [],
        "mixed_content": False
    }

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        final_url = response.url
        result["final_url"] = final_url

        # Check response delay
        response_time = response.elapsed.total_seconds()  # stocke le temps
        result["time"] = response_time
        if response_time > 2:
            result["comment"] += f"Temps de réponse élevé ({response_time:.2f}s). "


        # HTTPS check
        if final_url.startswith("https://"):
            result["uses_https"] = True
        else:
            result["comment"] += "Site non sécurisé (HTTP). "

        # Liste des headers de sécurité, HSTS inclus
        security_headers = [
            "Strict-Transport-Security",  # HSTS
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        # Vérification des headers
        for h in security_headers:
            value = response.headers.get(h)
            if value:
                result["score"] += 10  # chaque header présent = 10 points
            else:
                result["missing_headers"].append(h)
                result["comment"] += f"{h} absent. "

        # Mixed Content si HTTPS
        if result["uses_https"]:
            soup = BeautifulSoup(response.text, "html.parser")
            tags_attrs = {
                "img": "src",
                "script": "src",
                "link": "href",
                "iframe": "src",
            }
            mixed_urls = []
            for tag, attr in tags_attrs.items():
                for element in soup.find_all(tag):
                    src = element.get(attr)
                    if src and src.startswith("http://"):
                        mixed_urls.append(src)
            if mixed_urls:
                result["mixed_content"] = True
                result["score"] -= 10  # pénalisation pour contenu mixte
                result["comment"] += f"Contenu mixte détecté ({len(mixed_urls)} ressources HTTP). "

        # Score final borné entre 0 et 100
        result["score"] = max(0, min(result["score"], 100))

    except requests.RequestException as e:
        result["comment"] = f"Erreur lors de la connexion : {e}"

    return result


def analyze__http_redirections(response) -> dict:
    """
    Analyse la chaîne de redirections d'une requête HTTP.

    Args:
        response: objet `requests.Response` après une requête avec allow_redirects=True

    Returns:
        dict: {
            "num_redirects": int,
            "redirect_domains": list,
            "redirect_ips": list,
            "risk": str,
            "comment": str
        }
    """
    history = response.history
    result = {
        "num_redirects": len(history),
        "redirect_domains": [],
        "redirect_ips": [],
        "risk": "Low",
        "comment": ""
    }

    # Pas de redirection ?
    if len(history) == 0:
        result["comment"] = "Aucune redirection"
        return result

    # Analyser chaque URL de redirection
    for resp in history:
        parsed = urlparse(resp.headers.get("Location", resp.url))
        domain = parsed.hostname

        if domain:
            result["redirect_domains"].append(domain)
            # Vérifier si c'est une IP brute
            try:
                ipaddress.ip_address(domain)
                result["redirect_ips"].append(domain)
            except ValueError:
                pass

    # Commentaire et risque
    # Nombre de redirections
    if len(history) <= 2:
        result["comment"] += "Redirection normale. "
    elif len(history) <= 5:
        result["comment"] += "Plusieurs redirections détectées. "
        result["risk"] = "Medium"
    else:
        result["comment"] += "Nombre excessif de redirections ! "
        result["risk"] = "High"

    # Redirection vers un autre domaine
    original_domain = urlparse(response.url).hostname
    for dom in result["redirect_domains"]:
        if dom != original_domain and dom not in result["redirect_ips"]:
            result["comment"] += f"Redirection vers un autre domaine ({dom}). "
            result["risk"] = max_risk(result["risk"], "Medium")

    # Redirection vers IP brute
    if result["redirect_ips"]:
        result["comment"] += f"Redirection vers IP brute ({', '.join(result['redirect_ips'])}). "
        result["risk"] = max_risk(result["risk"], "Medium")

    return result

def max_risk(current, new):
    """Compare deux niveaux de risque et renvoie le plus élevé"""
    levels = {"Low": 0, "Medium": 1, "High": 2}
    return new if levels[new] > levels[current] else current


def check_mixed_content(url: str) -> dict:
    """
    Vérifie si une page HTTPS charge du contenu HTTP (mixed content)
    
    Args:
        url (str): URL de la page à analyser

    Returns:
        dict: {
            "mixed_content_detected": bool,
            "mixed_urls": list
        }
    """
    result = {
        "mixed_content_detected": False,
        "mixed_urls": []
    }

    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        response = requests.get(url, headers=headers, timeout=5)
        
        # On ne parse que si HTTPS
        if response.url.startswith("https://"):
            soup = BeautifulSoup(response.text, "html.parser")

            # Récupérer toutes les URLs dans src, href, link, script, img
            tags_attrs = {
                "img": "src",
                "script": "src",
                "link": "href",
                "iframe": "src",
            }

            mixed_urls = []
            for tag, attr in tags_attrs.items():
                for element in soup.find_all(tag):
                    src = element.get(attr)
                    if src and src.startswith("http://"):
                        mixed_urls.append(src)

            if mixed_urls:
                result["mixed_content_detected"] = True
                result["mixed_urls"] = mixed_urls

    except requests.RequestException as e:
        print(f"Erreur lors de la détection du contenu mixte : {e}")

    return result


def start_scan():
    url = url_entry.get().strip()
    if not url:
        messagebox.showwarning("Attention", "Veuillez entrer une URL")
        return
    
    # Disable button while scanning
    go_button.config(state="disabled")
    open_report_button.config(state="disabled")

    progress_bar["value"] = 0
    root.update_idletasks()

    results = check_http_config(url)
    print(results)

    # Simulation du scan
    def run_scan():
        for i in range(101):
            time.sleep(0.03) 
            progress_bar["value"] = i
            root.update_idletasks()
        messagebox.showinfo("Terminé", "Scan terminé !")
        open_report_button.config(state="normal")
        go_button.config(state="normal")

    threading.Thread(target=run_scan).start()

def open_settings():
    messagebox.showinfo("Settings")

def open_report():
    messagebox.showinfo("Report")

# ------------------ Main Window ------------------

root = ttk.Window(themename="cosmo")  
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
