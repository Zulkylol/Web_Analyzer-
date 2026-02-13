import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox
import threading
import time
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import ipaddress
from http_status_codes import HTTP_STATUS_CODES
from utils import *
from constants import *


# ------------------ Functions ------------------

def check_http_config(url : str) -> dict:
    """
    Comprehensive analysis of security headers and protocols:
    - Check if HTTPS is enabled
    - Get the version of HTTP
    - Standard security headers (HSTS, CSP, X-Frame-Options, etc.)
    - Mixed Content (if HTTPS)
    - Call the function analyze_http_redirections

    Args:
        url (str): URL to analyze

    Returns:
        result : dict = detailed results including score and comments
    """

    # Dict that store everything we need
    result = {
        "status_code": 0,
        "status_comment" : "",
        "http_version" : "",
        "uses_https": False,
        "https_comment": "",
        "mixed_content": False,
        "mixed_url" : [],
        "mixed_comment": "Aucun contenu mixte détecté",
        "original_url": url,
        "final_url": None,
        "time" : 0.0,
        "time_comment" : "",
        "missing_headers": [],
        "headers_comment": [],
        "score": 0,
        "redirects": {},
    }

    # Use utils.py => normalize() to format url
    url = normalize_url(url)

    try:
        # Get the response to my request
        response = requests.get(url, headers=HEADER, timeout=5, allow_redirects=True)

        # Alimentation of result 
        result["final_url"] = response.url
        result["http_version"] = map_http_version(response.raw.version)
        result["status_code"] = response.status_code
        result["status_message"] = HTTP_STATUS_CODES.get(result["status_code"], "Code inconnu")
        result["redirects"] = check_http_redirections(response)

        # Check response delay
        response_time = response.elapsed.total_seconds()  # stocke le temps
        result["time"] = response_time
        if response_time > 2:
            result["time_comment"] = f"Temps de réponse élevé ({response_time:.2f}s)"
        else :
            result["time_comment"] = f"Temps de réponse standard ({response_time:.2f}s)"

        # HTTPS check
        if result["final_url"].startswith("https://"):
            result["uses_https"] = True
            result["https_comment"] = "Site sécurisé (HTTPS)"
        else:
            result["https_comment"] = "Site non sécurisé (HTTP)"

        # Security headers check
        for h in SECURITY_HEADERS:
            value = response.headers.get(h)
            if value:
                result["score"] += 10  # chaque header présent = 10 points
            else:
                result["missing_headers"].append(h)
                result["headers_comment"].append("absent")

        # Check if HTTPS page use HTTP content
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
                        mixed_urls.append((src,tag))
            if mixed_urls:
                result["mixed_content"] = True
                result["score"] -= 10 
                result["mixed_comment"] = f"Contenu mixte détecté ({len(mixed_urls)} ressources HTTP)"
                result["mixed_url"] = mixed_urls

        # Final score between 0 and 100
        result["score"] = max(0, min(result["score"], 100))
    except requests.RequestException as e:
        result["comment"] = f"Erreur lors de la connexion : {e}"
    return result


def check_http_redirections(response) -> dict:
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
        "num_comment" : "",
        "redirect_domains": [],
        "rd_comment" : "",
        "redirect_ips": [],
        "ri_comment" : "",
        "risk": "Low",
    }

    # Check for redirection
    if len(history) == 0:
        result["num_comment"] = "Aucune redirection"
        return result

    # Find each redirection url
    for resp in history:
        parsed = urlparse(resp.headers.get("Location", resp.url))
        domain = parsed.hostname

        if domain:
            result["redirect_domains"].append(str(domain))
            # Check if hard IP redirection
            try:
                ipaddress.ip_address(domain)
                result["redirect_ips"].append(str(domain))
            except ValueError:
                pass

    # Comment and risk
    if len(history) <= 2:
        result["num_comment"] = "Nombre de redirection(s) normal"
    elif len(history) <= 5:
        result["num_comment"] = "Plusieurs redirections détectées. "
        result["risk"] = "Medium"
    else:
        result["num_comment"] = "Nombre excessif de redirections ! "
        result["risk"] = "High"

    # Check if redirects to another domain
    original_domain = urlparse(response.url).hostname
    for dom in result["redirect_domains"]:
        if dom != original_domain and dom not in result["redirect_ips"]:
            result["rd_comment"] = f"Redirection vers ({dom}). "
            result["risk"] = max_risk(result["risk"], "Medium")

    # Check if redirects to an IP 
    if result["redirect_ips"]:
        result["ri_comment"] += f"Redirection vers IP brute ({', '.join(result['redirect_ips'])}). "
        result["risk"] = max_risk(result["risk"], "Medium")

    return result


def affichage_http(result):
    spacer: str = "               "

    # Display the result in HTTP table
    http_table.insert("", "end", values=("Code de statut", result["status_code"], spacer + result["status_message"]))
    http_table.insert("", "end", values=("Version HTTP", result["http_version"][0], spacer + result["http_version"][1]))
    http_table.insert("", "end", values=("HTTPS activé", "Oui" if result["uses_https"] else "Non", spacer + result["https_comment"]))
    
    # If HTTPS is used display result for mixed content
    if result["uses_https"]:
        http_table.insert("", "end", values=("Contenu mixte", "Oui" if result["mixed_content"] else "Non", spacer + result["mixed_comment"]))
        
        # Display URL and type of mixed contents
        if result["mixed_url"]:
            count = 1
            for url, tag in result["mixed_url"]:
                http_table.insert("", "end", values=(f"URL {count}", url, spacer + tag))
                count += 1
    
    http_table.insert("", "end", values=("URL saisie", result["original_url"], ""))
    http_table.insert("", "end", values=("URL finale", result["final_url"], ""))
    http_table.insert("", "end", values=("Temps de réponse", result["time"], spacer + result["time_comment"]))

    # Display missing security headers => MUST DO TUPLE LIKE MIXED CONTENT
    if result["missing_headers"]:
        for i, (header, comment) in enumerate(zip(result["missing_headers"], result["headers_comment"])):
            if i == 0:
                http_table.insert("", "end", values=("Header de sécurité absent", header, spacer + comment))
            else:
                http_table.insert("", "end", values=("", header, spacer + comment))

    # Display redirection results
    http_table.insert("", "end", values=("Nombre de redirection", result["redirects"]["num_redirects"], spacer + result["redirects"]["num_comment"]))
    
    if result["redirects"]["num_redirects"] != 0:
        http_table.insert("", "end", values=("Domaines de redirection", result["redirects"]["redirect_domains"][0], spacer + result["redirects"]["rd_comment"]))
        for domaine in result["redirects"]["redirect_domains"][1:]:
            http_table.insert("", "end", values=("", domaine, ""))
    
    if result["redirects"]["redirect_ips"] != []:
        http_table.insert("", "end", values=("IPs de redirection", result["redirects"]["redirect_ips"][0], ""))
        http_table.insert("", "end", values=("", result["redirects"]["redirect_ips"][1:], ""))


def max_risk(current, new):
    """Compare deux niveaux de risque et renvoie le plus élevé"""
    levels = {"Low": 0, "Medium": 1, "High": 2}
    return new if levels[new] > levels[current] else current


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
            result = check_http_config(url)
            update_progress(70)

            # Step 3 : Display results
            affichage_http(result)
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


def open_settings():
    messagebox.showinfo("Settings")

def open_report():
    messagebox.showinfo("Report")

# ------------------ Main Window ------------------

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
