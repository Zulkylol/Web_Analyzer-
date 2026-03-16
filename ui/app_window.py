import tkinter as tk

import ttkbootstrap as ttk
from ttkbootstrap.constants import INFO, SUCCESS, WARNING

from ui.tables import create_result_table


# ===============================================================
# FUNCTION : build_main_window
# ===============================================================
def build_main_window(start_scan, open_settings, open_report, on_table_select, sync_http_options):
    """Construit la fenetre principale et retourne les references utiles au controleur."""
    root = ttk.Window(themename="cosmo")
    root.title("Web Analyzer")
    root.geometry("1580x1100")
    root.iconbitmap("resources/title_bar.ico")

    title_label = ttk.Label(
        root,
        text="Scanner de configuration de s\u00e9curit\u00e9 Web",
        font=("Helvetica", 16, "bold"),
    )
    title_label.pack(pady=10)

    # Zone de saisie de l'URL a analyser.
    url_frame = ttk.Frame(root)
    url_frame.pack(pady=5)
    ttk.Label(url_frame, text="URL du site:", font=("Helvetica", 12)).pack(side="left", padx=5)
    url_entry = ttk.Entry(url_frame, width=35)
    url_entry.pack(side="left", padx=5)

    controls_row = ttk.Frame(root)
    controls_row.pack(padx=10, pady=10, fill="x")

    # Bloc des options de scan.
    checkbox_frame = ttk.LabelFrame(
        controls_row,
        text="S\u00e9lection des v\u00e9rifications",
        font=("Helvetica", 11, "bold"),
    )
    checkbox_frame.pack(side="left", fill="both", expand=False, padx=(0, 8))
    checkbox_frame.configure(width=760)
    checkbox_frame.pack_propagate(False)

    scan_http_var = ttk.IntVar(value=1)
    force_https_var = ttk.IntVar(value=0)
    scan_tls_var = ttk.IntVar(value=1)
    scan_cookies_var = ttk.IntVar(value=1)

    ttk.Checkbutton(
        checkbox_frame,
        text="Analyser la r\u00e9ponse HTTP",
        variable=scan_http_var,
        command=sync_http_options,
    ).pack(anchor="w", pady=2, padx=5)
    force_https_check = ttk.Checkbutton(checkbox_frame, text="Forcer HTTPS", variable=force_https_var)
    force_https_check.pack(anchor="w", pady=2, padx=5)
    ttk.Checkbutton(checkbox_frame, text="Analyser TLS et les certificats", variable=scan_tls_var).pack(anchor="w", pady=2, padx=5)
    ttk.Checkbutton(checkbox_frame, text="Analyser les cookies", variable=scan_cookies_var).pack(anchor="w", pady=2, padx=5)

    # Bloc des actions et de la progression.
    actions_frame = ttk.LabelFrame(controls_row, text="Actions", font=("Helvetica", 11, "bold"))
    actions_frame.pack(side="left", fill="both", expand=True, padx=(8, 0))

    button_frame = ttk.Frame(actions_frame)
    button_frame.pack(anchor="n", pady=(12, 8))
    go_button = ttk.Button(button_frame, text="GO", bootstyle=SUCCESS, width=12, command=start_scan)
    go_button.pack(side="left", padx=10)
    settings_button = ttk.Button(button_frame, text="Settings", bootstyle=INFO, width=12, command=open_settings)
    settings_button.pack(side="left", padx=10)

    progress_bar = ttk.Progressbar(
        actions_frame,
        orient="horizontal",
        length=420,
        mode="determinate",
        bootstyle="warning-striped",
    )
    progress_bar.pack(anchor="n", pady=(6, 10), padx=12)

    open_report_button = ttk.Button(
        actions_frame,
        text="Open Report",
        bootstyle=WARNING,
        width=25,
        state="disabled",
        command=open_report,
    )
    open_report_button.pack(anchor="n", pady=(2, 12))

    tables_frame = ttk.Frame(root)
    tables_frame.pack(padx=10, pady=10, fill="both", expand=True)

    # Les resultats sont organises par onglet pour garder une lecture simple.
    results_notebook = ttk.Notebook(tables_frame)
    results_notebook.pack(fill="both", expand=True)

    tab_summary = ttk.Frame(results_notebook)
    tab_http = ttk.Frame(results_notebook)
    tab_tls = ttk.Frame(results_notebook)
    tab_cookies = ttk.Frame(results_notebook)

    results_notebook.add(tab_summary, text="Alertes globales")
    results_notebook.add(tab_http, text="HTTP")
    results_notebook.add(tab_tls, text="TLS")
    results_notebook.add(tab_cookies, text="Cookies")

    summary_scan_rows_var = ttk.StringVar(value="0")
    summary_alerts_var = ttk.StringVar(value="0")
    summary_high_var = ttk.StringVar(value="0")
    summary_risk_var = ttk.StringVar(value="-")

    summary_box = ttk.LabelFrame(tab_summary, text="Synthèse", font=("Helvetica", 11, "bold"))
    summary_box.pack(fill="x", padx=14, pady=14)

    # Les cartes du resume se repartissent uniformement sur la largeur.
    for col in range(4):
        summary_box.columnconfigure(col, weight=1, uniform="summary")

    ttk.Label(summary_box, text="Lignes analysées", font=("Helvetica", 11, "bold"), anchor="center", justify="center").grid(row=0, column=0, padx=24, pady=(10, 4), sticky="ew")
    ttk.Label(summary_box, textvariable=summary_scan_rows_var, font=("Helvetica", 16, "bold"), anchor="center", justify="center").grid(row=1, column=0, padx=24, pady=(0, 10), sticky="ew")
    ttk.Label(summary_box, text="Alertes totales", font=("Helvetica", 11, "bold"), anchor="center", justify="center").grid(row=0, column=1, padx=24, pady=(10, 4), sticky="ew")
    ttk.Label(summary_box, textvariable=summary_alerts_var, font=("Helvetica", 16, "bold"), anchor="center", justify="center").grid(row=1, column=1, padx=24, pady=(0, 10), sticky="ew")
    ttk.Label(summary_box, text="Alertes critiques", font=("Helvetica", 11, "bold"), anchor="center", justify="center").grid(row=0, column=2, padx=24, pady=(10, 4), sticky="ew")
    ttk.Label(summary_box, textvariable=summary_high_var, font=("Helvetica", 16, "bold"), anchor="center", justify="center").grid(row=1, column=2, padx=24, pady=(0, 10), sticky="ew")
    ttk.Label(summary_box, text="Risque global", font=("Helvetica", 11, "bold"), anchor="center", justify="center").grid(row=0, column=3, padx=24, pady=(10, 4), sticky="ew")
    ttk.Label(summary_box, textvariable=summary_risk_var, font=("Helvetica", 16, "bold"), anchor="center", justify="center").grid(row=1, column=3, padx=24, pady=(0, 10), sticky="ew")

    ttk.Label(
        tab_summary,
        text="S\u00e9lectionne une ligne dans HTTP/TLS/Cookies pour voir le d\u00e9tail complet ci-dessous.",
    ).pack(anchor="w", padx=14, pady=(0, 10))

    summary_table = create_result_table(tab_summary, "Alertes consolid\u00e9es")
    http_table = create_result_table(tab_http, "HTTP")
    ssl_table = create_result_table(tab_tls, "TLS")
    cookies_table = create_result_table(tab_cookies, "Cookies")

    # Tags de style reutilises par tous les tableaux.
    for tree in (summary_table, http_table, ssl_table, cookies_table):
        tree.tag_configure("zebra_even", background="#ffffff")
        tree.tag_configure("zebra_odd", background="#f3f6fa")
        tree.tag_configure("section_header", font=("Helvetica", 10, "bold"), background="#6c757d", foreground="#ffffff")
        tree.tag_configure("recommendation", font=("Helvetica", 9, "italic"))

    cookies_table.tag_configure("cookie_name", font=("Helvetica", 10, "bold"))

    summary_table.bind("<<TreeviewSelect>>", on_table_select)
    http_table.bind("<<TreeviewSelect>>", on_table_select)
    ssl_table.bind("<<TreeviewSelect>>", on_table_select)
    cookies_table.bind("<<TreeviewSelect>>", on_table_select)

    details_frame = ttk.LabelFrame(
        root,
        text="D\u00e9tail de la ligne s\u00e9lectionn\u00e9e",
        font=("Helvetica", 11, "bold"),
    )
    details_frame.pack(fill="x", padx=10, pady=(0, 10))
    details_text = tk.Text(details_frame, height=5, wrap="word")
    details_text.pack(fill="x", padx=8, pady=8)
    details_text.insert("end", "S\u00e9lectionne une ligne pour afficher son commentaire complet.")
    details_text.config(state="disabled")

    # Styles globaux de l'application.
    style = ttk.Style()
    style.configure("TNotebook.Tab", font=("Helvetica", 11, "bold"))
    style.configure("Treeview", rowheight=22)
    style.configure("Treeview.Heading", font=("Helvetica", 11, "bold"))
    root.bind("<Return>", lambda _event: start_scan())

    return {
        "root": root,
        "url_entry": url_entry,
        "scan_http_var": scan_http_var,
        "force_https_var": force_https_var,
        "scan_tls_var": scan_tls_var,
        "scan_cookies_var": scan_cookies_var,
        "force_https_check": force_https_check,
        "go_button": go_button,
        "open_report_button": open_report_button,
        "progress_bar": progress_bar,
        "summary_scan_rows_var": summary_scan_rows_var,
        "summary_alerts_var": summary_alerts_var,
        "summary_high_var": summary_high_var,
        "summary_risk_var": summary_risk_var,
        "summary_table": summary_table,
        "http_table": http_table,
        "ssl_table": ssl_table,
        "cookies_table": cookies_table,
        "details_text": details_text,
    }
