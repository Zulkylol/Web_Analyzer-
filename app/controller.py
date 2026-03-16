import threading
import time

import ttkbootstrap as ttk
from tkinter import messagebox

from core.cookies.scan_cookies import scan_cookies_config
from core.http.scan_http import scan_http_config
from core.tls.scan_tls import scan_tls_config
from ui.app_window import build_main_window
from ui.display_common import display_report_rows
from ui.tables import clear_tables


class WebAnalyzerApp:
    """Controleur principal: relie l'interface, les scans et la synthese globale."""

    # ===============================================================
    # FUNCTION : __init__
    # ===============================================================
    def __init__(self) -> None:
        """
        Initialize the main app controller.

        Returns :
            None : no return
        """
        self.selected_language = "fr"
        self.settings_window = None
        self.scan_results = {
            "HTTP": None,
            "SSL/TLS": None,
            "Cookies": None,
        }

        self._progress_plan = {}

        ui_refs = build_main_window(
            self.launch_scan,
            self.open_settings,
            self.open_report,
            self.on_table_select,
            self.sync_http_options,
        )
        self.root = ui_refs["root"]
        self.url_entry = ui_refs["url_entry"]
        self.scan_http_var = ui_refs["scan_http_var"]
        self.force_https_var = ui_refs["force_https_var"]
        self.scan_tls_var = ui_refs["scan_tls_var"]
        self.scan_cookies_var = ui_refs["scan_cookies_var"]
        self.force_https_check = ui_refs["force_https_check"]
        self.go_button = ui_refs["go_button"]
        self.open_report_button = ui_refs["open_report_button"]
        self.progress_bar = ui_refs["progress_bar"]
        self.summary_scan_rows_var = ui_refs["summary_scan_rows_var"]
        self.summary_alerts_var = ui_refs["summary_alerts_var"]
        self.summary_high_var = ui_refs["summary_high_var"]
        self.summary_risk_var = ui_refs["summary_risk_var"]
        self.summary_table = ui_refs["summary_table"]
        self.http_table = ui_refs["http_table"]
        self.ssl_table = ui_refs["ssl_table"]
        self.cookies_table = ui_refs["cookies_table"]
        self.details_text = ui_refs["details_text"]

        # L'etat initial des options depend des cases a cocher.
        self.sync_http_options()
        self.refresh_summary_view()

    # ===============================================================
    # FUNCTION : run
    # ===============================================================
    def run(self) -> None:
        """Launch of TK mainloop"""
        self.root.mainloop()

    # ===============================================================
    # FUNCTION : clear_tree
    # ===============================================================
    def clear_tree(self, tree) -> None:
        """Delete all the lines of a table"""
        tree.delete(*tree.get_children())

    # ===============================================================
    # FUNCTION : launch_scan
    # ===============================================================
    def launch_scan(self) -> None:
        """Prepare l'UI, normalise l'URL d'entree et demarre le scan hors thread UI."""
        clear_tables(self.http_table, self.ssl_table, self.cookies_table)
        self.clear_tree(self.summary_table)
        self.scan_results = {
            "HTTP": None,
            "SSL/TLS": None,
            "Cookies": None,
        }

        input_url = self.url_entry.get().strip()
        if not input_url:
            messagebox.showwarning("Attention", "Veuillez entrer une URL")
            return

        url = input_url
        if self.force_https_var.get() and not input_url.startswith(("http://", "https://")):
            url = "https://" + input_url
        elif self.force_https_var.get() and input_url.startswith("http://"):
            url = "https://" + input_url[len("http://"):]

        self.go_button.config(state="disabled")
        self.open_report_button.config(state="disabled")
        self._progress_plan = self.build_progress_plan()
        self.set_progress(0, style="warning-striped", allow_decrease=True)

        # Le scan tourne en arriere-plan pour garder l'interface fluide.
        threading.Thread(target=self.scan_in_background, args=(url,), daemon=True).start()

    # ===============================================================
    # FUNCTION : scan_in_background
    # ===============================================================
    def scan_in_background(self, url: str) -> None:
        """Execute les scans actifs puis met a jour les tables et la synthese."""
        try:
            self.set_progress(6)

            result_http = None
            if self.scan_http_var.get():
                phase = self._progress_plan.get("phases", {}).get("HTTP", {})
                self.set_progress(float(phase.get("start", 6.0)))
                result_http = scan_http_config(url)
                self.set_progress(float(phase.get("end", 6.0)))
            self.scan_results["HTTP"] = result_http

            result_tls = None
            if self.scan_tls_var.get():
                phase = self._progress_plan.get("phases", {}).get("SSL/TLS", {})
                self.set_progress(float(phase.get("start", 6.0)))
                result_tls = scan_tls_config(url)
                self.set_progress(float(phase.get("end", 6.0)))
            self.scan_results["SSL/TLS"] = result_tls

            result_cookies = None
            if self.scan_cookies_var.get():
                phase = self._progress_plan.get("phases", {}).get("Cookies", {})
                self.set_progress(float(phase.get("start", 6.0)))
                result_cookies = scan_cookies_config(url)
                self.set_progress(float(phase.get("end", 6.0)))
            self.scan_results["Cookies"] = result_cookies

            self.set_progress(self._progress_plan.get("after_scans", 82.0))
            if self.scan_http_var.get() and result_http is not None:
                display_report_rows(result_http.get("report", {}), self.http_table)
            if self.scan_tls_var.get() and result_tls is not None:
                display_report_rows(result_tls.get("report", {}), self.ssl_table)
            if self.scan_cookies_var.get() and result_cookies is not None:
                display_report_rows(result_cookies.get("report", {}), self.cookies_table)

            self.refresh_summary_view()
            self.set_progress(self._progress_plan.get("summary", 92.0))

        except Exception as exc:
            messagebox.showerror("Erreur", f"Erreur pendant le scan : {exc}")

        finally:
            self.set_progress(self._progress_plan.get("finish", 100.0), style="success-striped")
            time.sleep(0.35)
            self.open_report_button.config(state="normal")
            self.go_button.config(state="normal")

    # ===============================================================
    # FUNCTION : build_progress_plan
    # ===============================================================
    def build_progress_plan(self) -> dict:
        """Repartit la barre selon le cout estime de HTTP, TLS et Cookies."""
        enabled_phases = []
        if self.scan_http_var.get():
            enabled_phases.append(("HTTP", 5.0))
        if self.scan_tls_var.get():
            enabled_phases.append(("SSL/TLS", 3.0))
        if self.scan_cookies_var.get():
            enabled_phases.append(("Cookies", 2.0))

        start_value = 6.0
        scan_budget = 75.0
        total_weight = sum(weight for _, weight in enabled_phases) or 1.0
        cursor = start_value
        phases = {}

        for phase_name, weight in enabled_phases:
            span = scan_budget * (weight / total_weight)
            phases[phase_name] = {"start": cursor, "end": cursor + span}
            cursor += span

        return {
            "phases": phases,
            "after_scans": max(cursor, 82.0),
            "summary": 92.0,
            "finish": 100.0,
        }

    # ===============================================================
    # FUNCTION : set_progress
    # ===============================================================
    def set_progress(self, value: float, style: str | None = None, allow_decrease: bool = False) -> None:
        """Met a jour la barre, avec option explicite pour la reinitialiser."""
        current = float(self.progress_bar["value"])
        next_value = float(value)
        if allow_decrease:
            self.progress_bar["value"] = next_value
        else:
            self.progress_bar["value"] = max(next_value, current)
        if style:
            self.progress_bar.configure(bootstyle=style)
        self.root.update_idletasks()

    # ===============================================================
    # FUNCTION : open_settings
    # ===============================================================
    def open_settings(self) -> None:
        """Ouvre une petite fenetre de parametres centree sur la fenetre principale."""
        if self.settings_window is not None and self.settings_window.winfo_exists():
            self.settings_window.deiconify()
            self.settings_window.lift()
            self.settings_window.focus_force()
            return

        settings_win = ttk.Toplevel(self.root)
        self.settings_window = settings_win
        settings_win.title("Paramètres")
        settings_win.geometry("360x180")
        settings_win.resizable(False, False)
        settings_win.transient(self.root)
        settings_win.grab_set()
        # ===============================================================
        # FUNCTION : close_settings
        # ===============================================================
        def close_settings():
            """
            Close the settings window.

            Returns :
                None : no return
            """
            self.settings_window = None
            settings_win.destroy()

        settings_win.protocol("WM_DELETE_WINDOW", close_settings)

        container = ttk.Frame(settings_win, padding=14)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text="Langue de l'interface", font=("Helvetica", 11, "bold")).pack(anchor="w", pady=(0, 8))

        lang_choices = {"Français": "fr", "English": "en"}
        reverse_choices = {value: key for key, value in lang_choices.items()}
        lang_var = ttk.StringVar(value=reverse_choices.get(self.selected_language, "Français"))
        lang_combo = ttk.Combobox(
            container,
            textvariable=lang_var,
            values=("Français", "English"),
            state="readonly",
            width=20,
        )
        lang_combo.pack(anchor="w")
        lang_combo.set(reverse_choices.get(self.selected_language, "Français"))

        ttk.Label(
            container,
            text="Français est la langue par défaut.",
        ).pack(anchor="w", pady=(8, 14))

        # ===============================================================
        # FUNCTION : save_settings
        # ===============================================================
        def save_settings():
            """
            Save the selected UI language.

            Returns :
                None : no return
            """
            self.selected_language = lang_choices.get(lang_var.get(), "fr")
            messagebox.showinfo(
                "Paramètres",
                f"Langue enregistrée: {reverse_choices.get(self.selected_language, 'Français')}",
            )
            close_settings()

        actions = ttk.Frame(container)
        actions.pack(fill="x")
        ttk.Button(actions, text="Enregistrer", bootstyle="success", command=save_settings).pack(side="left")
        ttk.Button(actions, text="Annuler", bootstyle="secondary", command=close_settings).pack(side="left", padx=8)

    # ===============================================================
    # FUNCTION : open_report
    # ===============================================================
    def open_report(self) -> None:
        """Placeholder pour une future fonctionnalite d'export/ouverture de rapport."""
        messagebox.showinfo("Report")

    # ===============================================================
    # FUNCTION : sync_http_options
    # ===============================================================
    def sync_http_options(self) -> None:
        """Active 'Forcer HTTPS' uniquement quand le module HTTP est coche."""
        if self.scan_http_var.get():
            self.force_https_check.config(state="normal")
        else:
            self.force_https_var.set(0)
            self.force_https_check.config(state="disabled")

    # ===============================================================
    # FUNCTION : is_summary_risk
    # ===============================================================
    def is_summary_risk(self, risk: str) -> bool:
        """Filtre les niveaux qui doivent remonter dans l'onglet global."""
        return str(risk or "").strip().upper() in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    # ===============================================================
    # FUNCTION : refresh_summary_table
    # ===============================================================
    def refresh_summary_table(self) -> None:
        """Consolide les findings des trois modules dans la table globale."""
        self.clear_tree(self.summary_table)
        summary_rows = []
        for source_name, result in self.scan_results.items():
            report = (result or {}).get("report", {})
            for finding in report.get("findings", []):
                risk = str(finding.get("risk", "")).upper()
                if not self.is_summary_risk(risk):
                    continue
                summary_rows.append(
                    {
                        **finding,
                        "param": f"[{source_name}] {finding.get('param', '')}",
                        "tags": [],
                    }
                )

        display_report_rows({"rows": summary_rows}, self.summary_table)

    # ===============================================================
    # FUNCTION : refresh_summary_view
    # ===============================================================
    def refresh_summary_view(self) -> None:
        """Met a jour les compteurs de synthese a partir des reports deja calcules."""
        self.refresh_summary_table()

        total_rows = 0
        total_alerts = 0
        high_alerts = 0
        medium_alerts = 0

        for result in self.scan_results.values():
            report = (result or {}).get("report", {})
            report_summary = report.get("summary", {})
            total_rows += int(report_summary.get("total_rows", 0) or 0)
            total_alerts += int(report_summary.get("total_findings", 0) or 0)
            high_alerts += int(report_summary.get("high_findings", 0) or 0)
            medium_alerts += int(report_summary.get("medium_findings", 0) or 0)

        if high_alerts > 0:
            risk = "ELEVE"
        elif medium_alerts >= 2:
            risk = "MODERE"
        else:
            risk = "FAIBLE"

        self.summary_scan_rows_var.set(str(total_rows))
        self.summary_alerts_var.set(str(total_alerts))
        self.summary_high_var.set(str(high_alerts))
        self.summary_risk_var.set(risk)

    # ===============================================================
    # FUNCTION : on_table_select
    # ===============================================================
    def on_table_select(self, event) -> None:
        """Affiche le detail complet de la ligne selectionnee sous les onglets."""
        tree = event.widget
        selected = tree.selection()
        if not selected:
            return
        values = tree.item(selected[0], "values") or ("", "", "", "", "")
        param = values[0] if len(values) > 0 else ""
        value = values[1] if len(values) > 1 else ""
        check = values[2] if len(values) > 2 else ""
        risk = values[3] if len(values) > 3 else ""
        # Le commentaire brut est memorise au rendu pour eviter les troncatures visuelles.
        comment = getattr(tree, "_row_comments", {}).get(selected[0], values[4] if len(values) > 4 else "")
        comment = str(comment or "").strip()

        self.details_text.config(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert(
            "end",
            f"Parametre: {param}\n"
            f"Valeur: {value}\n"
            f"Check: {check}\n"
            f"Risque: {risk}\n"
            f"Commentaire: {comment}",
        )
        self.details_text.config(state="disabled")
