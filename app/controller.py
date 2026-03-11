import threading
import time

import ttkbootstrap as ttk
from tkinter import messagebox

from core.cookies.scan_cookies import scan_cookies_config
from core.http.scan_http import scan_http_config
from core.tls.scan_tls import scan_tls_config
from ui.app_window import build_main_window
from ui.display_common import display_report_rows
from ui.display_cookies import display_cookies
from ui.display_http import display_http
from ui.display_tls import display_ssl_tls
from ui.tables import clear_tables


class WebAnalyzerApp:
    def __init__(self) -> None:
        self.selected_language = "fr"
        self.settings_window = None
        self.scan_results = {
            "HTTP": None,
            "SSL/TLS": None,
            "Cookies": None,
        }

        self._progress_lock = threading.Lock()
        self._progress_plan = {}
        self._progress_target_value = 0.0
        self._progress_running = False
        self._progress_phase_active = False
        self._progress_phase_start_value = 0.0
        self._progress_phase_end_value = 0.0
        self._progress_phase_started_at = 0.0
        self._progress_phase_expected_seconds = 1.0
        self._progress_animation_job = None

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

        self.sync_http_options()
        self.refresh_summary_cards()

    def run(self) -> None:
        self.root.mainloop()

    def clear_tree(self, tree) -> None:
        for item in tree.get_children():
            tree.delete(item)

    def launch_scan(self) -> None:
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
        self.start_progress_tracking()

        threading.Thread(target=self.scan_in_background, args=(url,), daemon=True).start()

    def scan_in_background(self, url: str) -> None:
        try:
            self.set_progress_target(6)

            result_http = None
            if self.scan_http_var.get():
                self.start_progress_phase("HTTP")
                result_http = scan_http_config(url)
                self.complete_progress_phase("HTTP")
            self.scan_results["HTTP"] = result_http

            result_tls = None
            if self.scan_tls_var.get():
                self.start_progress_phase("SSL/TLS")
                result_tls = scan_tls_config(url)
                self.complete_progress_phase("SSL/TLS")
            self.scan_results["SSL/TLS"] = result_tls

            result_cookies = None
            if self.scan_cookies_var.get():
                self.start_progress_phase("Cookies")
                result_cookies = scan_cookies_config(url)
                self.complete_progress_phase("Cookies")
            self.scan_results["Cookies"] = result_cookies

            self.set_progress_target(self._progress_plan.get("after_scans", 82.0))
            if self.scan_http_var.get() and result_http is not None:
                display_http(result_http, self.http_table)
            if self.scan_tls_var.get() and result_tls is not None:
                display_ssl_tls(result_tls, self.ssl_table)
            if self.scan_cookies_var.get() and result_cookies is not None:
                display_cookies(result_cookies, self.cookies_table)

            self.refresh_summary_cards()
            self.set_progress_target(self._progress_plan.get("summary", 92.0))

        except Exception as exc:
            messagebox.showerror("Erreur", f"Erreur pendant le scan : {exc}")

        finally:
            self.finish_progress_tracking()
            time.sleep(0.35)
            self.open_report_button.config(state="normal")
            self.go_button.config(state="normal")

    def update_progress(self, value, steps=12, delay=0.008) -> None:
        self.set_progress_target(value)

    def build_progress_plan(self) -> dict:
        enabled_phases = []
        if self.scan_http_var.get():
            enabled_phases.append(("HTTP", 5.0, 6.0))
        if self.scan_tls_var.get():
            enabled_phases.append(("SSL/TLS", 3.0, 3.5))
        if self.scan_cookies_var.get():
            enabled_phases.append(("Cookies", 2.0, 2.5))

        start_value = 6.0
        scan_budget = 74.0
        total_weight = sum(weight for _, weight, _ in enabled_phases) or 1.0
        cursor = start_value
        phases = {}

        for phase_name, weight, expected_seconds in enabled_phases:
            span = scan_budget * (weight / total_weight)
            phases[phase_name] = {
                "start": cursor,
                "end": cursor + span,
                "expected_seconds": expected_seconds,
            }
            cursor += span

        return {
            "phases": phases,
            "after_scans": max(cursor, 82.0),
            "summary": 92.0,
            "finish": 100.0,
        }

    def reset_progress_tracking(self) -> None:
        if self._progress_animation_job is not None:
            try:
                self.root.after_cancel(self._progress_animation_job)
            except Exception:
                pass
            self._progress_animation_job = None

        with self._progress_lock:
            self._progress_plan = {}
            self._progress_target_value = 0.0
            self._progress_running = False
            self._progress_phase_active = False
            self._progress_phase_start_value = 0.0
            self._progress_phase_end_value = 0.0
            self._progress_phase_started_at = 0.0
            self._progress_phase_expected_seconds = 1.0

        self.progress_bar["value"] = 0
        self.progress_bar.configure(bootstyle="warning-striped")
        self.root.update_idletasks()

    def start_progress_tracking(self) -> None:
        self.reset_progress_tracking()
        with self._progress_lock:
            self._progress_plan = self.build_progress_plan()
            self._progress_running = True
            self._progress_target_value = 0.0
        self.schedule_progress_animation()

    def finish_progress_tracking(self) -> None:
        with self._progress_lock:
            self._progress_target_value = float(self._progress_plan.get("finish", 100.0))
            self._progress_running = False
            self._progress_phase_active = False

    def set_progress_target(self, value: float) -> None:
        with self._progress_lock:
            self._progress_target_value = max(float(value), self._progress_target_value)

    def start_progress_phase(self, phase_name: str) -> None:
        phase = self._progress_plan.get("phases", {}).get(phase_name)
        if not phase:
            return

        with self._progress_lock:
            self._progress_target_value = max(float(phase["start"]), self._progress_target_value)
            self._progress_phase_active = True
            self._progress_phase_start_value = float(phase["start"])
            self._progress_phase_end_value = float(phase["end"])
            self._progress_phase_started_at = time.monotonic()
            self._progress_phase_expected_seconds = float(phase["expected_seconds"])

    def complete_progress_phase(self, phase_name: str) -> None:
        phase = self._progress_plan.get("phases", {}).get(phase_name)
        if not phase:
            return

        with self._progress_lock:
            self._progress_target_value = max(float(phase["end"]), self._progress_target_value)
            self._progress_phase_active = False

    def schedule_progress_animation(self) -> None:
        if self._progress_animation_job is None:
            self._tick_progress_animation()

    def _tick_progress_animation(self) -> None:
        with self._progress_lock:
            target = self._progress_target_value
            running = self._progress_running
            phase_active = self._progress_phase_active
            phase_start = self._progress_phase_start_value
            phase_end = self._progress_phase_end_value
            phase_started_at = self._progress_phase_started_at
            expected_seconds = self._progress_phase_expected_seconds

        if phase_active:
            span = max(0.0, phase_end - phase_start)
            elapsed = max(0.0, time.monotonic() - phase_started_at)
            ratio = min(elapsed / max(expected_seconds, 0.5), 0.92)
            target = max(target, phase_start + span * ratio)

        current = float(self.progress_bar["value"])
        if target > current:
            speed = 0.28 if not running else 0.16
            max_step = 5.0 if not running else 2.8
            step = max(0.25, min(max_step, (target - current) * speed))
            current = min(target, current + step)
            self.progress_bar["value"] = current
            self.root.update_idletasks()

        if not running and current >= target - 0.1:
            self.progress_bar["value"] = target
            self.progress_bar.configure(bootstyle="success-striped")
            self.root.update_idletasks()
            self._progress_animation_job = None
            return

        self._progress_animation_job = self.root.after(33, self._tick_progress_animation)

    def open_settings(self) -> None:
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
        self.root.update_idletasks()
        settings_win.update_idletasks()
        root_x = self.root.winfo_rootx()
        root_y = self.root.winfo_rooty()
        root_w = self.root.winfo_width()
        root_h = self.root.winfo_height()
        win_w = settings_win.winfo_width() or 360
        win_h = settings_win.winfo_height() or 180
        pos_x = root_x + max(0, (root_w - win_w) // 2)
        pos_y = root_y + max(0, (root_h - win_h) // 2)
        settings_win.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")

        def close_settings():
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

        def save_settings():
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

    def open_report(self) -> None:
        messagebox.showinfo("Report")

    def sync_http_options(self) -> None:
        if self.scan_http_var.get():
            self.force_https_check.config(state="normal")
        else:
            self.force_https_var.set(0)
            self.force_https_check.config(state="disabled")

    def is_summary_risk(self, risk: str) -> bool:
        return str(risk or "").strip().upper() in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def refresh_summary_table(self) -> None:
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

    def refresh_summary_cards(self) -> None:
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
        elif total_alerts > 0:
            risk = "FAIBLE"
        else:
            risk = "FAIBLE"

        self.summary_scan_rows_var.set(str(total_rows))
        self.summary_alerts_var.set(str(total_alerts))
        self.summary_high_var.set(str(high_alerts))
        self.summary_risk_var.set(risk)

    def on_table_select(self, event) -> None:
        tree = event.widget
        selected = tree.selection()
        if not selected:
            return
        values = tree.item(selected[0], "values") or ("", "", "", "", "")
        param = values[0] if len(values) > 0 else ""
        value = values[1] if len(values) > 1 else ""
        check = values[2] if len(values) > 2 else ""
        risk = values[3] if len(values) > 3 else ""
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
