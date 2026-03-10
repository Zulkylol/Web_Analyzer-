import threading
import time

import ttkbootstrap as ttk
from tkinter import messagebox

from core.cookies.scan_cookies import scan_cookies_config
from core.http.scan_http import scan_http_config
from core.tls.scan_tls import scan_tls_config
from ui.app_window import build_main_window
from ui.display_cookies import display_cookies
from ui.display_http import display_http
from ui.display_tls import display_ssl_tls
from ui.tables import clear_tables


class WebAnalyzerApp:
    def __init__(self) -> None:
        self.selected_language = "fr"
        self.settings_window = None

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
        self.progress_bar["value"] = 0
        self.root.update_idletasks()

        threading.Thread(target=self.scan_in_background, args=(url,), daemon=True).start()

    def scan_in_background(self, url: str) -> None:
        try:
            self.update_progress(5, steps=8)

            result_http = None
            if self.scan_http_var.get():
                self.update_progress(20, steps=14)
                result_http = scan_http_config(url)

            result_tls = None
            if self.scan_tls_var.get():
                self.update_progress(40, steps=16)
                result_tls = scan_tls_config(url)

            result_cookies = None
            if self.scan_cookies_var.get():
                self.update_progress(60, steps=14)
                result_cookies = scan_cookies_config(url)

            self.update_progress(80, steps=14)
            if self.scan_http_var.get() and result_http is not None:
                display_http(result_http, self.http_table)
            if self.scan_tls_var.get() and result_tls is not None:
                display_ssl_tls(result_tls, self.ssl_table)
            if self.scan_cookies_var.get() and result_cookies is not None:
                display_cookies(result_cookies, self.cookies_table)

            self.refresh_summary_cards()
            self.update_progress(90, steps=10)
            self.update_progress(100, steps=12)

        except Exception as exc:
            messagebox.showerror("Erreur", f"Erreur pendant le scan : {exc}")

        finally:
            messagebox.showinfo("Terminé", "Scan terminé !")
            self.open_report_button.config(state="normal")
            self.go_button.config(state="normal")

    def update_progress(self, value, steps=12, delay=0.008) -> None:
        current = float(self.progress_bar["value"])
        target = float(value)
        if steps <= 1:
            self.progress_bar["value"] = target
            self.root.update_idletasks()
            return

        delta = (target - current) / steps
        for _ in range(steps):
            current += delta
            self.progress_bar["value"] = current
            self.root.update_idletasks()
            time.sleep(delay)
        self.progress_bar["value"] = target
        self.root.update_idletasks()

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

    def include_in_summary(self, source_name: str, param: str) -> bool:
        param_text = str(param or "")
        if source_name == "Cookies":
            return param_text.startswith("Alerte cookie #")
        if source_name == "HTTP" and not param_text.strip():
            return False
        return True

    def refresh_summary_table(self) -> None:
        self.clear_tree(self.summary_table)

        source_tables = (
            ("HTTP", self.http_table),
            ("SSL/TLS", self.ssl_table),
            ("Cookies", self.cookies_table),
        )
        row_idx = 0

        for source_name, tree in source_tables:
            items = list(tree.get_children())
            idx = 0
            while idx < len(items):
                item = items[idx]
                values = tree.item(item, "values") or ()
                if len(values) < 5:
                    idx += 1
                    continue

                param = values[0]
                value = values[1]
                check = values[2]
                risk = str(values[3] or "").upper()
                comment = values[4]

                if source_name == "HTTP" and param == "Domaines de redirection":
                    last_value = value
                    last_check = check
                    last_risk = risk
                    last_comment = comment
                    look_ahead = idx + 1
                    while look_ahead < len(items):
                        next_values = tree.item(items[look_ahead], "values") or ()
                        if len(next_values) < 5:
                            look_ahead += 1
                            continue
                        next_param = str(next_values[0] or "")
                        if next_param.strip():
                            break
                        last_value = next_values[1]
                        last_check = next_values[2]
                        last_risk = str(next_values[3] or "").upper()
                        last_comment = next_values[4]
                        look_ahead += 1
                    value = last_value
                    check = last_check
                    risk = last_risk
                    comment = last_comment
                    idx = look_ahead - 1

                if not self.is_summary_risk(risk):
                    idx += 1
                    continue
                if not self.include_in_summary(source_name, param):
                    idx += 1
                    continue

                zebra_tag = "zebra_even" if row_idx % 2 == 0 else "zebra_odd"
                self.summary_table.insert(
                    "",
                    "end",
                    values=(f"[{source_name}] {param}", value, check, risk, comment),
                    tags=(zebra_tag,),
                )
                row_idx += 1
                idx += 1

    def refresh_summary_cards(self) -> None:
        self.refresh_summary_table()

        total_rows = 0
        total_alerts = 0
        high_alerts = 0
        medium_alerts = 0

        for tree in (self.http_table, self.ssl_table, self.cookies_table):
            total_rows += len(tree.get_children())

        for item in self.summary_table.get_children():
            values = self.summary_table.item(item, "values") or ()
            if len(values) < 4:
                continue
            risk = str(values[3] or "").strip().upper()
            if self.is_summary_risk(risk):
                total_alerts += 1
                if risk in {"HIGH", "CRITICAL"}:
                    high_alerts += 1
                elif risk == "MEDIUM":
                    medium_alerts += 1

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
        comment = values[4] if len(values) > 4 else ""

        self.details_text.config(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert(
            "end",
            f"Parametre: {param}\n"
            f"Valeur: {value}\n"
            f"Check: {check}\n"
            f"Risque: {risk}\n"
            f"Commentaire:\n{comment}",
        )
        self.details_text.config(state="disabled")
