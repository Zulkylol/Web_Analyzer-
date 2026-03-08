# ui/tables.py

# ===============================================================
# IMPORTS
# ===============================================================
import ttkbootstrap as ttk

# ===============================================================
# FUNCTION : clear_tables()
# ===============================================================
def clear_tables(http_table,ssl_table,cookies_table):
    """
    Clear all rows from the HTTP, SSL, and Cookies tables.
    """
    for item in http_table.get_children():
        http_table.delete(item)
    for item in ssl_table.get_children():
        ssl_table.delete(item)
    for item in cookies_table.get_children():
        cookies_table.delete(item)

# ===============================================================
# FUNCTION : create_result_table()
# ===============================================================
def create_result_table(parent, title):
    """
    Create and return a styled result table (Treeview) with predefined columns and scrollbar.
    """
    frame = ttk.LabelFrame(parent, text=title)
    frame.pack(side="left", padx=5, pady=5, fill="both", expand=True)

    # -------------------- COLUMNS ---------------------
    columns = ("param", "value", "check", "comment")
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=14)
    
    # ------------------ COLUMNS NAME ------------------
    tree.heading("param", text="Paramètre")
    tree.heading("value", text="Valeur")
    tree.heading("check", text="Check")
    tree.heading("comment", text="Commentaire")
    
    # ---------------- WIDTH + ALIGNEMENT --------------
    tree.column("param", width=220, anchor="w", stretch=False)
    tree.column("value", width=200, anchor="w", stretch=False)
    tree.column("check", width=60, anchor="center", stretch=False)
    tree.column("comment", width=900, anchor="w", stretch=True)

    # ---------------- SCROLLBARS ----------------------
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    xscroll = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscroll=scrollbar.set)
    tree.configure(xscroll=xscroll.set)
    scrollbar.pack(side="right", fill="y")
    xscroll.pack(side="bottom", fill="x")
    tree.pack(fill="both", expand=True)
    return tree
