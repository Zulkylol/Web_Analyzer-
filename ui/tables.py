# ui/tables.py

# ===============================================================
# IMPORTS
# ===============================================================
import ttkbootstrap as ttk

# ===============================================================
# FUNCTION : clear_table
# ===============================================================
def clear_table(table):
    """
    Clear all rows from a single result table.
    """
    table.delete(*table.get_children())

# ===============================================================
# FUNCTION : clear_tables
# ===============================================================
def clear_tables(http_table,ssl_table,cookies_table):
    """
    Clear all rows from the HTTP, TLS, and Cookies tables.
    """
    clear_table(http_table)
    clear_table(ssl_table)
    clear_table(cookies_table)

# ===============================================================
# FUNCTION : create_result_table
# ===============================================================
def create_result_table(parent, title):
    """
    Create and return the standard result table used by every tab.
    """
    frame = ttk.LabelFrame(parent, text=title, font=("Helvetica", 11, "bold"))
    frame.pack(side="left", padx=5, pady=5, fill="both", expand=True)

    # -------------------- COLUMNS ---------------------
    columns = ("param", "value", "check", "risk", "comment")
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=14)
    
    # ------------------ COLUMNS NAME ------------------
    tree.heading("param", text="Paramètre")
    tree.heading("value", text="Valeur")
    tree.heading("check", text="État")
    tree.heading("risk", text="Risque")
    tree.heading("comment", text="Commentaire")
    
    # The comment column takes the remaining space while the others stay fixed.
    tree.column("param", width=220, anchor="w", stretch=False)
    tree.column("value", width=200, anchor="w", stretch=False)
    tree.column("check", width=190, anchor="center", stretch=False)
    tree.column("risk", width=90, anchor="center", stretch=False)
    tree.column("comment", width=820, anchor="w", stretch=True)

    # ---------------- SCROLLBARS ----------------------
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    xscroll = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscroll=scrollbar.set)
    tree.configure(xscroll=xscroll.set)
    scrollbar.pack(side="right", fill="y")
    xscroll.pack(side="bottom", fill="x")
    tree.pack(fill="both", expand=True)
    return tree
