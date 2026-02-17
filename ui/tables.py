import ttkbootstrap as ttk

def clear_tables(http_table,ssl_table,cookies_table):
    for item in http_table.get_children():
        http_table.delete(item)
    for item in ssl_table.get_children():
        ssl_table.delete(item)
    for item in cookies_table.get_children():
        cookies_table.delete(item)

def create_result_table(parent, title):
    """Crée un tableau avec 3 colonnes et un titre."""
    frame = ttk.LabelFrame(parent, text=title)
    frame.pack(side="left", padx=5, pady=5, fill="both", expand=True)

    # Columns
    columns = ("param", "value", "check", "comment")
    tree = ttk.Treeview(frame, columns=columns, show="headings", height=10)
    
    # Columns name
    tree.heading("param", text="Paramètre")
    tree.heading("value", text="Valeur")
    tree.heading("check", text="Check")
    tree.heading("comment", text="Commentaire")
    
    # width and alignment
    tree.column("param", width=180, anchor="w", stretch=False)
    tree.column("value", width=150, anchor="center", stretch=False)
    tree.column("check", width=30, anchor="center", stretch=False)
    tree.column("comment", width=200, anchor="w", stretch=True)

    # Vertical scrollbar 
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    tree.pack(fill="both", expand=True)
    return tree