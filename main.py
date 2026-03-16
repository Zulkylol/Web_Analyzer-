# main.py

# ===============================================================
# IMPORTS
# ===============================================================

from app.controller import WebAnalyzerApp

# ===============================================================
# FUNCTION : main
# ===============================================================
def main() -> None:
    """Builds the application and starts the UI loop"""
    app = WebAnalyzerApp()
    app.run()


if __name__ == "__main__":
    main()
