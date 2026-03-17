# main.py

# ===============================================================
# IMPORTS
# ===============================================================

from app.controller import WebAnalyzerApp

# ===============================================================
# FUNCTION : main
# ===============================================================
def main() -> None:
    """
    Build the application and start the UI loop.

    Returns :
        None : no return value
    """
    app = WebAnalyzerApp()
    app.run()


if __name__ == "__main__":
    main()
