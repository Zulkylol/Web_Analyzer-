"""Point d'entree minimal de l'application desktop."""

from app.controller import WebAnalyzerApp


# ===============================================================
# FUNCTION : main
# ===============================================================
def main() -> None:
    """Construit l'application et lance la boucle UI."""
    app = WebAnalyzerApp()
    app.run()


if __name__ == "__main__":
    main()
