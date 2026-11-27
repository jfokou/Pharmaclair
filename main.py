"""Point d'entrée standard pour les plateformes cloud (Nixpacks, Heroku, Railway, Render)."""
import runpy

if __name__ == "__main__":
    runpy.run_module("pharmaclair", run_name="__main__")
