# Instrucciones para Copilot (SPC Pro)

## Entorno de ejecución
- Este proyecto se ejecuta SIEMPRE dentro de un **Dev Container**.
- **No** sugerir, crear ni usar entornos virtuales (`venv`, `virtualenv`, `pipenv`, `poetry env`, etc.).
- **No** proponer pasos tipo `python -m venv ...` ni activación de entornos.

## Dependencias
- Instalar dependencias directamente en el entorno del devcontainer cuando haga falta.
- Preferir `pip install -r requirements.txt` (o actualizar `requirements.txt` si corresponde).

## Ejecución
- Para correr en desarrollo, usar `uvicorn app.main:app --reload` (según configuración de VS Code/launch).
