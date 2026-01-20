# spcpro_dev

MVP para administrar proyectos por cliente y comparar consumo anual vs presupuesto de **Soporte** y **Mejora Continua**.

## Requisitos
- Python 3.11+ recomendado

## Ejecutar
```bash
pip install -r requirements.txt
SPCPRO_DEFAULT_ADMIN_EMAIL=rodrigo.mocca@spcpro.com \
SPCPRO_DEFAULT_ADMIN_PASSWORD='SpCpRo2026!' \
uvicorn app.main:app --reload
```

Abrir: http://127.0.0.1:8000

## PWA (modo instalable)
La app incluye manifest + service worker.

Checklist para verificar:
- En el navegador, abrir DevTools → Application:
	- Manifest: debe cargar desde `/static/manifest.json`
	- Service Workers: debe aparecer `sw.js` con scope `/`
- Para probar “instalar”, usar HTTPS o `http://127.0.0.1:8000`/`http://localhost:8000` (los navegadores solo habilitan PWA en contextos seguros).

Archivos clave:
- `app/static/manifest.json`
- `app/static/sw.js` (servido en `/sw.js`)
- `app/templates/base.html` (registro del service worker)

## Compilar imagen Docker para Raspberry Pi
```bash
docker buildx build --platform linux/arm64 -t k8sregistry.moccraft.com/spcpro_projects:latest --push -f k8s/Dockerfile .
```

## Credenciales iniciales
- En desarrollo (F5), se setean en [.vscode/launch.json](.vscode/launch.json) para que se cree automáticamente el usuario admin si no existe.
- En Kubernetes, se definen en [k8s/secret.yaml](k8s/secret.yaml) y se inyectan al Deployment.

Nota: el usuario “por defecto” solo se crea si existen las variables `SPCPRO_DEFAULT_ADMIN_EMAIL` y `SPCPRO_DEFAULT_ADMIN_PASSWORD`.

## Datos
- Base SQLite local en `data/app.db`
- Se crean las tablas automáticamente al iniciar

### Nota de migración
Si ya habías corrido una versión previa, el esquema de `Project` cambió para soportar costos partidas (Soporte/Mejora/Extra).
La app intenta migrar automáticamente columnas nuevas y copiar datos desde el esquema viejo.
