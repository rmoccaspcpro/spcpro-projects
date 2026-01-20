# Kubernetes Deployment

Este directorio contiene los manifiestos de Kubernetes para desplegar la aplicación spcpro-projects.

## ⚠️ IMPORTANTE: Configuración de Secrets

El archivo `secret.yaml` es una **plantilla** y **NO** contiene valores reales de contraseñas.

### Antes de desplegar

**NUNCA** apliques `secret.yaml` directamente sin configurar los valores reales.

### Opciones para configurar los secrets

#### Opción 1: kubectl create (Recomendado para desarrollo)

```bash
kubectl create secret generic spcpro-projects-secrets \
  --from-literal=SPCPRO_DEFAULT_ADMIN_EMAIL=tu-email@ejemplo.com \
  --from-literal=SPCPRO_DEFAULT_ADMIN_PASSWORD='TuContraseñaSegura!' \
  --namespace=spcpro
```

#### Opción 2: Archivo local (NO versionado)

1. Crea un archivo `secret.local.yaml` (ya está en `.gitignore`):
   ```bash
   cp secret.yaml secret.local.yaml
   ```

2. Edita `secret.local.yaml` y reemplaza los valores de ejemplo:
   ```yaml
   stringData:
     SPCPRO_DEFAULT_ADMIN_EMAIL: "tu-email-real@ejemplo.com"
     SPCPRO_DEFAULT_ADMIN_PASSWORD: "TuContraseñaRealYSegura123!"
   ```

3. Aplica el secret:
   ```bash
   kubectl apply -f k8s/secret.local.yaml
   ```

#### Opción 3: Herramientas de gestión de secrets (RECOMENDADO para producción)

- **Sealed Secrets**: Encripta secrets para versionarlos en git de forma segura
  - https://github.com/bitnami-labs/sealed-secrets

- **External Secrets Operator**: Integra con gestores de secrets externos
  - https://external-secrets.io/

- **HashiCorp Vault**: Gestión centralizada de secrets
  - https://www.vaultproject.io/

## Orden de aplicación

Para desplegar la aplicación en Kubernetes:

```bash
# 1. Crear el namespace
kubectl apply -f namespace.yaml

# 2. Configurar los secrets (ver opciones arriba)
kubectl create secret generic spcpro-projects-secrets ...

# 3. Crear el almacenamiento persistente
kubectl apply -f pv.yaml
kubectl apply -f pvc.yaml

# 4. Desplegar la aplicación
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# 5. Configurar el ingress (opcional, para acceso externo)
kubectl apply -f ingress.yaml
```

## Verificación

```bash
# Verificar que todos los recursos se crearon correctamente
kubectl get all -n spcpro

# Verificar que el secret se creó
kubectl get secret spcpro-projects-secrets -n spcpro

# Ver los logs de la aplicación
kubectl logs -n spcpro deployment/spcpro-projects-deployment

# Acceder a la aplicación localmente
kubectl port-forward -n spcpro service/spcpro-projects-service 8000:80
# Luego abrir: http://localhost:8000
```

## Notas de seguridad

- ✅ Los archivos `.yaml` de este directorio (excepto `secret.yaml`) pueden versionarse en git
- ✅ El archivo `secret.yaml` es una plantilla y NO contiene credenciales reales
- ❌ **NUNCA** versionar archivos `*.local.yaml` que contengan credenciales reales
- ❌ **NUNCA** incluir contraseñas en texto plano en archivos versionados
- 🔐 Usar herramientas de gestión de secrets para entornos de producción
