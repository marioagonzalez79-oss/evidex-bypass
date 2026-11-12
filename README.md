# EVIDEX BYPASS
### Advanced Mobile Acquisition Platform

Extensión de adquisición forense avanzada para dispositivos Android.  
Se especializa en diagnóstico, adquisición física (chipsets MediaTek y Qualcomm legacy), análisis de particiones y evaluación de cifrado.

> **Requiere una licencia válida de [EVIDEX](https://www.e-videx.com.ar).**  
> EVIDEX BYPASS no tiene licencia propia — queda autorizado por cualquier licencia Evidex vigente.

---

## Requisitos

| Componente | Versión mínima |
|---|---|
| Python | 3.10 |
| ADB (Android Debug Bridge) | cualquiera reciente |
| EVIDEX | instalado en la carpeta hermana (`../evidex/`) |

**ADB** debe estar en el PATH del sistema.  
Descargá las [Platform Tools de Android](https://developer.android.com/studio/releases/platform-tools) y agregá la carpeta al PATH.

---

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/e-videx/evidex-bypass.git
cd evidex-bypass
```

### 2. Verificar la estructura de carpetas

EVIDEX BYPASS busca la licencia de Evidex en la carpeta hermana:

```
C:\Users\<usuario>\
├── evidex\                  ← instalación de EVIDEX
│   └── .evidex-licencia.json
└── evidex-bypass\           ← este repositorio
    └── server.py
```

Asegurate de que ambas carpetas queden al mismo nivel.

### 3. Instalar dependencias

```bash
pip install -r requirements.txt --break-system-packages
```

### 4. Iniciar el servidor

```bash
python server.py
```

El servidor queda disponible en `http://localhost:8765`.  
La documentación interactiva (Swagger) en `http://localhost:8765/docs`.

---

## Verificar la licencia

```
GET http://localhost:8765/api/v1/license
```

Respuesta esperada con licencia válida:

```json
{
  "status": "valid",
  "autorizado": true,
  "firma_ok": true,
  "vigente": true,
  "titular": "...",
  "modulos": ["extraccion", "apertura", "..."],
  "vence": "2027-..."
}
```

Si `autorizado` es `false`, verificá que:
- Evidex esté instalado en `../evidex/` relativo a esta carpeta
- El archivo `.evidex-licencia.json` exista dentro de esa carpeta
- La licencia no esté vencida

---

## Endpoints principales

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/v1/status` | Estado del servidor, ADB y Knowledge Base |
| GET | `/api/v1/devices` | Dispositivos Android conectados por ADB |
| POST | `/api/v1/scan` | Ejecutar Device Scanner |
| POST | `/api/v1/analyze/{id}` | Ejecutar Security Analyzer |
| POST | `/api/v1/pe` | Privilege Escalation Engine (dry-run por defecto) |
| POST | `/api/v1/extract` | Data Extractor |
| GET | `/api/v1/license` | Verificar licencia Evidex |
| WS | `/ws/progress` | Progreso en tiempo real (WebSocket) |

---

## Contacto

**EVIDEX** — Estudio Pericial en Informática Forense y Ciberseguridad  
🌐 [www.e-videx.com.ar](https://www.e-videx.com.ar)  
✉️ admin@e-videx.com.ar
