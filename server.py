#!/usr/bin/env python3
"""
server.py — EVIDEX BYPASS API Server
=====================================
Backend FastAPI que expone los 4 módulos del pipeline como endpoints REST.
Sirve también el frontend estático desde /static/.

Uso:
    pip install fastapi uvicorn aiofiles --break-system-packages
    python3 server.py
    → http://localhost:8765

Endpoints principales:
    GET  /api/v1/status           Estado del servidor + ADB + KB
    GET  /api/v1/devices          Dispositivos ADB conectados
    POST /api/v1/scan             Ejecutar Device Scanner
    GET  /api/v1/scan/{id}        Obtener resultado del scan
    POST /api/v1/analyze/{id}     Ejecutar Security Analyzer
    GET  /api/v1/analyze/{id}     Obtener resultado del análisis
    GET  /api/v1/pe/adapters      Listar adaptadores CVE disponibles
    POST /api/v1/pe               Ejecutar PE Engine (dry-run por defecto)
    POST /api/v1/extract          Ejecutar Data Extractor
    GET  /api/v1/sessions         Listar todas las sesiones
    GET  /api/v1/kb/stats         Estadísticas de la Knowledge Base
    GET  /api/v1/kb/search        Buscar chipset o modelo
    GET  /api/v1/license          Verificar licencia Evidex (BYPASS se ancla a ella)
    WS   /ws/progress             WebSocket para progreso en tiempo real
"""

import asyncio
import base64
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
    import uvicorn
except ImportError:
    print("Dependencias faltantes. Instalar con:")
    print("  pip install fastapi uvicorn aiofiles --break-system-packages")
    sys.exit(1)

# ─── Rutas base ───────────────────────────────────────────────────────────────

BASE_DIR     = Path(__file__).parent
KB_DIR       = BASE_DIR / "knowledge_base"
SESSIONS_DIR = BASE_DIR / "sessions"
STATIC_DIR   = BASE_DIR / "static"
SESSIONS_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

MODULES = {
    "scanner":   BASE_DIR / "device_scanner.py",
    "analyzer":  BASE_DIR / "security_analyzer.py",
    "pe_engine": BASE_DIR / "privilege_escalation_engine.py",
    "extractor": BASE_DIR / "data_extractor.py",
}

# ─── Licencia Evidex ──────────────────────────────────────────────────────────

try:
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from cryptography.exceptions import InvalidSignature
    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False

# Clave pública Ed25519 de Evidex (DER, SubjectPublicKeyInfo, base64)
_EVIDEX_PUBKEY_B64 = "MCowBQYDK2VwAyEAWEt0OYnDq0Ab68uMmCUJAqlolNMt1EfTTnhJH5hkWMU="

# EVIDEX BYPASS se ancla a la licencia de Evidex — ruta hermana de bypass/
_EVIDEX_LICENSE_PATH = BASE_DIR.parent / "evidex" / ".evidex-licencia.json"

# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="EVIDEX BYPASS API",
    description="Advanced Mobile Acquisition Platform — Backend API",
    version="1.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket manager para progreso en tiempo real
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws) if hasattr(self.active, 'discard') else None
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self.active:
                self.active.remove(ws)

manager = ConnectionManager()

# ─── Helpers ──────────────────────────────────────────────────────────────────

def ts() -> str:
    return datetime.now(timezone.utc).isoformat()

def session_path(sid: str) -> Path:
    return SESSIONS_DIR / f"{sid}.json"

def save_session(sid: str, data: dict):
    with open(session_path(sid), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def load_session(sid: str) -> dict:
    p = session_path(sid)
    if not p.exists():
        raise HTTPException(404, f"Sesión '{sid}' no encontrada.")
    with open(p, encoding="utf-8") as f:
        return json.load(f)

def adb_cmd(args: list[str], timeout=10) -> tuple[str, str, int]:
    try:
        r = subprocess.run(
            ["adb"] + args,
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except FileNotFoundError:
        return "", "ADB_NOT_FOUND", -1
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -2

async def run_module(module_key: str, args: list[str],
                     broadcast_prefix: str = "") -> tuple[str, str, int]:
    """Ejecuta un módulo Python como subproceso y broadcastea la salida."""
    script = MODULES[module_key]
    cmd = [sys.executable, str(script)] + args

    await manager.broadcast({
        "type": "start",
        "module": module_key,
        "cmd": " ".join(cmd),
        "timestamp": ts(),
    })

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stdout_lines = []
    stderr_lines = []

    async def read_stream(stream, store, label):
        while True:
            line = await stream.readline()
            if not line:
                break
            decoded = line.decode(errors="replace").rstrip()
            store.append(decoded)
            await manager.broadcast({
                "type": "output",
                "stream": label,
                "line": decoded,
                "module": module_key,
                "timestamp": ts(),
            })

    await asyncio.gather(
        read_stream(proc.stdout, stdout_lines, "stdout"),
        read_stream(proc.stderr, stderr_lines, "stderr"),
    )

    rc = await proc.wait()
    await manager.broadcast({
        "type": "done",
        "module": module_key,
        "returncode": rc,
        "timestamp": ts(),
    })

    return "\n".join(stdout_lines), "\n".join(stderr_lines), rc

# ─── Modelos Pydantic ─────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    serial: Optional[str] = None
    sim: Optional[str] = None      # mt6762, exynos7570, etc.
    props_file: Optional[str] = None

class AnalyzeRequest(BaseModel):
    scan_session_id: str

class PERequest(BaseModel):
    security_session_id: str
    dry_run: bool = True
    cve: Optional[str] = None
    serial: Optional[str] = None

class ExtractRequest(BaseModel):
    pe_session_id: str
    serial: Optional[str] = None
    out_dir: Optional[str] = None
    sim: Optional[str] = None

# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return JSONResponse({"message": "EVIDEX BYPASS API v1.0", "docs": "/docs"})

@app.get("/api/v1/status")
async def status():
    """Estado del servidor: ADB disponible, KB cargada, módulos OK."""
    adb_ok = adb_cmd(["version"])[2] == 0
    kb_ok = all((KB_DIR / f).exists() for f in ["chipsets.json", "manufacturers.json", "cves.json"])
    modules_ok = {k: v.exists() for k, v in MODULES.items()}

    # Contar KB
    kb_stats = {}
    if kb_ok:
        try:
            with open(KB_DIR / "manufacturers.json") as f:
                mfr = json.load(f)
            with open(KB_DIR / "chipsets.json") as f:
                chips = json.load(f)
            kb_stats = {
                "chipsets": chips["_meta"]["total_chipsets"],
                "fabricantes": len([k for k in mfr if k != "_meta"]),
                "modelos": sum(len(v["modelos"]) for k,v in mfr.items() if k != "_meta"),
                "version_chipsets": chips["_meta"]["version"],
                "version_fabricantes": mfr["_meta"]["version"],
            }
        except Exception as e:
            kb_stats = {"error": str(e)}

    return {
        "status": "ok",
        "timestamp": ts(),
        "adb": {"available": adb_ok},
        "kb": {"available": kb_ok, **kb_stats},
        "modules": modules_ok,
        "sessions_dir": str(SESSIONS_DIR),
    }

@app.get("/api/v1/devices")
async def devices():
    """Lista dispositivos Android conectados por ADB."""
    stdout, stderr, rc = adb_cmd(["devices", "-l"])
    if rc != 0:
        return {"error": "ADB no disponible", "devices": []}

    devs = []
    for line in stdout.splitlines()[1:]:
        if not line.strip() or "List of" in line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            serial = parts[0]
            estado = parts[1]
            # Intentar leer modelo
            model_out, _, _ = adb_cmd(["-s", serial, "shell",
                                        "getprop ro.product.model"], timeout=5)
            mfr_out, _, _ = adb_cmd(["-s", serial, "shell",
                                      "getprop ro.product.manufacturer"], timeout=5)
            devs.append({
                "serial": serial,
                "estado": estado,
                "model": model_out or "?",
                "manufacturer": mfr_out or "?",
            })

    return {"devices": devs, "count": len(devs), "timestamp": ts()}

@app.post("/api/v1/scan")
async def scan(req: ScanRequest):
    """
    Ejecuta el Device Scanner.
    - sim=<key>  → modo simulación (mt6762, msm8937, etc.)
    - serial=<s> → dispositivo ADB real
    - props_file → archivo de getprop en disco
    """
    args = ["--json", "--no-save"]

    if req.sim:
        args += ["--sim", req.sim]
    elif req.serial:
        args += ["--serial", req.serial]
    elif req.props_file:
        args += ["--props", req.props_file]
    else:
        raise HTTPException(400, "Requerido: sim, serial o props_file.")

    stdout, stderr, rc = await run_module("scanner", args)

    if rc != 0:
        raise HTTPException(500, f"Device Scanner falló (rc={rc}): {stderr[:300]}")

    try:
        result = json.loads(stdout)
    except json.JSONDecodeError:
        raise HTTPException(500, f"Salida no parseable: {stdout[:200]}")

    sid = str(uuid.uuid4())[:8].upper()
    result["_api_session_id"] = sid
    result["_api_timestamp"] = ts()
    result["_api_type"] = "scan"
    save_session(f"scan_{sid}", result)

    return {"session_id": sid, "data": result}

@app.get("/api/v1/scan/{session_id}")
async def get_scan(session_id: str):
    return load_session(f"scan_{session_id}")

@app.post("/api/v1/analyze/{scan_session_id}")
async def analyze(scan_session_id: str):
    """Ejecuta Security Analyzer sobre una sesión de scan existente."""
    scan_data = load_session(f"scan_{scan_session_id}")

    # Escribir la sesión de scan a un archivo temporal para pasarla al analizador
    tmp_path = SESSIONS_DIR / f"scan_{scan_session_id}.json"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, ensure_ascii=False)

    # Si fue una simulación, usar el mismo modo sim
    sim_key = scan_data.get("sim_key")
    args = ["--json"]
    if sim_key:
        args += ["--sim", sim_key]
    else:
        args += [str(tmp_path)]

    stdout, stderr, rc = await run_module("analyzer", args)

    if rc != 0:
        raise HTTPException(500, f"Security Analyzer falló (rc={rc}): {stderr[:300]}")

    try:
        result = json.loads(stdout)
    except json.JSONDecodeError:
        raise HTTPException(500, f"Salida no parseable: {stdout[:200]}")

    sid = str(uuid.uuid4())[:8].upper()
    result["_api_session_id"] = sid
    result["_api_scan_session_id"] = scan_session_id
    result["_api_timestamp"] = ts()
    result["_api_type"] = "analysis"
    save_session(f"analysis_{sid}", result)

    return {"session_id": sid, "data": result}

@app.get("/api/v1/analyze/{session_id}")
async def get_analysis(session_id: str):
    return load_session(f"analysis_{session_id}")

@app.get("/api/v1/pe/adapters")
async def pe_adapters():
    """Lista los adaptadores CVE disponibles en el PE Engine."""
    stdout, _, rc = await run_module("pe_engine", ["--listar-adaptadores", "--json"])
    if rc != 0:
        return {"adapters": [], "error": "PE Engine no disponible"}
    try:
        return json.loads(stdout)
    except Exception:
        return {"raw": stdout}

@app.post("/api/v1/pe")
async def pe_run(req: PERequest):
    """
    Ejecuta el Privilege Escalation Engine.
    Por defecto en dry-run (no ejecuta exploit, solo planifica).
    """
    analysis = load_session(f"analysis_{req.security_session_id}")

    # Escribir a tmp
    tmp_path = SESSIONS_DIR / f"analysis_{req.security_session_id}.json"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(analysis, f, ensure_ascii=False)

    sim_key = analysis.get("sim_key")
    args = ["--json"]

    if sim_key:
        args += ["--sim", sim_key]
    else:
        args += [str(tmp_path)]

    if req.dry_run:
        args.append("--dry-run")
    if req.cve:
        args += ["--cve", req.cve]
    if req.serial:
        args += ["--serial", req.serial]

    stdout, stderr, rc = await run_module("pe_engine", args)

    if rc != 0:
        raise HTTPException(500, f"PE Engine falló (rc={rc}): {stderr[:300]}")

    try:
        result = json.loads(stdout)
    except json.JSONDecodeError:
        raise HTTPException(500, f"Salida no parseable: {stdout[:200]}")

    sid = str(uuid.uuid4())[:8].upper()
    result["_api_session_id"] = sid
    result["_api_analysis_session_id"] = req.security_session_id
    result["_api_timestamp"] = ts()
    result["_api_type"] = "pe"
    result["_api_dry_run"] = req.dry_run
    save_session(f"pe_{sid}", result)

    return {"session_id": sid, "data": result}

@app.get("/api/v1/pe/{session_id}")
async def get_pe(session_id: str):
    return load_session(f"pe_{session_id}")

@app.post("/api/v1/extract")
async def extract(req: ExtractRequest):
    """Ejecuta el Data Extractor."""
    pe_data = load_session(f"pe_{req.pe_session_id}")

    tmp_path = SESSIONS_DIR / f"pe_{req.pe_session_id}.json"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(pe_data, f, ensure_ascii=False)

    sim_key = pe_data.get("sim_key") or req.sim
    args = ["--json"]

    if sim_key:
        args += ["--sim", sim_key]
    else:
        args += [str(tmp_path)]

    if req.out_dir:
        args += ["--out", req.out_dir]
    if req.serial:
        args += ["--serial", req.serial]

    stdout, stderr, rc = await run_module("extractor", args)

    if rc != 0:
        raise HTTPException(500, f"Data Extractor falló (rc={rc}): {stderr[:300]}")

    try:
        result = json.loads(stdout)
    except json.JSONDecodeError:
        raise HTTPException(500, f"Salida no parseable: {stdout[:200]}")

    sid = str(uuid.uuid4())[:8].upper()
    result["_api_session_id"] = sid
    result["_api_pe_session_id"] = req.pe_session_id
    result["_api_timestamp"] = ts()
    result["_api_type"] = "extraction"
    save_session(f"extract_{sid}", result)

    return {"session_id": sid, "data": result}

@app.get("/api/v1/sessions")
async def list_sessions(type: Optional[str] = Query(None)):
    """Lista todas las sesiones guardadas, opcionalmente filtrando por tipo."""
    sessions = []
    for f in sorted(SESSIONS_DIR.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            with open(f, encoding="utf-8") as fp:
                data = json.load(fp)
            sessions.append({
                "file": f.name,
                "type": data.get("_api_type", "unknown"),
                "session_id": data.get("_api_session_id", ""),
                "timestamp": data.get("_api_timestamp", ""),
                "device": f"{data.get('manufacturer','')} {data.get('model','')}".strip(),
            })
        except Exception:
            continue
    if type:
        sessions = [s for s in sessions if s["type"] == type]
    return {"sessions": sessions, "count": len(sessions)}

@app.get("/api/v1/kb/stats")
async def kb_stats():
    """Estadísticas completas de la Knowledge Base."""
    try:
        with open(KB_DIR / "manufacturers.json", encoding="utf-8") as f:
            mfr = json.load(f)
        with open(KB_DIR / "chipsets.json", encoding="utf-8") as f:
            chips = json.load(f)
        with open(KB_DIR / "cves.json", encoding="utf-8") as f:
            cves_data = json.load(f)
    except Exception as e:
        raise HTTPException(500, str(e))

    ceilings = {}
    for fab in [k for k in mfr if k != "_meta"]:
        for m in mfr[fab]["modelos"]:
            c = m["acquisition_ceiling"]
            ceilings[c] = ceilings.get(c, 0) + 1

    familias = {}
    for familia in ("mediatek","qualcomm","exynos","kirin","google_tensor","unisoc"):
        if familia in chips:
            familias[familia] = len(chips[familia])

    return {
        "chipsets": {
            "total": chips["_meta"]["total_chipsets"],
            "version": chips["_meta"]["version"],
            "por_familia": familias,
        },
        "fabricantes": {
            "total": len([k for k in mfr if k != "_meta"]),
            "version": mfr["_meta"]["version"],
        },
        "modelos": {
            "total": sum(len(v["modelos"]) for k,v in mfr.items() if k != "_meta"),
            "por_ceiling": ceilings,
        },
        "cves": {
            "total": len(cves_data.get("cves", [])),
        }
    }

@app.get("/api/v1/kb/search")
async def kb_search(
    q: str = Query(..., description="Nombre de chipset, modelo o ro.board.platform"),
    tipo: str = Query("auto", description="chipset | modelo | platform | auto")
):
    """Busca en la KB por nombre de chipset, modelo o ro.board.platform."""
    q_lower = q.lower()
    results = {"chipsets": [], "modelos": []}

    # Buscar chipsets
    with open(KB_DIR / "chipsets.json", encoding="utf-8") as f:
        chips = json.load(f)
    if tipo in ("chipset","auto"):
        for familia in ("mediatek","qualcomm","exynos","kirin","google_tensor","unisoc"):
            for chip in chips.get(familia, []):
                name = chip.get("chipset","").lower()
                mkt  = chip.get("marketing","").lower()
                if q_lower in name or q_lower in mkt:
                    results["chipsets"].append({
                        "familia": familia,
                        "chipset": chip.get("chipset"),
                        "marketing": chip.get("marketing"),
                        "acquisition_ceiling": chip.get("acquisition_ceiling"),
                        "herramienta": chip.get("herramienta",""),
                        "cifrado_tipico": chip.get("cifrado_tipico",""),
                    })

    # Buscar modelos
    with open(KB_DIR / "manufacturers.json", encoding="utf-8") as f:
        mfr = json.load(f)
    if tipo in ("modelo","platform","auto"):
        for fab_key, fab in mfr.items():
            if fab_key == "_meta":
                continue
            for m in fab["modelos"]:
                modelo = m.get("modelo","").lower()
                platform = m.get("ro_board_platform","").lower()
                ro_model = m.get("ro_model","").lower()
                if q_lower in modelo or q_lower in platform or q_lower in ro_model:
                    results["modelos"].append({
                        "fabricante": fab.get("nombre_comercial"),
                        "modelo": m.get("modelo"),
                        "chipset": m.get("chipset"),
                        "ro_board_platform": m.get("ro_board_platform"),
                        "ro_model": m.get("ro_model"),
                        "acquisition_ceiling": m.get("acquisition_ceiling"),
                        "android_stock": m.get("android_stock"),
                        "android_max": m.get("android_max"),
                        "notas": m.get("notas",""),
                    })

    total = len(results["chipsets"]) + len(results["modelos"])
    return {"query": q, "total": total, **results}

@app.get("/api/v1/license")
async def get_license():
    """
    Lee y verifica la licencia de Evidex.
    EVIDEX BYPASS no tiene licencia propia — queda autorizado por cualquier
    licencia Evidex vigente y con firma válida.

    Respuesta:
      status        → "valid" | "expired" | "invalid" | "no_license" | "error"
      autorizado    → true si la firma es correcta Y la licencia no venció
      firma_ok      → la firma Ed25519 coincide con el payload
      vigente       → la fecha de vencimiento todavía no pasó
      codigo        → código de licencia (ej. EVDX-K44X-…)
      titular       → nombre del titular
      modulos       → lista de módulos habilitados en Evidex
      emitido / vence / huella → metadatos del payload
    """
    if not _CRYPTO_OK:
        return JSONResponse(status_code=503, content={
            "status": "error",
            "detail": "Dependencia faltante: ejecutar  pip install cryptography --break-system-packages"
        })

    if not _EVIDEX_LICENSE_PATH.exists():
        return JSONResponse(status_code=404, content={
            "status": "no_license",
            "detail": f"Archivo de licencia no encontrado en {_EVIDEX_LICENSE_PATH}"
        })

    try:
        with open(_EVIDEX_LICENSE_PATH, encoding="utf-8") as f:
            lic = json.load(f)

        payload  = lic["manifiesto"]["payload"]
        firma_b64 = lic["manifiesto"]["firma"]

        # ── Verificar firma Ed25519 ──────────────────────────────────────────
        # El servidor firmó con canonico(payload): claves ordenadas recursivamente.
        # Equivale a json.dumps(..., sort_keys=True, separators=(",",":")).
        pub_der      = base64.b64decode(_EVIDEX_PUBKEY_B64)
        public_key   = load_der_public_key(pub_der)
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode("utf-8")
        firma_bytes  = base64.b64decode(firma_b64)

        try:
            public_key.verify(firma_bytes, payload_bytes)
            firma_ok = True
        except InvalidSignature:
            firma_ok = False

        # ── Verificar vencimiento ────────────────────────────────────────────
        ahora    = datetime.now(timezone.utc)
        vence_dt = datetime.fromisoformat(payload["vence"].replace("Z", "+00:00"))
        vigente  = vence_dt > ahora

        status = "valid" if (firma_ok and vigente) else \
                 ("expired" if firma_ok else "invalid")

        return {
            "status":      status,
            "autorizado":  firma_ok and vigente,
            "firma_ok":    firma_ok,
            "vigente":     vigente,
            "codigo":      lic.get("codigo"),
            "titular":     payload.get("titular"),
            "modulos":     payload.get("modulos", []),
            "emitido":     payload.get("emitido"),
            "vence":       payload.get("vence"),
            "huella":      payload.get("huella"),
            "timestamp":   ts(),
        }

    except (KeyError, ValueError) as e:
        return JSONResponse(status_code=422, content={
            "status": "error",
            "detail": f"Formato de licencia inválido: {e}"
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={
            "status": "error",
            "detail": str(e)
        })

# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/progress")
async def ws_progress(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        await websocket.send_json({"type": "connected", "timestamp": ts()})
        while True:
            data = await websocket.receive_text()
            # Ping/pong
            if data == "ping":
                await websocket.send_json({"type": "pong", "timestamp": ts()})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ─── Montar static ────────────────────────────────────────────────────────────

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  EVIDEX BYPASS — API Server v1.0")
    print(f"  Base: {BASE_DIR}")
    print(f"  Sesiones: {SESSIONS_DIR}")
    print(f"  KB: {KB_DIR}")
    print("=" * 60)
    print("  → http://localhost:8765")
    print("  → http://localhost:8765/docs  (Swagger UI)")
    print("=" * 60)
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8765,
        reload=True,
        reload_dirs=[str(BASE_DIR)],
        log_level="info",
    )
