#!/usr/bin/env python3
"""
data_extractor.py — Data Extractor de EVIDEX BYPASS
====================================================
Modulo 4 del Acquisition Engine. Recibe el comando de extraccion del
PE Engine y ejecuta la copia de /data/data/ desde el dispositivo AFU,
calculando hashes SHA-256 de cada archivo para cadena de custodia.

Dos rutas de entrada:
  A) Via PE Engine (escalada N-day): shell elevada disponible
  B) Via BROM/EDL: imagen fisica ya obtenida en disco

Salida:
  - Directorio estructurado con los datos extraidos
  - evidence_manifest.json con hashes, timestamps y metadatos
  - Listo para transferir a EVIDEX por la API REST

Uso:
  python3 data_extractor.py pe_XXXXXXXX.json
  python3 data_extractor.py --sim mt6762            (simula extraccion)
  python3 data_extractor.py --imagen userdata.bin   (desde imagen BROM/EDL)
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

# ─── Apps objetivo ────────────────────────────────────────────────────────────

APPS_OBJETIVO = [
    {
        "id":       "whatsapp",
        "paquete":  "com.whatsapp",
        "nombre":   "WhatsApp",
        "prioridad": 1,
        "rutas": [
            "databases/msgstore.db",
            "databases/wa.db",
            "databases/msgstore.db-wal",
            "databases/msgstore.db-shm",
            "files/key",
        ]
    },
    {
        "id":       "whatsapp_business",
        "paquete":  "com.whatsapp.w4b",
        "nombre":   "WhatsApp Business",
        "prioridad": 1,
        "rutas": [
            "databases/msgstore.db",
            "databases/wa.db",
            "files/key",
        ]
    },
    {
        "id":       "sms_mms",
        "paquete":  "com.android.providers.telephony",
        "nombre":   "SMS / MMS",
        "prioridad": 1,
        "rutas": [
            "databases/mmssms.db",
            "databases/telephony.db",
        ]
    },
    {
        "id":       "contactos",
        "paquete":  "com.android.providers.contacts",
        "nombre":   "Contactos",
        "prioridad": 1,
        "rutas": [
            "databases/contacts2.db",
            "databases/calllog.db",
        ]
    },
    {
        "id":       "telegram",
        "paquete":  "org.telegram.messenger",
        "nombre":   "Telegram",
        "prioridad": 2,
        "rutas": [
            "files/cache4.db",
            "files/account0/cache4.db",
        ]
    },
    {
        "id":       "instagram",
        "paquete":  "com.instagram.android",
        "nombre":   "Instagram",
        "prioridad": 2,
        "rutas": [
            "databases/direct.db",
            "databases/threads_db2.db",
        ]
    },
    {
        "id":       "messenger",
        "paquete":  "com.facebook.orca",
        "nombre":   "Messenger",
        "prioridad": 2,
        "rutas": [
            "databases/threads_db2.db",
            "databases/prefs_db",
        ]
    },
    {
        "id":       "chrome",
        "paquete":  "com.android.chrome",
        "nombre":   "Chrome",
        "prioridad": 2,
        "rutas": [
            "app_chrome/Default/History",
            "app_chrome/Default/Web Data",
            "app_chrome/Default/Cookies",
        ]
    },
    {
        "id":       "gmail",
        "paquete":  "com.google.android.gm",
        "nombre":   "Gmail",
        "prioridad": 3,
        "rutas": [
            "databases/EmailProvider.db",
            "databases/mailstore.db",
        ]
    },
    {
        "id":       "calendar",
        "paquete":  "com.android.providers.calendar",
        "nombre":   "Calendario",
        "prioridad": 3,
        "rutas": [
            "databases/calendar.db",
        ]
    },
    {
        "id":       "settings",
        "paquete":  "com.android.providers.settings",
        "nombre":   "Ajustes del sistema",
        "prioridad": 3,
        "rutas": [
            "databases/settings.db",
        ]
    },
]


# ─── ADB helpers ──────────────────────────────────────────────────────────────

def adb(cmd, serial=None, timeout=30):
    base = ["adb"] + (["-s", serial] if serial else [])
    try:
        r = subprocess.run(base + cmd, capture_output=True,
                           text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", "ADB_NOT_FOUND", -2


def sha256_de_archivo(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for bloque in iter(lambda: f.read(65536), b""):
            h.update(bloque)
    return h.hexdigest()


def sha256_de_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ─── Verificacion de acceso elevado ──────────────────────────────────────────

def verificar_acceso(serial=None):
    """
    Determina si tenemos acceso elevado al sistema de archivos.
    Devuelve (nivel, metodo_pull).
    """
    # Intentar leer un archivo de /data/data directamente
    stdout, _, rc = adb(
        ["shell", "ls /data/data/com.android.providers.contacts/databases/"],
        serial
    )
    if rc == 0 and "contacts" in stdout.lower():
        return "DIRECTO", "adb_pull"

    # Intentar via run-as (apps debuggables solamente)
    stdout, _, rc = adb(
        ["shell", "run-as com.whatsapp ls databases/"],
        serial
    )
    if rc == 0 and "msgstore" in stdout:
        return "RUN_AS", "run_as"

    # Intentar via su (root disponible)
    stdout, _, rc = adb(
        ["shell", "su -c 'ls /data/data/com.android.providers.contacts/databases/'"],
        serial
    )
    if rc == 0 and "contacts" in stdout.lower():
        return "ROOT_SU", "adb_pull_su"

    return "SIN_ACCESO", None


# ─── Extraccion de un archivo ────────────────────────────────────────────────

def extraer_archivo(remote_path: str, destino: Path,
                    nivel: str, serial=None) -> dict:
    """
    Extrae un archivo del dispositivo al directorio destino.
    Devuelve un dict con el resultado para el manifiesto.
    """
    destino.parent.mkdir(parents=True, exist_ok=True)
    nombre = Path(remote_path).name
    local  = destino / nombre

    resultado = {
        "ruta_remota": remote_path,
        "ruta_local":  str(local),
        "estado":      "PENDIENTE",
        "sha256":      "",
        "tamano_bytes": 0,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }

    if nivel in ("DIRECTO", "ROOT_SU"):
        if nivel == "ROOT_SU":
            # Copiar primero a /sdcard/ accesible
            tmp = f"/sdcard/evidex_tmp_{nombre}"
            adb(["shell", f"su -c 'cp {remote_path} {tmp}'"], serial, 15)
            stdout, stderr, rc = adb(["pull", tmp, str(local)], serial, 60)
            adb(["shell", f"rm -f {tmp}"], serial)
        else:
            stdout, stderr, rc = adb(
                ["pull", remote_path, str(local)], serial, 60
            )
        if rc == 0 and local.exists():
            resultado["estado"]       = "OK"
            resultado["sha256"]       = sha256_de_archivo(local)
            resultado["tamano_bytes"] = local.stat().st_size
        else:
            resultado["estado"] = "ERROR"
            resultado["error"]  = stderr[:200]

    elif nivel == "RUN_AS":
        paquete = remote_path.split("/data/data/")[1].split("/")[0]
        rel     = "/".join(remote_path.split("/data/data/")[1].split("/")[1:])
        # Copiar a /sdcard/ via run-as
        tmp = f"/sdcard/evidex_tmp_{nombre}"
        adb(["shell", f"run-as {paquete} cp {rel} {tmp}"], serial, 15)
        stdout, stderr, rc = adb(["pull", tmp, str(local)], serial, 60)
        adb(["shell", f"rm -f {tmp}"], serial)
        if rc == 0 and local.exists():
            resultado["estado"]       = "OK"
            resultado["sha256"]       = sha256_de_archivo(local)
            resultado["tamano_bytes"] = local.stat().st_size
        else:
            resultado["estado"] = "ERROR"
            resultado["error"]  = stderr[:200]

    return resultado


# ─── Extraccion completa via ADB ─────────────────────────────────────────────

def extraer_via_adb(session: dict, pe_session: dict,
                    out_dir: Path, serial=None) -> dict:
    """
    Extrae todas las apps objetivo via ADB con el nivel de acceso disponible.
    """
    nivel, _ = verificar_acceso(serial)
    if nivel == "SIN_ACCESO":
        return {
            "estado": "ERROR",
            "mensaje": (
                "Sin acceso elevado al sistema de archivos. "
                "Verificar que el PE Engine logro la escalada de privilegios "
                "y que el dispositivo sigue en estado AFU."
            )
        }

    print(f"  Nivel de acceso: {nivel}")
    archivos = []
    apps_ok  = []
    apps_err = []

    for app in APPS_OBJETIVO:
        paquete   = app["paquete"]
        app_dir   = out_dir / paquete
        ok_count  = 0

        # Verificar si la app existe en el dispositivo
        stdout, _, rc = adb(
            ["shell", f"ls /data/data/{paquete}/"], serial, 10
        )
        if rc != 0:
            continue    # app no instalada, saltar silenciosamente

        print(f"  [{app['nombre']}] extrayendo...")

        for ruta_rel in app["rutas"]:
            remote = f"/data/data/{paquete}/{ruta_rel}"
            destino = app_dir / Path(ruta_rel).parent
            res = extraer_archivo(remote, destino, nivel, serial)
            archivos.append(res)
            if res["estado"] == "OK":
                ok_count += 1
                print(f"    ✓ {ruta_rel} ({res['tamano_bytes']:,} bytes)")
            else:
                print(f"    - {ruta_rel} (no disponible)")

        if ok_count > 0:
            apps_ok.append(app["nombre"])
        else:
            apps_err.append(app["nombre"])

    # Extraer tambien multimedia de WhatsApp si esta disponible
    _extraer_media_whatsapp(out_dir, serial)

    return {
        "estado":    "OK",
        "nivel":     nivel,
        "archivos":  archivos,
        "apps_ok":   apps_ok,
        "apps_error": apps_err,
    }


def _extraer_media_whatsapp(out_dir: Path, serial=None):
    """Extrae la carpeta de media de WhatsApp desde /sdcard/ (acceso libre)."""
    wa_media = "/sdcard/Android/media/com.whatsapp/WhatsApp"
    stdout, _, rc = adb(["shell", f"ls {wa_media}"], serial, 10)
    if rc != 0:
        return

    destino = out_dir / "com.whatsapp" / "media"
    destino.mkdir(parents=True, exist_ok=True)
    print("  [WhatsApp Media] extrayendo desde /sdcard/...")
    adb(["pull", wa_media, str(destino)], serial, 300)   # puede tardar


# ─── Construccion del manifiesto ─────────────────────────────────────────────

def build_manifest(session: dict, pe_session: dict | None,
                   extraccion: dict, out_dir: Path) -> dict:
    """Construye el manifiesto de evidencias para cadena de custodia."""

    # Hash de cada archivo en el directorio de salida
    todos_los_archivos = []
    for root, _, files in os.walk(out_dir):
        for fname in sorted(files):
            fpath = Path(root) / fname
            try:
                sha = sha256_de_archivo(fpath)
                size = fpath.stat().st_size
            except Exception:
                sha, size = "", 0
            todos_los_archivos.append({
                "ruta":   str(fpath.relative_to(out_dir)),
                "sha256": sha,
                "bytes":  size,
            })

    # Hash global del directorio
    h = hashlib.sha256()
    for f in todos_los_archivos:
        h.update(f["sha256"].encode())
    hash_global = h.hexdigest()

    return {
        "extraction_id":    str(uuid.uuid4())[:8].upper(),
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "directorio":       str(out_dir),
        "hash_global":      hash_global,

        "dispositivo": {
            "manufacturer": session.get("manufacturer", ""),
            "model":        session.get("model", ""),
            "chipset":      session.get("chipset", ""),
            "android":      session.get("android_version", ""),
            "parche":       session.get("security_patch", ""),
            "imei":         session.get("imei", ""),
        },

        "sesiones": {
            "device_scan":   session.get("session_id", ""),
            "privilege_esc": pe_session.get("pe_session_id", "") if pe_session else "",
        },

        "extraccion": {
            "metodo":    extraccion.get("nivel",""),
            "apps_ok":   extraccion.get("apps_ok",[]),
            "apps_error": extraccion.get("apps_error",[]),
            "total_archivos": len(todos_los_archivos),
            "total_bytes": sum(f["bytes"] for f in todos_los_archivos),
        },

        "archivos": todos_los_archivos,

        "nota_legal": (
            "Extraccion realizada por EVIDEX BYPASS con autorizacion documentada. "
            "Los hashes SHA-256 individuales y el hash global permiten verificar "
            "la integridad de la evidencia en cualquier momento del proceso pericial."
        )
    }


# ─── Modo simulacion ─────────────────────────────────────────────────────────

def simular_extraccion(sim_key: str, out_dir: Path) -> dict:
    """
    Genera una estructura de directorio simulada para pruebas
    sin hardware conectado.
    """
    import random, string

    apps_sim = [
        ("com.whatsapp",   "databases/msgstore.db", 2_400_000),
        ("com.whatsapp",   "databases/wa.db",        180_000),
        ("com.whatsapp",   "files/key",               67),
        ("com.android.providers.telephony", "databases/mmssms.db", 450_000),
        ("com.android.providers.contacts",  "databases/contacts2.db", 120_000),
        ("com.android.providers.contacts",  "databases/calllog.db",   85_000),
        ("org.telegram.messenger", "files/cache4.db", 1_800_000),
    ]

    archivos_creados = []
    for paquete, ruta_rel, tam in apps_sim:
        path = out_dir / paquete / Path(ruta_rel).parent
        path.mkdir(parents=True, exist_ok=True)
        fpath = path / Path(ruta_rel).name
        # Generar contenido simulado (bytes aleatorios)
        data = bytes(random.getrandbits(8) for _ in range(tam))
        fpath.write_bytes(data)
        archivos_creados.append({
            "ruta_remota": f"/data/data/{paquete}/{ruta_rel}",
            "ruta_local":  str(fpath),
            "estado":      "OK",
            "sha256":      sha256_de_bytes(data),
            "tamano_bytes": tam,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        })

    return {
        "estado":    "OK",
        "nivel":     "SIMULACION",
        "archivos":  archivos_creados,
        "apps_ok":   ["WhatsApp", "SMS / MMS", "Contactos", "Telegram"],
        "apps_error": [],
    }


# ─── Impresion del resumen ────────────────────────────────────────────────────

def print_summary(manifest: dict):
    sep  = "=" * 64
    sep2 = "-" * 64
    ext  = manifest["extraccion"]

    print(sep)
    print("  EVIDEX BYPASS — Data Extractor")
    print(f"  ID extraccion : {manifest['extraction_id']}  ({manifest['timestamp'][:19]}Z)")
    print(sep)

    d = manifest["dispositivo"]
    print(f"  Dispositivo : {d['manufacturer']} {d['model']} / {d['chipset']}")
    print(sep2)

    print(f"  Metodo      : {ext['metodo']}")
    print(f"  Apps OK     : {', '.join(ext['apps_ok']) or 'ninguna'}")
    if ext["apps_error"]:
        print(f"  Sin datos   : {', '.join(ext['apps_error'])}")
    print(f"  Archivos    : {ext['total_archivos']}")
    total_mb = ext["total_bytes"] / (1024*1024)
    print(f"  Total       : {total_mb:.1f} MB")
    print(sep2)

    print(f"  Directorio  : {manifest['directorio']}")
    print(f"  Hash global : {manifest['hash_global'][:48]}...")
    print(sep)

    print("  Archivos extraidos:")
    for f in manifest["archivos"][:12]:
        kb = f["bytes"] // 1024
        print(f"    {f['ruta']:<52} {kb:>6} KB")
    if len(manifest["archivos"]) > 12:
        print(f"    ... y {len(manifest['archivos'])-12} archivos mas")
    print(sep)
    print("  Listo para transferir a EVIDEX via API REST.")
    print(sep)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="EVIDEX BYPASS — Data Extractor"
    )
    ap.add_argument("pe_session",  nargs="?",
                    help="Archivo pe_XXXXXXXX.json del PE Engine")
    ap.add_argument("--serial",    help="Serial ADB")
    ap.add_argument("--sim",       help="Simulacion (ej: mt6762)")
    ap.add_argument("--out",       default="evidex_extraccion",
                    help="Directorio de salida (default: evidex_extraccion/)")
    ap.add_argument("--json",      action="store_true")
    ap.add_argument("--no-manifest", action="store_true",
                    help="No guardar evidence_manifest.json")
    args = ap.parse_args()

    # Cargar sesiones
    session    = {}
    pe_session = None

    if args.sim:
        import subprocess
        scanner = Path(__file__).parent / "device_scanner.py"
        r = subprocess.run(
            [sys.executable, str(scanner), "--sim", args.sim, "--json", "--no-save"],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            session = json.loads(r.stdout)
    elif args.pe_session:
        with open(args.pe_session, encoding="utf-8") as f:
            pe_session = json.load(f)
        # Intentar cargar la sesion del device_scanner relacionada
        dev_id = pe_session.get("device_session_id","")
        sf = Path(f"session_{dev_id}.json")
        if sf.exists():
            with open(sf) as f:
                session = json.load(f)
        else:
            session = pe_session.get("dispositivo", {})
    else:
        ap.print_help()
        sys.exit(1)

    # Directorio de salida
    out_dir = Path(args.out) / datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n  Extrayendo en: {out_dir}\n")

    # Extraccion
    if args.sim:
        extraccion = simular_extraccion(args.sim, out_dir)
    else:
        # Verificar que el PE Engine tuvo exito
        if pe_session:
            estado_pe = pe_session.get("resultado",{}).get("estado","")
            if estado_pe not in ("EXITOSO",):
                print(f"ADVERTENCIA: PE Engine estado = '{estado_pe}'. "
                      "Intentando extraccion de todas formas...")
        extraccion = extraer_via_adb(session, pe_session, out_dir, args.serial)

    if extraccion["estado"] == "ERROR":
        print(f"ERROR: {extraccion['mensaje']}")
        sys.exit(1)

    # Manifiesto
    manifest = build_manifest(session, pe_session, extraccion, out_dir)

    # Guardar manifiesto
    if not args.no_manifest:
        mpath = out_dir / "evidence_manifest.json"
        with open(mpath, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)

    # Salida
    if args.json:
        print(json.dumps(manifest, ensure_ascii=False, indent=2))
    else:
        print_summary(manifest)


if __name__ == "__main__":
    main()
