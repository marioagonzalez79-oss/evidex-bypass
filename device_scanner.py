#!/usr/bin/env python3
"""
device_scanner.py — Device Scanner de EVIDEX BYPASS
=====================================================
Modulo 1 del Acquisition Engine. Identifica el dispositivo conectado por
USB, cruza contra la Knowledge Base y devuelve un perfil forense completo
con ceiling de adquisicion, herramienta recomendada, condiciones y
advertencias.

Modos de operacion:
  1. ADB real     → dispositivo fisicamente conectado
  2. Archivo      → salida de `adb shell getprop` previamente capturada
  3. Simulacion   → perfiles de prueba integrados (sin hardware)

Uso:
  python3 device_scanner.py                        # ADB (primer dispositivo)
  python3 device_scanner.py --serial ABC123        # ADB (dispositivo especifico)
  python3 device_scanner.py --props getprop.txt    # desde archivo
  python3 device_scanner.py --sim mt6762           # simulacion integrada
  python3 device_scanner.py --sim list             # listar simulaciones
  python3 device_scanner.py --json                 # salida JSON (para API)

Salida:
  Pantalla: informe legible con perfil forense
  Archivo:  session_<id>.json en el directorio actual
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

KB_DIR = Path(__file__).parent / "knowledge_base"
KB_CHIPS = KB_DIR / "chipsets.json"
KB_MFR   = KB_DIR / "manufacturers.json"

# ─── Propiedades ADB relevantes ──────────────────────────────────────────────
ADB_PROPS = [
    "ro.product.manufacturer",
    "ro.product.brand",
    "ro.product.model",
    "ro.product.name",
    "ro.board.platform",
    "ro.hardware",
    "ro.build.version.release",
    "ro.build.version.security_patch",
    "ro.build.fingerprint",
    "ro.crypto.type",
    "ro.crypto.state",
    "ro.boot.verifiedbootstate",
    "ro.boot.flash.locked",
    "ro.debuggable",
    "persist.sys.usb.config",
    "ro.build.type",
    "ro.product.cpu.abi",
    "ro.build.product",
]

# ─── Simulaciones integradas (sin hardware) ──────────────────────────────────
SIMULATIONS = {
    "mt6762": {
        "_desc": "Samsung Galaxy A10s (MT6762 / Helio P22) — FISICA",
        "ro.product.manufacturer": "samsung",
        "ro.product.brand":        "samsung",
        "ro.product.model":        "SM-A107M",
        "ro.product.name":         "a10sxx",
        "ro.board.platform":       "mt6762",
        "ro.hardware":             "mt6762",
        "ro.build.version.release": "11",
        "ro.build.version.security_patch": "2021-07-01",
        "ro.crypto.type":          "file",
        "ro.crypto.state":         "encrypted",
        "ro.boot.verifiedbootstate": "green",
        "ro.debuggable":           "0",
        "ro.build.type":           "user",
    },
    "exynos7570": {
        "_desc": "Samsung Galaxy J4 (Exynos 7570) — FS",
        "ro.product.manufacturer": "samsung",
        "ro.product.brand":        "samsung",
        "ro.product.model":        "SM-J400M",
        "ro.product.name":         "j4lteub",
        "ro.board.platform":       "exynos7570",
        "ro.hardware":             "samsungexynos7570",
        "ro.build.version.release": "9",
        "ro.build.version.security_patch": "2020-04-01",
        "ro.crypto.type":          "file",
        "ro.crypto.state":         "encrypted",
        "ro.boot.verifiedbootstate": "green",
        "ro.debuggable":           "0",
        "ro.build.type":           "user",
    },
    "msm8937": {
        "_desc": "Motorola Moto G5 (SDM430 / MSM8937) — FISICA",
        "ro.product.manufacturer": "motorola",
        "ro.product.brand":        "motorola",
        "ro.product.model":        "XT1676",
        "ro.product.name":         "cedric",
        "ro.board.platform":       "msm8937",
        "ro.hardware":             "qcom",
        "ro.build.version.release": "8.1",
        "ro.build.version.security_patch": "2018-11-01",
        "ro.crypto.type":          "block",
        "ro.crypto.state":         "encrypted",
        "ro.boot.verifiedbootstate": "green",
        "ro.debuggable":           "0",
        "ro.build.type":           "user",
    },
    "sdm732": {
        "_desc": "Xiaomi POCO X3 NFC (SDM732G) — FISICA",
        "ro.product.manufacturer": "Xiaomi",
        "ro.product.brand":        "POCO",
        "ro.product.model":        "M2007J20CG",
        "ro.product.name":         "surya",
        "ro.board.platform":       "sdm732",
        "ro.hardware":             "qcom",
        "ro.build.version.release": "12",
        "ro.build.version.security_patch": "2022-05-01",
        "ro.crypto.type":          "file",
        "ro.crypto.state":         "encrypted",
        "ro.boot.verifiedbootstate": "green",
        "ro.debuggable":           "0",
        "ro.build.type":           "user",
    },
    "kirin710": {
        "_desc": "Huawei P Smart 2019 (Kirin 710) — FS",
        "ro.product.manufacturer": "HUAWEI",
        "ro.product.brand":        "HUAWEI",
        "ro.product.model":        "POT-LX3",
        "ro.product.name":         "HWPOT-H",
        "ro.board.platform":       "kirin710",
        "ro.hardware":             "hi6250",
        "ro.build.version.release": "10",
        "ro.build.version.security_patch": "2021-01-01",
        "ro.crypto.type":          "file",
        "ro.crypto.state":         "encrypted",
        "ro.boot.verifiedbootstate": "green",
        "ro.debuggable":           "0",
        "ro.build.type":           "user",
    },
    "mt6739": {
        "_desc": "Noblex X7 (MT6739 / Helio A22) — FISICA, parche 2019",
        "ro.product.manufacturer": "NOBLEX",
        "ro.product.brand":        "NOBLEX",
        "ro.product.model":        "X7",
        "ro.product.name":         "X7",
        "ro.board.platform":       "mt6739",
        "ro.hardware":             "mt6739",
        "ro.build.version.release": "8.1",
        "ro.build.version.security_patch": "2019-06-01",
        "ro.crypto.type":          "file",
        "ro.crypto.state":         "encrypted",
        "ro.debuggable":           "0",
        "ro.build.type":           "user",
    },
}


# ─── Carga de KB ─────────────────────────────────────────────────────────────

def load_kb():
    with open(KB_CHIPS, encoding="utf-8") as f:
        chips = json.load(f)
    with open(KB_MFR, encoding="utf-8") as f:
        mfr = json.load(f)
    return chips, mfr


# ─── Coleccion de props ───────────────────────────────────────────────────────

def props_via_adb(serial=None):
    """Lee todas las props de un dispositivo ADB conectado."""
    base = ["adb"]
    if serial:
        base += ["-s", serial]

    # Verificar dispositivo
    try:
        r = subprocess.run(base + ["devices"], capture_output=True, text=True, timeout=5)
    except FileNotFoundError:
        return None, "ADB no encontrado. Instalar Android Platform Tools."
    except subprocess.TimeoutExpired:
        return None, "Timeout al conectar con ADB."

    lines = [l.strip() for l in r.stdout.splitlines() if "\t" in l]
    if not lines:
        return None, "Ningun dispositivo ADB conectado."
    if serial and not any(serial in l for l in lines):
        return None, f"Dispositivo {serial} no encontrado."

    # Leer props una por una
    props = {}
    for prop in ADB_PROPS:
        try:
            res = subprocess.run(
                base + ["shell", "getprop", prop],
                capture_output=True, text=True, timeout=5
            )
            val = res.stdout.strip().strip("[]")
            if val:
                props[prop] = val
        except Exception:
            pass

    if not props:
        return None, "No se pudieron leer propiedades del dispositivo."
    return props, None


def props_from_file(path):
    """Parsea la salida de `adb shell getprop` guardada en un archivo."""
    props = {}
    pattern = re.compile(r'\[([^\]]+)\]:\s*\[([^\]]*)\]')
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pattern.match(line.strip())
            if m:
                props[m.group(1)] = m.group(2)
    return props, None


def props_from_sim(key):
    """Devuelve props de una simulacion integrada."""
    if key not in SIMULATIONS:
        return None, f"Simulacion '{key}' no existe. Usar --sim list."
    p = dict(SIMULATIONS[key])
    p.pop("_desc", None)
    return p, None


# ─── Matching contra KB ───────────────────────────────────────────────────────

def normalize(s):
    return (s or "").lower().strip()


def match_manufacturer(props, mfr_kb):
    """Intenta match exacto en manufacturers.json por platform+manufacturer+model."""
    platform = normalize(props.get("ro.board.platform", ""))
    manuf    = normalize(props.get("ro.product.manufacturer", ""))
    model    = normalize(props.get("ro.product.model", ""))
    name     = normalize(props.get("ro.product.name", ""))

    best = None
    best_score = 0

    for fab_key, fab in mfr_kb.items():
        if fab_key == "_meta":
            continue
        for m in fab["modelos"]:
            score = 0
            if platform and normalize(m.get("ro_board_platform","")) == platform:
                score += 3
            if manuf and normalize(m.get("ro_manufacturer","")) == manuf:
                score += 2
            if model and normalize(m.get("ro_model","")) == model:
                score += 4
            if name and normalize(m.get("ro_model","")) == name:
                score += 2
            if score > best_score:
                best_score = score
                best = (fab, m, score)

    if best and best[2] >= 3:
        return best[0], best[1]
    return None, None


def match_chipset(props, chips_kb):
    """Busca el chipset en chipsets.json por ro.board.platform."""
    platform = normalize(props.get("ro.board.platform",""))
    hardware = normalize(props.get("ro.hardware",""))

    for familia in ("mediatek","qualcomm","exynos","kirin"):
        for c in chips_kb.get(familia, []):
            chipset_name = normalize(c["chipset"].replace(" ",""))
            if platform and (
                platform in chipset_name or
                chipset_name in platform or
                platform == normalize(c.get("chipset",""))
            ):
                return familia, c
            # Buscar en aliases implícitos (marketing name)
            marketing = normalize(c.get("marketing","").replace(" ",""))
            if platform and platform in marketing:
                return familia, c

    # Fallback por hardware prop
    if hardware:
        for familia in ("mediatek","qualcomm","exynos","kirin"):
            for c in chips_kb.get(familia, []):
                if hardware in normalize(c["chipset"]) or \
                   normalize(c["chipset"]) in hardware:
                    return familia, c

    return None, None


# ─── Construccion del perfil ──────────────────────────────────────────────────

def evaluate_conditions(chip, familia):
    """Genera lista de condiciones y advertencias desde el perfil del chipset."""
    conds = []
    warns = []
    ceiling = chip.get("acquisition_ceiling","NO_DISPONIBLE")

    if chip.get("advertencia"):
        warns.append(chip["advertencia"])
    if chip.get("notas_region"):
        conds.append(f"Nota regional: {chip['notas_region']}")

    cifrado = chip.get("cifrado_tipico","")
    if cifrado in ("FBE","FBE_FUERTE"):
        warns.append(
            "FBE activo: datos de usuario cifrados. Necesario estado AFU "
            "(encendido, desbloqueado al menos una vez desde el ultimo arranque) "
            "para acceso a claves en memoria."
        )
    elif cifrado == "FDE":
        conds.append(
            "FDE: descifrado posible con PIN/patron del usuario o estado AFU."
        )
    elif cifrado == "NINGUNO":
        conds.append("Sin cifrado activo: datos legibles directamente en la imagen.")

    if familia == "mediatek":
        if chip.get("brom_accesible") is True and not chip.get("daa_sla"):
            conds.append(f"Activacion BROM: {chip.get('activacion_brom','Ver documentacion')}")
            conds.append("Herramienta: MTKClient (Python, codigo abierto)")
        elif chip.get("daa_sla"):
            warns.append("DAA/SLA activo o condicional. Verificar firmware antes de intentar BROM.")

    elif familia == "qualcomm":
        if chip.get("edl_accesible") is True:
            prog = chip.get("programmer_publico", False)
            if prog is True:
                conds.append(f"EDL accesible. Programmer publico disponible.")
                conds.append(f"Activacion: {chip.get('activacion_edl','Ver documentacion')}")
                conds.append("Herramienta: edl.py (Bjoern Kerler, codigo abierto)")
            elif prog == "PARCIAL":
                warns.append("Programmer EDL parcialmente disponible. Verificar por modelo exacto.")
                conds.append(f"Activacion: {chip.get('activacion_edl','Ver documentacion')}")
            else:
                warns.append("Sin programmer publico disponible para EDL.")
        elif chip.get("edl_accesible") == "CONDICIONAL":
            warns.append("EDL condicional. Verificar por modelo especifico.")

    elif familia == "exynos":
        warns.append("Exynos/Knox: sin ruta de adquisicion fisica publica.")
        if ceiling == "FS":
            conds.append("Techo: sistema de archivos si ADB root disponible.")
        conds.append(f"Download Mode: {chip.get('activacion_download','Vol abajo + USB')}")

    elif familia == "kirin":
        warns.append("HiSilicon Kirin: sin equivalente publico a EDL/BROM.")
        warns.append("Techo maximo: FS si depuracion USB activa.")
        if "710" in chip["chipset"] or "659" in chip["chipset"]:
            warns.append("Post-2019 Huawei sin servicios Google limita extraccion logica.")

    return conds, warns


def evaluate_afu(props):
    """Infiere estado AFU/BFU desde las props disponibles."""
    crypto_state = props.get("ro.crypto.state","")
    debuggable   = props.get("ro.debuggable","")
    usb_config   = props.get("persist.sys.usb.config","")

    if "adb" in usb_config.lower() or debuggable == "1":
        return "AFU_PROBABLE", "Depuracion USB activa. Equipo en estado AFU (acceso a claves en memoria)."
    if crypto_state == "encrypted":
        return "DESCONOCIDO", "Estado AFU no determinable por props. Verificar fisicamente si el equipo esta desbloqueado."
    return "DESCONOCIDO", "No se puede determinar estado AFU desde las props disponibles."


def build_profile(props, chips_kb, mfr_kb, source_label):
    """Construye el perfil forense completo."""
    session_id = str(uuid.uuid4())[:8].upper()
    timestamp  = datetime.now(timezone.utc).isoformat()
    props_hash = hashlib.sha256(
        json.dumps(props, sort_keys=True).encode()
    ).hexdigest()

    # Match
    fab, modelo = match_manufacturer(props, mfr_kb)
    familia, chip = match_chipset(props, chips_kb)

    # Fallback ceiling desde modelo si no hay chip
    ceiling = "DESCONOCIDO"
    if modelo:
        ceiling = modelo.get("acquisition_ceiling","DESCONOCIDO")
    if chip:
        ceiling = chip.get("acquisition_ceiling", ceiling)

    conds, warns = [], []
    if chip and familia:
        conds, warns = evaluate_conditions(chip, familia)

    afu_status, afu_msg = evaluate_afu(props)

    # Nivel de parche
    patch = props.get("ro.build.version.security_patch","")
    patch_warn = None
    if patch:
        try:
            patch_date = datetime.strptime(patch, "%Y-%m-%d")
            age_months = (
                datetime.now().year * 12 + datetime.now().month
              - patch_date.year * 12 - patch_date.month
            )
            if age_months > 24:
                patch_warn = (
                    f"Parche de seguridad con {age_months} meses de antiguedad "
                    f"({patch}). Alta probabilidad de CVEs N-day aplicables."
                )
            elif age_months > 12:
                patch_warn = (
                    f"Parche de {age_months} meses ({patch}). "
                    "Posibles CVEs N-day aplicables. Verificar matriz de vulnerabilidades."
                )
        except ValueError:
            pass
    if patch_warn:
        warns.append(patch_warn)

    return {
        "session_id":   session_id,
        "timestamp":    timestamp,
        "source":       source_label,
        "props_hash":   props_hash,

        # Identificacion
        "manufacturer": props.get("ro.product.manufacturer",""),
        "brand":        props.get("ro.product.brand",""),
        "model":        props.get("ro.product.model",""),
        "board_platform": props.get("ro.board.platform",""),
        "android_version": props.get("ro.build.version.release",""),
        "security_patch": patch,
        "build_fingerprint": props.get("ro.build.fingerprint",""),

        # Chipset
        "chipset":      chip["chipset"] if chip else "DESCONOCIDO",
        "chipset_marketing": chip.get("marketing","") if chip else "",
        "familia":      familia or "DESCONOCIDO",

        # KB match
        "kb_modelo":    modelo["modelo"] if modelo else None,
        "kb_fabricante": fab["nombre_comercial"] if fab else None,
        "kb_match_score": "EXACTO" if (fab and modelo) else ("CHIPSET" if chip else "NO_ENCONTRADO"),

        # Perfil forense
        "acquisition_ceiling": ceiling,
        "cifrado_tipico": chip.get("cifrado_tipico","DESCONOCIDO") if chip else "DESCONOCIDO",
        "herramienta":    chip.get("herramienta","") if chip else "",
        "afu_status":     afu_status,
        "afu_mensaje":    afu_msg,

        "condiciones":   conds,
        "advertencias":  warns,

        "props_raw":     props,
    }


# ─── Impresion del informe ────────────────────────────────────────────────────

CEILING_MARK = {
    "FISICA":        "✓ FISICA",
    "FS":            "~ SISTEMA DE ARCHIVOS",
    "LOGICA":        "~ LOGICA",
    "NO_DISPONIBLE": "✗ NO DISPONIBLE",
    "DESCONOCIDO":   "? DESCONOCIDO",
}

def print_profile(p):
    sep  = "=" * 64
    sep2 = "-" * 64
    print(sep)
    print(f"  EVIDEX BYPASS — Device Scanner")
    print(f"  Sesion : {p['session_id']}   {p['timestamp'][:19]}Z")
    print(f"  Fuente : {p['source']}")
    print(sep)

    print(f"  Fabricante  : {p['manufacturer']}  ({p['brand']})")
    print(f"  Modelo      : {p['model']}")
    print(f"  Plataforma  : {p['board_platform']}")
    print(f"  Android     : {p['android_version']}   Parche: {p['security_patch']}")
    print(sep2)

    print(f"  Chipset     : {p['chipset']}  ({p['chipset_marketing']})")
    print(f"  Familia     : {p['familia'].upper()}")
    print(f"  Match KB    : {p['kb_match_score']}", end="")
    if p["kb_modelo"]:
        print(f"  →  {p['kb_fabricante']} {p['kb_modelo']}")
    else:
        print()
    print(sep2)

    ceiling_str = CEILING_MARK.get(p["acquisition_ceiling"], p["acquisition_ceiling"])
    print(f"  CEILING     : [{ceiling_str}]")
    print(f"  Cifrado     : {p['cifrado_tipico']}")
    print(f"  Herramienta : {p['herramienta']}")
    print(f"  AFU Status  : {p['afu_status']}  —  {p['afu_mensaje']}")
    print(sep2)

    if p["condiciones"]:
        print("  CONDICIONES:")
        for c in p["condiciones"]:
            print(f"    • {c}")

    if p["advertencias"]:
        print("  ADVERTENCIAS:")
        for w in p["advertencias"]:
            print(f"    ⚠ {w}")

    print(sep2)
    print(f"  Hash props  : {p['props_hash'][:32]}...")
    print(sep)


# ─── Guardado de sesion ───────────────────────────────────────────────────────

def save_session(profile, out_dir="."):
    path = Path(out_dir) / f"session_{profile['session_id']}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(profile, f, ensure_ascii=False, indent=2)
    return path


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="EVIDEX BYPASS — Device Scanner"
    )
    ap.add_argument("--serial",  help="Serial ADB del dispositivo")
    ap.add_argument("--props",   help="Archivo con salida de adb shell getprop")
    ap.add_argument("--sim",     help="Simulacion integrada (usar --sim list para ver opciones)")
    ap.add_argument("--json",    action="store_true", help="Salida JSON pura")
    ap.add_argument("--no-save", action="store_true", help="No guardar session_*.json")
    args = ap.parse_args()

    # Listar simulaciones
    if args.sim == "list":
        print("Simulaciones disponibles:")
        for k, v in SIMULATIONS.items():
            print(f"  --sim {k:<16} {v['_desc']}")
        return

    # Cargar KB
    try:
        chips_kb, mfr_kb = load_kb()
    except FileNotFoundError as e:
        print(f"ERROR: KB no encontrada: {e}")
        sys.exit(1)

    # Obtener props
    props, err = None, None
    source = ""

    if args.sim:
        props, err = props_from_sim(args.sim)
        source = f"simulacion:{args.sim}"
    elif args.props:
        props, err = props_from_file(args.props)
        source = f"archivo:{Path(args.props).name}"
    else:
        props, err = props_via_adb(args.serial)
        source = f"adb:{args.serial or 'auto'}"

    if err:
        print(f"ERROR: {err}")
        sys.exit(1)
    if not props:
        print("ERROR: No se obtuvieron propiedades.")
        sys.exit(1)

    # Construir perfil
    profile = build_profile(props, chips_kb, mfr_kb, source)

    # Salida
    if args.json:
        print(json.dumps(profile, ensure_ascii=False, indent=2))
    else:
        print_profile(profile)

    # Guardar sesion
    if not args.no_save:
        path = save_session(profile)
        if not args.json:
            print(f"  Sesion guardada: {path}")


if __name__ == "__main__":
    main()
