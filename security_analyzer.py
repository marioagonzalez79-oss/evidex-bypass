#!/usr/bin/env python3
"""
security_analyzer.py — Security Analyzer de EVIDEX BYPASS
==========================================================
Modulo 2 del Acquisition Engine. Toma la sesion generada por el
Device Scanner y produce una evaluacion de seguridad completa:

  1. Estado AFU/BFU detallado
  2. Analisis de cifrado (tipo, estado, implicaciones)
  3. Estado del bootloader
  4. Matriz de CVEs N-day aplicables segun parche y version Android
  5. Ruta de adquisicion recomendada con prioridades
  6. Informe de seguridad listo para incluir en el expediente

Uso:
  python3 security_analyzer.py session_XXXXXXXX.json
  python3 security_analyzer.py session_XXXXXXXX.json --json
  python3 security_analyzer.py --sim mt6762        (genera sesion simulada y analiza)
  python3 security_analyzer.py --sim exynos7570
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

KB_DIR   = Path(__file__).parent / "knowledge_base"
CVE_FILE = KB_DIR / "cves.json"


# ─── Helpers de fecha ─────────────────────────────────────────────────────────

def parse_date(s):
    """Convierte '2022-05-01' a datetime. Devuelve None si falla."""
    for fmt in ("%Y-%m-%d", "%Y-%m", "%Y"):
        try:
            return datetime.strptime(s.strip(), fmt)
        except ValueError:
            continue
    return None


def months_since(patch_str):
    """Meses desde el nivel de parche hasta hoy."""
    d = parse_date(patch_str)
    if not d:
        return None
    now = datetime.now()
    return (now.year - d.year) * 12 + (now.month - d.month)


def patch_before(patch_str, threshold_str):
    """True si el parche del dispositivo es ANTERIOR al umbral del CVE."""
    device_date = parse_date(patch_str)
    cve_date    = parse_date(threshold_str)
    if not device_date or not cve_date:
        return False
    return device_date < cve_date


# ─── Carga de CVEs ────────────────────────────────────────────────────────────

def load_cves():
    with open(CVE_FILE, encoding="utf-8") as f:
        return json.load(f)["cves"]


# ─── Evaluacion AFU/BFU ───────────────────────────────────────────────────────

def evaluate_afu_detailed(props):
    """
    Determina el estado AFU/BFU con mayor detalle que el Device Scanner.

    AFU (After First Unlock): el dispositivo ha sido desbloqueado al menos
    una vez desde el ultimo arranque. Las claves FBE CE estan en memoria.
    BFU (Before First Unlock): el dispositivo nunca se ha desbloqueado desde
    que arranco. Solo las claves DE estan disponibles (datos del sistema
    operativo, no datos de usuario).
    """
    crypto_state  = props.get("ro.crypto.state", "")
    crypto_type   = props.get("ro.crypto.type", "")
    debuggable    = props.get("ro.debuggable", "")
    usb_config    = props.get("persist.sys.usb.config", "")
    boot_state    = props.get("ro.boot.verifiedbootstate", "")
    flash_locked  = props.get("ro.boot.flash.locked", "")
    build_type    = props.get("ro.build.type", "")

    indicadores = []
    estado = "DESCONOCIDO"
    confianza = "BAJA"

    # Indicadores de AFU
    if "adb" in usb_config.lower():
        indicadores.append("ADB activo en usb.config → equipo desbloqueado (AFU confirmado)")
        estado = "AFU_CONFIRMADO"
        confianza = "ALTA"

    if debuggable == "1":
        indicadores.append("ro.debuggable=1 → build de desarrollo, ADB siempre activo")
        if estado == "DESCONOCIDO":
            estado = "AFU_PROBABLE"
            confianza = "MEDIA"

    if build_type in ("userdebug", "eng"):
        indicadores.append(f"Build type '{build_type}' → ADB root disponible")
        estado = "AFU_CONFIRMADO"
        confianza = "ALTA"

    # Estado del cifrado
    if crypto_state == "unencrypted":
        indicadores.append("Dispositivo SIN cifrado → datos accesibles sin desbloqueo (AFU irrelevante)")
        estado = "SIN_CIFRADO"
        confianza = "ALTA"
    elif crypto_state == "encrypted":
        if crypto_type == "file":
            indicadores.append("FBE activo → en BFU solo datos DE accesibles; en AFU tambien datos CE (usuario)")
        elif crypto_type == "block":
            indicadores.append("FDE activo → en BFU todo cifrado; en AFU datos accesibles con credencial")
        else:
            indicadores.append(f"Cifrado activo (tipo: {crypto_type or 'desconocido'})")

    # Bootloader
    if boot_state == "green":
        indicadores.append("Verified boot: GREEN (bootloader bloqueado, firmware oficial)")
    elif boot_state == "yellow":
        indicadores.append("Verified boot: YELLOW (bootloader desbloqueado con clave personalizada)")
    elif boot_state == "orange":
        indicadores.append("Verified boot: ORANGE (bootloader desbloqueado)")
        if estado == "DESCONOCIDO":
            estado = "AFU_PROBABLE"
    elif boot_state == "red":
        indicadores.append("Verified boot: RED (firmware no verificado o modificado)")

    if flash_locked == "0":
        indicadores.append("ro.boot.flash.locked=0 → bootloader desbloqueado")
    elif flash_locked == "1":
        indicadores.append("ro.boot.flash.locked=1 → bootloader bloqueado")

    if estado == "DESCONOCIDO" and crypto_state == "encrypted":
        indicadores.append("Estado AFU no determinable desde props. VERIFICAR FISICAMENTE.")

    return {
        "estado": estado,
        "confianza": confianza,
        "indicadores": indicadores,
        "crypto_state": crypto_state,
        "crypto_type": crypto_type,
        "boot_state": boot_state,
        "flash_locked": flash_locked,
    }


# ─── Evaluacion de cifrado ────────────────────────────────────────────────────

CIFRADO_IMPACTO = {
    "NINGUNO": {
        "impacto": "NULO",
        "descripcion": "Sin cifrado activo. Los datos son directamente accesibles en la imagen fisica.",
        "accion": "Extraccion fisica directa. Los datos son legibles sin ninguna clave adicional."
    },
    "FDE": {
        "impacto": "MEDIO",
        "descripcion": "Full Disk Encryption. Particion cifrada con clave derivada del PIN/patron del usuario.",
        "accion": "Con PIN/patron conocido: descifrar post-extraccion con viaforensics, Autopsy o herramienta compatible. Sin credencial: imagen obtenida pero ilegible."
    },
    "FBE": {
        "impacto": "ALTO",
        "descripcion": "File-Based Encryption. Claves CE (credential-encrypted) solo disponibles en AFU. Claves DE siempre disponibles.",
        "accion": "En AFU: con root temporal via N-day, copiar /data/data/ mientras las claves estan en memoria. En BFU: solo datos DE (contactos del marcador, configuracion de arranque), datos de usuario inaccesibles."
    },
    "FBE_FUERTE": {
        "impacto": "MUY ALTO",
        "descripcion": "FBE con Strongbox/TEE fuerte. Claves protegidas por hardware dedicado. No extraibles del dispositivo.",
        "accion": "Sin herramienta comercial con exploit propietario, los datos de usuario son inaccesibles incluso en AFU. Evaluar ruta N-day antes de concluir."
    },
    "DESCONOCIDO": {
        "impacto": "INDETERMINADO",
        "descripcion": "Estado de cifrado no determinado.",
        "accion": "Verificar con adb shell getprop ro.crypto.type y ro.crypto.state."
    }
}


# ─── Matching de CVEs ─────────────────────────────────────────────────────────

def match_cves(session, all_cves):
    """
    Determina que CVEs son aplicables dado el perfil del dispositivo.
    Un CVE aplica cuando:
      1. El nivel de parche del dispositivo es ANTERIOR a la fecha del parche del CVE
      2. La version de Android esta en la lista de afectados
      3. El chipset/familia es compatible (o el CVE afecta a todos)
    """
    android_ver  = session.get("android_version", "")
    patch_level  = session.get("security_patch", "")
    chipset      = session.get("chipset", "").upper()
    familia      = session.get("familia", "").lower()

    if not patch_level:
        return [], "Sin nivel de parche disponible. No se puede evaluar CVEs."

    aplicables = []
    no_aplican = []

    for cve in all_cves:
        # Verificar parche
        if not patch_before(patch_level, cve["parche_mes"]):
            no_aplican.append({
                "id": cve["id"],
                "razon": f"Parche {patch_level} incluye el fix de {cve['parche_mes']}"
            })
            continue

        # Verificar Android version
        afectados = cve.get("android_afectado", [])
        if afectados:
            version_ok = False
            for v in afectados:
                # Comparacion flexible: "12" aplica a "12", "12.1", "12L"
                if android_ver.startswith(v) or v.startswith(android_ver.split(".")[0]):
                    version_ok = True
                    break
            if not version_ok:
                no_aplican.append({
                    "id": cve["id"],
                    "razon": f"Android {android_ver} no en lista afectada {afectados}"
                })
                continue

        # Verificar chipset/familia
        chips_afect = cve.get("chipsets_afectados", "todos")
        fab_afect   = cve.get("fabricantes_afectados", "todos")

        chipset_ok = True
        if chips_afect != "todos" and isinstance(chips_afect, list):
            chipset_ok = any(c.upper() in chipset or chipset in c.upper()
                             for c in chips_afect)
        if fab_afect != "todos" and not chipset_ok:
            if isinstance(fab_afect, str):
                chipset_ok = fab_afect.lower() == familia
            elif isinstance(fab_afect, list):
                chipset_ok = familia in [f.lower() for f in fab_afect]

        if not chipset_ok:
            no_aplican.append({
                "id": cve["id"],
                "razon": f"Chipset {chipset} / familia {familia} no afectado"
            })
            continue

        # Solo incluir CVEs con PoC publico (politica de EVIDEX BYPASS)
        if not cve.get("poc_publico", False):
            no_aplican.append({
                "id": cve["id"],
                "razon": "Sin PoC publico — fuera del alcance de EVIDEX BYPASS"
            })
            continue

        aplicables.append(cve)

    # Ordenar por relevancia forense
    orden_relevancia = {"MUY ALTA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3}
    aplicables.sort(key=lambda c: (
        orden_relevancia.get(c.get("relevancia_forense","BAJA"), 3),
        0 if c.get("root_posible") else 1
    ))

    return aplicables, None


# ─── Ruta de adquisicion recomendada ──────────────────────────────────────────

def build_acquisition_path(session, afu_eval, cifrado_eval, cves_aplicables):
    """
    Genera la ruta de adquisicion recomendada en orden de prioridad.
    """
    ceiling   = session.get("acquisition_ceiling", "DESCONOCIDO")
    familia   = session.get("familia", "").lower()
    herramienta = session.get("herramienta", "")
    android   = session.get("android_version", "")
    cifrado   = session.get("cifrado_tipico", "DESCONOCIDO")
    afu_estado = afu_eval.get("estado", "DESCONOCIDO")

    pasos = []

    # Paso 1: Preservacion
    pasos.append({
        "orden": 1,
        "tipo": "PRESERVACION",
        "accion": "Aislar el dispositivo (Faraday o modo avion) encendido. No reiniciar.",
        "razon": "Mantener estado AFU. Un reinicio pasa a BFU y puede cerrar ventanas de explotacion.",
        "herramienta": "Bolsa Faraday o modo avion manual",
        "obligatorio": True
    })

    # Paso 2: Documentacion inicial
    pasos.append({
        "orden": 2,
        "tipo": "DOCUMENTACION",
        "accion": "Fotografiar estado fisico. Registrar IMEI, numero de serie, estado de la pantalla.",
        "razon": "Cadena de custodia. Estado previo a cualquier intervencion tecnica.",
        "herramienta": "Camara, formulario de recepcion EVIDEX",
        "obligatorio": True
    })

    # Paso 3: Extraccion logica (siempre disponible como minimo)
    pasos.append({
        "orden": 3,
        "tipo": "EXTRACCION_LOGICA",
        "accion": "Extraccion logica via ADB backup o agente forense.",
        "razon": "Nivel base siempre disponible. No depende de root ni exploits.",
        "herramienta": "ADB + EVIDEX (modulo logico)",
        "obligatorio": False,
        "condicion": "Si ADB esta habilitado o se puede habilitar con acceso fisico a la pantalla."
    })

    # Paso 4 en adelante: segun ceiling y familia
    if ceiling == "FISICA":
        if familia == "mediatek":
            pasos.append({
                "orden": 4,
                "tipo": "EXTRACCION_FISICA_BROM",
                "accion": f"Entrar en modo BROM ({session.get('condiciones',[''])[0] if session.get('condiciones') else 'Volumen abajo + USB sin bateria'}) y ejecutar MTKClient.",
                "razon": "Extraccion fisica completa de userdata sin modificar el dispositivo.",
                "herramienta": "MTKClient (Python) → imagen .bin de userdata",
                "obligatorio": False,
                "condicion": "DAA no activo en este firmware. Verificar antes de intentar."
            })
            if cifrado in ("FBE","FBE_FUERTE") and cves_aplicables:
                top_cve = cves_aplicables[0]
                pasos.append({
                    "orden": 5,
                    "tipo": "ESCALADA_PRIVILEGIOS_NDAY",
                    "accion": f"Aplicar {top_cve['id']} ({top_cve['nombre']}) para obtener shell privilegiada y copiar /data/data/ en AFU.",
                    "razon": "FBE cifra la imagen fisica. Con N-day en AFU se obtienen datos descifrados directamente.",
                    "herramienta": f"PoC: {top_cve.get('poc_url','')}",
                    "obligatorio": False,
                    "condicion": f"AFU confirmado. {top_cve.get('condiciones',[])}",
                    "advertencia": "Documentar CVE utilizado, version del PoC y resultado en el informe pericial."
                })

        elif familia == "qualcomm":
            pasos.append({
                "orden": 4,
                "tipo": "EXTRACCION_FISICA_EDL",
                "accion": "Entrar en modo EDL y ejecutar edl.py con el programmer correspondiente.",
                "razon": "Extraccion fisica completa de userdata.",
                "herramienta": "edl.py (Bjoern Kerler) + programmer especifico del modelo",
                "obligatorio": False,
                "condicion": "Programmer publico disponible para este modelo. Verificar KB antes de intentar."
            })
            if cifrado in ("FBE","FBE_FUERTE") and cves_aplicables:
                top_cve = cves_aplicables[0]
                pasos.append({
                    "orden": 5,
                    "tipo": "ESCALADA_PRIVILEGIOS_NDAY",
                    "accion": f"Aplicar {top_cve['id']} ({top_cve['nombre']}) para obtener shell privilegiada y copiar /data/data/ en AFU.",
                    "razon": "FBE cifra la imagen EDL. N-day en AFU obtiene datos descifrados.",
                    "herramienta": f"PoC: {top_cve.get('poc_url','')}",
                    "obligatorio": False,
                    "condicion": f"AFU confirmado. {top_cve.get('condiciones',[])}",
                    "advertencia": "Documentar CVE, version del PoC y resultado en el informe pericial."
                })

    elif ceiling in ("FS", "LOGICA"):
        if cves_aplicables:
            top_cve = cves_aplicables[0]
            pasos.append({
                "orden": 4,
                "tipo": "ESCALADA_PRIVILEGIOS_NDAY",
                "accion": f"Aplicar {top_cve['id']} ({top_cve['nombre']}) para elevar permisos y acceder a /data/data/ en AFU.",
                "razon": f"Sin ruta de extraccion fisica ({familia.upper()}). N-day es la ruta principal para datos de usuario.",
                "herramienta": f"PoC: {top_cve.get('poc_url','')}",
                "obligatorio": False,
                "condicion": f"AFU confirmado. {top_cve.get('condiciones',[])}",
                "advertencia": "Documentar CVE, version del PoC y resultado en el informe pericial."
            })
        else:
            pasos.append({
                "orden": 4,
                "tipo": "LIMITACION",
                "accion": "Sin CVEs aplicables identificados para este nivel de parche y version Android.",
                "razon": "El dispositivo tiene un nivel de parche que cubre los CVEs conocidos publicamente.",
                "herramienta": "Herramienta comercial (Cellebrite, GrayKey, XRY) requerida.",
                "obligatorio": False,
                "condicion": "Evaluar disponibilidad de herramienta comercial."
            })

    # Paso final: backup Drive si existe
    pasos.append({
        "orden": len(pasos) + 1,
        "tipo": "BACKUP_CLOUD",
        "accion": "Verificar si existe copia de seguridad en Google Drive / Samsung Cloud / iCloud anterior al evento.",
        "razon": "Una copia anterior al borrado puede contener datos ya eliminados del dispositivo.",
        "herramienta": "Acceso legal a cuenta (cooperacion del titular u orden fiscal)",
        "obligatorio": False,
        "condicion": "Requiere acceso a las credenciales de la cuenta o autorizacion judicial."
    })

    return pasos


# ─── Construccion del informe de seguridad ────────────────────────────────────

def build_security_report(session, afu_eval, cifrado_eval, cves_ap, path):
    """Construye el dict completo del informe de seguridad."""
    meses_parche = months_since(session.get("security_patch",""))

    return {
        "security_session_id": str(uuid.uuid4())[:8].upper(),
        "timestamp":           datetime.now(timezone.utc).isoformat(),
        "device_session_id":   session.get("session_id",""),

        "afu_evaluacion":  afu_eval,
        "cifrado_evaluacion": {
            **cifrado_eval,
            "tipo": session.get("cifrado_tipico","DESCONOCIDO")
        },

        "parche_seguridad": {
            "nivel":   session.get("security_patch",""),
            "meses_antiguedad": meses_parche,
            "riesgo":  "CRITICO" if (meses_parche or 0) > 36
                       else "ALTO" if (meses_parche or 0) > 18
                       else "MEDIO" if (meses_parche or 0) > 6
                       else "BAJO"
        },

        "cves_aplicables": [
            {
                "id":          c["id"],
                "nombre":      c["nombre"],
                "categoria":   c["categoria"],
                "severidad":   c["severidad"],
                "root_posible": c.get("root_posible", False),
                "acceso_datos": c.get("acceso_datos_posible", False),
                "relevancia":  c.get("relevancia_forense",""),
                "condiciones": c.get("condiciones",[]),
                "poc_url":     c.get("poc_url",""),
                "notas_forense": c.get("notas_forense",""),
            }
            for c in cves_ap
        ],
        "total_cves_aplicables": len(cves_ap),
        "cves_con_root":  sum(1 for c in cves_ap if c.get("root_posible")),
        "cves_con_acceso_datos": sum(1 for c in cves_ap if c.get("acceso_datos_posible")),

        "ruta_adquisicion": path,
        "total_pasos": len(path),
    }


# ─── Impresion del informe ────────────────────────────────────────────────────

RIESGO_PARCHE = {
    "CRITICO": "⚠⚠⚠ CRITICO",
    "ALTO":    "⚠⚠  ALTO",
    "MEDIO":   "⚠   MEDIO",
    "BAJO":    "✓   BAJO",
}

def print_security_report(r, session):
    sep  = "=" * 64
    sep2 = "-" * 64

    print(sep)
    print(f"  EVIDEX BYPASS — Security Analyzer")
    print(f"  Sesion    : {r['security_session_id']}  ({r['timestamp'][:19]}Z)")
    print(f"  Dispositivo: {session.get('manufacturer','')} {session.get('model','')} "
          f"/ {session.get('chipset','')} / Android {session.get('android_version','')}")
    print(sep)

    # AFU
    afu = r["afu_evaluacion"]
    print(f"\n  [ ESTADO AFU/BFU ]")
    print(f"  Estado     : {afu['estado']}  (confianza: {afu['confianza']})")
    print(f"  Cifrado    : {afu['crypto_type'] or 'desconocido'}  |  Estado: {afu['crypto_state'] or 'desconocido'}")
    print(f"  Boot       : {afu['boot_state'] or 'desconocido'}")
    for ind in afu["indicadores"]:
        print(f"    • {ind}")

    # Cifrado
    cif = r["cifrado_evaluacion"]
    print(f"\n  [ ANALISIS DE CIFRADO ]")
    print(f"  Tipo       : {cif['tipo']}")
    print(f"  Impacto    : {cif.get('impacto','')}")
    print(f"  Descripcion: {cif.get('descripcion','')}")
    print(f"  Accion     : {cif.get('accion','')}")

    # Parche
    p = r["parche_seguridad"]
    riesgo_str = RIESGO_PARCHE.get(p["riesgo"], p["riesgo"])
    print(f"\n  [ NIVEL DE PARCHE ]")
    print(f"  Parche     : {p['nivel']}  ({p['meses_antiguedad']} meses de antiguedad)")
    print(f"  Riesgo N-day: {riesgo_str}")

    # CVEs
    print(f"\n  [ CVEs N-DAY APLICABLES: {r['total_cves_aplicables']} ]")
    print(f"  Con root completo: {r['cves_con_root']}   "
          f"Con acceso a datos: {r['cves_con_acceso_datos']}")
    if r["cves_aplicables"]:
        print()
        for cve in r["cves_aplicables"][:6]:   # top 6
            root_mark = "ROOT" if cve["root_posible"] else "DATOS" if cve["acceso_datos"] else "    "
            print(f"  [{root_mark}] {cve['id']:<18} {cve['relevancia']:<9}  {cve['nombre'][:35]}")
            print(f"         {cve['notas_forense'][:70]}")
    else:
        print("  Ninguno aplicable con PoC publico para este nivel de parche.")

    # Ruta
    print(f"\n  [ RUTA DE ADQUISICION RECOMENDADA ]")
    for paso in r["ruta_adquisicion"]:
        obl = "* " if paso.get("obligatorio") else "  "
        print(f"  {obl}{paso['orden']}. [{paso['tipo']}]")
        print(f"     {paso['accion']}")
        if paso.get("condicion"):
            print(f"     Condicion: {paso['condicion']}")
        if paso.get("advertencia"):
            print(f"     ⚠ {paso['advertencia']}")

    print(sep)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="EVIDEX BYPASS — Security Analyzer"
    )
    ap.add_argument("session", nargs="?",
                    help="Archivo session_XXXXXXXX.json del Device Scanner")
    ap.add_argument("--sim",  help="Generar sesion simulada y analizar directamente")
    ap.add_argument("--json", action="store_true", help="Salida JSON pura")
    ap.add_argument("--save", action="store_true",
                    help="Guardar informe como security_XXXXXXXX.json")
    args = ap.parse_args()

    # Obtener sesion
    session = None

    if args.sim:
        # Generar sesion via device_scanner en modo simulacion
        import subprocess, tempfile, os
        scanner = Path(__file__).parent / "device_scanner.py"
        result = subprocess.run(
            [sys.executable, str(scanner), "--sim", args.sim, "--json", "--no-save"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            print(f"ERROR al ejecutar device_scanner: {result.stderr}")
            sys.exit(1)
        try:
            session = json.loads(result.stdout)
        except json.JSONDecodeError:
            print(f"ERROR: salida invalida del device_scanner")
            sys.exit(1)

    elif args.session:
        with open(args.session, encoding="utf-8") as f:
            session = json.load(f)
    else:
        ap.print_help()
        sys.exit(1)

    # Cargar CVEs
    try:
        all_cves = load_cves()
    except FileNotFoundError:
        print(f"ERROR: {CVE_FILE} no encontrado.")
        sys.exit(1)

    props = session.get("props_raw", {})

    # Evaluaciones
    afu_eval    = evaluate_afu_detailed(props)
    cifrado_tip = session.get("cifrado_tipico", "DESCONOCIDO")
    cifrado_ev  = CIFRADO_IMPACTO.get(cifrado_tip, CIFRADO_IMPACTO["DESCONOCIDO"])
    cves_ap, _  = match_cves(session, all_cves)
    path        = build_acquisition_path(session, afu_eval, cifrado_ev, cves_ap)
    report      = build_security_report(session, afu_eval, cifrado_ev, cves_ap, path)

    # Salida
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_security_report(report, session)

    # Guardar
    if args.save:
        fname = f"security_{report['security_session_id']}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        if not args.json:
            print(f"\n  Informe guardado: {fname}")


if __name__ == "__main__":
    main()
