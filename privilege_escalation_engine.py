#!/usr/bin/env python3
"""
privilege_escalation_engine.py — Privilege Escalation Engine de EVIDEX BYPASS
==============================================================================
Modulo 3 del Acquisition Engine. Orquesta la ejecucion controlada y
documentada de CVEs N-day para obtener acceso elevado en dispositivos AFU.

Pipeline:
  Security Analyzer → (CVEs priorizados) → PE Engine → Data Extractor

Funciones principales:
  1. Seleccionar el CVE mas adecuado segun el perfil del dispositivo
  2. Verificar precondiciones (ADB, AFU, chipset, Android, parche)
  3. Ejecutar el adaptador del CVE seleccionado
  4. Verificar y documentar el resultado
  5. Pasar el comando de extraccion al Data Extractor
  6. Registrar todo en la sesion para cadena de custodia

Uso:
  python3 privilege_escalation_engine.py security_XXXXXXXX.json
  python3 privilege_escalation_engine.py security_XXXXXXXX.json --cve CVE-2024-0044
  python3 privilege_escalation_engine.py security_XXXXXXXX.json --dry-run
  python3 privilege_escalation_engine.py --sim mt6762 --dry-run
  python3 privilege_escalation_engine.py --listar-adaptadores
"""

import argparse
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from adapters.base import (
    NivelAcceso, EstadoEjecucion, verificar_nivel_acceso, run_adb
)
from adapters.cve_adapters import ADAPTADORES, obtener_adaptador

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("evidex.pe_engine")


# ─── Pre-flight checks ────────────────────────────────────────────────────────

class PreFlightChecker:
    """
    Verificaciones previas obligatorias antes de cualquier ejecucion.
    Garantiza que el intento esta documentado y el entorno es el correcto.
    """

    def __init__(self, serial=None):
        self.serial = serial
        self.errores  = []
        self.warnings = []

    def verificar_todo(self, session: dict, security_report: dict) -> bool:
        self._verificar_autorizacion(security_report)
        self._verificar_adb()
        self._verificar_afu(session, security_report)
        self._verificar_cves_disponibles(security_report)
        return len(self.errores) == 0

    def _verificar_autorizacion(self, sr):
        # En produccion: verificar que existe el ID de expediente y la firma
        # del procurador. Aqui solo verificamos que el campo existe.
        device_id = sr.get("device_session_id","")
        if not device_id:
            self.errores.append(
                "Sin ID de sesion del dispositivo. "
                "Ejecutar device_scanner.py primero."
            )

    def _verificar_adb(self):
        stdout, stderr, rc = run_adb(["devices"], self.serial)
        if rc == -2:
            self.errores.append(
                "ADB no encontrado. Instalar Android Platform Tools."
            )
        elif rc != 0:
            self.errores.append(f"ADB error: {stderr}")
        else:
            lineas = [l for l in stdout.splitlines() if "\t" in l]
            if not lineas:
                self.errores.append("Ningun dispositivo ADB conectado.")
            elif self.serial and not any(self.serial in l for l in lineas):
                self.errores.append(f"Dispositivo {self.serial} no encontrado.")
            else:
                # Verificar que no esta en modo no autorizado
                if any("unauthorized" in l for l in lineas):
                    self.errores.append(
                        "Dispositivo en modo 'unauthorized'. "
                        "Aceptar la solicitud de depuracion en la pantalla del equipo."
                    )

    def _verificar_afu(self, session, sr):
        afu = sr.get("afu_evaluacion",{})
        estado = afu.get("estado","DESCONOCIDO")
        if estado == "DESCONOCIDO":
            self.warnings.append(
                "Estado AFU no confirmado. Los exploits de kernel "
                "REQUIEREN AFU para acceder a datos de usuario. "
                "Verificar fisicamente que el equipo fue desbloqueado "
                "al menos una vez desde el ultimo arranque."
            )
        elif estado not in ("AFU_CONFIRMADO","AFU_PROBABLE","SIN_CIFRADO"):
            self.errores.append(
                f"Estado AFU inaceptable: {estado}. "
                "El dispositivo puede estar en BFU."
            )

    def _verificar_cves_disponibles(self, sr):
        cves = sr.get("cves_aplicables", [])
        if not cves:
            self.errores.append(
                "Sin CVEs aplicables para este dispositivo segun el Security Analyzer. "
                "No se puede proceder con escalada N-day."
            )

    def imprimir(self):
        if self.errores:
            print("\n  [ PRE-FLIGHT: ERRORES — NO SE PUEDE CONTINUAR ]")
            for e in self.errores:
                print(f"    ✗ {e}")
        if self.warnings:
            print("\n  [ PRE-FLIGHT: ADVERTENCIAS ]")
            for w in self.warnings:
                print(f"    ⚠ {w}")
        if not self.errores and not self.warnings:
            print("  [ PRE-FLIGHT: OK ]")


# ─── Seleccion de CVE ─────────────────────────────────────────────────────────

def seleccionar_cve(security_report: dict, cve_forzado: str = None) -> dict | None:
    """
    Selecciona el CVE mas adecuado de la lista de aplicables.
    Prioridad: CVE forzado > MUY ALTA > ALTA > MEDIA > root_posible.
    Solo selecciona CVEs con adaptador implementado.
    """
    cves = security_report.get("cves_aplicables", [])
    if not cves:
        return None

    if cve_forzado:
        for c in cves:
            if c["id"] == cve_forzado:
                if c["id"] in ADAPTADORES:
                    return c
                else:
                    logger.warning(
                        f"{cve_forzado} no tiene adaptador implementado. "
                        f"Adaptadores disponibles: {list(ADAPTADORES.keys())}"
                    )
                    return None
        logger.warning(f"{cve_forzado} no encontrado en CVEs aplicables.")
        return None

    # Filtrar por adaptadores disponibles
    candidatos = [c for c in cves if c["id"] in ADAPTADORES]
    if not candidatos:
        return None

    # Ordenar por relevancia y capacidad
    orden = {"MUY ALTA": 0, "ALTA": 1, "MEDIA": 2, "BAJA": 3}
    candidatos.sort(key=lambda c: (
        orden.get(c.get("relevancia","BAJA"), 3),
        0 if c.get("root_posible") else 1
    ))
    return candidatos[0]


# ─── Modo dry-run ─────────────────────────────────────────────────────────────

def dry_run(session: dict, security_report: dict, cve_sel: dict):
    """
    Muestra exactamente lo que se ejecutaria sin hacerlo.
    Util para revisar el plan antes de conectar el hardware.
    """
    sep = "=" * 64
    print(sep)
    print("  EVIDEX BYPASS — PE Engine [DRY RUN — sin ejecucion real]")
    print(sep)

    print(f"\n  Dispositivo : {session.get('manufacturer','')} {session.get('model','')}")
    print(f"  Chipset     : {session.get('chipset','')} / Android {session.get('android_version','')}")
    print(f"  Parche      : {session.get('security_patch','')}")
    print(f"  Ceiling     : {session.get('acquisition_ceiling','')}")

    print(f"\n  CVE seleccionado : {cve_sel['id']}")
    print(f"  Nombre           : {cve_sel['nombre']}")
    print(f"  Root posible     : {'Si' if cve_sel.get('root_posible') else 'No'}")
    print(f"  Relevancia       : {cve_sel.get('relevancia','')}")
    print(f"  Condiciones      : {cve_sel.get('condiciones', [])}")
    print(f"  PoC URL          : {cve_sel.get('poc_url','')}")

    poc_path = Path(__file__).parent / "adapters" / "pocs" / cve_sel["id"]
    print(f"\n  Directorio PoC   : {poc_path}")
    if poc_path.exists() and list(poc_path.iterdir()):
        print(f"  Estado PoC       : PRESENTE ✓")
    else:
        print(f"  Estado PoC       : AUSENTE — descargar antes de ejecutar")
        print(f"  Comando:  mkdir -p {poc_path}")
        print(f"  Luego:    git clone {cve_sel.get('poc_url','')} {poc_path}")

    print(f"\n  Pasos que se ejecutarian:")
    print(f"    1. Pre-flight checks (ADB, AFU, chipset, parche)")
    print(f"    2. Verificar presencia y hash del binario PoC")
    print(f"    3. ADB push del binario a /data/local/tmp/")
    print(f"    4. chmod +x + ejecucion via ADB shell")
    print(f"    5. Verificar nivel de acceso obtenido (adb shell id)")
    print(f"    6. Registrar resultado en session JSON")
    print(f"    7. Pasar comando de extraccion al Data Extractor")
    print(sep)


# ─── Construccion del resultado de sesion ─────────────────────────────────────

def build_pe_session(session, security_report, cve_sel, resultado_adapter, dry=False):
    return {
        "pe_session_id":    str(uuid.uuid4())[:8].upper(),
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "device_session_id": session.get("session_id",""),
        "security_session_id": security_report.get("security_session_id",""),
        "dry_run":          dry,

        "dispositivo": {
            "manufacturer": session.get("manufacturer",""),
            "model":        session.get("model",""),
            "chipset":      session.get("chipset",""),
            "android":      session.get("android_version",""),
            "parche":       session.get("security_patch",""),
        },

        "cve_seleccionado": cve_sel,
        "resultado": resultado_adapter,

        "adaptadores_disponibles": list(ADAPTADORES.keys()),
    }


# ─── Impresion del resultado ──────────────────────────────────────────────────

def print_resultado(pe_session):
    sep  = "=" * 64
    sep2 = "-" * 64
    r = pe_session.get("resultado", {})

    print(sep)
    print("  EVIDEX BYPASS — PE Engine — Resultado")
    print(f"  Sesion PE  : {pe_session['pe_session_id']}  ({pe_session['timestamp'][:19]}Z)")
    print(sep)

    print(f"  CVE        : {r.get('cve_id','')}")
    print(f"  Estado     : {r.get('estado','')}")
    print(f"  Nivel      : {r.get('nivel_acceso','')}")
    print(f"  UID        : {r.get('uid_obtenido','')}")
    print(f"  SELinux    : {r.get('contexto_selinux','')}")
    print(f"  PoC hash   : {r.get('poc_hash','')[:32]}")
    print(sep2)

    if r.get("estado") == EstadoEjecucion.EXITOSO.value:
        print(f"\n  ✓ ESCALADA EXITOSA")
        print(f"\n  Comando de extraccion para Data Extractor:")
        print(f"  {r.get('comando_extraccion','')}")
    elif r.get("estado") == EstadoEjecucion.POC_NO_DISPONIBLE.value:
        print(f"\n  ✗ PoC no disponible localmente.")
        print(f"  {r.get('error_msg','')}")
    elif r.get("estado") == EstadoEjecucion.PRECONDICION_FALLIDA.value:
        print(f"\n  ✗ Precondicion fallida: {r.get('error_msg','')}")
    else:
        print(f"\n  ✗ Fallido: {r.get('error_msg','')}")

    if r.get("notas"):
        print(f"\n  Notas: {r['notas']}")
    print(sep)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="EVIDEX BYPASS — Privilege Escalation Engine"
    )
    ap.add_argument("security_report", nargs="?",
                    help="Archivo security_XXXXXXXX.json del Security Analyzer")
    ap.add_argument("--cve",    help="Forzar un CVE especifico (ej: CVE-2024-0044)")
    ap.add_argument("--serial", help="Serial ADB del dispositivo")
    ap.add_argument("--dry-run", action="store_true",
                    help="Mostrar plan sin ejecutar nada")
    ap.add_argument("--sim",    help="Usar sesion simulada (ej: mt6762)")
    ap.add_argument("--listar-adaptadores", action="store_true",
                    help="Listar CVEs con adaptador implementado")
    ap.add_argument("--json",   action="store_true", help="Salida JSON")
    ap.add_argument("--save",   action="store_true",
                    help="Guardar resultado como pe_XXXXXXXX.json")
    args = ap.parse_args()

    # Listar adaptadores
    if args.listar_adaptadores:
        print("Adaptadores de CVE implementados:")
        for cve_id, cls in ADAPTADORES.items():
            print(f"  {cve_id:<20} {cls.__doc__.strip().splitlines()[0] if cls.__doc__ else ''}")
        return

    # Cargar informes
    security_report = None
    session         = None

    if args.sim:
        # Generar sesion y security report simulados
        import subprocess
        scanner  = Path(__file__).parent / "device_scanner.py"
        analyzer = Path(__file__).parent / "security_analyzer.py"

        r1 = subprocess.run(
            [sys.executable, str(scanner), "--sim", args.sim, "--json", "--no-save"],
            capture_output=True, text=True
        )
        if r1.returncode != 0:
            print(f"ERROR device_scanner: {r1.stderr}")
            sys.exit(1)
        session = json.loads(r1.stdout)

        r2 = subprocess.run(
            [sys.executable, str(analyzer), "--sim", args.sim, "--json"],
            capture_output=True, text=True
        )
        if r2.returncode != 0:
            print(f"ERROR security_analyzer: {r2.stderr}")
            sys.exit(1)
        security_report = json.loads(r2.stdout)

    elif args.security_report:
        with open(args.security_report, encoding="utf-8") as f:
            security_report = json.load(f)
        # Intentar cargar la sesion del device_scanner relacionada
        dev_id = security_report.get("device_session_id","")
        session_file = Path(f"session_{dev_id}.json")
        if session_file.exists():
            with open(session_file) as f:
                session = json.load(f)
        else:
            # Construir sesion minima desde el security report
            session = {
                "session_id":        dev_id,
                "manufacturer":      security_report.get("dispositivo",{}).get("manufacturer",""),
                "model":             security_report.get("dispositivo",{}).get("model",""),
                "chipset":           security_report.get("dispositivo",{}).get("chipset",""),
                "android_version":   security_report.get("dispositivo",{}).get("android",""),
                "security_patch":    security_report.get("dispositivo",{}).get("parche",""),
                "board_platform":    "",
                "acquisition_ceiling": "",
                "cifrado_tipico":    "",
                "familia":           "",
                "props_raw":         {},
            }
    else:
        ap.print_help()
        sys.exit(1)

    # Pre-flight
    checker = PreFlightChecker(serial=args.serial)
    preflight_ok = checker.verificar_todo(session, security_report)

    # En dry-run mostramos aunque falle preflight
    if not args.dry_run:
        checker.imprimir()
        if not preflight_ok and not args.dry_run:
            print("\n  Corregir errores antes de continuar.")
            sys.exit(1)

    # Seleccionar CVE
    cve_sel = seleccionar_cve(security_report, args.cve)
    if not cve_sel:
        print("ERROR: no hay CVE seleccionable con adaptador disponible.")
        print(f"CVEs aplicables: {[c['id'] for c in security_report.get('cves_aplicables',[])]}")
        print(f"Adaptadores disponibles: {list(ADAPTADORES.keys())}")
        sys.exit(1)

    # Dry run
    if args.dry_run:
        checker.imprimir()
        dry_run(session, security_report, cve_sel)
        return

    # Ejecucion real
    adapter = obtener_adaptador(cve_sel["id"], serial=args.serial)
    resultado = adapter.ejecutar(session)
    resultado_dict = adapter.to_dict()

    # Sesion PE
    pe_session = build_pe_session(
        session, security_report, cve_sel, resultado_dict
    )

    # Salida
    if args.json:
        print(json.dumps(pe_session, ensure_ascii=False, indent=2))
    else:
        print_resultado(pe_session)

    # Guardar
    if args.save:
        fname = f"pe_{pe_session['pe_session_id']}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(pe_session, f, ensure_ascii=False, indent=2)
        if not args.json:
            print(f"  Resultado guardado: {fname}")


if __name__ == "__main__":
    main()
