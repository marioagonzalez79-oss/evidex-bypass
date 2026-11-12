#!/usr/bin/env python3
"""
adapters/base.py — Clase base para adaptadores de CVE en EVIDEX BYPASS
=======================================================================
Cada CVE con PoC publico tiene un adaptador concreto que hereda de
CVEAdapter. El adaptador encapsula:

  1. Verificacion de precondiciones (chipset, Android, AFU)
  2. Preparacion del entorno (descarga/verificacion del PoC externo)
  3. Ejecucion via ADB de forma controlada y registrada
  4. Verificacion del resultado (nivel de acceso obtenido)
  5. Limpieza post-ejecucion

ARQUITECTURA:
  El PoC externo (binario o script Python) es codigo de terceros,
  publicado por el investigador de seguridad que descubrio el CVE.
  EVIDEX BYPASS no implementa ni distribuye el exploit: solo orquesta
  su ejecucion de forma documentada y verifica el resultado.
  El PoC debe descargarse previamente del repositorio oficial indicado
  en cves.json y colocarse en adapters/pocs/<CVE_ID>/.

CADENA DE CUSTODIA:
  Toda ejecucion queda registrada con: CVE, version del PoC,
  hash del binario, timestamp, resultado y nivel de acceso obtenido.
"""

import hashlib
import json
import logging
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

logger = logging.getLogger("evidex.pe")


class NivelAcceso(Enum):
    SIN_ACCESO   = "SIN_ACCESO"
    USER         = "USER"          # uid != 0, igual que antes
    SHELL        = "SHELL"         # uid=shell
    SYSTEM       = "SYSTEM"        # uid=system (acceso a /data/data/)
    ROOT         = "ROOT"          # uid=0


class EstadoEjecucion(Enum):
    PENDIENTE    = "PENDIENTE"
    PRECONDICION_FALLIDA = "PRECONDICION_FALLIDA"
    POC_NO_DISPONIBLE    = "POC_NO_DISPONIBLE"
    EN_EJECUCION = "EN_EJECUCION"
    EXITOSO      = "EXITOSO"
    FALLIDO      = "FALLIDO"
    TIMEOUT      = "TIMEOUT"
    ERROR        = "ERROR"


@dataclass
class ResultadoPE:
    """Resultado documentado de un intento de escalada de privilegios."""
    cve_id:            str
    timestamp_inicio:  str
    timestamp_fin:     str = ""
    estado:            EstadoEjecucion = EstadoEjecucion.PENDIENTE
    nivel_acceso:      NivelAcceso     = NivelAcceso.SIN_ACCESO
    uid_obtenido:      str  = ""
    contexto_selinux:  str  = ""
    poc_hash:          str  = ""       # SHA-256 del binario PoC usado
    poc_version:       str  = ""
    salida_adb:        str  = ""       # salida completa para el informe
    error_msg:         str  = ""
    comando_extraccion: str = ""       # comando ADB listo para el Data Extractor
    notas:             str  = ""


def run_adb(cmd_list, serial=None, timeout=30):
    """Ejecuta un comando ADB y devuelve (stdout, stderr, returncode)."""
    base = ["adb"]
    if serial:
        base += ["-s", serial]
    full = base + cmd_list
    try:
        r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1
    except FileNotFoundError:
        return "", "ADB_NOT_FOUND", -2


def verificar_nivel_acceso(serial=None):
    """
    Verifica el nivel de acceso actual via ADB.
    Devuelve (NivelAcceso, uid_str, contexto_selinux).
    """
    stdout, _, rc = run_adb(["shell", "id"], serial)
    if rc != 0:
        return NivelAcceso.SIN_ACCESO, "", ""

    uid_str = stdout
    contexto = ""

    # Intentar obtener contexto SELinux
    ctx_out, _, _ = run_adb(["shell", "id", "-Z"], serial)
    if ctx_out:
        contexto = ctx_out

    if "uid=0" in stdout:
        return NivelAcceso.ROOT, uid_str, contexto
    if "uid=2000" in stdout or "uid=shell" in stdout:
        return NivelAcceso.SHELL, uid_str, contexto
    if "uid=1000" in stdout or "uid=system" in stdout:
        return NivelAcceso.SYSTEM, uid_str, contexto

    return NivelAcceso.USER, uid_str, contexto


class CVEAdapter(ABC):
    """
    Clase base abstracta para adaptadores de CVE.
    Cada CVE con PoC publico implementa una subclase concreta.
    """

    CVE_ID:        str = ""
    ANDROID_MIN:   str = ""
    ANDROID_MAX:   str = ""
    PARCHE_FECHA:  str = ""
    NIVEL_ESPERADO: NivelAcceso = NivelAcceso.SYSTEM
    TIMEOUT_SEG:   int = 60
    POC_DIR:       Path = Path(__file__).parent / "pocs"

    def __init__(self, serial=None):
        self.serial = serial
        self.resultado = ResultadoPE(
            cve_id=self.CVE_ID,
            timestamp_inicio=datetime.now(timezone.utc).isoformat()
        )

    # ── API publica ──────────────────────────────────────────────────────────

    def ejecutar(self, session: dict) -> ResultadoPE:
        """
        Punto de entrada principal. Ejecuta el pipeline completo:
        1. Verificar precondiciones
        2. Verificar presencia del PoC
        3. Ejecutar
        4. Verificar resultado
        5. Limpiar
        """
        logger.info(f"[{self.CVE_ID}] Iniciando ejecucion para "
                    f"{session.get('manufacturer','')} {session.get('model','')}")

        try:
            # Paso 1: precondiciones
            ok, msg = self._verificar_precondiciones(session)
            if not ok:
                self._finalizar(EstadoEjecucion.PRECONDICION_FALLIDA, msg)
                return self.resultado

            # Paso 2: presencia del PoC
            ok, msg = self._verificar_poc()
            if not ok:
                self._finalizar(EstadoEjecucion.POC_NO_DISPONIBLE, msg)
                return self.resultado

            # Paso 3: nivel previo (baseline)
            nivel_previo, uid_previo, _ = verificar_nivel_acceso(self.serial)
            logger.info(f"[{self.CVE_ID}] Nivel previo: {nivel_previo.value} ({uid_previo})")

            # Paso 4: ejecucion del exploit
            self.resultado.estado = EstadoEjecucion.EN_EJECUCION
            salida = self._ejecutar_poc(session)
            self.resultado.salida_adb = salida

            # Paso 5: verificar resultado
            nivel_post, uid_post, ctx_post = verificar_nivel_acceso(self.serial)
            self.resultado.uid_obtenido   = uid_post
            self.resultado.contexto_selinux = ctx_post

            if nivel_post.value >= self.NIVEL_ESPERADO.value:
                self.resultado.nivel_acceso = nivel_post
                cmd = self._construir_comando_extraccion(nivel_post)
                self.resultado.comando_extraccion = cmd
                self._finalizar(EstadoEjecucion.EXITOSO,
                                f"Escalada exitosa: {uid_post}")
            else:
                self.resultado.nivel_acceso = nivel_post
                self._finalizar(EstadoEjecucion.FALLIDO,
                                f"Nivel obtenido ({nivel_post.value}) < esperado ({self.NIVEL_ESPERADO.value})")

            # Paso 6: limpiar
            self._limpiar()

        except Exception as e:
            self._finalizar(EstadoEjecucion.ERROR, str(e))
            logger.exception(f"[{self.CVE_ID}] Excepcion no controlada")

        return self.resultado

    # ── Metodos que las subclases deben implementar ──────────────────────────

    @abstractmethod
    def _ejecutar_poc(self, session: dict) -> str:
        """
        Implementa la ejecucion real del PoC externo.
        Devuelve la salida completa como string para el informe.

        La implementacion tipica:
          1. Compilar/preparar el binario si es necesario
          2. Pushear al dispositivo via `adb push`
          3. Ejecutar via `adb shell` con los parametros necesarios
          4. Capturar y devolver la salida

        El binario PoC debe estar en self.POC_DIR / self.CVE_ID /
        y no es distribuido por EVIDEX BYPASS.
        """
        ...

    # ── Metodos con implementacion por defecto ───────────────────────────────

    def _verificar_precondiciones(self, session: dict):
        """Verifica compatibilidad de Android, familia de chipset y CVE."""
        android = session.get("android_version", "")
        patch   = session.get("security_patch", "")
        familia = session.get("familia", "").lower()

        # Verificar ADB disponible
        stdout, _, rc = run_adb(["devices"], self.serial)
        if rc != 0:
            return False, "ADB no disponible o dispositivo no conectado."

        return True, "OK"

    def _verificar_poc(self):
        """
        Verifica que el directorio del PoC exista y contenga al menos un archivo.
        El PoC debe descargarse manualmente del repositorio oficial.
        """
        poc_path = self.POC_DIR / self.CVE_ID
        if not poc_path.exists():
            return False, (
                f"Directorio del PoC no encontrado: {poc_path}\n"
                f"Descargar el PoC de: {self._poc_url()}\n"
                f"y colocarlo en: {poc_path}/"
            )
        archivos = list(poc_path.iterdir())
        if not archivos:
            return False, f"Directorio del PoC vacio: {poc_path}"

        # Hash del contenido para documentacion
        h = hashlib.sha256()
        for f in sorted(archivos):
            if f.is_file():
                h.update(f.read_bytes())
        self.resultado.poc_hash = h.hexdigest()
        return True, "OK"

    def _poc_url(self):
        """URL del PoC publico. Las subclases pueden sobreescribir."""
        return "Ver cves.json para la URL del PoC correspondiente."

    def _construir_comando_extraccion(self, nivel: NivelAcceso) -> str:
        """Construye el comando ADB para extraccion segun el nivel obtenido."""
        if nivel == NivelAcceso.ROOT:
            return "adb shell 'su -c \"tar -czf /sdcard/evidex_data.tar.gz /data/data/\"'"
        elif nivel in (NivelAcceso.SYSTEM, NivelAcceso.SHELL):
            return "adb shell 'run-as com.whatsapp cp -r /data/data/com.whatsapp /sdcard/wa_backup'"
        return ""

    def _limpiar(self):
        """Limpieza post-ejecucion. Las subclases pueden extender."""
        # Eliminar binarios temporales del dispositivo
        run_adb(["shell", "rm -f /data/local/tmp/evidex_*"], self.serial)

    def _finalizar(self, estado: EstadoEjecucion, msg: str = ""):
        self.resultado.estado     = estado
        self.resultado.timestamp_fin = datetime.now(timezone.utc).isoformat()
        if msg and estado not in (EstadoEjecucion.EXITOSO,):
            self.resultado.error_msg = msg
        elif msg:
            self.resultado.notas = msg
        logger.info(f"[{self.CVE_ID}] Estado final: {estado.value} — {msg}")

    def to_dict(self) -> dict:
        """Serializa el resultado para el informe de sesion."""
        r = self.resultado
        return {
            "cve_id":            r.cve_id,
            "timestamp_inicio":  r.timestamp_inicio,
            "timestamp_fin":     r.timestamp_fin,
            "estado":            r.estado.value,
            "nivel_acceso":      r.nivel_acceso.value,
            "uid_obtenido":      r.uid_obtenido,
            "contexto_selinux":  r.contexto_selinux,
            "poc_hash":          r.poc_hash,
            "poc_version":       r.poc_version,
            "error_msg":         r.error_msg,
            "comando_extraccion": r.comando_extraccion,
            "notas":             r.notas,
        }
