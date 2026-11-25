#!/usr/bin/env python3

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD_ROOT = ROOT / "build"
DIST = ROOT / "dist"
PROJECT_BIN = "esp_vault_secure_firmware.bin"

def idf_command() -> list[str]:

    idf_py = Path(os.environ.get("IDF_PATH", "")) / "tools" / "idf.py"
    if os.environ.get("IDF_PATH") and idf_py.is_file():
        return [sys.executable, str(idf_py)]
    return ["idf.py"]

def version_args() -> list[str]:

    v = os.environ.get("FIRMWARE_VERSION")
    return [f"-DPROJECT_VER={v}"] if v else []

def run_idf(target: str, build_dir: Path, sdkconfig: Path, *args: str, variant: str = "vault") -> None:
    env = os.environ.copy()
    env["SDKCONFIG"] = str(sdkconfig)
    defaults = [ROOT / "sdkconfig.defaults", ROOT / f"sdkconfig.defaults.{target}"]
    env.pop("VAULT_WITH_PASSKEY", None)
    if variant == "vaultkey":

        defaults.append(ROOT / "sdkconfig.defaults.vaultkey")
        env["VAULT_WITH_PASSKEY"] = "1"
    env["SDKCONFIG_DEFAULTS"] = ";".join(str(p) for p in defaults)
    subprocess.run(

        [*idf_command(), "-B", str(build_dir), f"-DSDKCONFIG={sdkconfig}", *version_args(), *args],
        cwd=ROOT,
        env=env,
        check=True,
    )

def main() -> int:
    key = ROOT / "secure_boot_signing_key.pem"
    if not key.is_file():
        print(
            "Missing secure_boot_signing_key.pem. Generate and protect your own "
            "RSA-3072 OTA signing key before building.",
            file=sys.stderr,
        )
        return 2
    if idf_command() == ["idf.py"] and shutil.which("idf.py") is None:
        print("idf.py was not found; activate an ESP-IDF 5.x environment first.", file=sys.stderr)
        return 2

    DIST.mkdir(parents=True, exist_ok=True)
    for target, variant in (("esp32c3", "vault"), ("esp32c6", "vault"), ("esp32s3", "vault"), ("esp32s3", "vaultkey")):
        name = target if variant == "vault" else f"{target}-{variant}"
        target_build = BUILD_ROOT / name
        sdkconfig = BUILD_ROOT / f"sdkconfig.{name}"
        run_idf(target, target_build, sdkconfig, "set-target", target, variant=variant)
        run_idf(target, target_build, sdkconfig, "build", variant=variant)
        factory = DIST / f"{target}-{variant}-factory.bin"
        run_idf(target, target_build, sdkconfig, "merge-bin", "-o", str(factory), variant=variant)
        ota = target_build / PROJECT_BIN
        if not ota.is_file() or not factory.is_file():
            raise RuntimeError(f"IDF did not produce both expected images for {name}")
        shutil.copy2(ota, DIST / f"{target}-{variant}-ota.bin")
        print(f"Built {factory.name} and {target}-{variant}-ota.bin")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
