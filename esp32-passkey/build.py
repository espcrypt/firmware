#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"
DIST = ROOT / "dist"

def idf() -> list[str]:
    idf_py = Path(os.environ.get("IDF_PATH", "")) / "tools" / "idf.py"
    if os.environ.get("IDF_PATH") and idf_py.is_file():
        return [sys.executable, str(idf_py)]
    return ["idf.py"]

def run(*args: str) -> None:
    v = os.environ.get("FIRMWARE_VERSION")
    subprocess.run([*idf(), "-B", str(BUILD), *([f"-DPROJECT_VER={v}"] if v else []), *args], cwd=ROOT, check=True)

def main() -> int:
    if idf() == ["idf.py"] and shutil.which("idf.py") is None:
        print("idf.py was not found; activate an ESP-IDF 5.x environment first.", file=sys.stderr)
        return 2
    DIST.mkdir(parents=True, exist_ok=True)
    run("set-target", "esp32s3")
    run("build")
    factory = DIST / "esp32s3-passkey-factory.bin"
    run("merge-bin", "-o", str(factory))
    print(f"Built {factory.name}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
