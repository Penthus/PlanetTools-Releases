from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "verify_release", ROOT / "scripts" / "verify_release.py"
)
assert SPEC and SPEC.loader
verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


def pe(machine: int) -> bytes:
    data = bytearray(256)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    return bytes(data)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def synthetic_assets(root: Path):
    tag = "v0.1.1"
    installer_name = "PlanetTools-v0.1.1-win-x64-Setup.exe"
    installer = pe(0x014C)
    (root / installer_name).write_bytes(installer)
    installed_files = {
        "PlanetTools.Launcher.Wpf/SEPT_PlanetTools.Launcher.Wpf.exe": "0" * 64,
        "PlanetSniffer.Wpf/SEPT_PlanetSniffer.Wpf.exe": "1" * 64,
        "PlanetCollection.Wpf/SEPT_PlanetCollection.Wpf.exe": "2" * 64,
        "PlanetCollection.Wpf/Assets/extractor-catalog.json": "3" * 64,
        "GalaxyMap.Wpf/SEPT_GalaxyMap.Wpf.exe": "4" * 64,
    }
    manifest = {
        "schema_version": 1,
        "version": "0.1.1",
        "tag": tag,
        "target": "windows-x64",
        "dotnet": "10.0",
        "self_contained": True,
        "package_kind": "inno-setup",
        "authenticode_signed": False,
        "provenance": "public-release-promotion",
        "installer": {
            "name": installer_name,
            "sha256": digest_bytes(installer),
            "size": len(installer),
        },
        "installed_files": installed_files,
    }
    manifest_path = root / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    checksums = (
        f"{digest_bytes(installer)}  {installer_name}\n"
        f"{verify.sha256(manifest_path)}  release-manifest.json\n"
    )
    checksums_path = root / "SHA256SUMS.txt"
    checksums_path.write_text(checksums, encoding="ascii")
    expected = {
        installer_name: digest_bytes(installer),
        "release-manifest.json": verify.sha256(manifest_path),
        "SHA256SUMS.txt": verify.sha256(checksums_path),
    }
    return tag, expected


class PathPolicyTests(unittest.TestCase):
    def test_accepts_required_files_and_runtime(self):
        verify.validate_installed_paths(
            verify.REQUIRED_INSTALLED_FILES
            | {"PlanetSniffer.Wpf/System.Text.Json.dll"}
        )

    def test_rejects_source_and_traversal(self):
        with self.assertRaisesRegex(RuntimeError, "not allowlisted"):
            verify.validate_installed_paths(
                verify.REQUIRED_INSTALLED_FILES | {"PlanetSniffer.Wpf/tool.cs"}
            )
        with self.assertRaisesRegex(RuntimeError, "not allowlisted"):
            verify.validate_installed_paths(
                verify.REQUIRED_INSTALLED_FILES | {"../escape.dll"}
            )

    def test_rejects_too_many_installed_files(self):
        excessive = {
            f"GalaxyMap.Wpf/runtime-{index}.dll"
            for index in range(verify.MAX_INSTALLED_FILES + 1)
        }
        with self.assertRaisesRegex(RuntimeError, "too many files"):
            verify.validate_installed_paths(excessive)


class PePolicyTests(unittest.TestCase):
    def test_accepts_x86_installer_bootstrap_and_x64_apps(self):
        verify.require_pe_data(pe(0x014C), "setup.exe", x64=False)
        verify.require_pe_data(pe(0x8664), "app.exe", x64=True)

    def test_rejects_x86_application(self):
        with self.assertRaisesRegex(RuntimeError, "not Windows x64"):
            verify.require_pe_data(pe(0x014C), "app.exe", x64=True)


class ExactAssetTests(unittest.TestCase):
    def test_accepts_exact_synthetic_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tag, expected = synthetic_assets(root)
            manifest = verify.load_and_verify_assets(tag, root, expected)
            self.assertEqual("0.1.1", manifest["version"])

    def test_rejects_extra_asset_and_dispatch_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tag, expected = synthetic_assets(root)
            (root / "unexpected.txt").write_text("no", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "differ from allowlist"):
                verify.load_and_verify_assets(tag, root, expected)
            (root / "unexpected.txt").unlink()
            expected["SHA256SUMS.txt"] = "f" * 64
            with self.assertRaisesRegex(RuntimeError, "Dispatch digest mismatch"):
                verify.load_and_verify_assets(tag, root, expected)


if __name__ == "__main__":
    unittest.main()
