"""Verify exact Planet Tools release assets and installed application files."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct


TAG_RE = re.compile(r"^v([0-9]+\.[0-9]+\.[0-9]+)$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_INSTALLER_SIZE = 256 * 1024 * 1024
MAX_INSTALLED_FILE_SIZE = 160 * 1024 * 1024
MAX_INSTALLED_TOTAL_SIZE = 768 * 1024 * 1024
MAX_INSTALLED_FILES = 1536
REQUIRED_INSTALLED_FILES = {
    "PlanetSniffer.Wpf/PlanetSniffer.Wpf.exe",
    "PlanetCollection.Wpf/PlanetCollection.Wpf.exe",
    "PlanetCollection.Wpf/Assets/extractor-catalog.json",
    "GalaxyMap.Wpf/GalaxyMap.Wpf.exe",
}
ALLOWED_INSTALLED_SUFFIXES = {".exe", ".dll", ".json", ".config", ".dat"}


def sha256(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def require_pe_data(data: bytes, label: str, *, x64: bool) -> None:
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise RuntimeError(f"{label} is not a PE executable")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 6 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise RuntimeError(f"{label} has an invalid PE header")
    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    if x64 and machine != 0x8664:
        raise RuntimeError(f"{label} is not Windows x64")
    if not x64 and machine not in {0x014C, 0x8664}:
        raise RuntimeError(f"{label} has an unsupported Windows machine type")


def expected_asset_names(tag: str) -> set[str]:
    match = TAG_RE.fullmatch(tag)
    if not match:
        raise RuntimeError("Dispatch tag is not strict semantic version form")
    return {
        f"PlanetTools-{tag}-win-x64-Setup.exe",
        "SHA256SUMS.txt",
        "release-manifest.json",
    }


def parse_expected(value: str, *, base64_encoded: bool) -> dict[str, str]:
    if base64_encoded:
        try:
            value = base64.b64decode(value, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError("Base64 dispatch digest map is malformed") from exc
    result = json.loads(value)
    if not isinstance(result, dict):
        raise RuntimeError("Dispatch digest map is malformed")
    return result


def validate_installed_paths(paths: set[str]) -> None:
    if len(paths) > MAX_INSTALLED_FILES:
        raise RuntimeError("Installed package contains too many files")
    if not REQUIRED_INSTALLED_FILES.issubset(paths):
        raise RuntimeError("Installed package is missing a required file")
    for name in paths:
        pure = PurePosixPath(name)
        if (
            name != pure.as_posix()
            or pure.is_absolute()
            or ".." in pure.parts
            or "\\" in name
            or pure.suffix.lower() not in ALLOWED_INSTALLED_SUFFIXES
        ):
            raise RuntimeError(f"Installed path is not allowlisted: {name}")


def load_and_verify_assets(tag: str, assets: Path, expected: dict[str, str]):
    names = expected_asset_names(tag)
    actual = {path.name for path in assets.iterdir() if path.is_file()}
    if actual != names:
        raise RuntimeError(f"Release assets differ from allowlist: {sorted(actual)}")
    if set(expected) != names or any(
        not isinstance(value, str) or not HASH_RE.fullmatch(value)
        for value in expected.values()
    ):
        raise RuntimeError("Dispatch digest map is malformed or incomplete")
    for name in names:
        if sha256(assets / name) != expected[name]:
            raise RuntimeError(f"Dispatch digest mismatch: {name}")

    installer_name = next(name for name in names if name.endswith(".exe"))
    installer = assets / installer_name
    if installer.stat().st_size > MAX_INSTALLER_SIZE:
        raise RuntimeError("Installer exceeds the size limit")
    require_pe_data(installer.read_bytes(), installer_name, x64=False)

    checksum_lines = (assets / "SHA256SUMS.txt").read_text(
        encoding="ascii"
    ).splitlines()
    checksums: dict[str, str] = {}
    for line in checksum_lines:
        parts = line.split("  ")
        if (
            len(parts) != 2
            or not HASH_RE.fullmatch(parts[0])
            or Path(parts[1]).name != parts[1]
            or parts[1] in checksums
        ):
            raise RuntimeError("SHA256SUMS.txt has invalid syntax")
        checksums[parts[1]] = parts[0]
    if set(checksums) != {installer_name, "release-manifest.json"}:
        raise RuntimeError("SHA256SUMS.txt has unexpected entries")
    for name, digest in checksums.items():
        if sha256(assets / name) != digest:
            raise RuntimeError(f"Checksum-file digest mismatch: {name}")

    manifest = json.loads(
        (assets / "release-manifest.json").read_text(encoding="utf-8-sig")
    )
    version = tag.removeprefix("v")
    installer_metadata = manifest.get("installer")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("version") != version
        or manifest.get("tag") != tag
        or manifest.get("target") != "windows-x64"
        or manifest.get("dotnet") != "10.0"
        or manifest.get("self_contained") is not True
        or manifest.get("package_kind") != "inno-setup"
        or not isinstance(manifest.get("authenticode_signed"), bool)
        or manifest.get("provenance") != "public-release-promotion"
        or installer_metadata != {
            "name": installer_name,
            "sha256": expected[installer_name],
            "size": installer.stat().st_size,
        }
    ):
        raise RuntimeError("Release manifest metadata is invalid")
    installed_files = manifest.get("installed_files")
    if (
        not isinstance(installed_files, dict)
        or any(
            not isinstance(name, str)
            or not isinstance(digest, str)
            or not HASH_RE.fullmatch(digest)
            for name, digest in installed_files.items()
        )
    ):
        raise RuntimeError("Manifest installed-file map is invalid")
    validate_installed_paths(set(installed_files))
    return manifest


def verify_installed(root: Path, manifest: dict) -> None:
    actual: dict[str, Path] = {}
    total = 0
    for path in root.rglob("*"):
        if not path.is_file() or (
            path.parent == root and path.name.lower().startswith("unins")
        ):
            continue
        relative = path.relative_to(root).as_posix()
        if path.stat().st_size > MAX_INSTALLED_FILE_SIZE:
            raise RuntimeError(f"Installed file exceeds size limit: {relative}")
        total += path.stat().st_size
        if total > MAX_INSTALLED_TOTAL_SIZE:
            raise RuntimeError("Installed package exceeds total size limit")
        actual[relative] = path
    expected = manifest["installed_files"]
    if set(actual) != set(expected):
        raise RuntimeError("Installed files differ from the manifest allowlist")
    for name, path in actual.items():
        if sha256(path) != expected[name]:
            raise RuntimeError(f"Installed-file digest mismatch: {name}")
    for name in REQUIRED_INSTALLED_FILES:
        if name.endswith(".exe"):
            require_pe_data(actual[name].read_bytes(), name, x64=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--installed-root", type=Path)
    expected_group = parser.add_mutually_exclusive_group(required=True)
    expected_group.add_argument("--expected-json")
    expected_group.add_argument("--expected-json-base64")
    args = parser.parse_args()
    expected = parse_expected(
        args.expected_json or args.expected_json_base64,
        base64_encoded=bool(args.expected_json_base64),
    )
    manifest = load_and_verify_assets(args.tag, args.assets, expected)
    if args.installed_root:
        verify_installed(args.installed_root, manifest)
    print(f"Verified release assets for {args.tag}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
