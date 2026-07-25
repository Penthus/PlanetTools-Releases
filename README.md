# Planet Tools

## Install

1. Open the [latest release](https://github.com/Penthus/PlanetTools-Releases/releases/latest).
2. Download `PlanetTools-vX.Y.Z-win-x64-Setup.exe`. Do not download either
   automatically generated **Source code** archive.
3. Compare the installer's SHA-256 with `SHA256SUMS.txt` from the same release.
4. Run the installer and follow the Windows prompts.

The installer is self-contained for Windows 10/11 x64. Npcap is required only
for live capture; Planet Collection works without it. Planet Tools does not
bundle or silently install Npcap. If needed, use the installer's optional link
or the Sniffer prompt to open the [official Npcap download page](https://npcap.com/#download),
complete its installer, then select **Recheck** or reopen Sniffer.

Windows may display a SmartScreen warning while releases are unsigned. Verify
the SHA-256 before running a downloaded installer.

## Safe support

When reporting a problem, include the Planet Tools version, Windows version,
the visible application state, and sanitized reproduction steps. Never attach
packet captures, raw streams, decoded sessions, databases, logs, credentials,
exports containing player data, or screenshots containing personal details.
