<div align="center">

&#x20; <img src="assets/logo.svg" width="112" height="112" alt="ArcSteam Logo" />

&#x20; <h1>ArcSteam</h1>

&#x20; <p><strong>Live Torrent-to-Unpack Streamer \& Universal Turbo Repack Engine for Windows</strong></p>



&#x20; <p>

&#x20;   <a href="https://github.com/eadxmz/ArcSteam/actions/workflows/build.yml">

&#x20;     <img src="https://github.com/eadxmz/ArcSteam/actions/workflows/build.yml/badge.svg" alt="Build Status" />

&#x20;   </a>

&#x20;   <img src="https://img.shields.io/badge/Rust-2024\_Edition-orange?logo=rust" alt="Rust 2024" />

&#x20;   <img src="https://img.shields.io/badge/Platform-Windows\_x64-0078D6?logo=windows" alt="Windows x64" />

&#x20;   <img src="https://img.shields.io/badge/VFS-WinFsp\_Demand--Paged-22D3EE" alt="WinFsp VFS" />

&#x20;   <a href="LICENSE">

&#x20;     <img src="https://img.shields.io/badge/License-AGPL--3.0-6366F1" alt="License: AGPL-3.0" />

&#x20;   </a>

&#x20; </p>

</div>



\---



\## Why ArcSteam?



Modern game repacks compress tens of gigabytes using multi-stage pipelines (`xtool` + `srep` + `lolz`). Standard installers bottleneck on three fronts:



1\. \*\*Sequential Wait Time\*\*: You have to wait for 100% of a torrent to download before installation can even begin.

2\. \*\*Conservative Memory Caps \& Same-Drive Thrashing\*\*: Stock installers cap `SREP` deduplication at 2–4 GB of RAM and swap gigabytes of temporary blocks onto the same drive they are reading from.

3\. \*\*Real-Time Antivirus Overhead\*\*: Windows Defender scans every unpacked chunk as `unarc.dll` writes it to disk, drastically throttling throughput.



\*\*ArcSteam\*\* solves both problems in a single lightweight Rust binary—streaming archives \*\*live while they download\*\* through a demand-paged virtual drive (`Z:\\`) and running headless, RAM-unlocked extraction with split-drive I/O routing.



\---



\## Architecture



```text

┌─────────────────────────────────────┐

│   BitTorrent / Magnet Swarm         │

│   (librqbit v9.1 + Piece Booster)   │

└──────────────────┬──────────────────┘

&#x20;                  │ HTTP Range (206 Partial Content) + 16 MB EOF Tail-Prime

&#x20;                  ▼

┌─────────────────────────────────────┐

│   WinFsp Virtual Drive (Z:\\)        │

│   • Serves ready pieces from disk   │

│   • Blocks cleanly on missing bytes │

│   • Boosts piece priority on seek   │

└──────────────────┬──────────────────┘

&#x20;                  │ Zero-modification file I/O

&#x20;                  ▼

┌─────────────────────────────────────┐

│   Headless Turbo Unpack Engine      │

│   • innounp {tmp} plugin dissector  │

│   • Dynamic cls-srep / arc.ini RAM  │

│   • Split-drive SSD TEMP routing    │

│   • RAII Defender exclusion guard   │

└──────────────────┬──────────────────┘

&#x20;                  │ HIGH\_PRIORITY\_CLASS

&#x20;                  ▼

┌─────────────────────────────────────┐

│   Target Game Directory + Registry  │

└─────────────────────────────────────┘

```



\---



\## Key Features



\* \*\*Install Live While Downloading (`Z:\\` Virtual Filesystem)\*\*

&#x20; Pre-fetches `setup.exe` and the final \*\*16 MB EOF directory footer\*\* of FreeArc archives (`ArC\\x01`) so `unarc.exe` initializes immediately. Whenever decompression outpaces your download speed, the WinFsp read callback promotes the exact missing torrent pieces to critical priority and waits cleanly without triggering `ISDone.dll` or `unarc -1` errors.

\* \*\*Universal Repack Blueprint \& Magic-Byte Detection\*\*

&#x20; Inspects file headers (`ArC\\x01`, `idska32`, `7z`, `Rar!`, `PK`) rather than relying blindly on file extensions—supporting FitGirl, DODI, R.G. Mechanics, ElAmigos, KaOs, GOG Inno, Scene ISOs, and portable archives.

\* \*\*Pre-Download Optional \& Language Filtering\*\*

&#x20; Automatically identifies and unchecks non-English `selective-\*` voice packs, soundtracks, and optional bonus videos before downloading a single byte.

\* \*\*Dynamic `cls-srep.ini` \& `arc.ini` RAM Patcher\*\*

&#x20; Extracts the repack's own `{tmp}` plugins via `innounp` and rewrites memory and thread limits to utilize \~65% of available system RAM and all logical CPU cores.

\* \*\*Split-Drive I/O \& Temporary Defender RAII Guard\*\*

&#x20; Routes `SREP` virtual memory swaps (`TEMP`/`TMP`) to your fastest NVMe/SSD while reading archives from secondary storage and writing game files to your target drive. Automatically adds temporary Windows Defender exclusions during extraction and reverts them on completion.

\* \*\*Automated `\[Registry]` \& Post-Install Replay\*\*

&#x20; Parses `install\_script.iss` to apply required game registry keys and execute local `xdelta`/`bink` post-install steps headlessly.



\---



\## Supported Repack Formats



| Format Archetype | Detection Signature | Execution Strategy |

| :--- | :--- | :--- |

| \*\*FitGirl Multi-BIN\*\* | `setup.exe` + `fg-\*.bin` / `setup-fitgirl-\*.bin` | Selective pack filter + 16 MB EOF prime + WinFsp VFS + Headless `unarc` |

| \*\*DODI Monolithic\*\* | `Setup.exe` + `data1.doi` | Byte-level WinFsp VFS + 16 MB EOF prime + Headless `unarc` |

| \*\*Classic / Scene FreeArc\*\* | `setup.exe` + `.bin` / `.arc` / `.kab` / `.bf` / `.cpk` | Magic-byte verified `unarc` + `install\_script.iss` `\[Registry]` replay |

| \*\*GOG Pure Inno Setup\*\* | `setup\_\*.exe` + `setup\_\*.bin` (`idska32`) | Zero-EOF-wait sequential stream directly via `innoextract` |

| \*\*Portable / Scene Archives\*\* | `.7z`, `.rar`, `.zip`, `.iso`, `.001`, `.zst` | High-priority `7z` extraction with split-drive `TEMP` |

| \*\*Generic Setup Installers\*\* | NSIS / InstallShield / SFX `.exe` | Elevated Turbo launch with Defender bypass \& SSD `TEMP` routing |



\---



\## Setup \& Prerequisites



\### 1. Runtime Requirements (Windows x64)

\* \*\*WinFsp 2.1+\*\*: Required for mounting the live `Z:\\` virtual drive during torrent streaming. Download from \[winfsp.dev](https://winfsp.dev/).

\* \*\*Administrator Privileges\*\*: Required when mounting virtual drive letters and toggling temporary Windows Defender exclusions.



\### 2. Helper Binaries (`tools/`)

Place the following CLI utilities inside a `tools/` folder next to `arcsteam.exe`:



```text

ArcSteam/

├── arcsteam.exe

└── tools/

&#x20;   ├── innounp.exe       # Extracts setup.exe {tmp} plugins \& install\_script.iss

&#x20;   ├── unarc.exe         # Headless FreeArc decompressor

&#x20;   ├── innoextract.exe   # Direct GOG / Inno Setup stream extractor

&#x20;   ├── 7z.exe            # Scene ISO / 7z / RAR / ZIP extractor

&#x20;   └── 7z.dll

```



\### 3. Building from Source

Requires \*\*Rust 1.95+ (2024 Edition)\*\* and the \*\*WinFsp Developer SDK\*\* (`ADDLOCAL=ALL`):



```powershell

cargo build --release

```



\---



\## License



Licensed under the \*\*GNU Affero General Public License v3.0\*\* — see \[LICENSE](LICENSE) for details.

