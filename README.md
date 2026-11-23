<div align="center">

<img src="assets/logo.svg" alt="ArcSteam Logo" width="96" height="96" />

# ArcSteam

**High-Performance Windows Archive Unpacker, Demand-Paged BitTorrent VFS Streamer & Zstd Preservation Vault**

[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-7c3aed?style=flat-square)](#)
[![Rust](https://img.shields.io/badge/Rust-2024%20Edition-a855f7?style=flat-square)](#)
[![Formats](https://img.shields.io/badge/Formats-FreeArc%20%7C%20Inno%20Setup%20%7C%20Zstd%20%7C%207z%20%7C%20ISO-4ade80?style=flat-square)](#)

*A self-contained, single-executable Windows desktop utility built in Rust for hardware-ceiling extraction of FreeArc, Inno Setup, 7z, and Zstd archives—supporting live demand-paged extraction over BitTorrent and 500+ MB/s personal archival backups.*

</div>

---

## Overview

Modern ultra-compressed distribution archives (combining **Inno Setup** containers with **FreeArc**, **SREP**, **LOLZ**, and external **CLS** codecs) often suffer from slow I/O pipelines, conservative memory caps, single-threaded secondary steps, and rigid installer wrappers.

**ArcSteam** replaces legacy extraction workflows with a modern **Rust** orchestration engine and a refined **Studio Dark** native interface (`eframe`/`egui` 0.37 with Windows Segoe UI typography). It automatically detects archive layouts, dynamically tunes memory and thread budgets to your live hardware, extracts directly at peak throughput, and lets you convert installed software or DRM-free games into ultra-fast **Zstandard (`.tar.zst`)** preservation vaults.

---

## Key Features

### 1. Zero-Setup Single Executable
* **All Extraction Engines Built-In**: GitHub Actions automatically compiles and embeds `unarc_host32.exe` (32-bit `/LARGEADDRESSAWARE` native `unarc.dll` host), `7z.exe` + `7z.dll`, `innoextract.exe`, `innounp.exe`, fallback `unarc.exe`, and the official signed **WinFsp MSI** directly inside `arcsteam.exe`.
* **Automatic Byte-Exact Synchronization**: On launch, ArcSteam verifies and extracts embedded helpers transparently into `%LOCALAPPDATA%\ArcSteam\bin\` (while still allowing optional overrides in a local `tools/` directory).
* **1-Click Built-In WinFsp Setup**: Install the WinFsp kernel driver silently from inside the app whenever you want to use live virtual-drive streaming—no external browser downloads or reboots required.

### 2. Universal Archive & Installer Engine
* **Native FreeArc & CLS Codec Host (`unarc_host32.exe`)**: Dissects Inno Setup containers (`setup.exe`) to extract their exact bundled `unarc.dll` and CLS plugins, initializes the required `Init_MapFile_` and `Global\Init_MapFile_` shared-memory handshakes with permissive security descriptors, and streams real-time progress callbacks.
* **Pure Inno Setup Support**: Streams standard Inno Setup installers (such as DRM-free GOG and open-source Windows distributions) directly via headless `innoextract`.
* **Standard Archives & Disk Images**: Full support for `.7z`, `.rar`, `.zip`, and `.iso` via embedded 7-Zip CLI.
* **Selective & Multi-Title Bundles**:
  * Automatically identifies optional/extra archive components so you can include or skip them before extraction.
  * Automatically detects multi-title collections (bundles containing 2+ separate titles under `{app}\`) and displays checkboxes to install only the titles you want using native archive exclusions (`-x` / `-xr!`).
* **Full Post-Unpack Finalization**:
  * Automatically discovers and executes post-unpack data reconstruction batch scripts (`build*.bat`, `unpack*.bat`, etc.) with smart working-directory detection and cleanup.
  * Deploys embedded `{app}`, `{userdocs}`, and `{localappdata}` installer files, creates `[Dirs]` profile paths, and replays `[Registry]` keys across both 32-bit (`WOW6432Node` `/reg:32`) and 64-bit (`/reg:64`) registry views.
  * Configurable **Desktop Icon** and **Start Menu Folder** controls right on the main Install card.

### 3. Live Demand-Paged BitTorrent-to-Unpack Streaming
* **In-Process `librqbit` + `WinFsp` Virtual Drive**: Mounts active BitTorrent downloads as a read-only virtual filesystem (`Z:\` by default) so extraction can run concurrently with downloading.
* **Solid-Block Stream Optimization**:
  * Primes the final **16 MB EOF directory footer** and opening **8 MB header window** before unpacking begins.
  * Serves sequential reads through a **4 MB in-RAM sliding cache** backed by a dedicated **32 MB contiguous swarm read-ahead prefetcher** that immediately re-anchors on seeks.
  * Configured with a **10-minute IRP timeout** to prevent Windows I/O timeout errors on high-latency peers.

### 4. Hardware-Ceiling Speed Optimizations
* **Dynamic Auto-RAM Engine**: Polls live available system memory prior to extraction and allocates up to 65% of total RAM to SREP while reserving `max(2 GB, 22% of total RAM)` for Windows so your desktop remains responsive (with manual slider override in Turbo Settings).
* **64-Bit SREP Offload & PE Bitness Guard**: Inspects binary PE headers (`x64`, `x86-LAA`, `x86`) to route large deduplication jobs to 64-bit workers when available, or safely clamp memory on 32-bit hosts to prevent out-of-memory crashes.
* **Section-Aware `CLS.ini` & `arc.ini` Tuning**: Unlocks `MaxThreadsUsage=100%`, increases shared-memory IPC buffers (`transfer_ReadBufSize` / `transfer_WriteBufSize` to `4m`, `[srep]` `Bufsize` to `32m`), and routes swap paths to your fastest SSD.
* **Split-Drive I/O & Parallel Secondary Extraction**: Separates source, SSD `TEMP`/`TMP`, and destination drives; unpacks smaller non-CLS secondary archives (`< 600 MB`) **2 at a time in parallel** inside isolated worker directories.
* **Crash-Safe System Guards (RAII)**:
  * Temporary Windows Defender path exclusions logged to `%LOCALAPPDATA%\ArcSteam\active_defender_exclusions.txt` with automatic stale-rule recovery on next launch in case of force-kill or power loss.
  * Automatic **High Performance** Windows power plan switching (`powercfg`) during active jobs with clean restoration on completion or cancel.
  * Automatic Windows sleep prevention (`SetThreadExecutionState`) while jobs run.

### 5. Process Control, Batch Queue & Telemetry
* **Safe Cancel & True Pause/Resume**: Attaches all child extractors to a **Win32 Job Object** so **Cancel** terminates the entire nested worker tree cleanly, while **Pause / Resume** suspends and resumes all worker processes via `NtSuspendProcess` / `NtResumeProcess`.
* **Anti-"Freeze" Live Telemetry**: Displays active worker process name, total worker tree RAM (MB), live disk write speed (MB/s), download speed (MB/s), byte-weighted progress, smoothed ETA, and pre-flight free disk space checks.
* **Unattended Batch Queue**: Drag-and-drop multiple folders or `.torrent` files onto the window to queue them sequentially, with optional **Sleep PC** or **Shutdown PC (30s delay)** actions on completion.

### 6. Native Library & 2-Mode Uninstaller (`Installed` Tab)
* **Safe Folder Tracking**: Snapshots the destination directory before and after extraction so only folders created by that installation are tracked—sibling folders are never touched.
* **Windows Installed Apps Integration**: Registers cleanly in Windows **Settings → Apps → Installed Apps** (`arcsteam.exe --uninstall <id>`) alongside a Start Menu Uninstall shortcut.
* **Two Uninstall Modes**:
  * **Uninstall (Keep Saves & Profile)**: Removes installed program files, Desktop/Start Menu shortcuts, and uninstall entries while keeping user saves, configs, and profiles in `Documents` / `AppData`.
  * **Complete Wipe**: Removes program files, shortcuts, detected profile/save directories, and all registered 32-bit/64-bit registry keys.

### 7. Preservation & Verification Tools (`Tools` Tab)
* **Zstd LDM Preservation Vault (`.tar.zst`)**: Compress installed DRM-free games or software libraries into multi-threaded Zstandard archives using **128 MB Long-Distance Matching (`window_log(27)`)** and **8 MB buffered I/O**. Achieves 20–45% space savings over raw folders while unpacking at **500+ MB/s** (storage-bus limited) for instant future restores.
* **Multi-Core MD5 / SFV Verifier**: Native Rust multi-threaded checksum verifier that automatically discovers `.md5` and `.sfv` manifests and reports `OK`, `Missing`, and `Corrupt` files across all CPU cores.
* **Post-Unpack Repair & Runtime Checker**: Re-run post-unpack builders, metadata deployment, and uninstall manifest registration on an existing installation in seconds, plus check for missing legacy 32-bit DirectX / Visual C++ runtimes.

---

## Architecture Overview

| Module | Responsibility |
| :--- | :--- |
| `src/main.rs` | Studio Dark `eframe`/`egui` 0.37 UI, native Windows font loader, Install / Queue / Installed / Tools views |
| `src/pipeline.rs` | Multi-stage orchestration, parallel secondary extraction, Job Object lifecycle, live telemetry & ETA |
| `src/detect.rs` | Archive magic-byte probing (`FreeArc`, `InnoSlice`, `7z`, `RAR`, `ZIP`, `ISO9660`) and selective pack classification |
| `src/dissect.rs` | Inno Setup container extraction, `[Dirs]`/`[Registry]`/`[Icons]` parser, multi-title detection, `build*.bat` discovery |
| `src/optimizer.rs` | Dynamic Auto-RAM planner, PE bitness inspector, section-aware `CLS.ini`/`arc.ini` tuner, crash-safe Defender guard |
| `src/stream_bridge.rs` | `librqbit` `FileStream` -> `WinFsp` virtual drive bridge, EOF/head priming, 4 MB RAM cache, 32 MB contiguous read-ahead |
| `src/manifest.rs` | Install manifests, Windows Apps uninstall registration, safe 2-mode uninstaller (Keep Profile vs. Complete Wipe) |
| `src/zstd_pack.rs` | Multi-threaded `.tar.zst` encoder/decoder with 128 MB LDM and 8 MB `BufReader`/`BufWriter` I/O |
| `src/verify.rs` | Multi-threaded native Rust MD5 and CRC32/SFV manifest verifier |
| `src/win_sys.rs` | Win32 Job Objects, `NtSuspendProcess`/`NtResumeProcess`, `HighPerformanceGuard`, `KeepAwakeGuard`, UAC/WinFsp helpers |
| `src/embedded_tools.rs` | Byte-exact extraction and resolution of embedded helper binaries and `winfsp.msi` |
| `tools_src/unarc_host32.c` | 32-bit `/LARGEADDRESSAWARE` native `unarc.dll` host with `Init_MapFile_` CLS handshake and 24-arg exclusion support |

---

## Building from Source

### Automated CI Build (Recommended)
Push to `main` or trigger the **Build ArcSteam (Windows x64)** workflow in GitHub Actions (`.github/workflows/build.yml`). The workflow installs the WinFsp SDK, compiles `unarc_host32.exe`, bundles all helper binaries and `winfsp.msi`, compiles the release binary with LTO enabled, and uploads the standalone `arcsteam.exe` artifact.

### Local Build Prerequisites (Windows x64)
1. **Rust Stable** (1.85+ / Rust 2024 Edition) with the `x86_64-pc-windows-msvc` toolchain.
2. **Visual Studio Build Tools** (x86 & x64 C/C++ toolsets for `unarc_host32.c` and Rust MSVC linking).
3. **WinFsp Developer SDK** (`choco install winfsp -y --install-arguments="ADDLOCAL=ALL"`).
4. Place optional helper binaries in `bundled_tools/` before running `cargo build --release` to embed them directly into the executable, or place them in a `tools/` folder next to `arcsteam.exe`.

```cmd
cargo build --release
```

---

## Requirements

* **OS**: Windows 10 or Windows 11 (64-bit)
* **Privileges**: Administrator elevation (requested automatically via embedded UAC manifest) for CLS shared-memory mappings, temporary Defender exclusions, High Performance power switching, Windows Apps registration, and WinFsp mounting.
* **Live BitTorrent Streaming**: WinFsp driver (bundled inside `arcsteam.exe` for 1-click installation; not required for local archive extraction or Zstd vaulting).

---

## Legal Notice & Intended Use

ArcSteam is an independent, general-purpose **archive extraction, file-streaming, and software preservation utility** designed for working with standard and high-compression archive formats (FreeArc, Inno Setup, Zstandard, 7-Zip, ZIP, RAR, ISO) and user-owned, open-source, or DRM-free software distributions.

* ArcSteam **does not** include any search engine, tracker list, torrent indexer, or links to third-party copyrighted content.
* ArcSteam **does not** provide, automate, or assist with DRM circumvention or unauthorized software distribution.
* Users are solely responsible for ensuring they have the legal right to download, extract, archive, or back up any files processed with this software.