use regex::Regex;
use crate::detect::{self, ArchiveMagic, RepackFileEntry, RepackFormat};
use crate::dissect;
use crate::optimizer::{self, DefenderExclusionGuard};
use crate::stream_bridge::{self, TorrentStreamFs, VirtualTorrentFile};
use anyhow::{Context, Result};
use librqbit::{AddTorrent, AddTorrentOptions, Api, Session};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct JobConfig {
    pub is_torrent_mode: bool,
    pub magnet_or_torrent: String,
    pub local_source_dir: PathBuf,
    pub download_cache_dir: PathBuf,
    pub fast_temp_dir: PathBuf,
    pub target_game_dir: PathBuf,
    pub virtual_drive: String, // e.g. "Z:"
    pub live_stream_install: bool,
    pub defender_bypass: bool,
    pub replay_registry: bool,
    pub srep_ram_mb: u64,
    pub selected_files: Vec<RepackFileEntry>,
    pub detected_format: RepackFormat,
}

#[derive(Debug, Default)]
pub struct SharedTelemetry {
    pub running: bool,
    pub download_pct: f32,
    pub unpack_pct: f32,
    pub stage_label: String,
    pub logs: Vec<String>,
}

impl SharedTelemetry {
    pub fn log(&mut self, msg: impl Into<String>) {
        self.logs.push(msg.into());
        if self.logs.len() > 500 {
            self.logs.drain(0..100);
        }
    }
}

fn push_log(shared: &Arc<Mutex<SharedTelemetry>>, msg: impl Into<String>) {
    if let Ok(mut s) = shared.lock() {
        s.log(msg);
    }
}

fn set_progress(
    shared: &Arc<Mutex<SharedTelemetry>>,
    dl: Option<f32>,
    unpack: Option<f32>,
    stage: Option<&str>,
) {
    if let Ok(mut s) = shared.lock() {
        if let Some(d) = dl {
            s.download_pct = d.clamp(0.0, 1.0);
        }
        if let Some(u) = unpack {
            s.unpack_pct = u.clamp(0.0, 1.0);
        }
        if let Some(st) = stage {
            s.stage_label = st.to_string();
        }
    }
}

fn tools_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("tools")))
        .filter(|d| d.exists())
        .unwrap_or_else(|| PathBuf::from("tools"))
}

pub fn spawn_pipeline_thread(cfg: JobConfig, shared: Arc<Mutex<SharedTelemetry>>) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                push_log(&shared, format!("[ERROR] Failed to start Tokio runtime: {e}"));
                return;
            }
        };

        if let Ok(mut s) = shared.lock() {
            s.running = true;
            s.download_pct = if cfg.is_torrent_mode { 0.0 } else { 1.0 };
            s.unpack_pct = 0.0;
        }

        let res = rt.block_on(async {
            if cfg.is_torrent_mode {
                run_torrent_stream_pipeline(&cfg, &shared).await
            } else {
                run_local_turbo_pipeline(&cfg, &cfg.local_source_dir, &shared)
            }
        });

        match res {
            Ok(()) => {
                set_progress(&shared, Some(1.0), Some(1.0), Some("Completed"));
                push_log(&shared, "[DONE] ArcSteam finished cleanly.");
            }
            Err(e) => {
                set_progress(&shared, None, None, Some("Failed"));
                push_log(&shared, format!("[ERROR] Pipeline aborted: {e:#}"));
            }
        }

        if let Ok(mut s) = shared.lock() {
            s.running = false;
        }
    });
}

async fn run_torrent_stream_pipeline(
    cfg: &JobConfig,
    shared: &Arc<Mutex<SharedTelemetry>>,
) -> Result<()> {
    set_progress(shared, Some(0.01), Some(0.0), Some("Connecting to BitTorrent swarm..."));
    std::fs::create_dir_all(&cfg.download_cache_dir)?;

    let session = Session::new(cfg.download_cache_dir.clone())
        .await
        .context("Failed to initialize librqbit Session")?;

    let add_input = if cfg.magnet_or_torrent.trim().starts_with("magnet:")
        || cfg.magnet_or_torrent.trim().starts_with("http")
    {
        AddTorrent::from_url(cfg.magnet_or_torrent.trim())
    } else {
        AddTorrent::from_local_filename(cfg.magnet_or_torrent.trim())?
    };

    // Pass selected file indices so unselected optional/language .bin files are skipped completely.
    let only_files: Option<Vec<usize>> = if cfg.selected_files.is_empty() {
        None
    } else {
        let indices: Vec<usize> = cfg
            .selected_files
            .iter()
            .filter(|f| f.selected)
            .filter_map(|f| f.torrent_file_idx)
            .collect();
        if indices.is_empty() { None } else { Some(indices) }
    };

    let opts = AddTorrentOptions {
        overwrite: true,
        only_files,
        ..Default::default()
    };

    let response = session
        .add_torrent(add_input, Some(opts))
        .await
        .context("Failed to add torrent/magnet")?;

    let (torrent_id, handle) = match response {
        librqbit::AddTorrentResponse::Added(id, h)
        | librqbit::AddTorrentResponse::AlreadyManaged(id, h) => (id, h),
        librqbit::AddTorrentResponse::ListOnly(_) => {
            anyhow::bail!("Torrent opened in list-only mode unexpectedly")
        }
    };

    push_log(shared, format!("[TORRENT] Managed torrent id={torrent_id}. Resolving metadata..."));

    // Build virtual file list from torrent metadata
    let mut virtual_files = Vec::new();
    let mut classified_raw = Vec::new();
    let _ = handle.with_metadata(|meta| {
        for (idx, info) in meta.file_infos.iter().enumerate() {
            let rel = info.relative_filename.to_string_lossy().replace('\\', "/");
            let flat_name = Path::new(&rel)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| rel.clone());
            virtual_files.push(VirtualTorrentFile {
                file_id: idx,
                virtual_name: flat_name,
                size: info.len,
            });
            classified_raw.push((Some(idx), rel, info.len));
        }
    });

    let (detected_fmt, detected_entries) = detect::classify_repack(&classified_raw);
    push_log(shared, format!("[DETECT] Blueprint identified: {}", detected_fmt.badge()));

    // Spawn live download progress tracker
    let handle_stats = handle.clone();
    let shared_stats = shared.clone();
    let stats_task = tokio::spawn(async move {
        loop {
            let st = handle_stats.stats();
            if st.total_bytes > 0 {
                let pct = st.progress_bytes as f32 / st.total_bytes as f32;
                set_progress(&shared_stats, Some(pct), None, None);
                if st.finished {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
        }
    });

    if !cfg.live_stream_install {
        set_progress(shared, None, None, Some("Downloading full torrent before turbo unpack..."));
        handle.wait_until_completed().await?;
        stats_task.abort();
        return run_local_turbo_pipeline(cfg, &cfg.download_cache_dir, shared);
    }

    // Start local loopback HTTP Range streamer for WinFsp bridge
    let api = Api::new(session.clone(), None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    drop(listener);

    let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let http_api = librqbit::http_api::HttpApi::new(api, None);
    tokio::spawn(async move {
        let _ = http_api.make_http_api_and_run(listen_addr, None).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    let stream_base = format!("http://127.0.0.1:{port}/torrents/{torrent_id}/stream");
    push_log(shared, format!("[STREAM] Loopback Range server active at {stream_base}"));

    let vfs = TorrentStreamFs::new(stream_base, virtual_files.clone())?;

    // Prime FreeArc / 7z EOF footers (last 16 MB) before mounting & unpacking
    if detected_fmt.needs_eof_tail_prime() {
        set_progress(shared, None, None, Some("Priming EOF archive footers (16 MB tail)..."));
        for entry in &detected_entries {
            if entry.selected && entry.is_archive {
                if let Some(fid) = entry.torrent_file_idx {
                    push_log(shared, format!("[PRIME] Fetching EOF footer for {}", entry.rel_path));
                    let _ = vfs.prime_eof_footer(fid, entry.size_bytes);
                }
            }
        }
    }

    // Mount WinFsp virtual drive Z:\ and run the exact same universal turbo unpacker over it
    push_log(shared, format!("[VFS] Mounting WinFsp virtual drive at {}\\", cfg.virtual_drive));
    let mut host = stream_bridge::mount_virtual_drive(&cfg.virtual_drive, vfs)?;
    let mount_root = PathBuf::from(format!("{}\\", cfg.virtual_drive));

    let mut live_cfg = cfg.clone();
    live_cfg.detected_format = detected_fmt;
    live_cfg.selected_files = detected_entries;

    let unpack_result = run_local_turbo_pipeline(&live_cfg, &mount_root, shared);

    host.stop();
    host.unmount();
    stats_task.abort();
    push_log(shared, format!("[VFS] Unmounted {}\\", cfg.virtual_drive));

    unpack_result
}

/// Universal Turbo Extractor: works identically on local folders (G:\...) or mounted WinFsp (Z:\).
pub fn run_local_turbo_pipeline(
    cfg: &JobConfig,
    source_root: &Path,
    shared: &Arc<Mutex<SharedTelemetry>>,
) -> Result<()> {
    let tools = tools_dir();
    let innounp = tools.join("innounp.exe");
    let unarc = tools.join("unarc.exe");
    let innoextract = tools.join("innoextract.exe");
    let seven_zip = tools.join("7z.exe");

    std::fs::create_dir_all(&cfg.fast_temp_dir)?;
    std::fs::create_dir_all(&cfg.target_game_dir)?;

    let work_dir = cfg.fast_temp_dir.join("arcsteam_work");
    std::fs::create_dir_all(&work_dir)?;

    let _defender_guard = if cfg.defender_bypass {
        push_log(shared, "[TURBO] Activating temporary Windows Defender RAII exclusions...");
        Some(DefenderExclusionGuard::activate(vec![
            source_root.to_path_buf(),
            cfg.fast_temp_dir.clone(),
            cfg.target_game_dir.clone(),
        ]))
    } else {
        None
    };

    let (fmt, scanned_entries) = if cfg.selected_files.is_empty() {
        detect::scan_local_directory(source_root)
    } else {
        (cfg.detected_format, cfg.selected_files.clone())
    };
    push_log(shared, format!("[ENGINE] Format: {} | Source: {}", fmt.badge(), source_root.display()));

    // Find setup.exe if present
    let setup_exe = scanned_entries
        .iter()
        .find(|e| e.is_setup_exe)
        .map(|e| resolve_source_file(source_root, &e.rel_path));

    // Step 1: GOG Pure Inno Fast-Path
    if fmt == RepackFormat::GogPureInno {
        if let Some(setup) = &setup_exe {
            if innoextract.exists() {
                set_progress(shared, None, Some(0.1), Some("Streaming Pure Inno Setup via innoextract..."));
                push_log(shared, format!("[INNO] Running headless innoextract on {}", setup.display()));
                let args = vec![
                    "-e".into(),
                    "-d".into(),
                    cfg.target_game_dir.display().to_string(),
                    setup.display().to_string(),
                ];
                run_and_stream_logs(&innoextract, &args, None, &cfg.fast_temp_dir, shared, 0.1, 0.95)?;
                return Ok(());
            }
        }
    }

    // Step 2: Dissect Inno Setup {tmp} payload (FreeArc plugins + arc.ini + install_script.iss)
    let mut dissected = dissect::DissectedSetup::default();
    if let Some(setup) = &setup_exe {
        if innounp.exists() {
            set_progress(shared, None, Some(0.05), Some("Dissecting setup.exe & patching SREP RAM..."));
            push_log(shared, format!("[DISSECT] Extracting plugins from {}", setup.display()));
            dissected = dissect::dissect_inno_setup(&innounp, setup, &work_dir)?;
            if dissected.has_unarc_payload {
                let threads = optimizer::logical_cpu_threads();
                optimizer::patch_unpacker_configs(&work_dir, &cfg.fast_temp_dir, cfg.srep_ram_mb, threads)?;
                push_log(
                    shared,
                    format!(
                        "[PATCH] SREP RAM -> {} MB | Threads -> {} | Swap -> {}",
                        cfg.srep_ram_mb,
                        threads,
                        cfg.fast_temp_dir.display()
                    ),
                );
            }
        }
    }

    // Step 3: Collect selected archives & route each by magic bytes (handles ALL repack formats)
    let archives: Vec<PathBuf> = scanned_entries
        .iter()
        .filter(|e| e.selected && e.is_archive)
        .map(|e| resolve_source_file(source_root, &e.rel_path))
        .filter(|p| p.exists())
        .collect();

    if archives.is_empty() {
        // Generic NSIS / InstallShield / Direct SFX fallback with Turbo env
        if let Some(setup) = setup_exe {
            set_progress(shared, None, Some(0.25), Some("Running Generic Setup in High-Priority Turbo Mode..."));
            push_log(shared, format!("[FALLBACK] Launching {} with Defender bypass + SSD TEMP", setup.display()));
            let mut child = optimizer::spawn_turbo_process(&setup, &[], None, &cfg.fast_temp_dir, true)?;
            let status = child.wait()?;
            if !status.success() {
                anyhow::bail!("Generic installer exited with status {status}");
            }
            return Ok(());
        }
        anyhow::bail!("No supported archives or setup.exe found in {}", source_root.display());
    }

    let total_archives = archives.len() as f32;
    for (idx, archive_path) in archives.iter().enumerate() {
        let start_p = 0.08 + (idx as f32 / total_archives) * 0.85;
        let end_p = 0.08 + ((idx + 1) as f32 / total_archives) * 0.85;
        let magic = detect::probe_archive_magic(archive_path);
        let fname = archive_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        set_progress(shared, None, Some(start_p), Some(&format!("Unpacking {fname} ({}/{})", idx + 1, archives.len())));
        push_log(shared, format!("[UNPACK] {fname} -> detected magic: {magic:?}"));

        match magic {
            ArchiveMagic::FreeArc | ArchiveMagic::Unknown if unarc.exists() && (dissected.has_unarc_payload || fmt != RepackFormat::SceneArchiveOrIso) => {
                // Ensure unarc.exe runs inside work_dir so it loads the repack's own cls-srep/cls-lolz/xtool DLLs
                let local_unarc = work_dir.join("unarc.exe");
                if !local_unarc.exists() {
                    let _ = std::fs::copy(&unarc, &local_unarc);
                }
                let mut args = vec![
                    "x".into(),
                    "-o+".into(),
                    format!("-dp{}", cfg.target_game_dir.display()),
                ];
                if let Some(pwd) = &dissected.archive_password {
                    args.push(format!("-p{pwd}"));
                }
                args.push(archive_path.display().to_string());
                run_and_stream_logs(&local_unarc, &args, Some(&work_dir), &cfg.fast_temp_dir, shared, start_p, end_p)?;
            }
            ArchiveMagic::InnoSlice if innoextract.exists() => {
                if let Some(setup) = &setup_exe {
                    let args = vec![
                        "-e".into(),
                        "-d".into(),
                        cfg.target_game_dir.display().to_string(),
                        setup.display().to_string(),
                    ];
                    run_and_stream_logs(&innoextract, &args, None, &cfg.fast_temp_dir, shared, start_p, end_p)?;
                    break; // innoextract processes all slices from setup.exe automatically
                }
            }
            ArchiveMagic::SevenZip | ArchiveMagic::Rar | ArchiveMagic::Zip | ArchiveMagic::Iso9660 | ArchiveMagic::Unknown => {
                if !seven_zip.exists() {
                    anyhow::bail!("tools/7z.exe is required to unpack {fname}");
                }
                let args = vec![
                    "x".into(),
                    "-y".into(),
                    format!("-o{}", cfg.target_game_dir.display()),
                    archive_path.display().to_string(),
                ];
                run_and_stream_logs(&seven_zip, &args, None, &cfg.fast_temp_dir, shared, start_p, end_p)?;
            }
        }
    }

    // Step 4: Replay [Registry] and safe [Run] post-install tasks from install_script.iss
    if cfg.replay_registry && !dissected.registry_entries.is_empty() {
        set_progress(shared, None, Some(0.95), Some("Applying game registry entries..."));
        let count = dissect::apply_registry_entries(&dissected.registry_entries, &cfg.target_game_dir);
        push_log(shared, format!("[REG] Applied {count} game registry key(s)."));
    }

    for post in &dissected.safe_post_run {
        let exe_path = PathBuf::from(
            post.filename
                .replace("{app}", &cfg.target_game_dir.display().to_string())
                .replace("{tmp}", &work_dir.display().to_string()),
        );
        if exe_path.exists() {
            push_log(shared, format!("[POST] Executing {}", exe_path.display()));
            let params: Vec<String> = post
                .parameters
                .replace("{app}", &cfg.target_game_dir.display().to_string())
                .split_whitespace()
                .map(String::from)
                .collect();
            let _ = optimizer::spawn_turbo_process(&exe_path, &params, Some(&cfg.target_game_dir), &cfg.fast_temp_dir, false)
                .and_then(|mut c| Ok(c.wait()?));
        }
    }

    Ok(())
}

fn resolve_source_file(source_root: &Path, rel_path: &str) -> PathBuf {
    let direct = source_root.join(rel_path);
    if direct.exists() {
        return direct;
    }
    // Flat virtual mount fallback (Z:\fg-01.bin)
    if let Some(fname) = Path::new(rel_path).file_name() {
        let flat = source_root.join(fname);
        if flat.exists() {
            return flat;
        }
    }
    direct
}

fn run_and_stream_logs(
    exe: &Path,
    args: &[String],
    cwd: Option<&Path>,
    fast_temp_dir: &Path,
    shared: &Arc<Mutex<SharedTelemetry>>,
    start_p: f32,
    end_p: f32,
) -> Result<()> {
    let mut child = optimizer::spawn_turbo_process(exe, args, cwd, fast_temp_dir, false)
        .with_context(|| format!("Failed to spawn {}", exe.display()))?;

    let re_pct = Regex::new(r"(\d{1,3})(?:\.\d+)?%").unwrap();

    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines().flatten() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(cap) = re_pct.captures(trimmed) {
                if let Ok(val) = cap[1].parse::<f32>() {
                    let frac = (val / 100.0).clamp(0.0, 1.0);
                    let mapped = start_p + frac * (end_p - start_p);
                    set_progress(shared, None, Some(mapped), None);
                }
            }
            push_log(shared, format!("  | {trimmed}"));
        }
    }

    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("{} exited with code {:?}", exe.display(), status.code());
    }
    set_progress(shared, None, Some(end_p), None);
    Ok(())
}
