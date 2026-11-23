use crate::detect::{self, ArchiveMagic, RepackFileEntry, RepackFormat};
use crate::dissect;
use crate::embedded_tools;
use crate::ifps::{self, IfpsAction};
use crate::manifest::{self, InstallManifest};
use crate::optimizer::{self, DefenderExclusionGuard};
use crate::stream_bridge::{self, TorrentStreamFs, VirtualTorrentFile};
use crate::win_sys::{self, HighPerformanceGuard, JobHandle, KeepAwakeGuard, PostQueueAction};
use anyhow::{Context, Result};
use librqbit::{AddTorrent, AddTorrentOptions, Api, Session};
use regex::Regex;
use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use sysinfo::System;

#[derive(Debug, Clone)]
pub struct JobConfig {
    pub display_name: String,
    pub is_torrent_mode: bool,
    pub magnet_or_torrent: String,
    pub local_source_dir: PathBuf,
    pub download_cache_dir: PathBuf,
    pub fast_temp_dir: PathBuf,
    pub target_game_dir: PathBuf,
    pub virtual_drive: String,
    pub live_stream_install: bool,
    pub defender_bypass: bool,
    pub replay_registry: bool,
    pub create_shortcuts: bool,
    pub create_start_menu: bool,
    pub start_menu_folder: String,
    pub auto_clean_temp: bool,
    pub auto_ram: bool,
    pub srep_ram_mb: u64,
    pub selected_files: Vec<RepackFileEntry>,
    pub excluded_games: Vec<String>,
    pub detected_format: RepackFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueItemState {
    Queued,
    Running,
    Done,
    Failed,
    Cancelled,
}

impl QueueItemState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "Queued",
            Self::Running => "Running",
            Self::Done => "Done",
            Self::Failed => "Failed",
            Self::Cancelled => "Cancelled",
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueueEntry {
    pub config: JobConfig,
    pub state: QueueItemState,
}

#[derive(Default)]
pub struct PipelineControl {
    pub cancel_requested: AtomicBool,
    pub paused: AtomicBool,
    pub active_root_pid: AtomicU32,
    pub active_job: Mutex<Option<JobHandle>>,
}

impl PipelineControl {
    pub fn reset(&self) {
        self.cancel_requested.store(false, Ordering::Relaxed);
        self.paused.store(false, Ordering::Relaxed);
        self.active_root_pid.store(0, Ordering::Relaxed);
        if let Ok(mut guard) = self.active_job.lock() {
            *guard = None;
        }
    }

    pub fn request_cancel(&self) {
        self.cancel_requested.store(true, Ordering::Relaxed);
        if self.paused.swap(false, Ordering::Relaxed) {
            let pid = self.active_root_pid.load(Ordering::Relaxed);
            win_sys::set_process_tree_paused(pid, false);
        }
        if let Ok(guard) = self.active_job.lock() {
            if let Some(ref job) = *guard {
                job.terminate_all();
            }
        }
    }

    pub fn toggle_pause(&self) -> bool {
        let now_paused = !self.paused.load(Ordering::Relaxed);
        self.paused.store(now_paused, Ordering::Relaxed);
        let pid = self.active_root_pid.load(Ordering::Relaxed);
        win_sys::set_process_tree_paused(pid, now_paused);
        now_paused
    }
}

#[derive(Debug, Default)]
pub struct SharedTelemetry {
    pub running: bool,
    pub download_pct: f32,
    pub unpack_pct: f32,
    pub dl_speed_mbps: f32,
    pub disk_write_mbps: f32,
    pub worker_ram_mb: u64,
    pub active_worker: String,
    pub eta_text: String,
    pub stage_label: String,
    pub active_queue_idx: Option<usize>,
    pub queue_states: Vec<QueueItemState>,
    pub manifests_dirty: bool,
    pub logs: Vec<String>,
}

impl SharedTelemetry {
    pub fn log(&mut self, msg: impl Into<String>) {
        self.logs.push(msg.into());
        if self.logs.len() > 2000 {
            self.logs.drain(0..400);
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
            let clamped = u.clamp(0.0, 1.0);
            if clamped == 0.0 || clamped >= s.unpack_pct {
                s.unpack_pct = clamped;
            }
        }
        if let Some(st) = stage {
            s.stage_label = st.to_string();
        }
    }
}

pub fn spawn_queue_thread(
    jobs: Vec<JobConfig>,
    post_action: PostQueueAction,
    shared: Arc<Mutex<SharedTelemetry>>,
    control: Arc<PipelineControl>,
) {
    control.reset();
    std::thread::spawn(move || {
        let _keep_awake = KeepAwakeGuard::activate();
        let _high_perf = HighPerformanceGuard::activate();
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
            s.queue_states = vec![QueueItemState::Queued; jobs.len()];
            s.dl_speed_mbps = 0.0;
            s.disk_write_mbps = 0.0;
            s.worker_ram_mb = 0;
            s.active_worker.clear();
            s.eta_text = "--".into();
        }

        let mut any_cancelled = false;
        let total_jobs = jobs.len();

        for (idx, cfg) in jobs.into_iter().enumerate() {
            if control.cancel_requested.load(Ordering::Relaxed) {
                any_cancelled = true;
                if let Ok(mut s) = shared.lock() {
                    if let Some(st) = s.queue_states.get_mut(idx) {
                        *st = QueueItemState::Cancelled;
                    }
                }
                continue;
            }

            if let Ok(mut s) = shared.lock() {
                s.active_queue_idx = Some(idx);
                if let Some(st) = s.queue_states.get_mut(idx) {
                    *st = QueueItemState::Running;
                }
                s.download_pct = if cfg.is_torrent_mode { 0.0 } else { 1.0 };
                s.unpack_pct = 0.0;
                s.eta_text = "Estimating...".into();
            }

            push_log(
                &shared,
                format!(
                    "[QUEUE {}/{}] Starting: {}",
                    idx + 1,
                    total_jobs,
                    cfg.display_name
                ),
            );

            let job_start = Instant::now();
            let res = rt.block_on(async {
                if cfg.is_torrent_mode {
                    run_torrent_stream_pipeline(&cfg, &shared, &control, job_start).await
                } else {
                    run_local_turbo_pipeline(&cfg, &cfg.local_source_dir, &shared, &control, job_start)
                }
            });

            if control.cancel_requested.load(Ordering::Relaxed) {
                any_cancelled = true;
                if let Ok(mut s) = shared.lock() {
                    if let Some(st) = s.queue_states.get_mut(idx) {
                        *st = QueueItemState::Cancelled;
                    }
                }
                set_progress(&shared, None, None, Some("Cancelled by user"));
                push_log(&shared, "[CANCEL] Job cancelled and worker process tree terminated.");
                break;
            }

            match res {
                Ok(()) => {
                    if let Ok(mut s) = shared.lock() {
                        if let Some(st) = s.queue_states.get_mut(idx) {
                            *st = QueueItemState::Done;
                        }
                        s.manifests_dirty = true;
                    }
                    set_progress(&shared, Some(1.0), Some(1.0), Some("Completed"));
                    push_log(&shared, format!("[DONE] {} finished cleanly.", cfg.display_name));
                }
                Err(e) => {
                    if let Ok(mut s) = shared.lock() {
                        if let Some(st) = s.queue_states.get_mut(idx) {
                            *st = QueueItemState::Failed;
                        }
                    }
                    set_progress(&shared, None, None, Some("Failed"));
                    push_log(&shared, format!("[ERROR] {} aborted: {e:#}", cfg.display_name));
                }
            }
        }

        if let Ok(mut s) = shared.lock() {
            s.running = false;
            s.active_queue_idx = None;
            s.active_worker.clear();
            s.disk_write_mbps = 0.0;
            s.dl_speed_mbps = 0.0;
            s.worker_ram_mb = 0;
        }
        control.active_root_pid.store(0, Ordering::Relaxed);
        if let Ok(mut guard) = control.active_job.lock() {
            *guard = None;
        }

        if !any_cancelled && post_action != PostQueueAction::DoNothing {
            push_log(
                &shared,
                format!("[POWER] Queue complete — triggering: {}", post_action.label()),
            );
            win_sys::execute_post_queue_action(post_action);
        }
    });
}

async fn run_torrent_stream_pipeline(
    cfg: &JobConfig,
    shared: &Arc<Mutex<SharedTelemetry>>,
    control: &Arc<PipelineControl>,
    job_start: Instant,
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

    let handle_stats = handle.clone();
    let shared_stats = shared.clone();
    let cancel_stats = control.clone();
    let stats_task = tokio::spawn(async move {
        let mut prev_bytes = 0u64;
        let mut prev_time = Instant::now();
        loop {
            if cancel_stats.cancel_requested.load(Ordering::Relaxed) {
                break;
            }
            let st = handle_stats.stats();
            let now = Instant::now();
            let dt = now.duration_since(prev_time).as_secs_f32().max(0.2);
            let delta = st.progress_bytes.saturating_sub(prev_bytes);
            let mbps = (delta as f32 / (1024.0 * 1024.0)) / dt;
            prev_bytes = st.progress_bytes;
            prev_time = now;

            if let Ok(mut s) = shared_stats.lock() {
                s.dl_speed_mbps = mbps;
                if st.total_bytes > 0 {
                    s.download_pct = (st.progress_bytes as f32 / st.total_bytes as f32).clamp(0.0, 1.0);
                }
            }
            if st.finished {
                break;
            }
            tokio::time::sleep(Duration::from_millis(800)).await;
        }
    });

    if !cfg.live_stream_install {
        set_progress(shared, None, None, Some("Downloading full torrent before turbo unpack..."));
        handle.wait_until_completed().await?;
        stats_task.abort();
        let cfg_clone = cfg.clone();
        let cache_dir = cfg.download_cache_dir.clone();
        let shared_clone = shared.clone();
        let ctrl_clone = control.clone();
        return tokio::task::spawn_blocking(move || {
            run_local_turbo_pipeline(&cfg_clone, &cache_dir, &shared_clone, &ctrl_clone, job_start)
        })
        .await?;
    }

    let api = Arc::new(Api::new(session.clone(), None));
    let rt_handle = tokio::runtime::Handle::current();
    let vfs = TorrentStreamFs::new(api, torrent_id, rt_handle, virtual_files);

    if detected_fmt.needs_eof_tail_prime() {
        set_progress(shared, None, None, Some("Priming EOF footers (16 MB) + solid block head (8 MB)..."));
        for entry in &detected_entries {
            if control.cancel_requested.load(Ordering::Relaxed) {
                anyhow::bail!("Cancelled during EOF priming");
            }
            if entry.selected && entry.is_archive {
                if let Some(fid) = entry.torrent_file_idx {
                    push_log(shared, format!("[PRIME] Priming EOF + head window for {}", entry.rel_path));
                    let _ = vfs.prime_eof_and_head(fid, entry.size_bytes).await;
                }
            }
        }
    }

    if !win_sys::is_winfsp_installed() {
        let msi = embedded_tools::resolve_tool("winfsp.msi");
        if msi.exists() {
            set_progress(shared, None, None, Some("Installing built-in WinFsp driver..."));
            push_log(shared, "[WINFSP] Auto-installing built-in WinFsp MSI...");
            if win_sys::install_embedded_winfsp(&msi) {
                let _ = winfsp::winfsp_init();
                push_log(shared, "[WINFSP] Driver ready.");
            }
        }
    }
    push_log(shared, format!("[VFS] Mounting WinFsp virtual drive at {}\\", cfg.virtual_drive));
    let mut host = stream_bridge::mount_virtual_drive(&cfg.virtual_drive, vfs)?;
    let mount_root = PathBuf::from(format!("{}\\", cfg.virtual_drive));

    let mut live_cfg = cfg.clone();
    live_cfg.detected_format = detected_fmt;
    live_cfg.selected_files = detected_entries;
    let shared_clone = shared.clone();
    let ctrl_clone = control.clone();

    let unpack_result = tokio::task::spawn_blocking(move || {
        run_local_turbo_pipeline(&live_cfg, &mount_root, &shared_clone, &ctrl_clone, job_start)
    })
    .await?;

    host.stop();
    host.unmount();
    stats_task.abort();
    push_log(shared, format!("[VFS] Unmounted {}\\", cfg.virtual_drive));

    unpack_result
}

pub fn run_local_turbo_pipeline(
    cfg: &JobConfig,
    source_root: &Path,
    shared: &Arc<Mutex<SharedTelemetry>>,
    control: &Arc<PipelineControl>,
    job_start: Instant,
) -> Result<()> {
    let tools = embedded_tools::bin_dir();
    let innounp = embedded_tools::resolve_tool("innounp.exe");
    let unarc = embedded_tools::resolve_tool("unarc.exe");
    let innoextract = embedded_tools::resolve_tool("innoextract.exe");
    let seven_zip = embedded_tools::resolve_tool("7z.exe");

    std::fs::create_dir_all(&cfg.fast_temp_dir)?;
    std::fs::create_dir_all(&cfg.target_game_dir)?;

    // Snapshot existing directories inside target_game_dir BEFORE extraction so the uninstaller
    // knows the exact game folder(s) created by this install (never deleting sibling games!).
    let dirs_before = manifest::snapshot_top_dirs(&cfg.target_game_dir);
    let files_before = manifest::snapshot_top_files(&cfg.target_game_dir);

    let work_dir = cfg.fast_temp_dir.join("arcsteam_work");
    if work_dir.exists() {
        let _ = std::fs::remove_dir_all(&work_dir);
    }
    std::fs::create_dir_all(&work_dir)?;

    let _defender_guard = if cfg.defender_bypass {
        push_log(shared, "[TURBO] Activating crash-safe Windows Defender exclusions...");
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

    let setup_exe = scanned_entries
        .iter()
        .find(|e| e.is_setup_exe)
        .map(|e| resolve_source_file(source_root, &e.rel_path));

    if fmt == RepackFormat::GogPureInno {
        if let Some(setup) = &setup_exe {
            if innoextract.exists() {
                set_progress(shared, None, Some(0.1), Some("Streaming Pure Inno Setup via innoextract..."));
                push_log(shared, format!("[INNO] Running headless innoextract on {}", setup.display()));
                let stage_dir = cfg.target_game_dir.join("_arcsteam_gog_stage");
                if stage_dir.exists() {
                    let _ = std::fs::remove_dir_all(&stage_dir);
                }
                std::fs::create_dir_all(&stage_dir)?;

                let args = vec![
                    "-e".into(),
                    "-d".into(),
                    stage_dir.display().to_string(),
                    setup.display().to_string(),
                ];
                let extract_res = run_and_stream_logs(
                    &innoextract,
                    &args,
                    None,
                    &cfg.fast_temp_dir,
                    shared,
                    control,
                    job_start,
                    0.1,
                    0.94,
                );
                if let Err(e) = extract_res {
                    let _ = std::fs::remove_dir_all(&stage_dir);
                    return Err(e);
                }

                // Promote `stage_dirpp` into `target_game_dir\<Game Name>`
                let game_folder_name = cfg
                    .display_name
                    .replace([':', '*', '?', '"', '<', '>', '|', '\\', '/'], "")
                    .trim()
                    .to_string();
                let clean_name = if game_folder_name.is_empty() {
                    "GOG Game".to_string()
                } else {
                    game_folder_name
                };
                let final_game_dir = cfg.target_game_dir.join(&clean_name);
                let staged_app = stage_dir.join("app");
                if staged_app.is_dir() {
                    if final_game_dir.exists() {
                        let _ = std::fs::remove_dir_all(&final_game_dir);
                    }
                    if std::fs::rename(&staged_app, &final_game_dir).is_err() {
                        std::fs::create_dir_all(&final_game_dir)?;
                    }
                    push_log(
                        shared,
                        format!("[INNO] Installed game files to {}", final_game_dir.display()),
                    );
                }
                let _ = std::fs::remove_dir_all(&stage_dir);

                let mut gog_dissected = dissect::DissectedSetup::default();
                if let Some(main_exe) = dissect::find_primary_game_exe(&final_game_dir) {
                    let rel_exe = main_exe
                        .strip_prefix(&cfg.target_game_dir)
                        .unwrap_or(&main_exe);
                    gog_dissected.icon_entries.push(dissect::IconEntry {
                        name: clean_name.clone(),
                        filename: format!("{{app}}\\{}", rel_exe.display()),
                        parameters: String::new(),
                        working_dir: String::new(),
                    });
                }

                finalize_setup_metadata(
                    &gog_dissected,
                    &work_dir,
                    cfg,
                    &dirs_before,
                    &files_before,
                    shared,
                    Some(control),
                )?;
                cleanup_work_dir(cfg.auto_clean_temp, &work_dir, shared);
                return Ok(());
            }
        }
    }

    let mut dissected = dissect::DissectedSetup::default();
    if let Some(setup) = &setup_exe {
        if innounp.exists() {
            set_progress(shared, None, Some(0.05), Some("Dissecting setup.exe & dynamically tuning RAM..."));
            push_log(shared, format!("[DISSECT] Extracting plugins from {}", setup.display()));
            dissected = dissect::dissect_inno_setup(&innounp, setup, &work_dir)?;
            if dissected.has_unarc_payload {
                let threads = optimizer::logical_cpu_threads();
                let target_ram_mb = if cfg.auto_ram {
                    let plan = optimizer::compute_dynamic_srep_ram();
                    push_log(
                        shared,
                        format!(
                            "[RAM-AUTO] Live free: {} MB / {} MB total -> allocating {} MB to SREP ({} MB reserved for OS)",
                            plan.available_mb, plan.total_mb, plan.recommended_mb, plan.reserved_mb
                        ),
                    );
                    plan.recommended_mb
                } else {
                    cfg.srep_ram_mb
                };

                let host32 = embedded_tools::resolve_tool("unarc_host32.exe");
                let active_unarc = if work_dir.join("unarc.dll").exists() && host32.exists() {
                    &host32
                } else {
                    &unarc
                };
                let report = optimizer::patch_unpacker_configs(
                    &work_dir,
                    &tools,
                    active_unarc,
                    &cfg.fast_temp_dir,
                    target_ram_mb,
                    threads,
                )?;
                if let Some(ref s64) = report.external_srep64_used {
                    push_log(
                        shared,
                        format!(
                            "[PATCH] External 64-bit {s64} active | SREP RAM -> {} MB | Threads -> 100% ({}) | IPC -> 8m/32m",
                            report.effective_ram_mb, threads
                        ),
                    );
                } else if report.clamped_for_32bit {
                    push_log(
                        shared,
                        format!(
                            "[WARN] unarc is {:?} without 64-bit srep helper; clamped SREP RAM to {} MB to prevent OOM.",
                            report.unarc_bitness, report.effective_ram_mb
                        ),
                    );
                } else {
                    push_log(
                        shared,
                        format!(
                            "[PATCH] SREP RAM -> {} MB ({:?}) | Threads -> 100% ({}) | Swap -> {}",
                            report.effective_ram_mb,
                            report.unarc_bitness,
                            threads,
                            cfg.fast_temp_dir.display()
                        ),
                    );
                }
            }
        }
    }

    let archives: Vec<PathBuf> = scanned_entries
        .iter()
        .filter(|e| e.selected && e.is_archive)
        .map(|e| resolve_source_file(source_root, &e.rel_path))
        .filter(|p| p.exists())
        .collect();

    if archives.is_empty() {
        if let Some(setup) = setup_exe {
            set_progress(shared, None, Some(0.25), Some("Running Generic Setup in High-Priority Turbo Mode..."));
            push_log(shared, format!("[FALLBACK] Launching {} with Defender bypass + SSD TEMP", setup.display()));
            let mut child = optimizer::spawn_turbo_process(&setup, &[], None, &cfg.fast_temp_dir, true)?;
            attach_job(&child, control);
            let status = child.wait()?;
            if !status.success() {
                anyhow::bail!("Generic installer exited with status {status}");
            }
            cleanup_work_dir(cfg.auto_clean_temp, &work_dir, shared);
            return Ok(());
        }
        anyhow::bail!("No supported archives or setup.exe found in {}", source_root.display());
    }

    let archive_sizes: Vec<u64> = archives
        .iter()
        .map(|p| std::fs::metadata(p).map(|m| m.len().max(1)).unwrap_or(1))
        .collect();
    let total_archive_bytes: u64 = archive_sizes.iter().sum::<u64>().max(1);
    let completed_bytes = Arc::new(AtomicU64::new(0));
    let unpack_clock = Instant::now();
    set_progress(shared, None, Some(0.0), None);

    let mut serial_items: Vec<(usize, PathBuf, u64, ArchiveMagic)> = Vec::new();
    let mut parallel_items: Vec<(usize, PathBuf, u64, ArchiveMagic)> = Vec::new();
    let src_is_ssd = win_sys::is_source_ssd(source_root);
    let allow_parallel = src_is_ssd && optimizer::logical_cpu_threads() >= 4;
    push_log(
        shared,
        format!(
            "[IO] Source drive mode: {} ({})",
            if src_is_ssd { "SSD/NVMe — parallel secondary bins ON" } else { "HDD/USB — sequential read ON (zero head thrashing)" },
            source_root.display()
        ),
    );

    for (idx, archive_path) in archives.iter().enumerate() {
        let sz = archive_sizes[idx];
        let magic = detect::probe_archive_magic(archive_path);
        let is_small_secondary = allow_parallel
            && idx > 0
            && sz < 600 * 1024 * 1024
            && magic != ArchiveMagic::InnoSlice
            && !archive_uses_cls(archive_path);

        if is_small_secondary {
            parallel_items.push((idx, archive_path.clone(), sz, magic));
        } else {
            serial_items.push((idx, archive_path.clone(), sz, magic));
        }
    }

    for (idx, archive_path, sz, magic) in serial_items {
        if control.cancel_requested.load(Ordering::Relaxed) {
            anyhow::bail!("Cancelled by user");
        }
        let done_before = completed_bytes.load(Ordering::Relaxed);
        let start_p = (done_before as f64 / total_archive_bytes as f64) as f32 * 0.94;
        let end_p = ((done_before + sz) as f64 / total_archive_bytes as f64) as f32 * 0.94;
        let fname = archive_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        set_progress(
            shared,
            None,
            Some(start_p),
            Some(&format!("Unpacking {fname} ({}/{})", idx + 1, archives.len())),
        );
        push_log(shared, format!("[UNPACK] {fname} -> detected magic: {magic:?}"));

        let broke = extract_single_archive(
            magic,
            fmt,
            dissected.has_unarc_payload,
            dissected.archive_password.as_deref(),
            &unarc,
            &innoextract,
            &seven_zip,
            setup_exe.as_deref(),
            &work_dir,
            &archive_path,
            &cfg.target_game_dir,
            &cfg.fast_temp_dir,
            &cfg.excluded_games,
            shared,
            control,
            unpack_clock,
            start_p,
            end_p,
            &fname,
        )?;
        completed_bytes.fetch_add(sz, Ordering::Relaxed);
        if broke {
            parallel_items.clear();
            break;
        }
    }

    if parallel_items.len() >= 2 {
        push_log(
            shared,
            format!(
                "[TURBO] Unpacking {} small secondary archive(s) in parallel (2 workers)...",
                parallel_items.len()
            ),
        );
        for chunk in parallel_items.chunks(2) {
            if control.cancel_requested.load(Ordering::Relaxed) {
                anyhow::bail!("Cancelled by user");
            }
            let names: Vec<String> = chunk
                .iter()
                .map(|(_, p, _, _)| {
                    p.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default()
                })
                .collect();
            set_progress(
                shared,
                None,
                None,
                Some(&format!("Parallel unpacking: {}", names.join(" + "))),
            );

            let chunk_err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
            std::thread::scope(|s| {
                for (slot, (_idx, archive_path, sz, magic)) in chunk.iter().enumerate() {
                    let completed_ref = completed_bytes.clone();
                    let shared_ref = shared.clone();
                    let ctrl_ref = control.clone();
                    let err_ref = &chunk_err;
                    let slot_work = cfg.fast_temp_dir.join(format!("arcsteam_work_p{slot}"));
                    let slot_swap = cfg.fast_temp_dir.join(format!("arcsteam_swap_p{slot}"));
                    let src_work = &work_dir;
                    let unarc_ref = &unarc;
                    let inno_ref = &innoextract;
                    let sz7_ref = &seven_zip;
                    let setup_ref = setup_exe.as_deref();
                    let pwd_ref = dissected.archive_password.as_deref();
                    let has_unarc = dissected.has_unarc_payload;
                    let dst_ref = &cfg.target_game_dir;
                    let excl_ref = &cfg.excluded_games;

                    s.spawn(move || {
                        let _ = copy_dir_flat(src_work, &slot_work);
                        let _ = std::fs::create_dir_all(&slot_swap);
                        let fname = archive_path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        let cur = completed_ref.load(Ordering::Relaxed);
                        let sp = (cur as f64 / total_archive_bytes as f64) as f32 * 0.94;
                        let ep = ((cur + *sz) as f64 / total_archive_bytes as f64) as f32 * 0.94;

                        push_log(&shared_ref, format!("[PARALLEL-{slot}] Unpacking {fname}"));
                        let res = extract_single_archive(
                            *magic,
                            fmt,
                            has_unarc,
                            pwd_ref,
                            unarc_ref,
                            inno_ref,
                            sz7_ref,
                            setup_ref,
                            &slot_work,
                            archive_path,
                            dst_ref,
                            &slot_swap,
                            excl_ref,
                            &shared_ref,
                            &ctrl_ref,
                            unpack_clock,
                            sp,
                            ep,
                            &fname,
                        );
                        let _ = std::fs::remove_dir_all(&slot_work);
                        let _ = std::fs::remove_dir_all(&slot_swap);

                        match res {
                            Ok(_) => {
                                let new_done = completed_ref.fetch_add(*sz, Ordering::Relaxed) + *sz;
                                let overall = (new_done as f64 / total_archive_bytes as f64) as f32 * 0.94;
                                set_progress(&shared_ref, None, Some(overall), None);
                            }
                            Err(e) => {
                                if let Ok(mut guard) = err_ref.lock() {
                                    if guard.is_none() {
                                        *guard = Some(e);
                                    }
                                }
                            }
                        }
                    });
                }
            });

            if let Some(err) = chunk_err.into_inner().unwrap() {
                return Err(err);
            }
        }
    } else {
        for (idx, archive_path, sz, magic) in parallel_items {
            if control.cancel_requested.load(Ordering::Relaxed) {
                anyhow::bail!("Cancelled by user");
            }
            let done_before = completed_bytes.load(Ordering::Relaxed);
            let start_p = (done_before as f64 / total_archive_bytes as f64) as f32 * 0.94;
            let end_p = ((done_before + sz) as f64 / total_archive_bytes as f64) as f32 * 0.94;
            let fname = archive_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();

            set_progress(
                shared,
                None,
                Some(start_p),
                Some(&format!("Unpacking {fname} ({}/{})", idx + 1, archives.len())),
            );
            push_log(shared, format!("[UNPACK] {fname} -> detected magic: {magic:?}"));

            let _ = extract_single_archive(
                magic,
                fmt,
                dissected.has_unarc_payload,
                dissected.archive_password.as_deref(),
                &unarc,
                &innoextract,
                &seven_zip,
                setup_exe.as_deref(),
                &work_dir,
                &archive_path,
                &cfg.target_game_dir,
                &cfg.fast_temp_dir,
                &cfg.excluded_games,
                shared,
                control,
                unpack_clock,
                start_p,
                end_p,
                &fname,
            )?;
            completed_bytes.fetch_add(sz, Ordering::Relaxed);
        }
    }

    finalize_setup_metadata(
        &dissected,
        &work_dir,
        cfg,
        &dirs_before,
        &files_before,
        shared,
        Some(control),
    )?;

    cleanup_work_dir(cfg.auto_clean_temp, &work_dir, shared);
    Ok(())
}

/// Runs post-unpack reconstruction builders (`work\work\build01.bat`), deploys setup.exe metadata,
/// creates shortcuts, and generates an ArcSteam Uninstall manifest for an already-unpacked game.
pub fn spawn_repair_existing_thread(
    cfg: JobConfig,
    shared: Arc<Mutex<SharedTelemetry>>,
) {
    std::thread::spawn(move || {
        if let Ok(mut s) = shared.lock() {
            s.running = true;
            s.unpack_pct = 0.2;
            s.stage_label = "Running post-unpack builders & finalizing metadata...".into();
        }
        let res = (|| -> Result<()> {
            let innounp = embedded_tools::resolve_tool("innounp.exe");
            let (_, entries) = detect::scan_local_directory(&cfg.local_source_dir);
            let setup_exe = entries
                .iter()
                .find(|e| e.is_setup_exe)
                .map(|e| resolve_source_file(&cfg.local_source_dir, &e.rel_path));

            let work_dir = cfg.fast_temp_dir.join("arcsteam_repair_work");
            if work_dir.exists() {
                let _ = std::fs::remove_dir_all(&work_dir);
            }
            std::fs::create_dir_all(&work_dir)?;

            let empty_before = HashSet::new();
            let empty_files_before = HashSet::new();
            let dissected = if let Some(setup) = setup_exe {
                if innounp.exists() {
                    push_log(&shared, format!("[REPAIR] Dissecting {}", setup.display()));
                    dissect::dissect_inno_setup(&innounp, &setup, &work_dir)?
                } else {
                    dissect::DissectedSetup::default()
                }
            } else {
                push_log(&shared, "[REPAIR] No setup.exe found — scanning for post-unpack scripts & runtimes.");
                dissect::DissectedSetup::default()
            };

            finalize_setup_metadata(
                &dissected,
                &work_dir,
                &cfg,
                &empty_before,
                &empty_files_before,
                &shared,
                None,
            )?;

            let _ = std::fs::remove_dir_all(&work_dir);
            Ok(())
        })();

        match res {
            Ok(()) => {
                if let Ok(mut s) = shared.lock() {
                    s.manifests_dirty = true;
                }
                set_progress(&shared, None, Some(1.0), Some("Repair & rebuild complete"));
                push_log(&shared, "[DONE] Post-unpack builders, metadata & uninstall registration finished.");
            }
            Err(e) => {
                set_progress(&shared, None, None, Some("Repair failed"));
                push_log(&shared, format!("[ERROR] Repair failed: {e:#}"));
            }
        }
        if let Ok(mut s) = shared.lock() {
            s.running = false;
        }
    });
}

fn log_missing_runtimes(shared: &Arc<Mutex<SharedTelemetry>>) {
    let missing = win_sys::check_legacy_game_runtimes();
    for rt in missing {
        push_log(
            shared,
            format!("[WARN] Missing required runtime: {rt} (can cause splash hangs or 0xc0000142 crashes)"),
        );
    }
}

fn finalize_setup_metadata(
    dissected: &dissect::DissectedSetup,
    work_dir: &Path,
    cfg: &JobConfig,
    dirs_before: &HashSet<String>,
    files_before: &HashSet<String>,
    shared: &Arc<Mutex<SharedTelemetry>>,
    control: Option<&Arc<PipelineControl>>,
) -> Result<()> {
    let target_game_dir = &cfg.target_game_dir;
    let fast_temp_dir = &cfg.fast_temp_dir;
    let excluded_games = &cfg.excluded_games;

    // 1. Replay compiled Inno Setup IFPS post-unpack pipeline (`ISExec` + nested `ISArcExtract`)
    //    if `embedded\CompiledCode.bin` is present (handles delzo, x5, x2n, x3, builder, sfk, fart,
    //    build01.bat, and nested `{app}\*.fgpack` archives in exact installer order!).
    let mut ran_ifps_pipeline = false;
    let compiled_code_bin = work_dir.join("embedded").join("CompiledCode.bin");
    if compiled_code_bin.is_file() {
        let (ifps_actions, ifps_notes) = ifps::extract_post_unpack_actions(&compiled_code_bin);
        for note in ifps_notes {
            push_log(shared, note);
        }
        if !ifps_actions.is_empty() {
            ran_ifps_pipeline = true;
            replay_ifps_post_unpack(
                &ifps_actions,
                work_dir,
                target_game_dir,
                fast_temp_dir,
                &cfg.local_source_dir,
                excluded_games,
                dissected.archive_password.as_deref(),
                shared,
                control,
            )?;
        }
    }

    // 1b. Fallback for repacks without IFPS ISExec steps: run discovered post-unpack build*.bat scripts
    let builder_scripts = if ran_ifps_pipeline {
        Vec::new()
    } else {
        dissect::discover_post_unpack_scripts(target_game_dir)
    };
    if !builder_scripts.is_empty() {
        let mut ran_work_builder = false;
        for (i, bat_path) in builder_scripts.iter().enumerate() {
            if let Some(ctrl) = control {
                if ctrl.cancel_requested.load(Ordering::Relaxed) {
                    anyhow::bail!("Cancelled by user");
                }
            }
            let bname = bat_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "build.bat".into());
            set_progress(
                shared,
                None,
                Some(0.95),
                Some(&format!(
                    "Rebuilding game data ({}/{}: {bname})...",
                    i + 1,
                    builder_scripts.len()
                )),
            );
            for note in dissect::patch_post_unpack_scripts(bat_path, target_game_dir, work_dir) {
                push_log(shared, note);
            }
            for diag in dissect::inspect_builder_diagnostics(bat_path) {
                push_log(shared, diag);
            }
            push_log(
                shared,
                format!("[REBUILD] Executing post-unpack builder: {}", bat_path.display()),
            );
            let ok = run_post_unpack_bat(bat_path, target_game_dir, work_dir, fast_temp_dir, shared, control);
            if ok
                && bat_path
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .contains("\\work\\")
            {
                ran_work_builder = true;
            } else if !ok {
                push_log(
                    shared,
                    "[WARN] Builder returned non-zero exit — keeping work\\ folder for inspection.",
                );
            }
        }

        // Check for any leftover *.fgpack.x5 packs; if they are nested FreeArc/7z archives, unpack them automatically!
        let leftover_fgpacks = process_leftover_fgpacks(
            target_game_dir,
            work_dir,
            fast_temp_dir,
            dissected.archive_password.as_deref(),
            shared,
            control,
        );
        if ran_work_builder {
            if leftover_fgpacks > 0 {
                push_log(
                    shared,
                    format!("[WARN] {leftover_fgpacks} .fgpack.x5 pack(s) still unconsumed — keeping work\\ folder for inspection."),
                );
            } else {
                let game_work = target_game_dir.join("work");
                if game_work.is_dir() && std::fs::remove_dir_all(&game_work).is_ok() {
                    push_log(shared, "[CLEANUP] Removed post-unpack work\\ folder.");
                }
            }
        }
    }

    // Remove residual folders for any excluded games
    for ex in excluded_games {
        let ex_dir = target_game_dir.join(ex);
        if ex_dir.is_dir() {
            let _ = manifest::force_remove_dir_all(&ex_dir);
            push_log(shared, format!("[SKIP] Excluded unselected game: {ex}"));
        }
    }

    set_progress(shared, None, Some(0.98), Some("Deploying setup files, shortcuts & uninstall manifest..."));

    let mut tracked_profiles: Vec<PathBuf> = Vec::new();

    let (embedded_copied, ext_profiles) =
        dissect::deploy_embedded_setup_files(work_dir, target_game_dir, excluded_games);
    tracked_profiles.extend(ext_profiles);
    if embedded_copied > 0 {
        push_log(
            shared,
            format!("[SETUP] Deployed {embedded_copied} embedded file(s) from setup.exe."),
        );
    }

    if !dissected.dir_entries.is_empty() {
        let (dir_count, dir_profiles) =
            dissect::create_script_dirs(&dissected.dir_entries, target_game_dir, work_dir);
        tracked_profiles.extend(dir_profiles);
        if dir_count > 0 {
            push_log(
                shared,
                format!("[DIRS] Created {dir_count} game/profile folder(s) from [Dirs]."),
            );
        }
    }

    let mut tracked_reg_keys: Vec<String> = Vec::new();
    if cfg.replay_registry && !dissected.registry_entries.is_empty() {
        let (count, keys) = dissect::apply_registry_entries(
            &dissected.registry_entries,
            target_game_dir,
            work_dir,
        );
        tracked_reg_keys = keys;
        push_log(
            shared,
            format!("[REG] Applied {count} game registry key(s) (32-bit WOW6432Node + 64-bit)."),
        );
    }

    let manifest_id = manifest::sanitize_id(&cfg.display_name);
    let mut tracked_shortcuts: Vec<PathBuf> = Vec::new();

    if cfg.create_shortcuts && !dissected.icon_entries.is_empty() {
        let desk_lnks =
            dissect::create_desktop_shortcuts(&dissected.icon_entries, target_game_dir, excluded_games);
        if !desk_lnks.is_empty() {
            push_log(
                shared,
                format!("[SHORTCUT] Created {} Desktop shortcut(s).", desk_lnks.len()),
            );
            tracked_shortcuts.extend(desk_lnks);
        }
    }

    let mut tracked_start_menu: Option<PathBuf> = None;
    if cfg.create_start_menu {
        let sm_name = if cfg.start_menu_folder.trim().is_empty() {
            cfg.display_name.as_str()
        } else {
            cfg.start_menu_folder.trim()
        };
        let (sm_dir, sm_lnks) = dissect::create_start_menu_shortcuts(
            &dissected.icon_entries,
            target_game_dir,
            excluded_games,
            sm_name,
            &manifest_id,
        );
        if let Some(ref d) = sm_dir {
            push_log(
                shared,
                format!(
                    "[STARTMENU] Created Start Menu folder '{}' ({} shortcut(s)).",
                    d.file_name().unwrap_or_default().to_string_lossy(),
                    sm_lnks.len()
                ),
            );
        }
        tracked_start_menu = sm_dir;
        tracked_shortcuts.extend(sm_lnks);
    }

    for post in &dissected.safe_post_run {
        if let Some(ctrl) = control {
            if ctrl.cancel_requested.load(Ordering::Relaxed) {
                anyhow::bail!("Cancelled by user");
            }
        }
        let exe_path = PathBuf::from(dissect::expand_inno_tokens(
            &post.filename,
            target_game_dir,
            work_dir,
        ));
        if exe_path.exists() {
            push_log(shared, format!("[POST] Executing {}", exe_path.display()));
            let params: Vec<String> = dissect::expand_inno_tokens(&post.parameters, target_game_dir, work_dir)
                .split_whitespace()
                .map(String::from)
                .collect();
            let _ = optimizer::spawn_turbo_process(
                &exe_path,
                &params,
                Some(target_game_dir),
                fast_temp_dir,
                false,
            )
            .and_then(|mut c| Ok(c.wait()?));
        }
    }

    // Always combine newly created directories with `[Icons]`-inferred game folders so reinstalling
    // over an existing `D:\Games\<Game>` folder still tracks the real game folder for Uninstall!
    let mut owned_game_dirs = manifest::diff_new_top_dirs(target_game_dir, dirs_before, excluded_games);
    let mut seen_owned: HashSet<String> = owned_game_dirs
        .iter()
        .map(|p| p.display().to_string().to_ascii_lowercase())
        .collect();
    for icon_dir in dissect::infer_game_dirs_from_icons(&dissected.icon_entries, target_game_dir, excluded_games) {
        let key = icon_dir.display().to_string().to_ascii_lowercase();
        if seen_owned.insert(key) {
            owned_game_dirs.push(icon_dir);
        }
    }
    let (emb_dirs, emb_files) =
        dissect::list_embedded_app_entries(work_dir, target_game_dir, excluded_games);
    for ed in emb_dirs {
        let key = ed.display().to_string().to_ascii_lowercase();
        if seen_owned.insert(key) {
            owned_game_dirs.push(ed);
        }
    }

    let mut owned_extra_files = manifest::diff_new_top_files(target_game_dir, files_before);
    let mut seen_files: HashSet<String> = owned_extra_files
        .iter()
        .map(|p| p.display().to_string().to_ascii_lowercase())
        .collect();
    for ef in emb_files {
        let key = ef.display().to_string().to_ascii_lowercase();
        if seen_files.insert(key) {
            owned_extra_files.push(ef);
        }
    }

    if owned_game_dirs.is_empty() {
        owned_game_dirs.push(target_game_dir.to_path_buf());
    }

    let uninstall_reg_key = format!(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\ArcSteam_{manifest_id}"
    );
    let install_manifest = InstallManifest {
        id: manifest_id,
        display_name: cfg.display_name.clone(),
        install_root: target_game_dir.to_path_buf(),
        game_dirs: owned_game_dirs,
        extra_files: owned_extra_files,
        start_menu_dir: tracked_start_menu,
        shortcuts: tracked_shortcuts,
        profile_dirs: tracked_profiles,
        registry_keys: tracked_reg_keys,
        uninstall_reg_key,
    };

    if manifest::save_manifest(&install_manifest).is_ok() {
        manifest::register_windows_uninstall_entry(&install_manifest);
        push_log(
            shared,
            format!(
                "[MANIFEST] Registered '{}' in ArcSteam Installed & Windows Apps (Uninstall ready).",
                install_manifest.display_name
            ),
        );
    }

    log_missing_runtimes(shared);
    Ok(())
}

fn run_post_unpack_bat(
    bat_path: &Path,
    target_game_dir: &Path,
    work_dir: &Path,
    fast_temp_dir: &Path,
    shared: &Arc<Mutex<SharedTelemetry>>,
    control: Option<&Arc<PipelineControl>>,
) -> bool {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    let (cwd, needs_app_arg) = dissect::detect_script_cwd_and_args(bat_path, target_game_dir);
    let bat_dir = bat_path.parent().unwrap_or(target_game_dir);

    let orig_path = std::env::var("PATH").unwrap_or_default();
    let combined_path = format!(
        "{};{};{};{}",
        bat_dir.display(),
        work_dir.display(),
        embedded_tools::bin_dir().display(),
        orig_path
    );

    let mut cmd = Command::new("cmd.exe");
    cmd.arg("/c").arg(bat_path);
    if needs_app_arg {
        cmd.arg(target_game_dir);
    }
    cmd.current_dir(&cwd)
        .env("PATH", combined_path)
        .env("TEMP", fast_temp_dir)
        .env("TMP", fast_temp_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(0x0000_8000 | 0x0800_0000);

    match cmd.spawn() {
        Ok(mut child) => {
            if let Some(ctrl) = control {
                attach_job(&child, ctrl);
            }
            let err_handle = child.stderr.take().map(|stderr| {
                let sh = shared.clone();
                std::thread::spawn(move || {
                    for line in BufReader::new(stderr).lines().flatten() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            push_log(&sh, format!("  | [stderr] {trimmed}"));
                        }
                    }
                })
            });
            if let Some(stdout) = child.stdout.take() {
                for line in BufReader::new(stdout).lines().flatten() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() {
                        push_log(shared, format!("  | {trimmed}"));
                    }
                }
            }
            if let Some(h) = err_handle {
                let _ = h.join();
            }
            match child.wait() {
                Ok(status) => {
                    let ok = status.success();
                    push_log(
                        shared,
                        format!("[REBUILD] {} finished (exit {:?}).", bat_path.display(), status.code()),
                    );
                    ok
                }
                Err(e) => {
                    push_log(shared, format!("[WARN] Error waiting on builder script: {e}"));
                    false
                }
            }
        }
        Err(e) => {
            push_log(shared, format!("[WARN] Could not launch {}: {e}", bat_path.display()));
            false
        }
    }
}

fn archive_uses_cls(path: &Path) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else {
        return true;
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return true;
    };
    let probe_len = len.min(256 * 1024) as usize;
    let start = len.saturating_sub(probe_len as u64);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return true;
    }
    let mut buf = vec![0u8; probe_len];
    if f.read_exact(&mut buf).is_err() {
        return true;
    }
    let lower = String::from_utf8_lossy(&buf).to_ascii_lowercase();
    ["srep", "lolz", "magic2", "lolly", "xtool", "oodle", "oo2reck"]
        .iter()
        .any(|sig| lower.contains(sig))
}

fn copy_dir_flat(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_file() {
            let _ = std::fs::copy(&p, dst.join(entry.file_name()));
        }
    }
    Ok(())
}

fn cleanup_work_dir(enabled: bool, work_dir: &Path, shared: &Arc<Mutex<SharedTelemetry>>) {
    if enabled && work_dir.exists() {
        if std::fs::remove_dir_all(work_dir).is_ok() {
            push_log(shared, "[CLEANUP] Removed temporary arcsteam_work directory.");
        }
    }
}

fn attach_job(child: &std::process::Child, control: &Arc<PipelineControl>) {
    control.active_root_pid.store(child.id(), Ordering::Relaxed);
    if let Some(job) = JobHandle::new() {
        job.assign_child(child);
        if let Ok(mut guard) = control.active_job.lock() {
            *guard = Some(job);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn extract_single_archive(
    magic: ArchiveMagic,
    fmt: RepackFormat,
    has_unarc_payload: bool,
    password: Option<&str>,
    unarc: &Path,
    innoextract: &Path,
    seven_zip: &Path,
    setup_exe: Option<&Path>,
    work_dir: &Path,
    archive_path: &Path,
    target_game_dir: &Path,
    fast_temp_dir: &Path,
    excluded_games: &[String],
    shared: &Arc<Mutex<SharedTelemetry>>,
    control: &Arc<PipelineControl>,
    unpack_clock: Instant,
    start_p: f32,
    end_p: f32,
    fname: &str,
) -> Result<bool> {
    match magic {
        ArchiveMagic::FreeArc => {
            run_unarc_extract(
                unarc,
                work_dir,
                archive_path,
                target_game_dir,
                fast_temp_dir,
                excluded_games,
                password,
                shared,
                control,
                unpack_clock,
                start_p,
                end_p,
                fname,
            )?;
            Ok(false)
        }
        ArchiveMagic::InnoSlice => {
            if !innoextract.exists() {
                anyhow::bail!("Built-in innoextract.exe is required to unpack Inno slice {fname}");
            }
            let setup = setup_exe.with_context(|| {
                format!("Found Inno slice {fname} but no matching setup*.exe")
            })?;
            let args = vec![
                "-e".into(),
                "-d".into(),
                target_game_dir.display().to_string(),
                setup.display().to_string(),
            ];
            run_and_stream_logs(
                innoextract,
                &args,
                None,
                fast_temp_dir,
                shared,
                control,
                unpack_clock,
                start_p,
                end_p,
            )?;
            Ok(true)
        }
        ArchiveMagic::SevenZip | ArchiveMagic::Rar | ArchiveMagic::Zip | ArchiveMagic::Iso9660 => {
            run_7z_extract(
                seven_zip,
                archive_path,
                target_game_dir,
                fast_temp_dir,
                excluded_games,
                shared,
                control,
                unpack_clock,
                start_p,
                end_p,
                fname,
            )?;
            Ok(false)
        }
        ArchiveMagic::Unknown => {
            if unarc.exists() && (has_unarc_payload || fmt != RepackFormat::SceneArchiveOrIso) {
                run_unarc_extract(
                    unarc,
                    work_dir,
                    archive_path,
                    target_game_dir,
                    fast_temp_dir,
                    excluded_games,
                    password,
                    shared,
                    control,
                    unpack_clock,
                    start_p,
                    end_p,
                    fname,
                )?;
            } else {
                run_7z_extract(
                    seven_zip,
                    archive_path,
                    target_game_dir,
                    fast_temp_dir,
                    excluded_games,
                    shared,
                    control,
                    unpack_clock,
                    start_p,
                    end_p,
                    fname,
                )?;
            }
            Ok(false)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_unarc_extract(
    unarc: &Path,
    work_dir: &Path,
    archive_path: &Path,
    target_game_dir: &Path,
    fast_temp_dir: &Path,
    _excluded_games: &[String],
    password: Option<&str>,
    shared: &Arc<Mutex<SharedTelemetry>>,
    control: &Arc<PipelineControl>,
    job_start: Instant,
    start_p: f32,
    end_p: f32,
    fname: &str,
) -> Result<()> {
    let host32 = embedded_tools::resolve_tool("unarc_host32.exe");
    let repack_unarc_dll = work_dir.join("unarc.dll");

    if repack_unarc_dll.exists() && host32.exists() {
        push_log(
            shared,
            format!("[UNARC-DLL] Extracting {fname} via repack's native unarc.dll (32-bit LAA host)"),
        );
        let mut args = vec![
            work_dir.display().to_string(),
            "x".into(),
            "-o+".into(),
            format!("-w{}", fast_temp_dir.display()),
            format!("-dp{}", target_game_dir.display()),
        ];
        if let Some(pwd) = password {
            args.push(format!("-p{pwd}"));
        }
        args.push("--".into());
        args.push(archive_path.display().to_string());
        return run_and_stream_logs(
            &host32,
            &args,
            Some(work_dir),
            fast_temp_dir,
            shared,
            control,
            job_start,
            start_p,
            end_p,
        );
    }

    if !unarc.exists() {
        anyhow::bail!("Built-in unarc.exe is required to unpack FreeArc archive {fname}");
    }
    let local_unarc = work_dir.join("unarc.exe");
    if !local_unarc.exists() {
        let _ = std::fs::copy(unarc, &local_unarc);
    }
    let mut args = vec![
        "x".into(),
        "-o+".into(),
        format!("-w{}", fast_temp_dir.display()),
        format!("-dp{}", target_game_dir.display()),
    ];
    if let Some(pwd) = password {
        args.push(format!("-p{pwd}"));
    }
    args.push(archive_path.display().to_string());
    run_and_stream_logs(&local_unarc, &args, Some(work_dir), fast_temp_dir, shared, control, job_start, start_p, end_p)
}

#[allow(clippy::too_many_arguments)]
fn run_7z_extract(
    seven_zip: &Path,
    archive_path: &Path,
    target_game_dir: &Path,
    fast_temp_dir: &Path,
    excluded_games: &[String],
    shared: &Arc<Mutex<SharedTelemetry>>,
    control: &Arc<PipelineControl>,
    job_start: Instant,
    start_p: f32,
    end_p: f32,
    fname: &str,
) -> Result<()> {
    if !seven_zip.exists() {
        anyhow::bail!("Built-in 7z.exe is required to unpack {fname}");
    }
    let mut args = vec![
        "x".into(),
        "-y".into(),
        format!("-o{}", target_game_dir.display()),
    ];
    for ex in excluded_games {
        args.push(format!("-xr!{ex}"));
    }
    args.push(archive_path.display().to_string());
    run_and_stream_logs(seven_zip, &args, None, fast_temp_dir, shared, control, job_start, start_p, end_p)
}

fn resolve_source_file(source_root: &Path, rel_path: &str) -> PathBuf {
    let direct = source_root.join(rel_path);
    if direct.exists() {
        return direct;
    }
    if let Some(fname) = Path::new(rel_path).file_name() {
        let flat = source_root.join(fname);
        if flat.exists() {
            return flat;
        }
    }
    direct
}

fn format_eta(seconds: f32) -> String {
    if !seconds.is_finite() || seconds <= 0.0 {
        return "--".into();
    }
    let secs = seconds as u64;
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h {m:02}m")
    } else {
        format!("{m:02}m {s:02}s")
    }
}

#[allow(clippy::too_many_arguments)]
fn run_and_stream_logs(
    exe: &Path,
    args: &[String],
    cwd: Option<&Path>,
    fast_temp_dir: &Path,
    shared: &Arc<Mutex<SharedTelemetry>>,
    control: &Arc<PipelineControl>,
    job_start: Instant,
    start_p: f32,
    end_p: f32,
) -> Result<()> {
    let mut child = optimizer::spawn_turbo_process(exe, args, cwd, fast_temp_dir, false)
        .with_context(|| format!("Failed to spawn {}", exe.display()))?;
    attach_job(&child, control);

    let root_pid = child.id();
    let monitor_done = Arc::new(AtomicBool::new(false));
    let mon_flag = monitor_done.clone();
    let mon_shared = shared.clone();
    let mon_ctrl = control.clone();
    let monitor_thread = std::thread::spawn(move || {
        let mut sys = System::new_all();
        let mut last_pct: f32 = 0.0;
        let mut idle_secs: u32 = 0;
        let mut smooth_eta: Option<f32> = None;

        while !mon_flag.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(1));
            if mon_flag.load(Ordering::Relaxed) {
                break;
            }
            if mon_ctrl.paused.load(Ordering::Relaxed) {
                if let Ok(mut s) = mon_shared.lock() {
                    s.eta_text = "Paused".into();
                }
                continue;
            }
            sys.refresh_all();
            let pids = win_sys::collect_process_tree(&sys, root_pid);
            let mut total_ram_bytes = 0u64;
            let mut total_written_bytes = 0u64;
            let mut top_worker = String::new();
            let mut top_mem = 0u64;

            for pid_u32 in pids {
                if let Some(p) = sys.process(sysinfo::Pid::from_u32(pid_u32)) {
                    let mem = p.memory();
                    total_ram_bytes += mem;
                    total_written_bytes += p.disk_usage().written_bytes;
                    if mem >= top_mem {
                        top_mem = mem;
                        top_worker = p.name().to_string_lossy().to_string();
                    }
                }
            }

            if let Ok(mut s) = mon_shared.lock() {
                s.worker_ram_mb = total_ram_bytes / (1024 * 1024);
                s.disk_write_mbps = total_written_bytes as f32 / (1024.0 * 1024.0);
                if !top_worker.is_empty() {
                    s.active_worker = top_worker;
                }
                let pct = s.unpack_pct;
                if (pct - last_pct).abs() > 0.0005 || total_written_bytes > 0 {
                    last_pct = pct;
                    idle_secs = 0;
                } else {
                    idle_secs += 1;
                }

                if idle_secs >= 15 && total_written_bytes == 0 {
                    s.eta_text = "Crunching block...".into();
                } else if pct >= 0.015 && pct < 0.995 {
                    let elapsed = job_start.elapsed().as_secs_f32();
                    let raw_rem = ((elapsed / pct) * (1.0 - pct)).min(36000.0);
                    let smoothed = match smooth_eta {
                        Some(prev) => prev * 0.85 + raw_rem * 0.15,
                        None => raw_rem,
                    };
                    smooth_eta = Some(smoothed);
                    s.eta_text = format_eta(smoothed);
                } else {
                    s.eta_text = "Calculating...".into();
                }
            }
        }
    });

    let re_pct = Regex::new(r"(\d{1,3})(?:\.\d+)?%").unwrap();

    if let Some(stdout) = child.stdout.take() {
        let reader = BufReader::new(stdout);
        for line in reader.lines().flatten() {
            if control.cancel_requested.load(Ordering::Relaxed) {
                break;
            }
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
    monitor_done.store(true, Ordering::Relaxed);
    let _ = monitor_thread.join();

    if control.cancel_requested.load(Ordering::Relaxed) {
        anyhow::bail!("Cancelled by user");
    }
    if !status.success() {
        anyhow::bail!("{} exited with code {:?}", exe.display(), status.code());
    }
    set_progress(shared, None, Some(end_p), None);
    Ok(())
}

fn process_leftover_fgpacks(
    target_game_dir: &Path,
    work_dir: &Path,
    fast_temp_dir: &Path,
    password: Option<&str>,
    shared: &Arc<Mutex<SharedTelemetry>>,
    control: Option<&Arc<PipelineControl>>,
) -> usize {
    use std::io::Read;
    let Ok(rd) = std::fs::read_dir(target_game_dir) else {
        return 0;
    };
    let fgpacks: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.file_name()
                    .map(|n| n.to_string_lossy().to_ascii_lowercase().ends_with(".fgpack.x5"))
                    .unwrap_or(false)
        })
        .collect();

    if fgpacks.is_empty() {
        return 0;
    }

    let unarc = embedded_tools::resolve_tool("unarc.exe");
    let seven_zip = embedded_tools::resolve_tool("7z.exe");
    let dummy_ctrl = Arc::new(PipelineControl::default());
    let ctrl_ref = control.unwrap_or(&dummy_ctrl);
    let clock = Instant::now();
    let mut remaining = 0usize;

    for pack in fgpacks {
        let fname = pack
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let magic = detect::probe_archive_magic(&pack);
        let sz = std::fs::metadata(&pack).map(|m| m.len()).unwrap_or(0);

        // Log first 12 bytes for exact format diagnostics
        let mut hdr = [0u8; 12];
        let hdr_hex = std::fs::File::open(&pack)
            .ok()
            .and_then(|mut f| f.read(&mut hdr).ok())
            .map(|n| {
                hdr[..n]
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();

        push_log(
            shared,
            format!("[FGPACK] Leftover {fname} ({sz} bytes) | magic={magic:?} | hdr=[{hdr_hex}]"),
        );

        let unpacked = match magic {
            ArchiveMagic::FreeArc => run_unarc_extract(
                &unarc,
                work_dir,
                &pack,
                target_game_dir,
                fast_temp_dir,
                &[],
                password,
                shared,
                ctrl_ref,
                clock,
                0.96,
                0.98,
                &fname,
            )
            .is_ok(),
            ArchiveMagic::SevenZip | ArchiveMagic::Rar | ArchiveMagic::Zip => run_7z_extract(
                &seven_zip,
                &pack,
                target_game_dir,
                fast_temp_dir,
                &[],
                shared,
                ctrl_ref,
                clock,
                0.96,
                0.98,
                &fname,
            )
            .is_ok(),
            _ => false,
        };

        if unpacked {
            let _ = std::fs::remove_file(&pack);
            push_log(shared, format!("[FGPACK] Unpacked and removed nested pack {fname}."));
        } else {
            remaining += 1;
        }
    }
    remaining
}

fn mirror_work_tools_into_tmp(target_game_dir: &Path, work_dir: &Path) {
    // Repack archives like fg-06.bin unpack `work\work\*` into `{app}\work\work\`, while
    // CompiledCode.bin invokes `{tmp}\work\fart.exe`, `{tmp}\work\build01.bat`, etc.
    // Mirroring `{app}\work\work\` (and `{app}\work\`) into `work_dir\work\` satisfies both!
    let dst_work = work_dir.join("work");
    let _ = std::fs::create_dir_all(&dst_work);
    for cand in [
        target_game_dir.join("work").join("work"),
        target_game_dir.join("work"),
    ] {
        if cand.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&cand) {
                for entry in rd.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        let dst = dst_work.join(entry.file_name());
                        if !dst.exists() {
                            let _ = std::fs::copy(&p, &dst);
                        }
                    }
                }
            }
        }
    }
}

fn targets_only_excluded_game(
    text_a: &str,
    text_b: &str,
    excluded_games: &[String],
) -> bool {
    if excluded_games.is_empty() {
        return false;
    }
    let a = text_a.to_ascii_lowercase();
    let b = text_b.to_ascii_lowercase();
    for ex in excluded_games {
        let exl = ex.to_ascii_lowercase();
        let needle_bs = format!("\\{exl}\\");
        let needle_fs = format!("/{exl}/");
        let needle_q = format!("\"{exl}\\");
        let needle_end = format!("\\{exl}");
        if a.contains(&needle_bs)
            || a.contains(&needle_fs)
            || a.ends_with(&needle_end)
            || b.contains(&needle_bs)
            || b.contains(&needle_fs)
            || b.contains(&needle_q)
        {
            return true;
        }
    }
    false
}

fn is_blocked_ifps_exec(exe_lower: &str, params_lower: &str) -> bool {
    exe_lower.starts_with("http")
        || exe_lower.contains("quicksfv")
        || exe_lower.contains("vcredist")
        || exe_lower.contains("vc_redist")
        || exe_lower.contains("dxwebsetup")
        || exe_lower.contains("dxsetup")
        || exe_lower.contains("dotnet")
        || exe_lower.contains("unins")
        || exe_lower.contains("flushfilecache")
        || params_lower.contains("check.bat")
}

#[allow(clippy::too_many_arguments)]
fn replay_ifps_post_unpack(
    actions: &[IfpsAction],
    work_dir: &Path,
    target_game_dir: &Path,
    fast_temp_dir: &Path,
    source_root: &Path,
    excluded_games: &[String],
    default_password: Option<&str>,
    shared: &Arc<Mutex<SharedTelemetry>>,
    control: Option<&Arc<PipelineControl>>,
) -> Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    mirror_work_tools_into_tmp(target_game_dir, work_dir);

    let unarc = embedded_tools::resolve_tool("unarc.exe");
    let dummy_ctrl = Arc::new(PipelineControl::default());
    let ctrl_ref = control.unwrap_or(&dummy_ctrl);
    let clock = Instant::now();

    let orig_path = std::env::var("PATH").unwrap_or_default();
    let combined_path = format!(
        "{};{};{};{}",
        work_dir.display(),
        work_dir.join("work").display(),
        embedded_tools::bin_dir().display(),
        orig_path
    );

    // Filter down to actionable post-unpack steps (skipping `{src}\*.bin` archives already extracted)
    let mut runnable = Vec::new();
    for act in actions {
        match act {
            IfpsAction::ArcExtract { archive, .. } => {
                let low = archive.trim().to_ascii_lowercase();
                if low.starts_with("{src}") || low.ends_with(".bin") {
                    continue;
                }
                runnable.push(act);
            }
            IfpsAction::Exec { exe, params, target_dir, .. } => {
                let el = exe.to_ascii_lowercase();
                let pl = params.to_ascii_lowercase();
                if is_blocked_ifps_exec(&el, &pl) {
                    continue;
                }
                if targets_only_excluded_game(target_dir, params, excluded_games) {
                    continue;
                }
                runnable.push(act);
            }
        }
    }

    let total = runnable.len();
    if total == 0 {
        return Ok(());
    }
    push_log(
        shared,
        format!("[IFPS] Executing {total} post-unpack reconstruction step(s)..."),
    );

    for (idx, act) in runnable.iter().enumerate() {
        if let Some(ctrl) = control {
            if ctrl.cancel_requested.load(Ordering::Relaxed) {
                anyhow::bail!("Cancelled by user");
            }
        }
        let step_pct = 0.94 + (idx as f32 / total as f32) * 0.04;

        match act {
            IfpsAction::ArcExtract {
                archive,
                out_dir,
                delete_after,
                password,
            } => {
                let arc_str = dissect::expand_inno_tokens_with_src(
                    archive.trim(),
                    target_game_dir,
                    work_dir,
                    source_root,
                );
                let arc_path = PathBuf::from(&arc_str);
                if !arc_path.is_file() {
                    continue;
                }
                let out_str = if out_dir.trim().is_empty() {
                    target_game_dir.display().to_string()
                } else {
                    dissect::expand_inno_tokens_with_src(
                        out_dir.trim(),
                        target_game_dir,
                        work_dir,
                        source_root,
                    )
                };
                let out_path = PathBuf::from(&out_str);
                let _ = std::fs::create_dir_all(&out_path);
                let fname = arc_path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| arc_str.clone());
                let pwd = if !password.trim().is_empty() {
                    Some(password.as_str())
                } else {
                    default_password
                };

                set_progress(
                    shared,
                    None,
                    Some(step_pct),
                    Some(&format!("Rebuilding ({}/{total}): unpacking {fname}", idx + 1)),
                );
                push_log(
                    shared,
                    format!("[IFPS-ARC {}/{total}] Unpacking {} -> {}", idx + 1, fname, out_path.display()),
                );
                match run_unarc_extract(
                    &unarc,
                    work_dir,
                    &arc_path,
                    &out_path,
                    fast_temp_dir,
                    &[],
                    pwd,
                    shared,
                    ctrl_ref,
                    clock,
                    step_pct,
                    step_pct + 0.001,
                    &fname,
                ) {
                    Ok(()) => {
                        if *delete_after {
                            let _ = std::fs::remove_file(&arc_path);
                        }
                    }
                    Err(e) => {
                        push_log(shared, format!("[WARN] Nested pack {fname} failed: {e}"));
                    }
                }
            }
            IfpsAction::Exec {
                exe,
                params,
                target_dir,
                desc,
            } => {
                let exe_exp = dissect::expand_inno_tokens_with_src(
                    exe.trim(),
                    target_game_dir,
                    work_dir,
                    source_root,
                );
                let params_exp = dissect::expand_inno_tokens_with_src(
                    params.trim(),
                    target_game_dir,
                    work_dir,
                    source_root,
                );
                let cwd_str = if target_dir.trim().is_empty() {
                    target_game_dir.display().to_string()
                } else {
                    dissect::expand_inno_tokens_with_src(
                        target_dir.trim(),
                        target_game_dir,
                        work_dir,
                        source_root,
                    )
                };
                let cwd_path = PathBuf::from(cwd_str.trim().trim_end_matches('\\'));
                let effective_cwd = if cwd_path.is_dir() {
                    cwd_path
                } else {
                    target_game_dir.to_path_buf()
                };

                // Build exact shell command line matching ISDone's ISExec (`cmd.exe /c ...`)
                let exe_low = exe_exp.to_ascii_lowercase();
                let is_cmd_shell = exe_low == "cmd"
                    || exe_low == "cmd.exe"
                    || exe_low.ends_with("\\cmd.exe");

                let full_cmdline = if is_cmd_shell {
                    let trimmed = params_exp.trim();
                    let stripped = trimmed
                        .strip_prefix("/c ")
                        .or_else(|| trimmed.strip_prefix("/C "))
                        .unwrap_or(trimmed);
                    stripped.to_string()
                } else {
                    // Verify external helper exists if it's an absolute path
                    let ep = Path::new(&exe_exp);
                    if ep.is_absolute() && !ep.exists() {
                        continue;
                    }
                    if params_exp.is_empty() {
                        format!("\"{exe_exp}\"")
                    } else {
                        format!("\"{exe_exp}\" {params_exp}")
                    }
                };

                let label = if !desc.trim().is_empty() {
                    desc.trim().to_string()
                } else {
                    Path::new(&exe_exp)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "rebuild".into())
                };
                set_progress(
                    shared,
                    None,
                    Some(step_pct),
                    Some(&format!("Rebuilding ({}/{total}): {label}", idx + 1)),
                );
                push_log(
                    shared,
                    format!("[IFPS-EXEC {}/{total}] ({})> {}", idx + 1, effective_cwd.display(), full_cmdline),
                );

                // Wrap full_cmdline in outer quotes for `cmd.exe /c "..."` so quoted exe + quoted args + `&&` work reliably
                let wrapped = format!("/c \"{full_cmdline}\"");
                let mut cmd = Command::new("cmd.exe");
                cmd.raw_arg(&wrapped)
                    .current_dir(&effective_cwd)
                    .env("PATH", &combined_path)
                    .env("TEMP", fast_temp_dir)
                    .env("TMP", fast_temp_dir)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .creation_flags(0x0000_8000 | 0x0800_0000);

                match cmd.spawn() {
                    Ok(mut child) => {
                        if let Some(ctrl) = control {
                            attach_job(&child, ctrl);
                        }
                        // Drain stdout & stderr without flooding logs with thousands of repetitive PNG lines
                        let err_h = child.stderr.take().map(|se| {
                            let sh = shared.clone();
                            std::thread::spawn(move || {
                                let mut shown = 0usize;
                                for line in BufReader::new(se).lines().flatten() {
                                    let t = line.trim();
                                    if !t.is_empty() && shown < 12 {
                                        push_log(&sh, format!("  | [err] {t}"));
                                        shown += 1;
                                    }
                                }
                            })
                        });
                        if let Some(so) = child.stdout.take() {
                            let mut shown = 0usize;
                            for line in BufReader::new(so).lines().flatten() {
                                let t = line.trim();
                                if !t.is_empty() && shown < 12 {
                                    push_log(shared, format!("  | {t}"));
                                    shown += 1;
                                }
                            }
                        }
                        if let Some(h) = err_h {
                            let _ = h.join();
                        }
                        let _ = child.wait();
                    }
                    Err(e) => {
                        push_log(shared, format!("[WARN] Failed to run step {}: {e}", idx + 1));
                    }
                }
            }
        }
    }

    // Clean up temporary work\ and temp-fitgirl\ directories after IFPS post-unpack finishes
    for tmp_sub in ["work", "temp-fitgirl"] {
        let p = target_game_dir.join(tmp_sub);
        if p.is_dir() && manifest::force_remove_dir_all(&p).is_ok() {
            push_log(shared, format!("[CLEANUP] Removed post-unpack {tmp_sub}\\ folder."));
        }
    }

    Ok(())
}
