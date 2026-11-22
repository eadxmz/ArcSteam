use crate::detect::{self, ArchiveMagic, RepackFileEntry, RepackFormat};
use crate::dissect;
use crate::embedded_tools;
use crate::optimizer::{self, DefenderExclusionGuard};
use crate::stream_bridge::{self, TorrentStreamFs, VirtualTorrentFile};
use crate::win_sys::{self, JobHandle, KeepAwakeGuard, PostQueueAction};
use anyhow::{Context, Result};
use librqbit::{AddTorrent, AddTorrentOptions, Api, Session};
use regex::Regex;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
    pub auto_clean_temp: bool,
    pub srep_ram_mb: u64,
    pub selected_files: Vec<RepackFileEntry>,
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
    pub logs: Vec<String>,
}

impl SharedTelemetry {
    pub fn log(&mut self, msg: impl Into<String>) {
        self.logs.push(msg.into());
        if self.logs.len() > 600 {
            self.logs.drain(0..150);
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

#[allow(dead_code)]
pub fn tools_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("tools")))
        .filter(|d| d.exists())
        .unwrap_or_else(|| PathBuf::from("tools"))
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
                let args = vec![
                    "-e".into(),
                    "-d".into(),
                    cfg.target_game_dir.display().to_string(),
                    setup.display().to_string(),
                ];
                run_and_stream_logs(&innoextract, &args, None, &cfg.fast_temp_dir, shared, control, job_start, 0.1, 0.95)?;
                cleanup_work_dir(cfg.auto_clean_temp, &work_dir, shared);
                return Ok(());
            }
        }
    }

    let mut dissected = dissect::DissectedSetup::default();
    if let Some(setup) = &setup_exe {
        if innounp.exists() {
            set_progress(shared, None, Some(0.05), Some("Dissecting setup.exe & patching SREP RAM..."));
            push_log(shared, format!("[DISSECT] Extracting plugins from {}", setup.display()));
            dissected = dissect::dissect_inno_setup(&innounp, setup, &work_dir)?;
            if dissected.has_unarc_payload {
                let threads = optimizer::logical_cpu_threads();
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
                    cfg.srep_ram_mb,
                    threads,
                )?;
                if let Some(ref s64) = report.external_srep64_used {
                    push_log(
                        shared,
                        format!(
                            "[PATCH] External 64-bit {s64} active | SREP RAM -> {} MB | Threads -> {} | Swap -> {}",
                            report.effective_ram_mb,
                            threads,
                            cfg.fast_temp_dir.display()
                        ),
                    );
                } else if report.clamped_for_32bit {
                    push_log(
                        shared,
                        format!(
                            "[WARN] unarc.exe is {:?} and no 64-bit srep64.exe found in tools/. Clamped SREP RAM to {} MB to prevent 32-bit OOM crash.",
                            report.unarc_bitness,
                            report.effective_ram_mb
                        ),
                    );
                } else {
                    push_log(
                        shared,
                        format!(
                            "[PATCH] SREP RAM -> {} MB ({:?}) | Threads -> {} | Swap -> {}",
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
    let total_archive_bytes: f64 = archive_sizes.iter().sum::<u64>().max(1) as f64;
    let mut cumulative_bytes: u64 = 0;
    let unpack_clock = Instant::now();
    set_progress(shared, None, Some(0.0), None);

    for (idx, archive_path) in archives.iter().enumerate() {
        if control.cancel_requested.load(Ordering::Relaxed) {
            anyhow::bail!("Cancelled by user");
        }
        let sz = archive_sizes[idx];
        let start_p = (cumulative_bytes as f64 / total_archive_bytes) as f32 * 0.96;
        cumulative_bytes += sz;
        let end_p = (cumulative_bytes as f64 / total_archive_bytes) as f32 * 0.96;
        let magic = detect::probe_archive_magic(archive_path);
        let fname = archive_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        set_progress(shared, None, Some(start_p), Some(&format!("Unpacking {fname} ({}/{})", idx + 1, archives.len())));
        push_log(shared, format!("[UNPACK] {fname} -> detected magic: {magic:?}"));

        match magic {
            ArchiveMagic::FreeArc => {
                run_unarc_extract(
                    &unarc,
                    &work_dir,
                    archive_path,
                    &cfg.target_game_dir,
                    &cfg.fast_temp_dir,
                    dissected.archive_password.as_deref(),
                    shared,
                    control,
                    unpack_clock,
                    start_p,
                    end_p,
                    &fname,
                )?;
            }
            ArchiveMagic::InnoSlice => {
                if !innoextract.exists() {
                    anyhow::bail!("tools/innoextract.exe is required to unpack Inno slice {fname}");
                }
                let setup = setup_exe.as_ref().with_context(|| {
                    format!("Found Inno slice {fname} but no matching setup*.exe")
                })?;
                let args = vec![
                    "-e".into(),
                    "-d".into(),
                    cfg.target_game_dir.display().to_string(),
                    setup.display().to_string(),
                ];
                run_and_stream_logs(&innoextract, &args, None, &cfg.fast_temp_dir, shared, control, unpack_clock, start_p, end_p)?;
                break;
            }
            ArchiveMagic::SevenZip | ArchiveMagic::Rar | ArchiveMagic::Zip | ArchiveMagic::Iso9660 => {
                run_7z_extract(
                    &seven_zip,
                    archive_path,
                    &cfg.target_game_dir,
                    &cfg.fast_temp_dir,
                    shared,
                    control,
                    unpack_clock,
                    start_p,
                    end_p,
                    &fname,
                )?;
            }
            ArchiveMagic::Unknown => {
                if unarc.exists() && (dissected.has_unarc_payload || fmt != RepackFormat::SceneArchiveOrIso) {
                    run_unarc_extract(
                        &unarc,
                        &work_dir,
                        archive_path,
                        &cfg.target_game_dir,
                        &cfg.fast_temp_dir,
                        dissected.archive_password.as_deref(),
                        shared,
                        control,
                        unpack_clock,
                        start_p,
                        end_p,
                        &fname,
                    )?;
                } else {
                    run_7z_extract(
                        &seven_zip,
                        archive_path,
                        &cfg.target_game_dir,
                        &cfg.fast_temp_dir,
                        shared,
                        control,
                        unpack_clock,
                        start_p,
                        end_p,
                        &fname,
                    )?;
                }
            }
        }
    }

    if cfg.replay_registry && !dissected.registry_entries.is_empty() {
        set_progress(shared, None, Some(0.95), Some("Applying game registry entries..."));
        let count = dissect::apply_registry_entries(&dissected.registry_entries, &cfg.target_game_dir);
        push_log(shared, format!("[REG] Applied {count} game registry key(s)."));
    }

    if cfg.create_shortcuts && !dissected.icon_entries.is_empty() {
        let created = dissect::create_desktop_shortcuts(&dissected.icon_entries, &cfg.target_game_dir);
        if created > 0 {
            push_log(shared, format!("[SHORTCUT] Created {created} Desktop shortcut(s)."));
        }
    }

    for post in &dissected.safe_post_run {
        if control.cancel_requested.load(Ordering::Relaxed) {
            anyhow::bail!("Cancelled by user");
        }
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

    cleanup_work_dir(cfg.auto_clean_temp, &work_dir, shared);
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
fn run_unarc_extract(
    unarc: &Path,
    work_dir: &Path,
    archive_path: &Path,
    target_game_dir: &Path,
    fast_temp_dir: &Path,
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

    // Preferred path: invoke the repack's OWN unarc.dll via our 32-bit LAA host.
    // Supports FitGirl, DODI, CODEX, R.G. Mechanics, and custom FreeArc 0.67/modified descriptors!
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
    run_and_stream_logs(&local_unarc, &args, Some(work_dir), fast_temp_dir, shared, control, unpack_clock, start_p, end_p)
}

#[allow(clippy::too_many_arguments)]
fn run_7z_extract(
    seven_zip: &Path,
    archive_path: &Path,
    target_game_dir: &Path,
    fast_temp_dir: &Path,
    shared: &Arc<Mutex<SharedTelemetry>>,
    control: &Arc<PipelineControl>,
    job_start: Instant,
    start_p: f32,
    end_p: f32,
    fname: &str,
) -> Result<()> {
    if !seven_zip.exists() {
        anyhow::bail!("tools/7z.exe is required to unpack {fname}");
    }
    let args = vec![
        "x".into(),
        "-y".into(),
        format!("-o{}", target_game_dir.display()),
        archive_path.display().to_string(),
    ];
    run_and_stream_logs(seven_zip, &args, None, fast_temp_dir, shared, control, unpack_clock, start_p, end_p)
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

    // Spawn live anti-"freeze" worker monitor (RAM MB, Disk Write MB/s, Active Worker Name, ETA)
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
                } else if pct >= 0.01 && pct < 0.995 {
                    let elapsed = job_start.elapsed().as_secs_f32();
                    let raw_rem = (elapsed / pct) * (1.0 - pct);
                    let smoothed = match smooth_eta {
                        Some(prev) => prev * 0.75 + raw_rem * 0.25,
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
