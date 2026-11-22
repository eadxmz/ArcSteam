#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod detect;
mod dissect;
mod optimizer;
mod pipeline;
mod stream_bridge;
mod verify;
mod win_sys;
mod zstd_pack;

use config::AppConfig;
use detect::{RepackFileEntry, RepackFormat};
use eframe::egui::{self, Color32, CornerRadius, Frame, Margin, RichText, Stroke, Vec2};
use optimizer::PeBitness;
use pipeline::{JobConfig, PipelineControl, QueueEntry, QueueItemState, SharedTelemetry};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use verify::{FileVerifyOutcome, VerifyProgress};
use win_sys::PostQueueAction;
use zstd_pack::ZstdProgress;

#[derive(PartialEq, Eq)]
enum AppTab {
    TorrentStream,
    LocalTurbo,
    Queue,
    VerifyAndZstd,
}

struct ToolsHealth {
    is_admin: bool,
    winfsp_ok: bool,
    innounp_ok: bool,
    unarc_ok: bool,
    unarc_bitness: PeBitness,
    srep64_ok: bool,
    innoextract_ok: bool,
    seven_zip_ok: bool,
}

impl ToolsHealth {
    fn probe() -> Self {
        let tools = pipeline::tools_dir();
        let unarc_path = tools.join("unarc.exe");
        let unarc_ok = unarc_path.exists();
        let unarc_bitness = if unarc_ok {
            optimizer::inspect_pe_bitness(&unarc_path)
        } else {
            PeBitness::Unknown
        };
        let srep64_ok = ["srep64.exe", "cls-srep_x64.exe", "srep_x64.exe", "srep.exe"]
            .iter()
            .any(|name| {
                let p = tools.join(name);
                p.exists() && optimizer::inspect_pe_bitness(&p) == PeBitness::Bit64
            });

        Self {
            is_admin: win_sys::is_elevated(),
            winfsp_ok: win_sys::is_winfsp_installed(),
            innounp_ok: tools.join("innounp.exe").exists(),
            unarc_ok,
            unarc_bitness,
            srep64_ok,
            innoextract_ok: tools.join("innoextract.exe").exists(),
            seven_zip_ok: tools.join("7z.exe").exists(),
        }
    }
}

struct ArcSteamApp {
    tab: AppTab,
    cfg: AppConfig,
    magnet_or_torrent: String,
    detected_format: RepackFormat,
    scanned_files: Vec<RepackFileEntry>,
    queue: Vec<QueueEntry>,
    telemetry: Arc<Mutex<SharedTelemetry>>,
    control: Arc<PipelineControl>,
    health: ToolsHealth,
    // Verifier state
    verify_dir: PathBuf,
    verify_progress: Arc<Mutex<VerifyProgress>>,
    verify_cancel: Arc<AtomicBool>,
    // Zstd Fast-Archive state
    zstd_src: PathBuf,
    zstd_dst: PathBuf,
    zstd_level: i32,
    zstd_progress: Arc<Mutex<ZstdProgress>>,
    zstd_cancel: Arc<AtomicBool>,
}

impl Default for ArcSteamApp {
    fn default() -> Self {
        let cfg = AppConfig::load();
        let mut initial_telemetry = SharedTelemetry::default();
        initial_telemetry.stage_label = "Idle — Ready to stream or turbo-unpack".into();
        initial_telemetry.eta_text = "--".into();
        initial_telemetry.log(
            "ArcSteam initialized | FreeArc / DODI / FitGirl / GOG Inno / 7z / ISO / Zstd",
        );

        let telemetry = Arc::new(Mutex::new(initial_telemetry));
        let sweep_telemetry = telemetry.clone();
        std::thread::spawn(move || {
            let swept = optimizer::sweep_stale_defender_exclusions();
            if !swept.is_empty() {
                if let Ok(mut t) = sweep_telemetry.lock() {
                    t.log(format!(
                        "[RECOVERY] Swept {} stale Defender exclusion(s) from prior unclean exit.",
                        swept.len()
                    ));
                }
            }
        });

        let verify_dir = cfg.local_source.clone();
        let zstd_src = cfg.target_game_dir.clone();
        let zstd_dst = PathBuf::from(r"G:\GameBackup.tar.zst");

        Self {
            tab: AppTab::TorrentStream,
            cfg,
            magnet_or_torrent: String::new(),
            detected_format: RepackFormat::FitGirlMultiArc,
            scanned_files: Vec::new(),
            queue: Vec::new(),
            telemetry,
            control: Arc::new(PipelineControl::default()),
            health: ToolsHealth::probe(),
            verify_dir,
            verify_progress: Arc::new(Mutex::new(VerifyProgress::default())),
            verify_cancel: Arc::new(AtomicBool::new(false)),
            zstd_src,
            zstd_dst,
            zstd_level: 4,
            zstd_progress: Arc::new(Mutex::new(ZstdProgress::default())),
            zstd_cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl ArcSteamApp {
    fn configure_theme(ctx: &egui::Context) {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = Color32::from_rgb(9, 13, 24);
        visuals.window_fill = Color32::from_rgb(14, 20, 36);
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(22, 31, 52);
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(30, 44, 72);
        visuals.widgets.inactive.corner_radius = CornerRadius::same(10);
        visuals.widgets.hovered.corner_radius = CornerRadius::same(10);
        visuals.widgets.active.corner_radius = CornerRadius::same(10);
        visuals.selection.bg_fill = Color32::from_rgb(34, 211, 238);
        visuals.selection.stroke = Stroke::new(1.0, Color32::from_rgb(10, 14, 24));
        ctx.set_visuals(visuals);
    }

    fn glass_card() -> Frame {
        Frame::new()
            .fill(Color32::from_rgba_unmultiplied(18, 27, 46, 230))
            .stroke(Stroke::new(1.0, Color32::from_rgba_unmultiplied(56, 189, 248, 52)))
            .corner_radius(CornerRadius::same(14))
            .inner_margin(Margin::same(12))
    }

    fn scan_local_now(&mut self) {
        if self.cfg.local_source.is_dir() {
            let (fmt, entries) = detect::scan_local_directory(&self.cfg.local_source);
            self.detected_format = fmt;
            self.scanned_files = entries;
            self.verify_dir = self.cfg.local_source.clone();
            if let Ok(mut t) = self.telemetry.lock() {
                t.log(format!(
                    "[SCAN] {} -> {} ({} files)",
                    self.cfg.local_source.display(),
                    fmt.badge(),
                    self.scanned_files.len()
                ));
            }
        }
    }

    fn build_current_job(&self, torrent_mode: bool) -> JobConfig {
        let display_name = if torrent_mode {
            let s = self.magnet_or_torrent.trim();
            if s.starts_with("magnet:") {
                "Magnet Stream Job".into()
            } else {
                PathBuf::from(s)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "Torrent Job".into())
            }
        } else {
            self.cfg
                .local_source
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| self.cfg.local_source.display().to_string())
        };

        JobConfig {
            display_name,
            is_torrent_mode: torrent_mode,
            magnet_or_torrent: self.magnet_or_torrent.clone(),
            local_source_dir: self.cfg.local_source.clone(),
            download_cache_dir: self.cfg.download_cache_dir.clone(),
            fast_temp_dir: self.cfg.temp_ssd_dir.clone(),
            target_game_dir: self.cfg.target_game_dir.clone(),
            virtual_drive: self.cfg.virtual_drive.clone(),
            live_stream_install: self.cfg.live_install_while_dl,
            defender_bypass: self.cfg.defender_bypass,
            replay_registry: self.cfg.replay_registry,
            create_shortcuts: self.cfg.create_shortcuts,
            auto_clean_temp: self.cfg.auto_clean_temp,
            srep_ram_mb: self.cfg.srep_ram_mb,
            selected_files: if torrent_mode {
                Vec::new()
            } else {
                self.scanned_files.clone()
            },
            detected_format: self.detected_format,
        }
    }

    fn draw_dual_frontier_bar(ui: &mut egui::Ui, dl_pct: f32, unpack_pct: f32, stage: &str) {
        let desired = Vec2::new(ui.available_width(), 24.0);
        let (rect, _) = ui.allocate_exact_size(desired, egui::Sense::hover());
        let p = ui.painter();

        p.rect_filled(rect, CornerRadius::same(12), Color32::from_rgb(13, 20, 36));

        let mut dl_rect = rect;
        dl_rect.set_width(rect.width() * dl_pct.clamp(0.0, 1.0));
        p.rect_filled(dl_rect, CornerRadius::same(12), Color32::from_rgb(99, 102, 241));

        let mut un_rect = rect;
        un_rect.set_width(rect.width() * unpack_pct.clamp(0.0, 1.0));
        p.rect_filled(un_rect, CornerRadius::same(12), Color32::from_rgb(34, 211, 238));

        let label = format!(
            "DL {:.1}%   |   UNPACK {:.1}%   —   {}",
            dl_pct * 100.0,
            unpack_pct * 100.0,
            stage
        );
        p.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(12.0),
            Color32::WHITE,
        );
    }

    fn draw_pill(ui: &mut egui::Ui, label: &str, ok: bool) {
        let (bg, fg) = if ok {
            (
                Color32::from_rgba_unmultiplied(16, 185, 129, 36),
                Color32::from_rgb(52, 211, 153),
            )
        } else {
            (
                Color32::from_rgba_unmultiplied(245, 158, 11, 36),
                Color32::from_rgb(251, 191, 36),
            )
        };
        Frame::new()
            .fill(bg)
            .corner_radius(CornerRadius::same(8))
            .inner_margin(Margin::symmetric(7, 3))
            .show(ui, |ui| {
                ui.label(RichText::new(label).size(11.0).strong().color(fg));
            });
    }

    fn draw_free_space_badge(ui: &mut egui::Ui, path: &PathBuf, warn_under_gb: u64) {
        if let Some(free) = win_sys::free_disk_bytes(path) {
            let color = if free < warn_under_gb * 1024 * 1024 * 1024 {
                Color32::from_rgb(251, 191, 36)
            } else {
                Color32::from_rgb(52, 211, 153)
            };
            ui.label(
                RichText::new(format!("{} free", detect::format_bytes(free)))
                    .size(11.0)
                    .color(color),
            );
        }
    }
}

impl eframe::App for ArcSteamApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Drag-and-drop support: multiple folders/torrents automatically queue up!
        let dropped: Vec<PathBuf> = ui.ctx().input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .filter(|p| !p.as_os_str().is_empty())
                .collect()
        });
        if dropped.len() > 1 {
            for path in dropped {
                if path.is_dir() {
                    let (fmt, entries) = detect::scan_local_directory(&path);
                    let mut job = self.build_current_job(false);
                    job.display_name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| path.display().to_string());
                    job.local_source_dir = path;
                    job.detected_format = fmt;
                    job.selected_files = entries;
                    self.queue.push(QueueEntry {
                        config: job,
                        state: QueueItemState::Queued,
                    });
                } else if path.extension().and_then(|e| e.to_str()) == Some("torrent") {
                    let mut job = self.build_current_job(true);
                    job.display_name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "Torrent".into());
                    job.magnet_or_torrent = path.display().to_string();
                    self.queue.push(QueueEntry {
                        config: job,
                        state: QueueItemState::Queued,
                    });
                }
            }
            self.tab = AppTab::Queue;
        } else if let Some(path) = dropped.into_iter().next() {
            if path.is_dir() {
                self.tab = AppTab::LocalTurbo;
                self.cfg.local_source = path;
                self.scan_local_now();
                self.cfg.save();
            } else if path.extension().and_then(|e| e.to_str()) == Some("torrent") {
                self.tab = AppTab::TorrentStream;
                self.magnet_or_torrent = path.display().to_string();
            }
        }

        let (
            running,
            dl_pct,
            unpack_pct,
            dl_mbps,
            write_mbps,
            worker_ram,
            active_worker,
            eta_text,
            stage_label,
            active_q_idx,
            queue_states,
            logs_snapshot,
        ) = {
            let t = self.telemetry.lock().unwrap();
            (
                t.running,
                t.download_pct,
                t.unpack_pct,
                t.dl_speed_mbps,
                t.disk_write_mbps,
                t.worker_ram_mb,
                t.active_worker.clone(),
                t.eta_text.clone(),
                t.stage_label.clone(),
                t.active_queue_idx,
                t.queue_states.clone(),
                t.logs.clone(),
            )
        };

        // Sync queue item statuses back into UI list
        if queue_states.len() == self.queue.len() {
            for (entry, st) in self.queue.iter_mut().zip(queue_states.iter()) {
                entry.state = *st;
            }
        }

        let verify_running = self.verify_progress.lock().unwrap().running;
        let zstd_running = self.zstd_progress.lock().unwrap().running;
        if running || verify_running || zstd_running {
            ui.ctx().request_repaint_after(Duration::from_millis(140));
        }

        let mut cfg_dirty = false;

        egui::CentralPanel::default().show(ui, |ui| {
            // Top Header with Embedded SVG Logo & 4-Tab Pill Switcher
            ui.horizontal(|ui| {
                ui.add(
                    egui::Image::new(egui::include_image!("../assets/logo.svg"))
                        .max_size(Vec2::splat(42.0)),
                );
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("ArcSteam")
                            .size(21.0)
                            .strong()
                            .color(Color32::from_rgb(241, 245, 249)),
                    );
                    ui.label(
                        RichText::new("Live Torrent-to-Unpack Streamer & Universal Turbo Engine")
                            .size(11.0)
                            .color(Color32::from_rgb(148, 163, 184)),
                    );
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.selectable_value(&mut self.tab, AppTab::VerifyAndZstd, "Verify & Zstd");
                    let q_label = if self.queue.is_empty() {
                        "Queue".to_string()
                    } else {
                        format!("Queue ({})", self.queue.len())
                    };
                    ui.selectable_value(&mut self.tab, AppTab::Queue, q_label);
                    ui.selectable_value(&mut self.tab, AppTab::LocalTurbo, "Local Turbo");
                    ui.selectable_value(&mut self.tab, AppTab::TorrentStream, "Torrent / Magnet");
                });
            });

            ui.add_space(8.0);

            match self.tab {
                AppTab::TorrentStream | AppTab::LocalTurbo => {
                    // Source Input Card
                    Self::glass_card().show(ui, |ui| {
                        if self.tab == AppTab::TorrentStream {
                            ui.label(RichText::new("Magnet URI or .torrent File").strong());
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.magnet_or_torrent)
                                        .hint_text("magnet:?xt=urn:btih:... or drop .torrent file(s)")
                                        .desired_width(ui.available_width() - 125.0),
                                );
                                if ui.button("Browse .torrent").clicked() {
                                    if let Some(p) = rfd::FileDialog::new()
                                        .add_filter("BitTorrent", &["torrent"])
                                        .pick_file()
                                    {
                                        self.magnet_or_torrent = p.display().to_string();
                                    }
                                }
                            });
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                if ui
                                    .checkbox(
                                        &mut self.cfg.live_install_while_dl,
                                        "Install LIVE while downloading (WinFsp Z:\\ + 32 MB contiguous read-ahead)",
                                    )
                                    .changed()
                                {
                                    cfg_dirty = true;
                                }
                                ui.separator();
                                ui.label("Mount:");
                                if ui
                                    .add(
                                        egui::TextEdit::singleline(&mut self.cfg.virtual_drive)
                                            .desired_width(36.0),
                                    )
                                    .changed()
                                {
                                    cfg_dirty = true;
                                }
                            });
                        } else {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Local Repack Folder").strong());
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.label(
                                        RichText::new(self.detected_format.badge())
                                            .size(11.5)
                                            .color(Color32::from_rgb(34, 211, 238)),
                                    );
                                });
                            });
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                let mut s = self.cfg.local_source.display().to_string();
                                if ui
                                    .add(
                                        egui::TextEdit::singleline(&mut s)
                                            .desired_width(ui.available_width() - 165.0),
                                    )
                                    .changed()
                                {
                                    self.cfg.local_source = PathBuf::from(s);
                                    cfg_dirty = true;
                                }
                                if ui.button("Pick Folder").clicked() {
                                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                        self.cfg.local_source = p;
                                        self.scan_local_now();
                                        cfg_dirty = true;
                                    }
                                }
                                if ui.button("Scan").clicked() {
                                    self.scan_local_now();
                                }
                            });

                            if !self.scanned_files.is_empty() {
                                ui.add_space(4.0);
                                let skipped_bytes: u64 = self
                                    .scanned_files
                                    .iter()
                                    .filter(|f| !f.selected)
                                    .map(|f| f.size_bytes)
                                    .sum();
                                ui.label(
                                    RichText::new(format!(
                                        "Archive Blueprint ({} files | skipping {} of optional/extra packs)",
                                        self.scanned_files.len(),
                                        detect::format_bytes(skipped_bytes)
                                    ))
                                    .size(11.2)
                                    .color(Color32::from_rgb(148, 163, 184)),
                                );
                                egui::ScrollArea::vertical()
                                    .id_salt("blueprint_scroll")
                                    .max_height(84.0)
                                    .show(ui, |ui| {
                                        for entry in &mut self.scanned_files {
                                            if entry.is_archive {
                                                let tag = if entry.is_optional { " [optional]" } else { "" };
                                                let label = format!(
                                                    "{} ({}){}",
                                                    entry.rel_path,
                                                    detect::format_bytes(entry.size_bytes),
                                                    tag
                                                );
                                                ui.checkbox(&mut entry.selected, label);
                                            }
                                        }
                                    });
                            }
                        }
                    });

                    ui.add_space(6.0);

                    // Real-Time Speed Pipeline Card with Pre-Flight Free Space Checks
                    Self::glass_card().show(ui, |ui| {
                        ui.label(RichText::new("Real-Time Speed Pipeline (Split-Drive I/O + RAM Boost)").strong());
                        ui.add_space(4.0);

                        egui::Grid::new("paths_grid").num_columns(4).spacing([8.0, 4.0]).show(ui, |ui| {
                            if self.tab == AppTab::TorrentStream {
                                ui.label("Torrent Cache:");
                                let mut c = self.cfg.download_cache_dir.display().to_string();
                                if ui.add(egui::TextEdit::singleline(&mut c).desired_width(390.0)).changed() {
                                    self.cfg.download_cache_dir = PathBuf::from(c);
                                    cfg_dirty = true;
                                }
                                if ui.button("Browse").clicked() {
                                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                        self.cfg.download_cache_dir = p;
                                        cfg_dirty = true;
                                    }
                                }
                                Self::draw_free_space_badge(ui, &self.cfg.download_cache_dir, 15);
                                ui.end_row();
                            }

                            ui.label("Fast SSD TEMP:");
                            let mut tmp = self.cfg.temp_ssd_dir.display().to_string();
                            if ui.add(egui::TextEdit::singleline(&mut tmp).desired_width(390.0)).changed() {
                                self.cfg.temp_ssd_dir = PathBuf::from(tmp);
                                cfg_dirty = true;
                            }
                            if ui.button("Browse").clicked() {
                                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                    self.cfg.temp_ssd_dir = p;
                                    cfg_dirty = true;
                                }
                            }
                            Self::draw_free_space_badge(ui, &self.cfg.temp_ssd_dir, 8);
                            ui.end_row();

                            ui.label("Install Target:");
                            let mut dst = self.cfg.target_game_dir.display().to_string();
                            if ui.add(egui::TextEdit::singleline(&mut dst).desired_width(390.0)).changed() {
                                self.cfg.target_game_dir = PathBuf::from(dst);
                                cfg_dirty = true;
                            }
                            if ui.button("Browse").clicked() {
                                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                    self.cfg.target_game_dir = p;
                                    cfg_dirty = true;
                                }
                            }
                            Self::draw_free_space_badge(ui, &self.cfg.target_game_dir, 25);
                            ui.end_row();
                        });

                        ui.add_space(5.0);
                        ui.horizontal_wrapped(|ui| {
                            if ui.checkbox(&mut self.cfg.defender_bypass, "Defender Guard").changed() {
                                cfg_dirty = true;
                            }
                            if ui.checkbox(&mut self.cfg.replay_registry, "Replay [Registry]").changed() {
                                cfg_dirty = true;
                            }
                            if ui.checkbox(&mut self.cfg.create_shortcuts, "Desktop Shortcuts").changed() {
                                cfg_dirty = true;
                            }
                            if ui.checkbox(&mut self.cfg.auto_clean_temp, "Auto-Clean Temp").changed() {
                                cfg_dirty = true;
                            }
                            ui.separator();
                            ui.label("SREP RAM:");
                            if ui
                                .add(egui::Slider::new(&mut self.cfg.srep_ram_mb, 1024..=12288).suffix(" MB"))
                                .changed()
                            {
                                cfg_dirty = true;
                            }
                        });
                    });
                }

                AppTab::Queue => {
                    Self::glass_card().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Batch Install Queue (Drag & Drop Multiple Folders)").strong());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.add_enabled(!running && !self.queue.is_empty(), egui::Button::new("Clear Queue")).clicked() {
                                    self.queue.clear();
                                }
                                if ui.button("+ Add Local Folder").clicked() {
                                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                        let (fmt, entries) = detect::scan_local_directory(&p);
                                        let mut job = self.build_current_job(false);
                                        job.display_name = p
                                            .file_name()
                                            .map(|n| n.to_string_lossy().to_string())
                                            .unwrap_or_else(|| p.display().to_string());
                                        job.local_source_dir = p;
                                        job.detected_format = fmt;
                                        job.selected_files = entries;
                                        self.queue.push(QueueEntry {
                                            config: job,
                                            state: QueueItemState::Queued,
                                        });
                                    }
                                }
                            });
                        });
                        ui.add_space(6.0);

                        if self.queue.is_empty() {
                            ui.label(
                                RichText::new("Queue is empty. Add repacks from Torrent/Local tabs or drag multiple folders onto this window.")
                                    .color(Color32::from_rgb(148, 163, 184)),
                            );
                        } else {
                            let mut remove_idx: Option<usize> = None;
                            egui::ScrollArea::vertical()
                                .id_salt("queue_scroll")
                                .max_height(190.0)
                                .show(ui, |ui| {
                                    for (i, item) in self.queue.iter().enumerate() {
                                        ui.horizontal(|ui| {
                                            let badge_color = match item.state {
                                                QueueItemState::Done => Color32::from_rgb(52, 211, 153),
                                                QueueItemState::Running => Color32::from_rgb(34, 211, 238),
                                                QueueItemState::Failed | QueueItemState::Cancelled => {
                                                    Color32::from_rgb(248, 113, 113)
                                                }
                                                QueueItemState::Queued => Color32::from_rgb(148, 163, 184),
                                            };
                                            ui.label(
                                                RichText::new(format!("[{}]", item.state.label()))
                                                    .strong()
                                                    .color(badge_color),
                                            );
                                            ui.label(RichText::new(&item.config.display_name).strong());
                                            ui.label(
                                                RichText::new(format!(
                                                    "-> {}",
                                                    item.config.target_game_dir.display()
                                                ))
                                                .size(11.0)
                                                .color(Color32::from_rgb(148, 163, 184)),
                                            );
                                            if !running && ui.small_button("Remove").clicked() {
                                                remove_idx = Some(i);
                                            }
                                        });
                                    }
                                });
                            if let Some(idx) = remove_idx {
                                self.queue.remove(idx);
                            }
                        }

                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            ui.label("When Queue Finishes:");
                            egui::ComboBox::from_id_salt("post_queue_action")
                                .selected_text(self.cfg.post_queue_action.label())
                                .show_ui(ui, |ui| {
                                    for opt in [
                                        PostQueueAction::DoNothing,
                                        PostQueueAction::SleepPc,
                                        PostQueueAction::ShutdownPc,
                                    ] {
                                        if ui
                                            .selectable_value(
                                                &mut self.cfg.post_queue_action,
                                                opt,
                                                opt.label(),
                                            )
                                            .changed()
                                        {
                                            cfg_dirty = true;
                                        }
                                    }
                                });
                            ui.label(
                                RichText::new("(Windows sleep is blocked automatically while running)")
                                    .size(11.0)
                                    .color(Color32::from_rgb(148, 163, 184)),
                            );
                        });
                    });
                }

                AppTab::VerifyAndZstd => {
                    // Multi-Threaded MD5 / SFV Verifier Card
                    Self::glass_card().show(ui, |ui| {
                        ui.label(RichText::new("Multi-Threaded MD5 / SFV Verifier (Native Rust)").strong());
                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            let mut s = self.verify_dir.display().to_string();
                            if ui
                                .add(egui::TextEdit::singleline(&mut s).desired_width(ui.available_width() - 220.0))
                                .changed()
                            {
                                self.verify_dir = PathBuf::from(s);
                            }
                            if ui.button("Pick Folder").clicked() {
                                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                    self.verify_dir = p;
                                }
                            }
                            if verify_running {
                                if ui.button("Stop").clicked() {
                                    self.verify_cancel.store(true, Ordering::Relaxed);
                                }
                            } else if ui.button("Verify Now").clicked() {
                                verify::spawn_verify_thread(
                                    self.verify_dir.clone(),
                                    self.verify_progress.clone(),
                                    self.verify_cancel.clone(),
                                );
                            }
                        });

                        let vp = self.verify_progress.lock().unwrap().clone();
                        if !vp.manifest_found.is_empty() {
                            ui.add_space(4.0);
                            ui.label(
                                RichText::new(format!(
                                    "Manifest: {}  |  {}/{} checked  |  OK: {}  Missing: {}  Corrupt: {}",
                                    vp.manifest_found,
                                    vp.completed,
                                    vp.total,
                                    vp.ok_count,
                                    vp.missing_count,
                                    vp.corrupt_count
                                ))
                                .size(11.5)
                                .color(if vp.corrupt_count > 0 || vp.missing_count > 0 {
                                    Color32::from_rgb(248, 113, 113)
                                } else {
                                    Color32::from_rgb(52, 211, 153)
                                }),
                            );
                            if !vp.results.is_empty() {
                                egui::ScrollArea::vertical()
                                    .id_salt("verify_scroll")
                                    .max_height(64.0)
                                    .show(ui, |ui| {
                                        for res in &vp.results {
                                            match res {
                                                FileVerifyOutcome::Ok(f) => {
                                                    ui.label(RichText::new(format!("[OK] {f}")).monospace().size(10.8).color(Color32::from_rgb(52, 211, 153)));
                                                }
                                                FileVerifyOutcome::Missing(f) => {
                                                    ui.label(RichText::new(format!("[MISSING] {f}")).monospace().size(10.8).color(Color32::from_rgb(251, 191, 36)));
                                                }
                                                FileVerifyOutcome::Corrupt { file, expected, actual } => {
                                                    ui.label(RichText::new(format!("[CORRUPT] {file} (expected {expected}, got {actual})")).monospace().size(10.8).color(Color32::from_rgb(248, 113, 113)));
                                                }
                                            }
                                        }
                                    });
                            }
                        }
                    });

                    ui.add_space(6.0);

                    // Zstd Fast-Archive Re-Pack / Unpack Card
                    Self::glass_card().show(ui, |ui| {
                        ui.label(RichText::new("Zstd Fast-Archive (.tar.zst — 500+ MB/s Decompression)").strong());
                        ui.add_space(4.0);
                        egui::Grid::new("zstd_grid").num_columns(3).spacing([8.0, 4.0]).show(ui, |ui| {
                            ui.label("Game Folder:");
                            let mut s = self.zstd_src.display().to_string();
                            if ui.add(egui::TextEdit::singleline(&mut s).desired_width(470.0)).changed() {
                                self.zstd_src = PathBuf::from(s);
                            }
                            if ui.button("Browse").clicked() {
                                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                    self.zstd_src = p;
                                }
                            }
                            ui.end_row();

                            ui.label(".tar.zst Archive:");
                            let mut d = self.zstd_dst.display().to_string();
                            if ui.add(egui::TextEdit::singleline(&mut d).desired_width(470.0)).changed() {
                                self.zstd_dst = PathBuf::from(d);
                            }
                            if ui.button("Pick File").clicked() {
                                if let Some(p) = rfd::FileDialog::new()
                                    .add_filter("Zstd Tar", &["zst"])
                                    .save_file()
                                {
                                    self.zstd_dst = p;
                                }
                            }
                            ui.end_row();
                        });

                        ui.add_space(4.0);
                        let zp = self.zstd_progress.lock().unwrap().clone();
                        ui.horizontal(|ui| {
                            ui.label("Level:");
                            ui.add(egui::Slider::new(&mut self.zstd_level, 1..=12));
                            if ui.add_enabled(!zstd_running, egui::Button::new("Pack Folder -> .tar.zst")).clicked() {
                                zstd_pack::spawn_zstd_pack(
                                    self.zstd_src.clone(),
                                    self.zstd_dst.clone(),
                                    self.zstd_level,
                                    self.zstd_progress.clone(),
                                    self.zstd_cancel.clone(),
                                );
                            }
                            if ui.add_enabled(!zstd_running, egui::Button::new("Unpack .tar.zst -> Folder")).clicked() {
                                zstd_pack::spawn_zstd_unpack(
                                    self.zstd_dst.clone(),
                                    self.zstd_src.clone(),
                                    self.zstd_progress.clone(),
                                    self.zstd_cancel.clone(),
                                );
                            }
                            if zstd_running && ui.button("Cancel").clicked() {
                                self.zstd_cancel.store(true, Ordering::Relaxed);
                            }
                        });
                        if !zp.status.is_empty() {
                            ui.add_space(3.0);
                            ui.add(egui::ProgressBar::new(zp.pct).text(zp.status));
                        }
                    });
                }
            }

            ui.add_space(6.0);

            // Dual Frontier Progress + Anti-"Freeze" Telemetry + Pause/Cancel Controls
            Self::glass_card().show(ui, |ui| {
                ui.horizontal(|ui| {
                    let worker_txt = if active_worker.is_empty() {
                        "Idle"
                    } else {
                        &active_worker
                    };
                    let q_prefix = match active_q_idx {
                        Some(i) if queue_states.len() > 1 => format!("Job {}/{}   |   ", i + 1, queue_states.len()),
                        _ => String::new(),
                    };
                    ui.label(
                        RichText::new(format!(
                            "{q_prefix}Worker: {worker_txt}   |   RAM: {worker_ram} MB   |   Write: {write_mbps:.1} MB/s   |   DL: {dl_mbps:.1} MB/s   |   ETA: {eta_text}"
                        ))
                        .size(11.3)
                        .color(Color32::from_rgb(148, 163, 184)),
                    );
                });
                ui.add_space(4.0);

                Self::draw_dual_frontier_bar(ui, dl_pct, unpack_pct, &stage_label);
                ui.add_space(7.0);

                ui.horizontal(|ui| {
                    let is_queue_tab = self.tab == AppTab::Queue;
                    let btn_text = if running {
                        "  Pipeline Running...  "
                    } else if is_queue_tab {
                        "  Start Batch Queue  "
                    } else if self.tab == AppTab::TorrentStream {
                        "  Start Live Stream Install  "
                    } else {
                        "  Start Turbo Local Unpack  "
                    };

                    let can_start = !running && (!is_queue_tab || !self.queue.is_empty());
                    let launch = egui::Button::new(
                        RichText::new(btn_text)
                            .strong()
                            .color(Color32::from_rgb(10, 14, 24)),
                    )
                    .fill(if can_start {
                        Color32::from_rgb(34, 211, 238)
                    } else {
                        Color32::from_rgb(71, 85, 105)
                    })
                    .corner_radius(CornerRadius::same(10));

                    if ui.add_enabled(can_start, launch).clicked() {
                        self.cfg.save();
                        let jobs: Vec<JobConfig> = if is_queue_tab {
                            self.queue.iter().map(|q| q.config.clone()).collect()
                        } else {
                            let j = self.build_current_job(self.tab == AppTab::TorrentStream);
                            self.queue = vec![QueueEntry {
                                config: j.clone(),
                                state: QueueItemState::Queued,
                            }];
                            vec![j]
                        };
                        pipeline::spawn_queue_thread(
                            jobs,
                            self.cfg.post_queue_action,
                            self.telemetry.clone(),
                            self.control.clone(),
                        );
                    }

                    if matches!(self.tab, AppTab::TorrentStream | AppTab::LocalTurbo)
                        && ui.add_enabled(!running, egui::Button::new("+ Add to Queue")).clicked()
                    {
                        let j = self.build_current_job(self.tab == AppTab::TorrentStream);
                        self.queue.push(QueueEntry {
                            config: j,
                            state: QueueItemState::Queued,
                        });
                    }

                    if running {
                        let paused = self.control.paused.load(Ordering::Relaxed);
                        let p_label = if paused { "Resume" } else { "Pause" };
                        if ui.button(p_label).clicked() {
                            let now_paused = self.control.toggle_pause();
                            if let Ok(mut t) = self.telemetry.lock() {
                                t.stage_label = if now_paused {
                                    "Paused (process tree suspended)".into()
                                } else {
                                    "Resumed".into()
                                };
                            }
                        }

                        let cancel_btn = egui::Button::new(
                            RichText::new("Cancel").strong().color(Color32::WHITE),
                        )
                        .fill(Color32::from_rgb(220, 38, 38))
                        .corner_radius(CornerRadius::same(10));
                        if ui.add(cancel_btn).clicked() {
                            self.control.request_cancel();
                        }
                    }

                    if ui.button("Copy Log").clicked() {
                        ui.ctx().copy_text(logs_snapshot.join("\n"));
                    }
                });
            });

            ui.add_space(5.0);

            // Live Console Log
            let log_height = (ui.available_height() - 36.0).max(70.0);
            egui::ScrollArea::vertical()
                .id_salt("console_log")
                .max_height(log_height)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &logs_snapshot {
                        ui.label(
                            RichText::new(line)
                                .monospace()
                                .size(11.0)
                                .color(Color32::from_rgb(148, 163, 184)),
                        );
                    }
                });

            ui.separator();

            // Built-In Environment & tools/ Health Bar
            ui.horizontal_wrapped(|ui| {
                Self::draw_pill(
                    ui,
                    if self.health.is_admin { "Admin" } else { "No Admin" },
                    self.health.is_admin,
                );
                if !self.health.is_admin && ui.small_button("Elevate").clicked() {
                    if win_sys::relaunch_as_admin() {
                        std::process::exit(0);
                    }
                }
                Self::draw_pill(ui, "WinFsp", self.health.winfsp_ok);
                Self::draw_pill(ui, "innounp", self.health.innounp_ok);
                let unarc_tag = match self.health.unarc_bitness {
                    PeBitness::Bit64 => "unarc x64",
                    PeBitness::Bit32Laa => "unarc x86-LAA",
                    PeBitness::Bit32 => "unarc x86",
                    PeBitness::Unknown => "unarc",
                };
                Self::draw_pill(ui, unarc_tag, self.health.unarc_ok);
                Self::draw_pill(ui, "srep64", self.health.srep64_ok);
                Self::draw_pill(ui, "innoextract", self.health.innoextract_ok);
                Self::draw_pill(ui, "7z", self.health.seven_zip_ok);

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Refresh").clicked() {
                        self.health = ToolsHealth::probe();
                    }
                    if ui.small_button("Open tools/").clicked() {
                        win_sys::open_in_explorer(&pipeline::tools_dir());
                    }
                });
            });
        });

        if cfg_dirty {
            self.cfg.save();
        }
    }
}

fn main() -> eframe::Result {
    let _winfsp_init = winfsp::winfsp_init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([920.0, 740.0])
            .with_min_inner_size([780.0, 620.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "ArcSteam",
        options,
        Box::new(|cc| {
            egui_extras::install_image_loaders(&cc.egui_ctx);
            ArcSteamApp::configure_theme(&cc.egui_ctx);
            Ok(Box::new(ArcSteamApp::default()))
        }),
    )
}
