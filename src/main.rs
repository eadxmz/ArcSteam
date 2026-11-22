#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod config;
mod detect;
mod dissect;
mod embedded_tools;
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

const APP_ICON_RGBA: &[u8] = include_bytes!("../assets/icon_rgba.bin");

// Obsidian + Electric Purple Palette
const BG_CANVAS: Color32 = Color32::from_rgb(10, 8, 20);
const BG_CARD: Color32 = Color32::from_rgb(19, 14, 36);
const BG_INPUT: Color32 = Color32::from_rgb(26, 20, 48);
const BG_HOVER: Color32 = Color32::from_rgb(38, 28, 70);
const BORDER_PURPLE: Color32 = Color32::from_rgb(84, 52, 145);
const ACCENT_PURPLE: Color32 = Color32::from_rgb(147, 51, 234);
const ACCENT_VIOLET: Color32 = Color32::from_rgb(168, 85, 247);
const ACCENT_CYAN: Color32 = Color32::from_rgb(56, 189, 248);
const TEXT_PRIMARY: Color32 = Color32::from_rgb(245, 243, 255);
const TEXT_MUTED: Color32 = Color32::from_rgb(165, 158, 194);
const OK_GREEN: Color32 = Color32::from_rgb(52, 211, 153);
const WARN_AMBER: Color32 = Color32::from_rgb(251, 191, 36);
const ERR_RED: Color32 = Color32::from_rgb(248, 113, 113);

#[derive(PartialEq, Eq)]
enum MainTab {
    Install,
    Queue,
    Tools,
}

#[derive(PartialEq, Eq)]
enum SourceKind {
    LocalFolder,
    TorrentMagnet,
}

struct ToolsHealth {
    is_admin: bool,
    winfsp_ok: bool,
    innounp_ok: bool,
    unarc_ok: bool,
    unarc_bitness: PeBitness,
    innoextract_ok: bool,
    seven_zip_ok: bool,
    bundled_count: usize,
}

impl ToolsHealth {
    fn probe() -> Self {
        let unarc_path = embedded_tools::resolve_tool("unarc.exe");
        let unarc_ok = unarc_path.exists();
        let unarc_bitness = if unarc_ok {
            optimizer::inspect_pe_bitness(&unarc_path)
        } else {
            PeBitness::Unknown
        };
        Self {
            is_admin: win_sys::is_elevated(),
            winfsp_ok: win_sys::is_winfsp_installed(),
            innounp_ok: embedded_tools::resolve_tool("innounp.exe").exists(),
            unarc_ok,
            unarc_bitness,
            innoextract_ok: embedded_tools::resolve_tool("innoextract.exe").exists(),
            seven_zip_ok: embedded_tools::resolve_tool("7z.exe").exists(),
            bundled_count: embedded_tools::embedded_count(),
        }
    }

    fn core_engines_ready(&self) -> bool {
        self.innounp_ok && self.unarc_ok && self.innoextract_ok && self.seven_zip_ok
    }
}

struct ArcSteamApp {
    tab: MainTab,
    source_kind: SourceKind,
    cfg: AppConfig,
    magnet_or_torrent: String,
    detected_format: RepackFormat,
    scanned_files: Vec<RepackFileEntry>,
    queue: Vec<QueueEntry>,
    telemetry: Arc<Mutex<SharedTelemetry>>,
    control: Arc<PipelineControl>,
    health: ToolsHealth,
    show_logs: bool,
    // Tools tab state
    verify_dir: PathBuf,
    verify_progress: Arc<Mutex<VerifyProgress>>,
    verify_cancel: Arc<AtomicBool>,
    zstd_src: PathBuf,
    zstd_dst: PathBuf,
    zstd_level: i32,
    zstd_progress: Arc<Mutex<ZstdProgress>>,
    zstd_cancel: Arc<AtomicBool>,
}

impl Default for ArcSteamApp {
    fn default() -> Self {
        let extracted = embedded_tools::ensure_extracted();
        let cfg = AppConfig::load();

        let mut initial_telemetry = SharedTelemetry::default();
        initial_telemetry.stage_label = "Ready to install".into();
        initial_telemetry.eta_text = "--".into();
        if extracted > 0 {
            initial_telemetry.log(format!(
                "[INIT] ArcSteam ready — {extracted} built-in unpack engines verified."
            ));
        } else {
            initial_telemetry.log("[INIT] ArcSteam ready (using local tools/ folder).");
        }

        let telemetry = Arc::new(Mutex::new(initial_telemetry));
        let sweep_telemetry = telemetry.clone();
        std::thread::spawn(move || {
            let swept = optimizer::sweep_stale_defender_exclusions();
            if !swept.is_empty() {
                if let Ok(mut t) = sweep_telemetry.lock() {
                    t.log(format!(
                        "[RECOVERY] Cleaned up {} leftover Defender rule(s) from prior run.",
                        swept.len()
                    ));
                }
            }
        });

        let verify_dir = cfg.local_source.clone();
        let zstd_src = cfg.target_game_dir.clone();
        let zstd_dst = cfg.download_cache_dir.join("GameBackup.tar.zst");

        Self {
            tab: MainTab::Install,
            source_kind: SourceKind::LocalFolder,
            cfg,
            magnet_or_torrent: String::new(),
            detected_format: RepackFormat::FitGirlMultiArc,
            scanned_files: Vec::new(),
            queue: Vec::new(),
            telemetry,
            control: Arc::new(PipelineControl::default()),
            health: ToolsHealth::probe(),
            show_logs: false,
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
        visuals.panel_fill = BG_CANVAS;
        visuals.window_fill = Color32::from_rgb(16, 12, 30);
        visuals.extreme_bg_color = Color32::from_rgb(14, 10, 26);

        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
        visuals.widgets.inactive.bg_fill = BG_INPUT;
        visuals.widgets.inactive.weak_bg_fill = BG_INPUT;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, Color32::from_rgb(66, 44, 112));
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
        visuals.widgets.inactive.corner_radius = CornerRadius::same(10);

        visuals.widgets.hovered.bg_fill = BG_HOVER;
        visuals.widgets.hovered.weak_bg_fill = BG_HOVER;
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT_VIOLET);
        visuals.widgets.hovered.corner_radius = CornerRadius::same(10);

        visuals.widgets.active.bg_fill = ACCENT_PURPLE;
        visuals.widgets.active.bg_stroke = Stroke::new(1.0, Color32::from_rgb(216, 180, 254));
        visuals.widgets.active.corner_radius = CornerRadius::same(10);

        visuals.selection.bg_fill = ACCENT_PURPLE;
        visuals.selection.stroke = Stroke::new(1.0, TEXT_PRIMARY);

        ctx.set_visuals(visuals);
    }

    fn glass_card() -> Frame {
        Frame::new()
            .fill(BG_CARD)
            .stroke(Stroke::new(1.0, BORDER_PURPLE))
            .corner_radius(CornerRadius::same(16))
            .inner_margin(Margin::same(16))
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
                "Live Torrent Stream".into()
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

    fn draw_progress_bar(ui: &mut egui::Ui, dl_pct: f32, unpack_pct: f32, stage: &str, is_torrent: bool) {
        let desired = Vec2::new(ui.available_width(), 28.0);
        let (rect, _) = ui.allocate_exact_size(desired, egui::Sense::hover());
        let p = ui.painter();

        p.rect_filled(rect, CornerRadius::same(14), Color32::from_rgb(16, 12, 32));
        p.rect_stroke(
            rect,
            CornerRadius::same(14),
            Stroke::new(1.0, Color32::from_rgb(76, 48, 130)),
            egui::StrokeKind::Inside,
        );

        if is_torrent && dl_pct > 0.001 {
            let mut dl_rect = rect;
            dl_rect.set_width((rect.width() * dl_pct.clamp(0.0, 1.0)).max(14.0));
            p.rect_filled(dl_rect, CornerRadius::same(14), Color32::from_rgb(91, 33, 182));
        }

        if unpack_pct > 0.001 {
            let mut un_rect = rect;
            un_rect.set_width((rect.width() * unpack_pct.clamp(0.0, 1.0)).max(14.0));
            p.rect_filled(un_rect, CornerRadius::same(14), ACCENT_PURPLE);
        }

        let label = if is_torrent {
            format!(
                "Download {:.0}%   •   Install {:.0}%   —   {}",
                dl_pct * 100.0,
                unpack_pct * 100.0,
                stage
            )
        } else {
            format!("Install {:.0}%   —   {}", unpack_pct * 100.0, stage)
        };
        p.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(12.5),
            Color32::WHITE,
        );
    }

    fn draw_status_pill(ui: &mut egui::Ui, label: &str, ok: bool) -> egui::Response {
        let (bg, fg) = if ok {
            (Color32::from_rgb(16, 46, 38), OK_GREEN)
        } else {
            (Color32::from_rgb(50, 36, 16), WARN_AMBER)
        };
        Frame::new()
            .fill(bg)
            .corner_radius(CornerRadius::same(9))
            .inner_margin(Margin::symmetric(8, 3))
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(RichText::new(label).size(11.0).strong().color(fg))
                        .sense(egui::Sense::click()),
                )
            })
            .inner
    }

    fn draw_free_badge(ui: &mut egui::Ui, path: &PathBuf, warn_under_gb: u64) {
        if let Some(free) = win_sys::free_disk_bytes(path) {
            let color = if free < warn_under_gb * 1024 * 1024 * 1024 {
                WARN_AMBER
            } else {
                OK_GREEN
            };
            ui.label(
                RichText::new(format!("{} free", detect::format_bytes(free)))
                    .size(11.5)
                    .color(color),
            );
        }
    }

    fn path_picker_row(
        ui: &mut egui::Ui,
        label: &str,
        path: &mut PathBuf,
        hint: &str,
        pick_file_filter: Option<(&str, &[&str])>,
        warn_gb: Option<u64>,
    ) -> bool {
        let mut changed = false;
        ui.horizontal(|ui| {
            ui.add_sized([115.0, 22.0], egui::Label::new(RichText::new(label).color(TEXT_MUTED)));
            let reserve = if warn_gb.is_some() { 185.0 } else { 95.0 };
            let input_w = (ui.available_width() - reserve).max(200.0);
            let mut s = path.display().to_string();
            if ui
                .add(
                    egui::TextEdit::singleline(&mut s)
                        .hint_text(hint)
                        .desired_width(input_w),
                )
                .changed()
            {
                *path = PathBuf::from(s);
                changed = true;
            }
            if ui.button("Browse").clicked() {
                let picked = if let Some((name, exts)) = pick_file_filter {
                    rfd::FileDialog::new().add_filter(name, exts).save_file()
                } else {
                    rfd::FileDialog::new().pick_folder()
                };
                if let Some(p) = picked {
                    *path = p;
                    changed = true;
                }
            }
            if let Some(gb) = warn_gb {
                Self::draw_free_badge(ui, path, gb);
            }
        });
        changed
    }
}

impl eframe::App for ArcSteamApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Drag-and-drop folders or .torrent files directly onto the window
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
            self.tab = MainTab::Queue;
        } else if let Some(path) = dropped.into_iter().next() {
            if path.is_dir() {
                self.tab = MainTab::Install;
                self.source_kind = SourceKind::LocalFolder;
                self.cfg.local_source = path;
                self.scan_local_now();
                self.cfg.save();
            } else if path.extension().and_then(|e| e.to_str()) == Some("torrent") {
                self.tab = MainTab::Install;
                self.source_kind = SourceKind::TorrentMagnet;
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

        if stage_label == "Failed" {
            self.show_logs = true;
        }

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
            // Top Brand Bar with Crisp Purple ArcSteam SVG + Clean 3-Tab Pill Nav
            ui.horizontal(|ui| {
                ui.add(
                    egui::Image::new(egui::include_image!("../assets/logo.svg"))
                        .max_size(Vec2::splat(46.0)),
                );
                ui.add_space(4.0);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("ArcSteam")
                            .size(23.0)
                            .strong()
                            .color(TEXT_PRIMARY),
                    );
                    ui.label(
                        RichText::new("Fast Game Repack Installer & Live Torrent Streamer")
                            .size(11.5)
                            .color(TEXT_MUTED),
                    );
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.selectable_value(&mut self.tab, MainTab::Tools, "  Tools  ");
                    let q_label = if self.queue.is_empty() {
                        "  Queue  ".to_string()
                    } else {
                        format!("  Queue ({})  ", self.queue.len())
                    };
                    ui.selectable_value(&mut self.tab, MainTab::Queue, q_label);
                    ui.selectable_value(&mut self.tab, MainTab::Install, "  Install  ");
                });
            });

            ui.add_space(10.0);

            egui::ScrollArea::vertical()
                .id_salt("main_body_scroll")
                .max_height((ui.available_height() - 155.0).max(200.0))
                .show(ui, |ui| {
                    match self.tab {
                        MainTab::Install => {
                            // Step 1: Choose Source (Simple Segmented Switch)
                            Self::glass_card().show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new("1. Select Repack Source")
                                            .size(14.5)
                                            .strong()
                                            .color(TEXT_PRIMARY),
                                    );
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        ui.selectable_value(
                                            &mut self.source_kind,
                                            SourceKind::TorrentMagnet,
                                            "Torrent / Magnet",
                                        );
                                        ui.selectable_value(
                                            &mut self.source_kind,
                                            SourceKind::LocalFolder,
                                            "Local Folder",
                                        );
                                    });
                                });
                                ui.add_space(8.0);

                                if self.source_kind == SourceKind::LocalFolder {
                                    ui.horizontal(|ui| {
                                        let input_w = (ui.available_width() - 155.0).max(200.0);
                                        let mut s = self.cfg.local_source.display().to_string();
                                        if ui
                                            .add(
                                                egui::TextEdit::singleline(&mut s)
                                                    .hint_text("Drop a repack folder anywhere here or click Browse...")
                                                    .desired_width(input_w),
                                            )
                                            .changed()
                                        {
                                            self.cfg.local_source = PathBuf::from(s);
                                            cfg_dirty = true;
                                        }
                                        if ui.button("Browse").clicked() {
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
                                        ui.add_space(6.0);
                                        let skipped_bytes: u64 = self
                                            .scanned_files
                                            .iter()
                                            .filter(|f| !f.selected)
                                            .map(|f| f.size_bytes)
                                            .sum();
                                        let active_archives = self
                                            .scanned_files
                                            .iter()
                                            .filter(|f| f.is_archive && f.selected)
                                            .count();

                                        ui.horizontal(|ui| {
                                            ui.label(
                                                RichText::new(format!("Detected: {}", self.detected_format.badge()))
                                                    .size(12.0)
                                                    .strong()
                                                    .color(ACCENT_VIOLET),
                                            );
                                            ui.label(
                                                RichText::new(format!(
                                                    "•  {active_archives} core packs  •  skipping {} of optional extras",
                                                    detect::format_bytes(skipped_bytes)
                                                ))
                                                .size(11.5)
                                                .color(TEXT_MUTED),
                                            );
                                        });

                                        egui::CollapsingHeader::new(
                                            RichText::new("Customize Included Files & Languages")
                                                .size(12.0)
                                                .color(ACCENT_CYAN),
                                        )
                                        .default_open(false)
                                        .show(ui, |ui| {
                                            egui::ScrollArea::vertical()
                                                .id_salt("blueprint_scroll")
                                                .max_height(110.0)
                                                .show(ui, |ui| {
                                                    for entry in &mut self.scanned_files {
                                                        if entry.is_archive {
                                                            let tag = if entry.is_optional { "  [optional]" } else { "" };
                                                            let label = format!(
                                                                "{}  ({}){}",
                                                                entry.rel_path,
                                                                detect::format_bytes(entry.size_bytes),
                                                                tag
                                                            );
                                                            ui.checkbox(&mut entry.selected, label);
                                                        }
                                                    }
                                                });
                                        });
                                    }
                                } else {
                                    ui.horizontal(|ui| {
                                        let input_w = (ui.available_width() - 125.0).max(200.0);
                                        ui.add(
                                            egui::TextEdit::singleline(&mut self.magnet_or_torrent)
                                                .hint_text("Paste a magnet:? link or drop a .torrent file here...")
                                                .desired_width(input_w),
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
                                    ui.add_space(6.0);
                                    ui.horizontal(|ui| {
                                        if ui
                                            .checkbox(
                                                &mut self.cfg.live_install_while_dl,
                                                "Install live while downloading (streams directly via virtual drive)",
                                            )
                                            .changed()
                                        {
                                            cfg_dirty = true;
                                        }
                                        if !self.health.winfsp_ok && self.cfg.live_install_while_dl {
                                            if ui.small_button("Install WinFsp Driver").clicked() {
                                                win_sys::open_url("https://winfsp.dev/rel/");
                                            }
                                        }
                                    });
                                }
                            });

                            ui.add_space(8.0);

                            // Step 2: Install Destination (Clean, Full-Width)
                            Self::glass_card().show(ui, |ui| {
                                ui.label(
                                    RichText::new("2. Install Destination")
                                        .size(14.5)
                                        .strong()
                                        .color(TEXT_PRIMARY),
                                );
                                ui.add_space(6.0);
                                if Self::path_picker_row(
                                    ui,
                                    "Install Game To:",
                                    &mut self.cfg.target_game_dir,
                                    r"C:\Games",
                                    None,
                                    Some(25),
                                ) {
                                    cfg_dirty = true;
                                }
                            });

                            ui.add_space(8.0);

                            // Step 3: Collapsible Turbo Settings (Pre-tuned, clean by default)
                            Self::glass_card().show(ui, |ui| {
                                egui::CollapsingHeader::new(
                                    RichText::new(format!(
                                        "Turbo Settings  (Auto-Tuned: {} MB RAM • Defender Boost {})",
                                        self.cfg.srep_ram_mb,
                                        if self.cfg.defender_bypass { "ON" } else { "OFF" }
                                    ))
                                    .size(13.0)
                                    .strong()
                                    .color(TEXT_PRIMARY),
                                )
                                .default_open(false)
                                .show(ui, |ui| {
                                    ui.add_space(6.0);
                                    if Self::path_picker_row(
                                        ui,
                                        "Fast Temp Drive:",
                                        &mut self.cfg.temp_ssd_dir,
                                        "Pick your fastest SSD for temporary swap files",
                                        None,
                                        Some(8),
                                    ) {
                                        cfg_dirty = true;
                                    }
                                    if self.source_kind == SourceKind::TorrentMagnet {
                                        ui.add_space(4.0);
                                        if Self::path_picker_row(
                                            ui,
                                            "Download Cache:",
                                            &mut self.cfg.download_cache_dir,
                                            "Where torrent pieces are cached",
                                            None,
                                            Some(15),
                                        ) {
                                            cfg_dirty = true;
                                        }
                                    }

                                    ui.add_space(8.0);
                                    ui.horizontal_wrapped(|ui| {
                                        if ui.checkbox(&mut self.cfg.defender_bypass, "Temporary Defender Boost").changed() {
                                            cfg_dirty = true;
                                        }
                                        if ui.checkbox(&mut self.cfg.replay_registry, "Auto Registry Keys").changed() {
                                            cfg_dirty = true;
                                        }
                                        if ui.checkbox(&mut self.cfg.create_shortcuts, "Desktop Shortcuts").changed() {
                                            cfg_dirty = true;
                                        }
                                        if ui.checkbox(&mut self.cfg.auto_clean_temp, "Clean Temp Files").changed() {
                                            cfg_dirty = true;
                                        }
                                    });

                                    ui.add_space(6.0);
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new("Memory Limit (SREP):").color(TEXT_MUTED));
                                        if ui
                                            .add(egui::Slider::new(&mut self.cfg.srep_ram_mb, 1024..=12288).suffix(" MB"))
                                            .changed()
                                        {
                                            cfg_dirty = true;
                                        }
                                        ui.separator();
                                        ui.label(RichText::new("Stream Drive:").color(TEXT_MUTED));
                                        if ui
                                            .add(egui::TextEdit::singleline(&mut self.cfg.virtual_drive).desired_width(36.0))
                                            .changed()
                                        {
                                            cfg_dirty = true;
                                        }
                                    });
                                });
                            });
                        }

                        MainTab::Queue => {
                            Self::glass_card().show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(
                                        RichText::new("Batch Install Queue")
                                            .size(15.0)
                                            .strong()
                                            .color(TEXT_PRIMARY),
                                    );
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui
                                            .add_enabled(!running && !self.queue.is_empty(), egui::Button::new("Clear"))
                                            .clicked()
                                        {
                                            self.queue.clear();
                                        }
                                        if ui.button("+ Add Repack Folder").clicked() {
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
                                ui.add_space(8.0);

                                if self.queue.is_empty() {
                                    ui.label(
                                        RichText::new("Drag & drop multiple repack folders onto ArcSteam to install them overnight back-to-back.")
                                            .color(TEXT_MUTED),
                                    );
                                } else {
                                    let mut remove_idx: Option<usize> = None;
                                    for (i, item) in self.queue.iter().enumerate() {
                                        ui.horizontal(|ui| {
                                            let badge_color = match item.state {
                                                QueueItemState::Done => OK_GREEN,
                                                QueueItemState::Running => ACCENT_VIOLET,
                                                QueueItemState::Failed | QueueItemState::Cancelled => ERR_RED,
                                                QueueItemState::Queued => TEXT_MUTED,
                                            };
                                            ui.label(
                                                RichText::new(format!("[{}]", item.state.label()))
                                                    .strong()
                                                    .color(badge_color),
                                            );
                                            ui.label(RichText::new(&item.config.display_name).strong());
                                            ui.label(
                                                RichText::new(format!("-> {}", item.config.target_game_dir.display()))
                                                    .size(11.5)
                                                    .color(TEXT_MUTED),
                                            );
                                            if !running && ui.small_button("Remove").clicked() {
                                                remove_idx = Some(i);
                                            }
                                        });
                                    }
                                    if let Some(idx) = remove_idx {
                                        self.queue.remove(idx);
                                    }
                                }

                                ui.add_space(10.0);
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("After Queue Finishes:").color(TEXT_MUTED));
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
                                        RichText::new("(PC sleep is automatically prevented while installing)")
                                            .size(11.0)
                                            .color(TEXT_MUTED),
                                    );
                                });
                            });
                        }

                        MainTab::Tools => {
                            // Tool 1: Fast File Integrity Checker (MD5 / SFV)
                            Self::glass_card().show(ui, |ui| {
                                ui.label(
                                    RichText::new("Verify Repack Files (Multi-Core MD5 / SFV)")
                                        .size(14.5)
                                        .strong()
                                        .color(TEXT_PRIMARY),
                                );
                                ui.add_space(6.0);
                                ui.horizontal(|ui| {
                                    let input_w = (ui.available_width() - 185.0).max(200.0);
                                    let mut s = self.verify_dir.display().to_string();
                                    if ui
                                        .add(
                                            egui::TextEdit::singleline(&mut s)
                                                .hint_text("Select a repack folder containing MD5 or SFV files...")
                                                .desired_width(input_w),
                                        )
                                        .changed()
                                    {
                                        self.verify_dir = PathBuf::from(s);
                                    }
                                    if ui.button("Browse").clicked() {
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
                                    ui.add_space(6.0);
                                    ui.label(
                                        RichText::new(format!(
                                            "{}  •  {}/{} checked  •  OK: {}  Missing: {}  Corrupt: {}",
                                            vp.manifest_found,
                                            vp.completed,
                                            vp.total,
                                            vp.ok_count,
                                            vp.missing_count,
                                            vp.corrupt_count
                                        ))
                                        .size(11.8)
                                        .color(if vp.corrupt_count > 0 || vp.missing_count > 0 {
                                            ERR_RED
                                        } else {
                                            OK_GREEN
                                        }),
                                    );
                                    if !vp.results.is_empty() {
                                        egui::ScrollArea::vertical()
                                            .id_salt("verify_scroll")
                                            .max_height(80.0)
                                            .show(ui, |ui| {
                                                for res in &vp.results {
                                                    match res {
                                                        FileVerifyOutcome::Ok(f) => {
                                                            ui.label(RichText::new(format!("[OK] {f}")).monospace().size(11.0).color(OK_GREEN));
                                                        }
                                                        FileVerifyOutcome::Missing(f) => {
                                                            ui.label(RichText::new(format!("[MISSING] {f}")).monospace().size(11.0).color(WARN_AMBER));
                                                        }
                                                        FileVerifyOutcome::Corrupt { file, expected, actual } => {
                                                            ui.label(RichText::new(format!("[CORRUPT] {file} (expected {expected}, got {actual})")).monospace().size(11.0).color(ERR_RED));
                                                        }
                                                    }
                                                }
                                            });
                                    }
                                }
                            });

                            ui.add_space(8.0);

                            // Tool 2: Fast Game Backup (.tar.zst)
                            Self::glass_card().show(ui, |ui| {
                                ui.label(
                                    RichText::new("Fast Game Backup (.tar.zst — Unpacks at 500+ MB/s)")
                                        .size(14.5)
                                        .strong()
                                        .color(TEXT_PRIMARY),
                                );
                                ui.add_space(6.0);
                                Self::path_picker_row(
                                    ui,
                                    "Game Folder:",
                                    &mut self.zstd_src,
                                    r"C:\Games\MyGame",
                                    None,
                                    None,
                                );
                                ui.add_space(4.0);
                                Self::path_picker_row(
                                    ui,
                                    "Backup Archive:",
                                    &mut self.zstd_dst,
                                    "Choose .tar.zst output file",
                                    Some(("Zstd Archive", &["zst"])),
                                    None,
                                );

                                ui.add_space(8.0);
                                let zp = self.zstd_progress.lock().unwrap().clone();
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("Compression:").color(TEXT_MUTED));
                                    ui.add(egui::Slider::new(&mut self.zstd_level, 1..=12));
                                    if ui
                                        .add_enabled(!zstd_running, egui::Button::new("Pack Folder"))
                                        .clicked()
                                    {
                                        zstd_pack::spawn_zstd_pack(
                                            self.zstd_src.clone(),
                                            self.zstd_dst.clone(),
                                            self.zstd_level,
                                            self.zstd_progress.clone(),
                                            self.zstd_cancel.clone(),
                                        );
                                    }
                                    if ui
                                        .add_enabled(!zstd_running, egui::Button::new("Unpack Archive"))
                                        .clicked()
                                    {
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
                                    ui.add_space(6.0);
                                    ui.add(egui::ProgressBar::new(zp.pct).text(zp.status));
                                }
                            });
                        }
                    }

                    // Collapsible Activity Log inside scroll area when expanded
                    if self.show_logs {
                        ui.add_space(8.0);
                        Self::glass_card().show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("Activity Log").strong().color(TEXT_PRIMARY));
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if ui.small_button("Copy Log").clicked() {
                                        ui.ctx().copy_text(logs_snapshot.join("\n"));
                                    }
                                });
                            });
                            ui.add_space(4.0);
                            egui::ScrollArea::vertical()
                                .id_salt("console_log")
                                .max_height(130.0)
                                .stick_to_bottom(true)
                                .show(ui, |ui| {
                                    for line in &logs_snapshot {
                                        let color = if line.contains("[ERROR]") {
                                            ERR_RED
                                        } else if line.contains("[WARN]") {
                                            WARN_AMBER
                                        } else if line.contains("[DONE]") {
                                            OK_GREEN
                                        } else {
                                            TEXT_MUTED
                                        };
                                        ui.label(RichText::new(line).monospace().size(11.0).color(color));
                                    }
                                });
                        });
                    }
                });

            ui.add_space(8.0);

            // Bottom Action & Progress Dock
            Self::glass_card().show(ui, |ui| {
                let is_torrent_active = self.source_kind == SourceKind::TorrentMagnet;
                Self::draw_progress_bar(ui, dl_pct, unpack_pct, &stage_label, is_torrent_active);
                ui.add_space(8.0);

                ui.horizontal(|ui| {
                    let is_queue_tab = self.tab == MainTab::Queue;
                    let btn_text = if running {
                        "   Installing...   "
                    } else if is_queue_tab {
                        "   Start Queue   "
                    } else if is_torrent_active {
                        "   Stream & Install   "
                    } else {
                        "   Install Now   "
                    };

                    let has_input = if is_queue_tab {
                        !self.queue.is_empty()
                    } else if is_torrent_active {
                        !self.magnet_or_torrent.trim().is_empty()
                    } else {
                        !self.cfg.local_source.as_os_str().is_empty()
                    };
                    let can_start = !running && has_input;

                    let launch = egui::Button::new(
                        RichText::new(btn_text)
                            .size(13.5)
                            .strong()
                            .color(Color32::WHITE),
                    )
                    .fill(if can_start {
                        ACCENT_PURPLE
                    } else {
                        Color32::from_rgb(56, 46, 84)
                    })
                    .corner_radius(CornerRadius::same(11))
                    .min_size(Vec2::new(140.0, 32.0));

                    if ui.add_enabled(can_start, launch).clicked() {
                        self.cfg.save();
                        let jobs: Vec<JobConfig> = if is_queue_tab {
                            self.queue.iter().map(|q| q.config.clone()).collect()
                        } else {
                            let j = self.build_current_job(is_torrent_active);
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

                    if self.tab == MainTab::Install
                        && ui.add_enabled(can_start, egui::Button::new("+ Queue")).clicked()
                    {
                        let j = self.build_current_job(is_torrent_active);
                        self.queue.push(QueueEntry {
                            config: j,
                            state: QueueItemState::Queued,
                        });
                    }

                    if !running && unpack_pct >= 0.999 && self.cfg.target_game_dir.exists() {
                        if ui.button("Open Game Folder").clicked() {
                            win_sys::open_in_explorer(&self.cfg.target_game_dir);
                        }
                    }

                    if running {
                        let paused = self.control.paused.load(Ordering::Relaxed);
                        if ui.button(if paused { "Resume" } else { "Pause" }).clicked() {
                            let now_paused = self.control.toggle_pause();
                            if let Ok(mut t) = self.telemetry.lock() {
                                t.stage_label = if now_paused {
                                    "Paused".into()
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

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let log_btn = if self.show_logs { "Hide Logs" } else { "Show Logs" };
                        if ui.button(log_btn).clicked() {
                            self.show_logs = !self.show_logs;
                        }
                        if running || !active_worker.is_empty() {
                            let q_prefix = match active_q_idx {
                                Some(i) if queue_states.len() > 1 => {
                                    format!("Job {}/{} • ", i + 1, queue_states.len())
                                }
                                _ => String::new(),
                            };
                            let worker_txt = if active_worker.is_empty() {
                                "Working"
                            } else {
                                &active_worker
                            };
                            ui.label(
                                RichText::new(format!(
                                    "{q_prefix}{worker_txt} • {worker_ram} MB RAM • {write_mbps:.0} MB/s • DL {dl_mbps:.1} MB/s • ETA {eta_text}"
                                ))
                                .size(11.0)
                                .color(TEXT_MUTED),
                            );
                        }
                    });
                });
            });

            ui.add_space(5.0);

            // Minimal Clean Status Footer
            ui.horizontal(|ui| {
                let engine_txt = if self.health.core_engines_ready() {
                    if self.health.bundled_count > 0 {
                        "Engines: Built-in Ready"
                    } else {
                        "Engines: Ready"
                    }
                } else {
                    "Engines: Missing Helper"
                };
                Self::draw_status_pill(ui, engine_txt, self.health.core_engines_ready());

                let unarc_lbl = match self.health.unarc_bitness {
                    PeBitness::Bit64 => "FreeArc x64",
                    PeBitness::Bit32Laa => "FreeArc LAA",
                    PeBitness::Bit32 => "FreeArc x86",
                    PeBitness::Unknown => "FreeArc",
                };
                if self.health.unarc_ok {
                    Self::draw_status_pill(ui, unarc_lbl, true);
                }

                if Self::draw_status_pill(
                    ui,
                    if self.health.winfsp_ok {
                        "Live Stream: Ready"
                    } else {
                        "WinFsp Needed for Live Torrent"
                    },
                    self.health.winfsp_ok,
                )
                .clicked()
                    && !self.health.winfsp_ok
                {
                    win_sys::open_url("https://winfsp.dev/rel/");
                }

                Self::draw_status_pill(
                    ui,
                    if self.health.is_admin {
                        "Admin"
                    } else {
                        "Standard Mode"
                    },
                    self.health.is_admin,
                );
                if !self.health.is_admin && ui.small_button("Run as Admin").clicked() {
                    if win_sys::relaunch_as_admin() {
                        std::process::exit(0);
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Refresh").clicked() {
                        self.health = ToolsHealth::probe();
                    }
                });
            });
        });

        if cfg_dirty {
            self.cfg.save();
        }
    }
}

fn load_app_icon() -> egui::IconData {
    egui::IconData {
        rgba: APP_ICON_RGBA.to_vec(),
        width: 64,
        height: 64,
    }
}

fn main() -> eframe::Result {
    let _winfsp_init = winfsp::winfsp_init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([880.0, 660.0])
            .with_min_inner_size([740.0, 560.0])
            .with_drag_and_drop(true)
            .with_icon(load_app_icon()),
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
