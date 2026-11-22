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
use eframe::egui::{
    self, Color32, CornerRadius, Frame, Margin, Pos2, Rect, RichText, Sense, Stroke,
    TextureHandle, TextureOptions, Vec2,
};
use pipeline::{JobConfig, PipelineControl, QueueEntry, QueueItemState, SharedTelemetry};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use verify::{FileVerifyOutcome, VerifyProgress};
use win_sys::PostQueueAction;
use zstd_pack::ZstdProgress;

const APP_ICON_RGBA: &[u8] = include_bytes!("../assets/icon_rgba.bin");
const BG_AURA_RGBA: &[u8] = include_bytes!("../assets/bg_aura.bin");

// Frosted Lavender-Obsidian Glass Palette (inspired by luminous glass UI)
const GLASS_CARD_BG: Color32 = Color32::from_rgba_premultiplied(11, 8, 20, 182);
const GLASS_PILL_BG: Color32 = Color32::from_rgba_premultiplied(9, 6, 17, 212);
const GLASS_INPUT_BG: Color32 = Color32::from_rgba_premultiplied(8, 5, 15, 195);
const GLASS_BORDER: Color32 = Color32::from_rgba_premultiplied(55, 51, 60, 60);
const GLASS_BORDER_SOFT: Color32 = Color32::from_rgba_premultiplied(32, 28, 38, 38);
const LAVENDER_TEXT: Color32 = Color32::from_rgb(203, 166, 247);
const LAVENDER_GRAD_L: Color32 = Color32::from_rgb(154, 92, 232);
const LAVENDER_GRAD_R: Color32 = Color32::from_rgb(218, 186, 252);
const TEXT_WHITE: Color32 = Color32::from_rgb(248, 246, 255);
const TEXT_SOFT: Color32 = Color32::from_rgb(184, 174, 212);
const OK_MINT: Color32 = Color32::from_rgb(74, 222, 128);
const WARN_GOLD: Color32 = Color32::from_rgb(251, 191, 36);
const ERR_CORAL: Color32 = Color32::from_rgb(248, 113, 113);

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
    winfsp_msi_ready: bool,
    core_ready: bool,
}

impl ToolsHealth {
    fn probe() -> Self {
        let core_ready = embedded_tools::resolve_tool("innounp.exe").exists()
            && (embedded_tools::resolve_tool("unarc_host32.exe").exists()
                || embedded_tools::resolve_tool("unarc.exe").exists())
            && embedded_tools::resolve_tool("innoextract.exe").exists()
            && embedded_tools::resolve_tool("7z.exe").exists();

        Self {
            is_admin: win_sys::is_elevated(),
            winfsp_ok: win_sys::is_winfsp_installed(),
            winfsp_msi_ready: embedded_tools::resolve_tool("winfsp.msi").exists(),
            core_ready,
        }
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
    winfsp_installing: Arc<AtomicBool>,
    show_settings: bool,
    show_logs: bool,
    bg_texture: Option<TextureHandle>,
    // Tools tab
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
        initial_telemetry.stage_label = "Ready".into();
        initial_telemetry.eta_text = "--".into();
        let bundled = embedded_tools::embedded_count();
        initial_telemetry.log(format!(
            "[INIT] ArcSteam ready — {extracted}/{bundled} built-in components loaded (native unarc.dll host + WinFsp MSI)."
        ));

        let telemetry = Arc::new(Mutex::new(initial_telemetry));
        let sweep_telemetry = telemetry.clone();
        std::thread::spawn(move || {
            let swept = optimizer::sweep_stale_defender_exclusions();
            if !swept.is_empty() {
                if let Ok(mut t) = sweep_telemetry.lock() {
                    t.log(format!(
                        "[RECOVERY] Cleaned up {} leftover Defender rule(s).",
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
            winfsp_installing: Arc::new(AtomicBool::new(false)),
            show_settings: false,
            show_logs: false,
            bg_texture: None,
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
        visuals.panel_fill = Color32::TRANSPARENT;
        visuals.window_fill = Color32::from_rgb(14, 9, 24);
        visuals.extreme_bg_color = GLASS_INPUT_BG;

        visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_WHITE);
        visuals.widgets.inactive.bg_fill = GLASS_INPUT_BG;
        visuals.widgets.inactive.weak_bg_fill = Color32::from_rgba_unmultiplied(24, 17, 42, 160);
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, GLASS_BORDER_SOFT);
        visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_WHITE);
        visuals.widgets.inactive.corner_radius = CornerRadius::same(14);

        visuals.widgets.hovered.bg_fill = Color32::from_rgba_unmultiplied(44, 30, 74, 210);
        visuals.widgets.hovered.weak_bg_fill = Color32::from_rgba_unmultiplied(44, 30, 74, 210);
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, LAVENDER_TEXT);
        visuals.widgets.hovered.corner_radius = CornerRadius::same(14);

        visuals.widgets.active.bg_fill = LAVENDER_GRAD_L;
        visuals.widgets.active.bg_stroke = Stroke::new(1.0, LAVENDER_GRAD_R);
        visuals.widgets.active.corner_radius = CornerRadius::same(14);

        visuals.selection.bg_fill = Color32::from_rgba_unmultiplied(168, 108, 244, 200);
        visuals.selection.stroke = Stroke::new(1.0, TEXT_WHITE);

        ctx.set_visuals(visuals);
    }

    fn ensure_bg_texture(&mut self, ctx: &egui::Context) -> &TextureHandle {
        self.bg_texture.get_or_insert_with(|| {
            let img = egui::ColorImage::from_rgba_unmultiplied([320, 240], BG_AURA_RGBA);
            ctx.load_texture("arcsteam_bg_aura", img, TextureOptions::LINEAR)
        })
    }

    /// Paints a true horizontal lavender-to-orchid gradient capsule button (matching the reference CTA pills).
    fn gradient_pill_button(
        ui: &mut egui::Ui,
        label: &str,
        width: f32,
        height: f32,
        enabled: bool,
    ) -> egui::Response {
        let (rect, response) = ui.allocate_exact_size(Vec2::new(width, height), Sense::click());
        let painter = ui.painter();
        let r = (height * 0.5).min(24.0);

        let (c_left, c_right) = if !enabled {
            (
                Color32::from_rgba_unmultiplied(64, 48, 92, 160),
                Color32::from_rgba_unmultiplied(88, 68, 122, 160),
            )
        } else if response.is_pointer_button_down_on() {
            (
                Color32::from_rgb(134, 72, 214),
                Color32::from_rgb(198, 162, 242),
            )
        } else if response.hovered() {
            (
                Color32::from_rgb(168, 108, 244),
                Color32::from_rgb(232, 206, 255),
            )
        } else {
            (LAVENDER_GRAD_L, LAVENDER_GRAD_R)
        };

        // Smooth horizontal gradient inside rounded capsule via vertical strips clipped to capsule
        let steps = 24usize;
        let step_w = rect.width() / steps as f32;
        for i in 0..steps {
            let t = i as f32 / (steps - 1) as f32;
            let col = Color32::from_rgba_unmultiplied(
                (c_left.r() as f32 + (c_right.r() as f32 - c_left.r() as f32) * t) as u8,
                (c_left.g() as f32 + (c_right.g() as f32 - c_left.g() as f32) * t) as u8,
                (c_left.b() as f32 + (c_right.b() as f32 - c_left.b() as f32) * t) as u8,
                c_left.a(),
            );
            let x0 = rect.left() + i as f32 * step_w;
            let x1 = if i == steps - 1 { rect.right() } else { x0 + step_w + 1.0 };
            let cr = CornerRadius {
                nw: if i == 0 { r as u8 } else { 0 },
                sw: if i == 0 { r as u8 } else { 0 },
                ne: if i == steps - 1 { r as u8 } else { 0 },
                se: if i == steps - 1 { r as u8 } else { 0 },
            };
            painter.rect_filled(
                Rect::from_min_max(Pos2::new(x0, rect.top()), Pos2::new(x1, rect.bottom())),
                cr,
                col,
            );
        }

        // Subtle luminous glass sheen rim
        painter.rect_stroke(
            rect,
            CornerRadius::same(r as u8),
            Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, if enabled { 95 } else { 30 })),
            egui::StrokeKind::Inside,
        );

        let txt_col = if enabled {
            Color32::from_rgb(255, 255, 255)
        } else {
            Color32::from_rgb(175, 165, 198)
        };
        painter.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(14.5),
            txt_col,
        );

        response
    }

    fn draw_glass_progress(ui: &mut egui::Ui, dl_pct: f32, unpack_pct: f32, stage: &str, is_torrent: bool) {
        let desired = Vec2::new(ui.available_width(), 38.0);
        let (rect, _) = ui.allocate_exact_size(desired, Sense::hover());
        let p = ui.painter();

        p.rect_filled(rect, CornerRadius::same(19), GLASS_INPUT_BG);
        p.rect_stroke(rect, CornerRadius::same(19), Stroke::new(1.0, GLASS_BORDER), egui::StrokeKind::Inside);

        if is_torrent && dl_pct > 0.005 {
            let mut dl_r = rect;
            dl_r.set_width((rect.width() * dl_pct.clamp(0.0, 1.0)).max(24.0));
            p.rect_filled(dl_r, CornerRadius::same(19), Color32::from_rgba_unmultiplied(109, 40, 217, 175));
        }

        if unpack_pct > 0.005 {
            let fill_w = (rect.width() * unpack_pct.clamp(0.0, 1.0)).max(24.0);
            let r_rect = Rect::from_min_size(rect.min, Vec2::new(fill_w, rect.height()));
            p.rect_filled(r_rect, CornerRadius::same(19), Color32::from_rgba_unmultiplied(168, 108, 244, 215));
        }

        let label = if is_torrent {
            format!("DL {:.0}%  •  Install {:.0}%  —  {}", dl_pct * 100.0, unpack_pct * 100.0, stage)
        } else {
            format!("{:.0}%  —  {}", unpack_pct * 100.0, stage)
        };
        p.text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            label,
            egui::FontId::proportional(13.0),
            TEXT_WHITE,
        );
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

    fn trigger_builtin_winfsp_install(&mut self) {
        if self.winfsp_installing.swap(true, Ordering::Relaxed) {
            return;
        }
        let msi = embedded_tools::resolve_tool("winfsp.msi");
        let flag = self.winfsp_installing.clone();
        let telemetry = self.telemetry.clone();
        std::thread::spawn(move || {
            if let Ok(mut t) = telemetry.lock() {
                t.log("[WINFSP] Installing built-in WinFsp driver silently (approve UAC prompt if shown)...");
            }
            let ok = win_sys::install_embedded_winfsp(&msi);
            if let Ok(mut t) = telemetry.lock() {
                if ok {
                    let _ = winfsp::winfsp_init();
                    t.log("[WINFSP] Installed cleanly! Live torrent streaming is now ready.");
                } else {
                    t.log("[WARN] Built-in WinFsp installation was cancelled or failed.");
                }
            }
            flag.store(false, Ordering::Relaxed);
        });
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

    fn input_row(
        ui: &mut egui::Ui,
        label: &str,
        path: &mut PathBuf,
        hint: &str,
        save_filter: Option<(&str, &[&str])>,
        warn_gb: Option<u64>,
    ) -> bool {
        let mut changed = false;
        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(label).size(12.0).color(TEXT_SOFT));
                if let Some(gb) = warn_gb {
                    if let Some(free) = win_sys::free_disk_bytes(path) {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let col = if free < gb * 1024 * 1024 * 1024 { WARN_GOLD } else { OK_MINT };
                            ui.label(
                                RichText::new(format!("{} free", detect::format_bytes(free)))
                                    .size(11.0)
                                    .color(col),
                            );
                        });
                    }
                }
            });
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                let w = (ui.available_width() - 84.0).max(160.0);
                let mut s = path.display().to_string();
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut s)
                            .hint_text(hint)
                            .margin(Margin::symmetric(12, 8))
                            .desired_width(w),
                    )
                    .changed()
                {
                    *path = PathBuf::from(s);
                    changed = true;
                }
                if ui
                    .add(egui::Button::new("Browse").min_size(Vec2::new(72.0, 32.0)))
                    .clicked()
                {
                    let picked = if let Some((name, exts)) = save_filter {
                        rfd::FileDialog::new().add_filter(name, exts).save_file()
                    } else {
                        rfd::FileDialog::new().pick_folder()
                    };
                    if let Some(p) = picked {
                        *path = p;
                        changed = true;
                    }
                }
            });
        });
        changed
    }
}

impl eframe::App for ArcSteamApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Drag-and-drop folders or .torrent files directly onto the glass card
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

        let wf_installing = self.winfsp_installing.load(Ordering::Relaxed);
        if !wf_installing && !self.health.winfsp_ok && win_sys::is_winfsp_installed() {
            self.health = ToolsHealth::probe();
        }

        let verify_running = self.verify_progress.lock().unwrap().running;
        let zstd_running = self.zstd_progress.lock().unwrap().running;
        if running || verify_running || zstd_running || wf_installing {
            ui.ctx().request_repaint_after(Duration::from_millis(140));
        }

        let mut cfg_dirty = false;

        // Paint full-bleed luminous diagonal purple aura background behind everything
        let screen_rect = ui.max_rect();
        let bg_id = self.ensure_bg_texture(ui.ctx()).id();
        ui.painter().image(
            bg_id,
            screen_rect,
            Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)),
            Color32::WHITE,
        );

        egui::CentralPanel::default()
            .frame(Frame::NONE.inner_margin(Margin::symmetric(24, 18)))
            .show(ui, |ui| {
                // ===============================================================
                // 1. FLOATING TOP GLASS CAPSULE NAVBAR (matching reference top pill)
                // ===============================================================
                ui.vertical_centered(|ui| {
                    Frame::new()
                        .fill(GLASS_PILL_BG)
                        .stroke(Stroke::new(1.1, GLASS_BORDER))
                        .corner_radius(CornerRadius::same(28))
                        .inner_margin(Margin::symmetric(14, 8))
                        .show(ui, |ui| {
                            ui.set_max_width(540.0);
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::Image::new(egui::include_image!("../assets/logo.svg"))
                                        .max_size(Vec2::splat(30.0)),
                                );
                                ui.add_space(4.0);
                                ui.label(
                                    RichText::new("ArcSteam")
                                        .size(15.0)
                                        .strong()
                                        .color(TEXT_WHITE),
                                );
                                ui.add_space(18.0);

                                ui.selectable_value(&mut self.tab, MainTab::Install, "  Install  ");
                                let q_lbl = if self.queue.is_empty() {
                                    "  Queue  ".to_string()
                                } else {
                                    format!("  Queue ({})  ", self.queue.len())
                                };
                                ui.selectable_value(&mut self.tab, MainTab::Queue, q_lbl);
                                ui.selectable_value(&mut self.tab, MainTab::Tools, "  Tools  ");

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    let log_lbl = if self.show_logs { "Logs" } else { "Log" };
                                    if ui.small_button(log_lbl).clicked() {
                                        self.show_logs = !self.show_logs;
                                    }
                                });
                            });
                        });
                });

                ui.add_space(16.0);

                // ===============================================================
                // 2. CENTERED FROSTED-GLASS HERO CARD (glow shines right through)
                // ===============================================================
                let card_w = (ui.available_width() - 20.0).clamp(480.0, 680.0);
                let max_card_h = (ui.available_height() - 56.0).max(260.0);

                ui.vertical_centered(|ui| {
                    Frame::new()
                        .fill(GLASS_CARD_BG)
                        .stroke(Stroke::new(1.2, GLASS_BORDER))
                        .corner_radius(CornerRadius::same(28))
                        .inner_margin(Margin::symmetric(28, 22))
                        .show(ui, |ui| {
                            ui.set_width(card_w);

                            egui::ScrollArea::vertical()
                                .id_salt("hero_card_scroll")
                                .max_height(max_card_h)
                                .show(ui, |ui| {
                                    match self.tab {
                                        MainTab::Install => {
                                            // Hero Title (white + lavender accent word like reference)
                                            ui.vertical_centered(|ui| {
                                                ui.label(
                                                    RichText::new("Zero-Wait Repack Engine")
                                                        .size(12.5)
                                                        .color(TEXT_SOFT),
                                                );
                                                ui.horizontal(|ui| {
                                                    ui.add_space((card_w - 270.0).max(0.0) * 0.5);
                                                    ui.label(
                                                        RichText::new("Turbo")
                                                            .size(32.0)
                                                            .strong()
                                                            .color(LAVENDER_TEXT),
                                                    );
                                                    ui.label(
                                                        RichText::new("Installer")
                                                            .size(32.0)
                                                            .strong()
                                                            .color(TEXT_WHITE),
                                                    );
                                                });
                                                ui.add_space(10.0);

                                                // Source Mode Segmented Pill
                                                Frame::new()
                                                    .fill(GLASS_INPUT_BG)
                                                    .stroke(Stroke::new(1.0, GLASS_BORDER_SOFT))
                                                    .corner_radius(CornerRadius::same(18))
                                                    .inner_margin(Margin::symmetric(6, 4))
                                                    .show(ui, |ui| {
                                                        ui.horizontal(|ui| {
                                                            ui.selectable_value(
                                                                &mut self.source_kind,
                                                                SourceKind::LocalFolder,
                                                                "   Local Folder   ",
                                                            );
                                                            ui.selectable_value(
                                                                &mut self.source_kind,
                                                                SourceKind::TorrentMagnet,
                                                                "   Torrent / Magnet   ",
                                                            );
                                                        });
                                                    });
                                            });

                                            ui.add_space(16.0);

                                            // Source Input
                                            if self.source_kind == SourceKind::LocalFolder {
                                                let changed = Self::input_row(
                                                    ui,
                                                    "Repack Folder (or drag & drop anywhere)",
                                                    &mut self.cfg.local_source,
                                                    "Select a repack folder...",
                                                    None,
                                                    None,
                                                );
                                                if changed {
                                                    self.scan_local_now();
                                                    cfg_dirty = true;
                                                }

                                                if !self.scanned_files.is_empty() {
                                                    ui.add_space(6.0);
                                                    let skipped: u64 = self
                                                        .scanned_files
                                                        .iter()
                                                        .filter(|f| !f.selected)
                                                        .map(|f| f.size_bytes)
                                                        .sum();
                                                    let count = self
                                                        .scanned_files
                                                        .iter()
                                                        .filter(|f| f.is_archive && f.selected)
                                                        .count();
                                                    ui.horizontal(|ui| {
                                                        ui.label(
                                                            RichText::new(self.detected_format.badge())
                                                                .size(12.0)
                                                                .strong()
                                                                .color(LAVENDER_TEXT),
                                                        );
                                                        ui.label(
                                                            RichText::new(format!(
                                                                "•  {count} core files  •  skipping {} optional",
                                                                detect::format_bytes(skipped)
                                                            ))
                                                            .size(11.5)
                                                            .color(TEXT_SOFT),
                                                        );
                                                    });

                                                    egui::CollapsingHeader::new(
                                                        RichText::new("Select languages & optional packs")
                                                            .size(11.8)
                                                            .color(TEXT_SOFT),
                                                    )
                                                    .default_open(false)
                                                    .show(ui, |ui| {
                                                        egui::ScrollArea::vertical()
                                                            .id_salt("bp_scroll")
                                                            .max_height(100.0)
                                                            .show(ui, |ui| {
                                                                for entry in &mut self.scanned_files {
                                                                    if entry.is_archive {
                                                                        let tag = if entry.is_optional { " [optional]" } else { "" };
                                                                        ui.checkbox(
                                                                            &mut entry.selected,
                                                                            format!(
                                                                                "{} ({}){}",
                                                                                entry.rel_path,
                                                                                detect::format_bytes(entry.size_bytes),
                                                                                tag
                                                                            ),
                                                                        );
                                                                    }
                                                                }
                                                            });
                                                    });
                                                }
                                            } else {
                                                ui.label(RichText::new("Magnet Link or .torrent File").size(12.0).color(TEXT_SOFT));
                                                ui.add_space(3.0);
                                                ui.horizontal(|ui| {
                                                    let w = (ui.available_width() - 92.0).max(160.0);
                                                    ui.add(
                                                        egui::TextEdit::singleline(&mut self.magnet_or_torrent)
                                                            .hint_text("magnet:?xt=urn:btih:... or drop a .torrent file")
                                                            .margin(Margin::symmetric(12, 8))
                                                            .desired_width(w),
                                                    );
                                                    if ui
                                                        .add(egui::Button::new("Browse").min_size(Vec2::new(78.0, 32.0)))
                                                        .clicked()
                                                    {
                                                        if let Some(p) = rfd::FileDialog::new()
                                                            .add_filter("BitTorrent", &["torrent"])
                                                            .pick_file()
                                                        {
                                                            self.magnet_or_torrent = p.display().to_string();
                                                        }
                                                    }
                                                });
                                                ui.add_space(6.0);
                                                if ui
                                                    .checkbox(
                                                        &mut self.cfg.live_install_while_dl,
                                                        "Stream & install live while downloading (WinFsp virtual drive)",
                                                    )
                                                    .changed()
                                                {
                                                    cfg_dirty = true;
                                                }
                                            }

                                            ui.add_space(12.0);

                                            // Destination Input
                                            if Self::input_row(
                                                ui,
                                                "Install Destination",
                                                &mut self.cfg.target_game_dir,
                                                r"C:\Games",
                                                None,
                                                Some(25),
                                            ) {
                                                cfg_dirty = true;
                                            }

                                            ui.add_space(18.0);

                                            // Primary Gradient Hero Pill OR Live Progress Pill
                                            let is_torrent_active = self.source_kind == SourceKind::TorrentMagnet;
                                            if running {
                                                Self::draw_glass_progress(
                                                    ui,
                                                    dl_pct,
                                                    unpack_pct,
                                                    &stage_label,
                                                    is_torrent_active,
                                                );
                                                ui.add_space(8.0);
                                                ui.horizontal(|ui| {
                                                    let paused = self.control.paused.load(Ordering::Relaxed);
                                                    if ui.button(if paused { "Resume" } else { "Pause" }).clicked() {
                                                        let now_p = self.control.toggle_pause();
                                                        if let Ok(mut t) = self.telemetry.lock() {
                                                            t.stage_label = if now_p { "Paused".into() } else { "Resumed".into() };
                                                        }
                                                    }
                                                    if ui
                                                        .add(
                                                            egui::Button::new(RichText::new("Cancel").color(TEXT_WHITE))
                                                                .fill(Color32::from_rgb(190, 36, 48)),
                                                        )
                                                        .clicked()
                                                    {
                                                        self.control.request_cancel();
                                                    }
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        let worker_txt = if active_worker.is_empty() { "Working" } else { &active_worker };
                                                        let q_pre = match active_q_idx {
                                                            Some(i) if queue_states.len() > 1 => format!("Job {}/{} • ", i + 1, queue_states.len()),
                                                            _ => String::new(),
                                                        };
                                                        ui.label(
                                                            RichText::new(format!(
                                                                "{q_pre}{worker_txt} • {worker_ram} MB • {write_mbps:.0} MB/s • DL {dl_mbps:.1} MB/s • ETA {eta_text}"
                                                            ))
                                                            .size(11.0)
                                                            .color(TEXT_SOFT),
                                                        );
                                                    });
                                                });
                                            } else {
                                                let has_input = if is_torrent_active {
                                                    !self.magnet_or_torrent.trim().is_empty()
                                                } else {
                                                    !self.cfg.local_source.as_os_str().is_empty()
                                                };
                                                let cta_text = if is_torrent_active {
                                                    "Stream & Install Now   >"
                                                } else {
                                                    "Install Now   >"
                                                };
                                                let cta_w = ui.available_width();
                                                if Self::gradient_pill_button(ui, cta_text, cta_w, 46.0, has_input)
                                                    .clicked()
                                                    && has_input
                                                {
                                                    self.cfg.save();
                                                    let j = self.build_current_job(is_torrent_active);
                                                    self.queue = vec![QueueEntry {
                                                        config: j.clone(),
                                                        state: QueueItemState::Queued,
                                                    }];
                                                    pipeline::spawn_queue_thread(
                                                        vec![j],
                                                        self.cfg.post_queue_action,
                                                        self.telemetry.clone(),
                                                        self.control.clone(),
                                                    );
                                                }

                                                ui.add_space(10.0);
                                                ui.horizontal(|ui| {
                                                    if ui.add_enabled(has_input, egui::Button::new("+ Add to Queue")).clicked() {
                                                        let j = self.build_current_job(is_torrent_active);
                                                        self.queue.push(QueueEntry {
                                                            config: j,
                                                            state: QueueItemState::Queued,
                                                        });
                                                    }
                                                    if unpack_pct >= 0.999 && self.cfg.target_game_dir.exists() {
                                                        if ui.button("Open Game Folder").clicked() {
                                                            win_sys::open_in_explorer(&self.cfg.target_game_dir);
                                                        }
                                                    }
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        let s_lbl = if self.show_settings { "Hide Turbo Settings" } else { "Turbo Settings" };
                                                        if ui.button(s_lbl).clicked() {
                                                            self.show_settings = !self.show_settings;
                                                        }
                                                    });
                                                });
                                            }

                                            // Collapsible Turbo Settings Drawer
                                            if self.show_settings {
                                                ui.add_space(10.0);
                                                ui.separator();
                                                ui.add_space(8.0);
                                                if Self::input_row(
                                                    ui,
                                                    "Fast SSD Temp / Swap Folder",
                                                    &mut self.cfg.temp_ssd_dir,
                                                    "Fastest SSD partition",
                                                    None,
                                                    Some(8),
                                                ) {
                                                    cfg_dirty = true;
                                                }
                                                if self.source_kind == SourceKind::TorrentMagnet {
                                                    ui.add_space(6.0);
                                                    if Self::input_row(
                                                        ui,
                                                        "Torrent Cache Folder",
                                                        &mut self.cfg.download_cache_dir,
                                                        "Torrent piece storage",
                                                        None,
                                                        Some(15),
                                                    ) {
                                                        cfg_dirty = true;
                                                    }
                                                }
                                                ui.add_space(8.0);
                                                ui.horizontal_wrapped(|ui| {
                                                    if ui.checkbox(&mut self.cfg.defender_bypass, "Defender Boost").changed() { cfg_dirty = true; }
                                                    if ui.checkbox(&mut self.cfg.replay_registry, "Auto Registry").changed() { cfg_dirty = true; }
                                                    if ui.checkbox(&mut self.cfg.create_shortcuts, "Desktop Shortcuts").changed() { cfg_dirty = true; }
                                                    if ui.checkbox(&mut self.cfg.auto_clean_temp, "Clean Temp").changed() { cfg_dirty = true; }
                                                });
                                                ui.add_space(6.0);
                                                ui.horizontal(|ui| {
                                                    ui.label(RichText::new("SREP Memory:").size(12.0).color(TEXT_SOFT));
                                                    if ui.add(egui::Slider::new(&mut self.cfg.srep_ram_mb, 1024..=12288).suffix(" MB")).changed() {
                                                        cfg_dirty = true;
                                                    }
                                                    ui.separator();
                                                    ui.label(RichText::new("Drive:").size(12.0).color(TEXT_SOFT));
                                                    if ui.add(egui::TextEdit::singleline(&mut self.cfg.virtual_drive).desired_width(34.0)).changed() {
                                                        cfg_dirty = true;
                                                    }
                                                });
                                            }
                                        }

                                        MainTab::Queue => {
                                            ui.vertical_centered(|ui| {
                                                ui.label(RichText::new("Unattended Overnight Mode").size(12.0).color(TEXT_SOFT));
                                                ui.label(RichText::new("Batch Queue").size(28.0).strong().color(LAVENDER_TEXT));
                                            });
                                            ui.add_space(10.0);

                                            ui.horizontal(|ui| {
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
                                                if ui.add_enabled(!running && !self.queue.is_empty(), egui::Button::new("Clear")).clicked() {
                                                    self.queue.clear();
                                                }
                                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                    egui::ComboBox::from_id_salt("post_q_act")
                                                        .selected_text(self.cfg.post_queue_action.label())
                                                        .show_ui(ui, |ui| {
                                                            for opt in [
                                                                PostQueueAction::DoNothing,
                                                                PostQueueAction::SleepPc,
                                                                PostQueueAction::ShutdownPc,
                                                            ] {
                                                                if ui.selectable_value(&mut self.cfg.post_queue_action, opt, opt.label()).changed() {
                                                                    cfg_dirty = true;
                                                                }
                                                            }
                                                        });
                                                    ui.label(RichText::new("When done:").size(12.0).color(TEXT_SOFT));
                                                });
                                            });

                                            ui.add_space(10.0);
                                            if self.queue.is_empty() {
                                                ui.vertical_centered(|ui| {
                                                    ui.add_space(20.0);
                                                    ui.label(RichText::new("Drop multiple repack folders onto ArcSteam to queue them.").color(TEXT_SOFT));
                                                    ui.add_space(20.0);
                                                });
                                            } else {
                                                let mut remove_idx: Option<usize> = None;
                                                for (i, item) in self.queue.iter().enumerate() {
                                                    ui.horizontal(|ui| {
                                                        let col = match item.state {
                                                            QueueItemState::Done => OK_MINT,
                                                            QueueItemState::Running => LAVENDER_TEXT,
                                                            QueueItemState::Failed | QueueItemState::Cancelled => ERR_CORAL,
                                                            QueueItemState::Queued => TEXT_SOFT,
                                                        };
                                                        ui.label(RichText::new(format!("[{}]", item.state.label())).strong().color(col));
                                                        ui.label(RichText::new(&item.config.display_name).strong().color(TEXT_WHITE));
                                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                            if !running && ui.small_button("Remove").clicked() {
                                                                remove_idx = Some(i);
                                                            }
                                                        });
                                                    });
                                                }
                                                if let Some(idx) = remove_idx {
                                                    self.queue.remove(idx);
                                                }
                                            }

                                            ui.add_space(14.0);
                                            if running {
                                                Self::draw_glass_progress(ui, dl_pct, unpack_pct, &stage_label, false);
                                            } else {
                                                let can_q = !self.queue.is_empty();
                                                let w = ui.available_width();
                                                if Self::gradient_pill_button(ui, "Start Batch Queue   >", w, 44.0, can_q)
                                                    .clicked()
                                                    && can_q
                                                {
                                                    self.cfg.save();
                                                    let jobs: Vec<JobConfig> = self.queue.iter().map(|q| q.config.clone()).collect();
                                                    pipeline::spawn_queue_thread(
                                                        jobs,
                                                        self.cfg.post_queue_action,
                                                        self.telemetry.clone(),
                                                        self.control.clone(),
                                                    );
                                                }
                                            }
                                        }

                                        MainTab::Tools => {
                                            ui.vertical_centered(|ui| {
                                                ui.label(RichText::new("Verify & Fast Backup").size(12.0).color(TEXT_SOFT));
                                                ui.label(RichText::new("Repack Tools").size(28.0).strong().color(LAVENDER_TEXT));
                                            });
                                            ui.add_space(12.0);

                                            // MD5 / SFV Verifier
                                            Self::input_row(
                                                ui,
                                                "Multi-Core MD5 / SFV File Verifier",
                                                &mut self.verify_dir,
                                                "Select a repack folder...",
                                                None,
                                                None,
                                            );
                                            ui.add_space(6.0);
                                            ui.horizontal(|ui| {
                                                if verify_running {
                                                    if ui.button("Stop Verification").clicked() {
                                                        self.verify_cancel.store(true, Ordering::Relaxed);
                                                    }
                                                } else if ui.button("Verify Files Now").clicked() {
                                                    verify::spawn_verify_thread(
                                                        self.verify_dir.clone(),
                                                        self.verify_progress.clone(),
                                                        self.verify_cancel.clone(),
                                                    );
                                                }
                                                let vp = self.verify_progress.lock().unwrap().clone();
                                                if !vp.manifest_found.is_empty() {
                                                    let col = if vp.corrupt_count > 0 || vp.missing_count > 0 { ERR_CORAL } else { OK_MINT };
                                                    ui.label(
                                                        RichText::new(format!(
                                                            "{}/{} checked • OK {} • Missing {} • Corrupt {}",
                                                            vp.completed, vp.total, vp.ok_count, vp.missing_count, vp.corrupt_count
                                                        ))
                                                        .size(11.5)
                                                        .color(col),
                                                    );
                                                }
                                            });
                                            let vp_res = self.verify_progress.lock().unwrap().results.clone();
                                            if !vp_res.is_empty() {
                                                egui::ScrollArea::vertical().id_salt("v_res").max_height(70.0).show(ui, |ui| {
                                                    for r in &vp_res {
                                                        match r {
                                                            FileVerifyOutcome::Ok(f) => {
                                                                ui.label(RichText::new(format!("[OK] {f}")).monospace().size(10.8).color(OK_MINT));
                                                            }
                                                            FileVerifyOutcome::Missing(f) => {
                                                                ui.label(RichText::new(format!("[MISSING] {f}")).monospace().size(10.8).color(WARN_GOLD));
                                                            }
                                                            FileVerifyOutcome::Corrupt { file, expected, actual } => {
                                                                ui.label(RichText::new(format!("[CORRUPT] {file} ({expected} != {actual})")).monospace().size(10.8).color(ERR_CORAL));
                                                            }
                                                        }
                                                    }
                                                });
                                            }

                                            ui.add_space(12.0);
                                            ui.separator();
                                            ui.add_space(10.0);

                                            // Zstd Fast-Archive
                                            Self::input_row(
                                                ui,
                                                "Zstd Fast-Archive — Game Folder",
                                                &mut self.zstd_src,
                                                r"C:\Games\MyGame",
                                                None,
                                                None,
                                            );
                                            ui.add_space(6.0);
                                            Self::input_row(
                                                ui,
                                                "Zstd Backup File (.tar.zst — 500+ MB/s extract)",
                                                &mut self.zstd_dst,
                                                "Choose .tar.zst archive path",
                                                Some(("Zstd Tar", &["zst"])),
                                                None,
                                            );
                                            ui.add_space(8.0);
                                            let zp = self.zstd_progress.lock().unwrap().clone();
                                            ui.horizontal(|ui| {
                                                ui.label(RichText::new("Level:").size(12.0).color(TEXT_SOFT));
                                                ui.add(egui::Slider::new(&mut self.zstd_level, 1..=12));
                                                if ui.add_enabled(!zstd_running, egui::Button::new("Pack")).clicked() {
                                                    zstd_pack::spawn_zstd_pack(
                                                        self.zstd_src.clone(),
                                                        self.zstd_dst.clone(),
                                                        self.zstd_level,
                                                        self.zstd_progress.clone(),
                                                        self.zstd_cancel.clone(),
                                                    );
                                                }
                                                if ui.add_enabled(!zstd_running, egui::Button::new("Unpack")).clicked() {
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
                                        }
                                    }

                                    // Inline Activity Log drawer when toggled or on error
                                    if self.show_logs {
                                        ui.add_space(12.0);
                                        ui.separator();
                                        ui.add_space(6.0);
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new("Activity Log").size(12.0).strong().color(TEXT_WHITE));
                                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                if ui.small_button("Copy").clicked() {
                                                    ui.ctx().copy_text(logs_snapshot.join("\n"));
                                                }
                                            });
                                        });
                                        egui::ScrollArea::vertical()
                                            .id_salt("glass_log_scroll")
                                            .max_height(115.0)
                                            .stick_to_bottom(true)
                                            .show(ui, |ui| {
                                                for line in &logs_snapshot {
                                                    let col = if line.contains("[ERROR]") || line.contains("ERROR:") {
                                                        ERR_CORAL
                                                    } else if line.contains("[WARN]") {
                                                        WARN_GOLD
                                                    } else if line.contains("[DONE]") {
                                                        OK_MINT
                                                    } else {
                                                        TEXT_SOFT
                                                    };
                                                    ui.label(RichText::new(line).monospace().size(10.8).color(col));
                                                }
                                            });
                                    }
                                });
                        });
                });

                ui.add_space(12.0);

                // ===============================================================
                // 3. FLOATING BOTTOM STATUS CAPSULE (matching reference bottom pill)
                // ===============================================================
                ui.vertical_centered(|ui| {
                    Frame::new()
                        .fill(GLASS_PILL_BG)
                        .stroke(Stroke::new(1.0, GLASS_BORDER))
                        .corner_radius(CornerRadius::same(20))
                        .inner_margin(Margin::symmetric(16, 6))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(if self.health.core_ready {
                                        "● All Engines Built-in"
                                    } else {
                                        "● Missing Engine"
                                    })
                                    .size(11.5)
                                    .color(if self.health.core_ready { OK_MINT } else { WARN_GOLD }),
                                );

                                ui.label(RichText::new("•").color(TEXT_SOFT));

                                if self.health.winfsp_ok {
                                    ui.label(RichText::new("● Live Stream Ready").size(11.5).color(OK_MINT));
                                } else if wf_installing {
                                    ui.label(RichText::new("Installing WinFsp...").size(11.5).color(LAVENDER_TEXT));
                                } else if self.health.winfsp_msi_ready {
                                    if ui
                                        .add(
                                            egui::Button::new(
                                                RichText::new("Install Built-in WinFsp >")
                                                    .size(11.5)
                                                    .strong()
                                                    .color(TEXT_WHITE),
                                            )
                                            .fill(LAVENDER_GRAD_L)
                                            .corner_radius(CornerRadius::same(12)),
                                        )
                                        .clicked()
                                    {
                                        self.trigger_builtin_winfsp_install();
                                    }
                                } else if ui.small_button("Get WinFsp >").clicked() {
                                    win_sys::open_url("https://winfsp.dev/rel/");
                                }

                                ui.label(RichText::new("•").color(TEXT_SOFT));

                                if self.health.is_admin {
                                    ui.label(RichText::new("● Admin").size(11.5).color(OK_MINT));
                                } else if ui.small_button("Run as Admin").clicked() {
                                    if win_sys::relaunch_as_admin() {
                                        std::process::exit(0);
                                    }
                                }
                            });
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
            .with_inner_size([840.0, 680.0])
            .with_min_inner_size([660.0, 560.0])
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
