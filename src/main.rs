#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod detect;
mod dissect;
mod optimizer;
mod pipeline;
mod stream_bridge;

use detect::{RepackFileEntry, RepackFormat};
use eframe::egui::{self, Color32, CornerRadius, Frame, Margin, RichText, Stroke, Vec2};
use pipeline::{JobConfig, SharedTelemetry};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(PartialEq, Eq)]
enum SourceTab {
    TorrentStream,
    LocalTurbo,
}

struct ArcSteamApp {
    tab: SourceTab,
    magnet_or_torrent: String,
    local_source: PathBuf,
    download_cache_dir: PathBuf,
    temp_ssd_dir: PathBuf,
    target_game_dir: PathBuf,
    virtual_drive: String,
    live_install_while_dl: bool,
    defender_bypass: bool,
    replay_registry: bool,
    srep_ram_mb: u64,
    detected_format: RepackFormat,
    scanned_files: Vec<RepackFileEntry>,
    telemetry: Arc<Mutex<SharedTelemetry>>,
}

impl Default for ArcSteamApp {
    fn default() -> Self {
        let mut initial_telemetry = SharedTelemetry::default();
        initial_telemetry.stage_label = "Idle — Ready to stream or turbo-unpack".into();
        initial_telemetry.log(
            "ArcSteam initialized | Universal Engine: FreeArc / DODI / FitGirl / GOG Inno / 7z / ISO / NSIS",
        );

        Self {
            tab: SourceTab::TorrentStream,
            magnet_or_torrent: String::new(),
            local_source: PathBuf::from(r"G:\Setup (After NEET)"),
            download_cache_dir: PathBuf::from(r"G:\ArcSteamCache"),
            temp_ssd_dir: PathBuf::from(r"C:\ArcSteamTemp"),
            target_game_dir: PathBuf::from(r"D:\Games"),
            virtual_drive: "Z:".into(),
            live_install_while_dl: true,
            defender_bypass: true,
            replay_registry: true,
            srep_ram_mb: optimizer::optimal_srep_ram_mb(),
            detected_format: RepackFormat::FitGirlMultiArc,
            scanned_files: Vec::new(),
            telemetry: Arc::new(Mutex::new(initial_telemetry)),
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
            .corner_radius(CornerRadius::same(16))
            .inner_margin(Margin::same(14))
    }

    fn scan_local_now(&mut self) {
        if self.local_source.is_dir() {
            let (fmt, entries) = detect::scan_local_directory(&self.local_source);
            self.detected_format = fmt;
            self.scanned_files = entries;
            if let Ok(mut t) = self.telemetry.lock() {
                t.log(format!(
                    "[SCAN] {} -> {} ({} files)",
                    self.local_source.display(),
                    fmt.badge(),
                    self.scanned_files.len()
                ));
            }
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
}

impl eframe::App for ArcSteamApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Handle drag-and-drop for .torrent files or local repack folders
        let dropped: Vec<PathBuf> = ui.ctx().input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        for path in dropped {
            if path.is_dir() {
                self.tab = SourceTab::LocalTurbo;
                self.local_source = path;
                self.scan_local_now();
            } else if path.extension().and_then(|e| e.to_str()) == Some("torrent") {
                self.tab = SourceTab::TorrentStream;
                self.magnet_or_torrent = path.display().to_string();
            }
        }

        let (running, dl_pct, unpack_pct, stage_label, logs_snapshot) = {
            let t = self.telemetry.lock().unwrap();
            (
                t.running,
                t.download_pct,
                t.unpack_pct,
                t.stage_label.clone(),
                t.logs.clone(),
            )
        };

        if running {
            ui.ctx().request_repaint_after(Duration::from_millis(120));
        }

        egui::CentralPanel::default().show(ui, |ui| {
            // Header with SVG Logo & Mode Switcher
            ui.horizontal(|ui| {
                ui.add(
                    egui::Image::new(egui::include_image!("../assets/logo.svg"))
                        .max_size(Vec2::splat(44.0)),
                );
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new("ArcSteam")
                            .size(22.0)
                            .strong()
                            .color(Color32::from_rgb(241, 245, 249)),
                    );
                    ui.label(
                        RichText::new("Live Torrent-to-Unpack Streamer & Universal Repack Engine")
                            .size(11.5)
                            .color(Color32::from_rgb(148, 163, 184)),
                    );
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.selectable_value(&mut self.tab, SourceTab::LocalTurbo, "Local Turbo");
                    ui.selectable_value(&mut self.tab, SourceTab::TorrentStream, "Torrent / Magnet");
                });
            });

            ui.add_space(10.0);

            // Source Input Card
            Self::glass_card().show(ui, |ui| {
                if self.tab == SourceTab::TorrentStream {
                    ui.label(RichText::new("Magnet URI or .torrent File").strong());
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.magnet_or_torrent)
                                .hint_text("magnet:?xt=urn:btih:... or drop a .torrent file here")
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
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        ui.checkbox(
                            &mut self.live_install_while_dl,
                            "Install LIVE while downloading (WinFsp VFS + 16 MB EOF tail-priming)",
                        );
                        ui.separator();
                        ui.label("Mount:");
                        ui.add(egui::TextEdit::singleline(&mut self.virtual_drive).desired_width(36.0));
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
                    ui.add_space(5.0);
                    ui.horizontal(|ui| {
                        let mut s = self.local_source.display().to_string();
                        if ui
                            .add(egui::TextEdit::singleline(&mut s).desired_width(ui.available_width() - 165.0))
                            .changed()
                        {
                            self.local_source = PathBuf::from(s);
                        }
                        if ui.button("Pick Folder").clicked() {
                            if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                self.local_source = p;
                                self.scan_local_now();
                            }
                        }
                        if ui.button("Scan").clicked() {
                            self.scan_local_now();
                        }
                    });

                    // Optional / Selective Repack File Filter List
                    if !self.scanned_files.is_empty() {
                        ui.add_space(6.0);
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
                            .size(11.5)
                            .color(Color32::from_rgb(148, 163, 184)),
                        );
                        egui::ScrollArea::vertical()
                            .id_salt("blueprint_scroll")
                            .max_height(92.0)
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

            ui.add_space(8.0);

            // Real-Time Speed Pipeline Card
            Self::glass_card().show(ui, |ui| {
                ui.label(RichText::new("Real-Time Speed Pipeline (Split-Drive I/O + RAM Boost)").strong());
                ui.add_space(5.0);

                egui::Grid::new("paths_grid").num_columns(3).spacing([8.0, 5.0]).show(ui, |ui| {
                    if self.tab == SourceTab::TorrentStream {
                        ui.label("Torrent Cache Drive:");
                        let mut c = self.download_cache_dir.display().to_string();
                        if ui.add(egui::TextEdit::singleline(&mut c).desired_width(470.0)).changed() {
                            self.download_cache_dir = PathBuf::from(c);
                        }
                        if ui.button("Browse").clicked() {
                            if let Some(p) = rfd::FileDialog::new().pick_folder() {
                                self.download_cache_dir = p;
                            }
                        }
                        ui.end_row();
                    }

                    ui.label("Fast SSD Swap / TEMP:");
                    let mut tmp = self.temp_ssd_dir.display().to_string();
                    if ui.add(egui::TextEdit::singleline(&mut tmp).desired_width(470.0)).changed() {
                        self.temp_ssd_dir = PathBuf::from(tmp);
                    }
                    if ui.button("Browse").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            self.temp_ssd_dir = p;
                        }
                    }
                    ui.end_row();

                    ui.label("Game Install Target:");
                    let mut dst = self.target_game_dir.display().to_string();
                    if ui.add(egui::TextEdit::singleline(&mut dst).desired_width(470.0)).changed() {
                        self.target_game_dir = PathBuf::from(dst);
                    }
                    if ui.button("Browse").clicked() {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            self.target_game_dir = p;
                        }
                    }
                    ui.end_row();
                });

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.defender_bypass, "Temp Defender Exclusion");
                    ui.checkbox(&mut self.replay_registry, "Replay [Registry]");
                    ui.separator();
                    ui.label("SREP RAM:");
                    ui.add(egui::Slider::new(&mut self.srep_ram_mb, 1024..=12288).suffix(" MB"));
                });
            });

            ui.add_space(8.0);

            // Dual Frontier Progress + Launch Controls
            Self::glass_card().show(ui, |ui| {
                Self::draw_dual_frontier_bar(ui, dl_pct, unpack_pct, &stage_label);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let btn_text = if running {
                        "  Pipeline Running...  "
                    } else if self.tab == SourceTab::TorrentStream {
                        "  Start Live Stream Install  "
                    } else {
                        "  Start Turbo Local Unpack  "
                    };

                    let launch = egui::Button::new(
                        RichText::new(btn_text)
                            .strong()
                            .color(Color32::from_rgb(10, 14, 24)),
                    )
                    .fill(if running {
                        Color32::from_rgb(71, 85, 105)
                    } else {
                        Color32::from_rgb(34, 211, 238)
                    })
                    .corner_radius(CornerRadius::same(11));

                    if ui.add_enabled(!running, launch).clicked() {
                        let cfg = JobConfig {
                            is_torrent_mode: self.tab == SourceTab::TorrentStream,
                            magnet_or_torrent: self.magnet_or_torrent.clone(),
                            local_source_dir: self.local_source.clone(),
                            download_cache_dir: self.download_cache_dir.clone(),
                            fast_temp_dir: self.temp_ssd_dir.clone(),
                            target_game_dir: self.target_game_dir.clone(),
                            virtual_drive: self.virtual_drive.clone(),
                            live_stream_install: self.live_install_while_dl,
                            defender_bypass: self.defender_bypass,
                            replay_registry: self.replay_registry,
                            srep_ram_mb: self.srep_ram_mb,
                            selected_files: self.scanned_files.clone(),
                            detected_format: self.detected_format,
                        };
                        pipeline::spawn_pipeline_thread(cfg, self.telemetry.clone());
                    }

                    if ui.button("Copy Log").clicked() {
                        ui.ctx().copy_text(logs_snapshot.join("\n"));
                    }
                });
            });

            ui.add_space(6.0);

            // Live Console Log
            egui::ScrollArea::vertical()
                .id_salt("console_log")
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &logs_snapshot {
                        ui.label(
                            RichText::new(line)
                                .monospace()
                                .size(11.2)
                                .color(Color32::from_rgb(148, 163, 184)),
                        );
                    }
                });
        });
    }
}

fn main() -> eframe::Result {
    // Initialize WinFsp delay-load runtime if installed on the system.
    let _winfsp_init = winfsp::winfsp_init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([880.0, 680.0])
            .with_min_inner_size([740.0, 560.0])
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
