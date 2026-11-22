use std::fs::File;
use std::io::Read;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepackFormat {
    FitGirlMultiArc,
    DodiMonolithic,
    ClassicFreeArc,       // R.G. Mechanics, ElAmigos, Xatab, KaOs, Empress, Codex
    GogPureInno,          // GOG setup_*.exe + setup_*.bin
    SceneArchiveOrIso,    // .7z, .rar, .zip, .iso, .tar.zst (SteamRIP / Portable / Scene)
    GenericInstallerTurbo, // NSIS / InstallShield / Direct SFX fallback
}

impl RepackFormat {
    pub fn badge(self) -> &'static str {
        match self {
            Self::FitGirlMultiArc => "FitGirl Multi-BIN (FreeArc)",
            Self::DodiMonolithic => "DODI Monolithic (.doi FreeArc)",
            Self::ClassicFreeArc => "Classic / Scene FreeArc (.bin/.arc)",
            Self::GogPureInno => "GOG Pure Inno Setup (Direct Stream)",
            Self::SceneArchiveOrIso => "Portable / Scene Archive (7z / RAR / ISO)",
            Self::GenericInstallerTurbo => "Generic Setup (Turbo Bypass Mode)",
        }
    }

    pub fn needs_eof_tail_prime(self) -> bool {
        matches!(
            self,
            Self::FitGirlMultiArc | Self::DodiMonolithic | Self::ClassicFreeArc | Self::SceneArchiveOrIso
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveMagic {
    FreeArc,      // "ArC\x01"
    InnoSlice,    // "idska32"
    SevenZip,     // 37 7A BC AF 27 1C
    Rar,          // "Rar!"
    Zip,          // "PK\x03\x04"
    Iso9660,      // "CD001" at 0x8001 (handled by extension)
    Unknown,
}

#[derive(Debug, Clone)]
pub struct RepackFileEntry {
    pub torrent_file_idx: Option<usize>,
    pub rel_path: String,
    pub size_bytes: u64,
    pub is_setup_exe: bool,
    pub is_archive: bool,
    pub is_optional: bool,
    pub selected: bool,
}

/// Inspects the first bytes of a file (including renamed .bin/.doi/.dat containers)
/// so ArcSteam routes every container to the exact right unpacker.
pub fn probe_archive_magic(path: &Path) -> ArchiveMagic {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if ext == "iso" {
        return ArchiveMagic::Iso9660;
    }

    let Ok(mut f) = File::open(path) else {
        return ArchiveMagic::Unknown;
    };
    let mut header = [0u8; 8];
    let Ok(n) = f.read(&mut header) else {
        return ArchiveMagic::Unknown;
    };
    if n < 4 {
        return ArchiveMagic::Unknown;
    }

    if &header[..4] == b"ArC\x01" {
        ArchiveMagic::FreeArc
    } else if n >= 7 && &header[..7] == b"idska32" {
        ArchiveMagic::InnoSlice
    } else if n >= 6 && header[..6] == [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        ArchiveMagic::SevenZip
    } else if &header[..4] == b"Rar!" {
        ArchiveMagic::Rar
    } else if &header[..4] == b"PK\x03\x04" {
        ArchiveMagic::Zip
    } else {
        ArchiveMagic::Unknown
    }
}

pub fn scan_local_directory(root: &Path) -> (RepackFormat, Vec<RepackFileEntry>) {
    let mut raw = Vec::new();
    for entry in WalkDir::new(root).max_depth(3).into_iter().flatten() {
        if entry.file_type().is_file() {
            let rel = entry
                .path()
                .strip_prefix(root)
                .unwrap_or(entry.path())
                .to_string_lossy()
                .replace('\\', "/");
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            raw.push((None, rel, size));
        }
    }
    classify_repack(&raw)
}

pub fn classify_repack(files: &[(Option<usize>, String, u64)]) -> (RepackFormat, Vec<RepackFileEntry>) {
    let mut has_fg = false;
    let mut has_doi = false;
    let mut has_gog_setup = false;
    let mut has_setup_exe = false;
    let mut has_freearc_like = false;
    let mut has_generic_archive = false;

    let mut entries = Vec::with_capacity(files.len());

    for (idx, rel, size) in files {
        let lower = rel.to_ascii_lowercase();
        let name = Path::new(&lower)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&lower);

        let is_setup_exe = name == "setup.exe"
            || name == "install.exe"
            || (name.starts_with("setup_") && name.ends_with(".exe"));

        let is_doi = name.ends_with(".doi");
        let is_fg = name.starts_with("fg-") || name.starts_with("setup-fitgirl-");
        let is_bin_or_arc = name.ends_with(".bin")
            || name.ends_with(".arc")
            || name.ends_with(".kab")
            || name.ends_with(".bf")
            || name.ends_with(".cpk")
            || name.ends_with(".dodi")
            || name.ends_with(".xatab");

        let is_std_archive = name.ends_with(".7z")
            || name.ends_with(".rar")
            || name.ends_with(".zip")
            || name.ends_with(".iso")
            || name.ends_with(".001")
            || name.ends_with(".zst");

        if is_setup_exe {
            has_setup_exe = true;
        }
        if name.starts_with("setup_") && name.ends_with(".exe") {
            has_gog_setup = true;
        }
        if is_fg {
            has_fg = true;
        }
        if is_doi {
            has_doi = true;
        }
        if is_bin_or_arc {
            has_freearc_like = true;
        }
        if is_std_archive {
            has_generic_archive = true;
        }

        let is_optional = name.contains("optional")
            || (name.contains("selective-") && !name.contains("english"))
            || name.contains("_ost_")
            || name.contains("bonus-content")
            || name.contains("credits-video")
            || name.contains("gallery-video")
            || (name.contains("lang") && !name.contains("eng") && is_bin_or_arc);

        let is_archive = is_doi || is_bin_or_arc || is_std_archive;

        entries.push(RepackFileEntry {
            torrent_file_idx: *idx,
            rel_path: rel.clone(),
            size_bytes: *size,
            is_setup_exe,
            is_archive,
            is_optional,
            selected: !is_optional,
        });
    }

    let format = if has_fg {
        RepackFormat::FitGirlMultiArc
    } else if has_doi {
        RepackFormat::DodiMonolithic
    } else if has_gog_setup && has_freearc_like {
        RepackFormat::GogPureInno
    } else if has_freearc_like && has_setup_exe {
        RepackFormat::ClassicFreeArc
    } else if has_generic_archive && !has_setup_exe {
        RepackFormat::SceneArchiveOrIso
    } else if has_setup_exe {
        RepackFormat::GenericInstallerTurbo
    } else {
        RepackFormat::SceneArchiveOrIso
    };

    (format, entries)
}

pub fn format_bytes(bytes: u64) -> String {
    const GB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    if bytes as f64 >= GB {
        format!("{:.2} GB", bytes as f64 / GB)
    } else if bytes as f64 >= MB {
        format!("{:.1} MB", bytes as f64 / MB)
    } else {
        format!("{} KB", bytes / 1024)
    }
}
