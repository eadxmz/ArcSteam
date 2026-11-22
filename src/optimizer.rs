use anyhow::Result;
use regex::Regex;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use sysinfo::System;

const HIGH_PRIORITY_CLASS: u32 = 0x0000_0080;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeBitness {
    Bit64,
    Bit32Laa,
    Bit32,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SrepPatchReport {
    pub effective_ram_mb: u64,
    pub external_srep64_used: Option<String>,
    pub unarc_bitness: PeBitness,
    pub clamped_for_32bit: bool,
}

fn exclusion_state_file() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let dir = PathBuf::from(local).join("ArcSteam");
        let _ = fs::create_dir_all(&dir);
        return dir.join("active_defender_exclusions.txt");
    }
    std::env::temp_dir().join("arcsteam_active_defender_exclusions.txt")
}

fn ps_escape(path: &Path) -> String {
    path.display().to_string().replace('\'', "''")
}

fn remove_defender_exclusion(path: &Path) {
    let escaped = ps_escape(path);
    let _ = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Remove-MpPreference -ExclusionPath '{escaped}'"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}

pub fn sweep_stale_defender_exclusions() -> Vec<String> {
    let state_path = exclusion_state_file();
    let Ok(content) = fs::read_to_string(&state_path) else {
        return Vec::new();
    };
    let mut swept = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            remove_defender_exclusion(Path::new(trimmed));
            swept.push(trimmed.to_string());
        }
    }
    let _ = fs::remove_file(&state_path);
    swept
}

pub struct DefenderExclusionGuard {
    paths: Vec<PathBuf>,
}

impl DefenderExclusionGuard {
    pub fn activate(paths: Vec<PathBuf>) -> Self {
        let state_path = exclusion_state_file();
        let serialized: String = paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let _ = fs::write(&state_path, serialized);

        for p in &paths {
            let escaped = ps_escape(p);
            let _ = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!("Add-MpPreference -ExclusionPath '{escaped}'"),
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
        Self { paths }
    }
}

impl Drop for DefenderExclusionGuard {
    fn drop(&mut self) {
        for p in &self.paths {
            remove_defender_exclusion(p);
        }
        let _ = fs::remove_file(exclusion_state_file());
    }
}

pub fn inspect_pe_bitness(exe_path: &Path) -> PeBitness {
    let Ok(mut f) = File::open(exe_path) else {
        return PeBitness::Unknown;
    };
    let mut dos = [0u8; 64];
    if f.read_exact(&mut dos).is_err() || &dos[0..2] != b"MZ" {
        return PeBitness::Unknown;
    }
    let e_lfanew = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as u64;
    if f.seek(SeekFrom::Start(e_lfanew)).is_err() {
        return PeBitness::Unknown;
    }
    let mut coff = [0u8; 24];
    if f.read_exact(&mut coff).is_err() || &coff[0..4] != b"PE\0\0" {
        return PeBitness::Unknown;
    }
    let machine = u16::from_le_bytes([coff[4], coff[5]]);
    let characteristics = u16::from_le_bytes([coff[22], coff[23]]);

    match machine {
        0x8664 | 0xAA64 => PeBitness::Bit64,
        0x014C => {
            if (characteristics & 0x0020) != 0 {
                PeBitness::Bit32Laa
            } else {
                PeBitness::Bit32
            }
        }
        _ => PeBitness::Unknown,
    }
}

pub fn optimal_srep_ram_mb() -> u64 {
    let mut sys = System::new_all();
    sys.refresh_memory();
    let avail_mb = sys.available_memory() / (1024 * 1024);
    ((avail_mb as f64) * 0.65).clamp(1536.0, 12288.0) as u64
}

pub fn logical_cpu_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

fn locate_and_stage_srep64(work_dir: &Path, tools_dir: &Path) -> Option<String> {
    let candidates = ["cls-srep_x64.exe", "srep64.exe", "srep_x64.exe", "srep.exe"];
    for dir in [work_dir, tools_dir] {
        for name in candidates {
            let p = dir.join(name);
            if p.exists() && inspect_pe_bitness(&p) == PeBitness::Bit64 {
                let staged_name = if name == "cls-srep_x64.exe" {
                    "cls-srep_x64.exe"
                } else {
                    "srep64.exe"
                };
                let dst = work_dir.join(staged_name);
                if p != dst {
                    let _ = fs::copy(&p, &dst);
                }
                let cls_x64 = work_dir.join("cls-srep_x64.exe");
                if !cls_x64.exists() {
                    let _ = fs::copy(&p, &cls_x64);
                }
                return Some(staged_name.to_string());
            }
        }
    }
    None
}

fn read_ini_lossy(path: &Path) -> String {
    let Ok(bytes) = fs::read(path) else {
        return String::new();
    };
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Section-aware CLS.ini Turbo Optimizer:
/// - Unlocks `MaxThreadsUsage=100%` across `[lolz]`, `[magic2]`, `[magic2l]`, `[srep]`
/// - Bumps shared-memory IPC `transfer_ReadBufSize` / `transfer_WriteBufSize` to `4m`
/// - Bumps `[srep]` `Bufsize` to `32m` and other CLS `Bufsize` to `4m`
/// - Routes all `TempPath=` & `{app}`/`{tmp}` placeholders to the fastest SSD swap folder
fn optimize_cls_ini_text(
    raw: &str,
    temp_with_slash: &str,
    fast_temp_dir: &Path,
    work_dir: &Path,
    effective_ram_mb: u64,
    threads: usize,
) -> String {
    let mut out = String::with_capacity(raw.len() + 256);
    let mut section = String::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            section = trimmed.to_ascii_lowercase();
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if let Some((key_raw, _val_raw)) = line.split_once('=') {
            let key_lower = key_raw.trim().to_ascii_lowercase();
            let rewritten = match key_lower.as_str() {
                "temppath" => format!("{key_raw}={temp_with_slash}"),
                "memory" => format!("{key_raw}={effective_ram_mb}m"),
                "maxthreadsusage" => format!("{key_raw}=100%"),
                "transfer_readbufsize" | "transfer_writebufsize" => format!("{key_raw}=4m"),
                "bufsize" => {
                    if section == "[srep]" {
                        format!("{key_raw}=32m")
                    } else {
                        format!("{key_raw}=4m")
                    }
                }
                _ => line
                    .replace("{app}", &fast_temp_dir.display().to_string())
                    .replace("{tmp}", &work_dir.display().to_string()),
            };
            out.push_str(&rewritten);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }

    let lower_all = out.to_ascii_lowercase();
    if !lower_all.contains("[srep]") {
        out.push_str(&format!(
            "\n[srep]\nMemory={effective_ram_mb}m\nTempPath={temp_with_slash}\nBufsize=32m\n"
        ));
    }
    if !lower_all.contains("[lolz]") {
        out.push_str(&format!(
            "\n[lolz]\nMaxThreadsUsage=100%\nThreads={threads}\nTempPath={temp_with_slash}\nBufsize=4m\ntransfer_ReadBufSize=4m\ntransfer_WriteBufSize=4m\n"
        ));
    }
    out
}

pub fn patch_unpacker_configs(
    work_dir: &Path,
    tools_dir: &Path,
    unarc_exe: &Path,
    fast_temp_dir: &Path,
    requested_ram_mb: u64,
    threads: usize,
) -> Result<SrepPatchReport> {
    fs::create_dir_all(fast_temp_dir)?;

    let unarc_bitness = inspect_pe_bitness(unarc_exe);
    let external_srep64 = locate_and_stage_srep64(work_dir, tools_dir);

    let (effective_ram_mb, clamped) = if external_srep64.is_some() || unarc_bitness == PeBitness::Bit64 {
        (requested_ram_mb, false)
    } else {
        let cap = match unarc_bitness {
            PeBitness::Bit32Laa => 2600,
            PeBitness::Bit32 | PeBitness::Unknown => 1400,
            PeBitness::Bit64 => requested_ram_mb,
        };
        if requested_ram_mb > cap {
            (cap, true)
        } else {
            (requested_ram_mb, false)
        }
    };

    let mut temp_with_slash = fast_temp_dir.display().to_string();
    if !temp_with_slash.ends_with('\\') {
        temp_with_slash.push('\\');
    }

    let srep_cfg = format!(
        "[srep]\nMemory={effective_ram_mb}m\nTempPath={temp_with_slash}\nBufsize=32m\n"
    );
    fs::write(work_dir.join("cls-srep.ini"), &srep_cfg)?;

    let cls_ini = if work_dir.join("CLS.ini").exists() {
        work_dir.join("CLS.ini")
    } else {
        work_dir.join("cls.ini")
    };
    let raw_cls = if cls_ini.exists() {
        read_ini_lossy(&cls_ini)
    } else {
        String::new()
    };
    let tuned_cls = optimize_cls_ini_text(
        &raw_cls,
        &temp_with_slash,
        fast_temp_dir,
        work_dir,
        effective_ram_mb,
        threads,
    );
    fs::write(&cls_ini, tuned_cls)?;

    let arc_ini = work_dir.join("arc.ini");
    if arc_ini.exists() {
        let mut text = read_ini_lossy(&arc_ini);
        let re_fgrplc = Regex::new(r"(?i)fgrplc")?;
        text = re_fgrplc.replace_all(&text, "-1").to_string();
        text = text.replace("{tmp}", &work_dir.display().to_string());
        let re_mem = Regex::new(r"(?i)-mem\d+m?b?")?;
        text = re_mem.replace_all(&text, format!("-mem{effective_ram_mb}mb")).to_string();
        let re_threads = Regex::new(r"(?i)-t\d+")?;
        text = re_threads.replace_all(&text, format!("-t{threads}")).to_string();
        if let Some(ref exe64) = external_srep64 {
            let re_srep_cmd = Regex::new(r"(?i)\bsrep\.exe\b")?;
            text = re_srep_cmd.replace_all(&text, exe64.as_str()).to_string();
        }
        fs::write(&arc_ini, text)?;
    }

    Ok(SrepPatchReport {
        effective_ram_mb,
        external_srep64_used: external_srep64,
        unarc_bitness,
        clamped_for_32bit: clamped,
    })
}

pub fn spawn_turbo_process(
    exe: &Path,
    args: &[String],
    cwd: Option<&Path>,
    fast_temp_dir: &Path,
    show_window: bool,
) -> Result<Child> {
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .env("TEMP", fast_temp_dir)
        .env("TMP", fast_temp_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }

    let flags = if show_window {
        HIGH_PRIORITY_CLASS
    } else {
        HIGH_PRIORITY_CLASS | CREATE_NO_WINDOW
    };
    cmd.creation_flags(flags);

    Ok(cmd.spawn()?)
}
