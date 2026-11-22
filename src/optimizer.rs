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
    Bit32Laa, // 32-bit with IMAGE_FILE_LARGE_ADDRESS_AWARE (up to ~4 GB)
    Bit32,    // 32-bit standard (strict 2 GB user-space limit)
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

/// Sweeps any leftover temporary Windows Defender exclusions recorded in the state file
/// from an earlier Task Manager force-kill or unexpected power loss.
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

/// Crash-safe RAII guard: logs active paths to disk before registering exclusions so even
/// a force-kill or power loss gets automatically cleaned up on next launch.
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

/// Inspects a Windows PE header to distinguish 64-bit, 32-bit LAA, and standard 32-bit binaries.
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

/// Returns ~65% of currently available system RAM (clamped safely for SREP).
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

/// Searches work_dir and tools_dir for a 64-bit standalone srep binary and stages it into work_dir
/// so 32-bit unarc.exe can offload multi-GB deduplication into a 64-bit child process.
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
                // Also mirror as cls-srep_x64.exe because ProFrager's cls-srep.dll probes that exact name.
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

/// Patches extracted cls-srep.ini, cls.ini, and arc.ini to scale RAM safely:
/// - If a 64-bit srep helper or 64-bit unarc.exe is available, unlocks full requested RAM via external 64-bit process.
/// - If unarc.exe is 32-bit with no 64-bit srep helper, clamps RAM to prevent 32-bit OOM crashes.
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

    let srep_cfg = if let Some(ref exe64) = external_srep64 {
        format!(
            "[srep]\nMemory={effective_ram_mb}m\nTempPath={temp_with_slash}\nExe={exe64}\n"
        )
    } else {
        format!(
            "[srep]\nMemory={effective_ram_mb}m\nTempPath={temp_with_slash}\n"
        )
    };
    fs::write(work_dir.join("cls-srep.ini"), &srep_cfg)?;

    let cls_ini = work_dir.join("cls.ini");
    let mut cls_content = if cls_ini.exists() {
        fs::read_to_string(&cls_ini).unwrap_or_default()
    } else {
        String::new()
    };
    if !cls_content.to_ascii_lowercase().contains("[srep]") {
        cls_content.push('\n');
        cls_content.push_str(&srep_cfg);
    }
    if !cls_content.to_ascii_lowercase().contains("[lolz]") {
        cls_content.push_str(&format!("\n[lolz]\nMaxThreadsUsage={threads}\n"));
    }
    fs::write(&cls_ini, cls_content)?;

    let arc_ini = work_dir.join("arc.ini");
    if arc_ini.exists() {
        let mut text = fs::read_to_string(&arc_ini)?;
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

/// Spawns any unpacker (unarc.exe, innoextract.exe, 7z.exe) headlessly at HIGH_PRIORITY_CLASS
/// with split-drive TEMP/TMP environment variables.
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
