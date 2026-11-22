use anyhow::Result;
use regex::Regex;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use sysinfo::System;

const HIGH_PRIORITY_CLASS: u32 = 0x0000_0080;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// RAII guard: temporarily excludes active extraction paths from Windows Defender
/// real-time scanning and automatically removes exclusions on Drop.
pub struct DefenderExclusionGuard {
    paths: Vec<PathBuf>,
}

impl DefenderExclusionGuard {
    pub fn activate(paths: Vec<PathBuf>) -> Self {
        for p in &paths {
            let _ = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!("Add-MpPreference -ExclusionPath '{}'", p.display()),
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
            let _ = Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!("Remove-MpPreference -ExclusionPath '{}'", p.display()),
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
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

/// Patches extracted cls-srep.ini, cls.ini, and arc.ini to lift 2-4 GB repack RAM caps,
/// unlock all CPU threads, and route SREP swap files to the fastest SSD temp directory.
pub fn patch_unpacker_configs(
    work_dir: &Path,
    fast_temp_dir: &Path,
    ram_mb: u64,
    threads: usize,
) -> Result<()> {
    fs::create_dir_all(fast_temp_dir)?;

    let srep_cfg = format!(
        "[srep]\nMemory={ram_mb}m\nTempPath={}\n",
        fast_temp_dir.display()
    );
    fs::write(work_dir.join("cls-srep.ini"), &srep_cfg)?;

    let cls_ini = work_dir.join("cls.ini");
    let mut cls_content = if cls_ini.exists() {
        fs::read_to_string(&cls_ini).unwrap_or_default()
    } else {
        String::new()
    };
    if !cls_content.to_ascii_lowercase().contains("[srep]") {
        cls_content.push_str("\n");
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
        text = re_mem.replace_all(&text, format!("-mem{ram_mb}mb")).to_string();
        let re_threads = Regex::new(r"(?i)-t\d+")?;
        text = re_threads.replace_all(&text, format!("-t{threads}")).to_string();
        fs::write(&arc_ini, text)?;
    }
    Ok(())
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
