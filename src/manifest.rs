use std::collections::HashSet;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UninstallMode {
    /// Deletes game install folder(s), shortcuts, and uninstall registration; preserves saves/profiles.
    KeepProfile,
    /// Deletes game files, shortcuts, profile/save folders (Documents/AppData), and registered registry keys.
    DeleteEverything,
}

#[derive(Debug, Clone, Default)]
pub struct InstallManifest {
    pub id: String,
    pub display_name: String,
    pub install_root: PathBuf,
    pub game_dirs: Vec<PathBuf>,
    pub extra_files: Vec<PathBuf>,
    pub start_menu_dir: Option<PathBuf>,
    pub shortcuts: Vec<PathBuf>,
    pub profile_dirs: Vec<PathBuf>,
    pub registry_keys: Vec<String>,
    pub uninstall_reg_key: String,
}

pub fn manifests_dir() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let dir = PathBuf::from(local).join("ArcSteam").join("manifests");
        let _ = fs::create_dir_all(&dir);
        return dir;
    }
    let dir = std::env::temp_dir().join("ArcSteamManifests");
    let _ = fs::create_dir_all(&dir);
    dir
}

pub fn sanitize_id(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "arcsteam_game".into()
    } else {
        trimmed
    }
}

pub fn snapshot_top_dirs(root: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(rd) = fs::read_dir(root) {
        for entry in rd.flatten() {
            if entry.path().is_dir() {
                set.insert(entry.file_name().to_string_lossy().to_ascii_lowercase());
            }
        }
    }
    set
}

pub fn diff_new_top_dirs(root: &Path, before: &HashSet<String>, excluded: &[String]) -> Vec<PathBuf> {
    let mut added = Vec::new();
    if let Ok(rd) = fs::read_dir(root) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_dir() {
                continue;
            }
            let name_l = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name_l == "work" {
                continue;
            }
            let is_excl = excluded.iter().any(|e| e.to_ascii_lowercase() == name_l);
            if !is_excl && !before.contains(&name_l) {
                added.push(p);
            }
        }
    }
    added.sort();
    added
}


pub fn snapshot_top_files(root: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    if let Ok(rd) = fs::read_dir(root) {
        for entry in rd.flatten() {
            if entry.path().is_file() {
                set.insert(entry.file_name().to_string_lossy().to_ascii_lowercase());
            }
        }
    }
    set
}

pub fn diff_new_top_files(root: &Path, before: &HashSet<String>) -> Vec<PathBuf> {
    let mut added = Vec::new();
    if let Ok(rd) = fs::read_dir(root) {
        for entry in rd.flatten() {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let name_l = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if !before.contains(&name_l) {
                added.push(p);
            }
        }
    }
    added.sort();
    added
}

/// Checks if a directory path is safe to delete (never a drive root or system/profile root).
fn is_safe_delete_dir(path: &Path) -> bool {
    let s = path.display().to_string();
    let trimmed = s.trim_end_matches('\\').trim_end_matches('/');
    if trimmed.len() <= 3 {
        return false; // e.g. "C:" or "D:\"
    }
    let lower = trimmed.to_ascii_lowercase();
    let forbidden = [
        r"c:\windows",
        r"c:\users",
        r"c:\program files",
        r"c:\program files (x86)",
        r"c:\programdata",
        r"c:\games",
        r"d:\games",
    ];
    if forbidden.contains(&lower.as_str()) {
        return false;
    }
    // Never delete the root of Documents, AppData, or My Games itself
    for env_k in ["USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PUBLIC"] {
        if let Ok(v) = std::env::var(env_k) {
            let vl = v.trim_end_matches('\\').to_ascii_lowercase();
            if lower == vl
                || lower == format!(r"{vl}\documents")
                || lower == format!(r"{vl}\documents\my games")
                || lower == format!(r"{vl}\desktop")
            {
                return false;
            }
        }
    }
    // Require at least 2 path components beyond the drive root
    path.components().count() >= 3
}

/// Discovers any extra save/profile folders created by the game after first launch
/// (e.g., `Documents\My Games\Far Cry 3*` or `%APPDATA%\<Game>`).
pub fn discover_related_profile_dirs(manifest: &InstallManifest) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = manifest
        .profile_dirs
        .iter()
        .filter(|p| is_safe_delete_dir(p))
        .cloned()
        .collect();
    let mut seen: HashSet<String> = dirs
        .iter()
        .map(|p| p.display().to_string().to_ascii_lowercase())
        .collect();

    let mut needles = Vec::new();
    for gd in &manifest.game_dirs {
        if let Some(n) = gd.file_name().and_then(|s| s.to_str()) {
            let norm = normalize_alnum(n);
            if norm.len() >= 4 {
                needles.push(norm);
            }
        }
    }
    let disp_norm = normalize_alnum(&manifest.display_name);
    if disp_norm.len() >= 4 {
        needles.push(disp_norm);
    }

    let mut search_roots = Vec::new();
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        let docs = PathBuf::from(&profile).join("Documents");
        search_roots.push(docs.join("My Games"));
        search_roots.push(docs);
    }
    if let Some(roaming) = std::env::var_os("APPDATA") {
        search_roots.push(PathBuf::from(roaming));
    }
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        search_roots.push(PathBuf::from(local));
    }
    if let Some(public) = std::env::var_os("PUBLIC") {
        search_roots.push(PathBuf::from(public).join("Documents"));
    }

    for root in search_roots {
        if let Ok(rd) = fs::read_dir(&root) {
            for entry in rd.flatten() {
                let p = entry.path();
                if !p.is_dir() || !is_safe_delete_dir(&p) {
                    continue;
                }
                let fname = entry.file_name().to_string_lossy().to_string();
                let fn_norm = normalize_alnum(&fname);
                if fn_norm.len() < 4 || fn_norm == "arcsteam" {
                    continue;
                }
                let matched = needles.iter().any(|n| {
                    fn_norm == *n
                        || (n.len() >= 6 && fn_norm.starts_with(n.as_str()))
                        || (fn_norm.len() >= 6 && n.starts_with(fn_norm.as_str()))
                });
                if matched {
                    let key = p.display().to_string().to_ascii_lowercase();
                    if seen.insert(key) {
                        dirs.push(p);
                    }
                }
            }
        }
    }

    dirs
}

fn normalize_alnum(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

pub fn save_manifest(m: &InstallManifest) -> std::io::Result<PathBuf> {
    let mut out = String::new();
    out.push_str(&format!("id={}\n", m.id));
    out.push_str(&format!("display_name={}\n", m.display_name));
    out.push_str(&format!("install_root={}\n", m.install_root.display()));
    out.push_str(&format!("uninstall_reg_key={}\n", m.uninstall_reg_key));
    if let Some(ref sm) = m.start_menu_dir {
        out.push_str(&format!("start_menu_dir={}\n", sm.display()));
    }
    for d in &m.game_dirs {
        out.push_str(&format!("game_dir={}\n", d.display()));
    }
    for f in &m.extra_files {
        out.push_str(&format!("extra_file={}\n", f.display()));
    }
    for s in &m.shortcuts {
        out.push_str(&format!("shortcut={}\n", s.display()));
    }
    for p in &m.profile_dirs {
        out.push_str(&format!("profile_dir={}\n", p.display()));
    }
    for r in &m.registry_keys {
        out.push_str(&format!("reg_key={r}\n"));
    }

    let path = manifests_dir().join(format!("{}.manifest", m.id));
    fs::write(&path, out)?;
    Ok(path)
}

pub fn load_all_manifests() -> Vec<InstallManifest> {
    let dir = manifests_dir();
    let mut list = Vec::new();
    let Ok(rd) = fs::read_dir(&dir) else {
        return list;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) != Some("manifest") {
            continue;
        }
        let Ok(content) = fs::read_to_string(&p) else {
            continue;
        };
        let mut m = InstallManifest::default();
        for line in content.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let val = v.trim();
            if val.is_empty() {
                continue;
            }
            match k.trim() {
                "id" => m.id = val.to_string(),
                "display_name" => m.display_name = val.to_string(),
                "install_root" => m.install_root = PathBuf::from(val),
                "uninstall_reg_key" => m.uninstall_reg_key = val.to_string(),
                "start_menu_dir" => m.start_menu_dir = Some(PathBuf::from(val)),
                "game_dir" => m.game_dirs.push(PathBuf::from(val)),
                "extra_file" => m.extra_files.push(PathBuf::from(val)),
                "shortcut" => m.shortcuts.push(PathBuf::from(val)),
                "profile_dir" => m.profile_dirs.push(PathBuf::from(val)),
                "reg_key" => m.registry_keys.push(val.to_string()),
                _ => {}
            }
        }
        if !m.id.is_empty() && !m.display_name.is_empty() {
            list.push(m);
        }
    }
    list.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
    list
}

/// Registers the game in Windows Settings -> Apps -> Installed Apps (Control Panel Uninstall).
pub fn register_windows_uninstall_entry(m: &InstallManifest) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let key = &m.uninstall_reg_key;
    if key.is_empty() {
        return;
    }
    let uninstall_cmd = format!("\"{}\" --uninstall {}", exe.display(), m.id);
    let install_loc = m
        .game_dirs
        .first()
        .unwrap_or(&m.install_root)
        .display()
        .to_string();
    let icon_str = exe.display().to_string();

    let entries = [
        ("DisplayName", "REG_SZ", m.display_name.as_str()),
        ("Publisher", "REG_SZ", "ArcSteam"),
        ("InstallLocation", "REG_SZ", install_loc.as_str()),
        ("DisplayIcon", "REG_SZ", icon_str.as_str()),
        ("UninstallString", "REG_SZ", uninstall_cmd.as_str()),
        ("NoModify", "REG_DWORD", "1"),
        ("NoRepair", "REG_DWORD", "1"),
    ];
    for (name, ty, data) in entries {
        let _ = Command::new("reg")
            .args(["add", key, "/v", name, "/t", ty, "/d", data, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }
}

fn is_safe_reg_delete_key(key: &str) -> bool {
    let parts: Vec<&str> = key.split('\\').filter(|s| !s.is_empty()).collect();
    if parts.len() < 4 {
        return false; // Never delete HKLM\SOFTWARE\Publisher root; require HKLM\SOFTWARE\Publisher\Game
    }
    let lower = key.to_ascii_lowercase();
    !lower.starts_with(r"hklm\software\microsoft\windows")
        && !lower.starts_with(r"hkcu\software\microsoft\windows")
}

/// Executes uninstallation in either `KeepProfile` or `DeleteEverything` mode.
/// Returns a summary log vector of all actions performed.

/// Sweeps User + Public Desktop and User + All-Users Start Menu for any `.lnk` shortcut
/// whose TargetPath points inside any of the uninstalled `game_dirs`, removes those `.lnk` files
/// (even if created by an earlier install or outside the manifest), prunes empty Start Menu folders,
/// and notifies Windows Shell to refresh Start Menu & Desktop icons immediately.
fn sweep_shortcuts_targeting_dirs(game_dirs: &[PathBuf]) -> Vec<String> {
    let mut removed = Vec::new();
    let prefixes: Vec<String> = game_dirs
        .iter()
        .filter(|d| is_safe_delete_dir(d))
        .map(|d| {
            let mut s = d.display().to_string().trim_end_matches('\\').to_string();
            s.push('\\');
            s.replace('\'', "''")
        })
        .collect();
    if prefixes.is_empty() {
        return removed;
    }

    let prefixes_ps = prefixes
        .iter()
        .map(|s| format!("'{s}'"))
        .collect::<Vec<_>>()
        .join(",");

    let ps = format!(
        "$ErrorActionPreference = 'SilentlyContinue'; \
         $prefixes = @({prefixes_ps}); \
         $ws = New-Object -ComObject WScript.Shell; \
         $roots = @( \
           [Environment]::GetFolderPath('Desktop'), \
           [Environment]::GetFolderPath('CommonDesktopDirectory'), \
           (Join-Path ([Environment]::GetFolderPath('Programs')) ''), \
           (Join-Path ([Environment]::GetFolderPath('CommonPrograms')) '') \
         ) | Where-Object {{ $_ -and (Test-Path $_) }}; \
         foreach ($r in $roots) {{ \
           Get-ChildItem -Path $r -Filter '*.lnk' -Recurse -File | ForEach-Object {{ \
             $t = $ws.CreateShortcut($_.FullName).TargetPath; \
             if ($t) {{ \
               $tl = $t.ToLowerInvariant(); \
               foreach ($px in $prefixes) {{ \
                 if ($tl.StartsWith($px.ToLowerInvariant())) {{ \
                   Remove-Item -LiteralPath $_.FullName -Force; \
                   Write-Output $_.FullName; \
                   break; \
                 }} \
               }} \
             }} \
           }}; \
         }}; \
         foreach ($sm in @([Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('CommonPrograms'))) {{ \
           if ($sm -and (Test-Path $sm)) {{ \
             Get-ChildItem -Path $sm -Directory | ForEach-Object {{ \
               if ((Get-ChildItem -LiteralPath $_.FullName -Force | Measure-Object).Count -eq 0) {{ \
                 Remove-Item -LiteralPath $_.FullName -Force; \
               }} \
             }}; \
           }} \
         }}"
    );

    if let Ok(out) = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                removed.push(trimmed.to_string());
            }
        }
    }
    removed
}

pub fn execute_uninstall(m: &InstallManifest, mode: UninstallMode) -> Vec<String> {
    let mut logs = Vec::new();
    logs.push(format!(
        "[UNINSTALL] Removing '{}' (mode: {:?})",
        m.display_name, mode
    ));

    // 1. Delete game install directories (strictly safety-checked!)
    for dir in &m.game_dirs {
        if !dir.exists() {
            continue;
        }
        if is_safe_delete_dir(dir) {
            match fs::remove_dir_all(dir) {
                Ok(()) => logs.push(format!("[UNINSTALL] Deleted game folder: {}", dir.display())),
                Err(e) => logs.push(format!(
                    "[WARN] Partial delete on {} ({e}) — close game processes if running.",
                    dir.display()
                )),
            }
        } else {
            logs.push(format!(
                "[WARN] Safety guard protected shared root folder: {} (only game subfolders are deleted).",
                dir.display()
            ));
        }
    }

    // 1b. Delete loose top-level files placed in the install root (e.g. .reg, .bat, .fgpack.x5)
    for f in &m.extra_files {
        if f.is_file() {
            if fs::remove_file(f).is_ok() {
                logs.push(format!("[UNINSTALL] Deleted extra install file: {}", f.display()));
            }
        }
    }

    // 2. Delete Desktop & Start Menu shortcuts
    for sc in &m.shortcuts {
        if sc.exists() {
            if fs::remove_file(sc).is_ok() {
                logs.push(format!("[UNINSTALL] Removed shortcut: {}", sc.display()));
            }
        }
    }
    if let Some(ref sm) = m.start_menu_dir {
        if sm.exists() && is_safe_delete_dir(sm) {
            if fs::remove_dir_all(sm).is_ok() {
                logs.push(format!("[UNINSTALL] Removed Start Menu folder: {}", sm.display()));
            }
        }
    }

    // Sweep Desktop & Start Menu for any additional/stale shortcuts targeting the deleted game folder(s)
    let swept_lnks = sweep_shortcuts_targeting_dirs(&m.game_dirs);
    for lnk in swept_lnks {
        logs.push(format!("[UNINSTALL] Swept shortcut: {lnk}"));
    }
    crate::win_sys::notify_shell_changed();

    // 3. Profile/Saves & Registry cleanup (ONLY in DeleteEverything mode!)
    if mode == UninstallMode::DeleteEverything {
        let profiles = discover_related_profile_dirs(m);
        for pdir in profiles {
            if pdir.exists() && is_safe_delete_dir(&pdir) {
                if fs::remove_dir_all(&pdir).is_ok() {
                    logs.push(format!(
                        "[UNINSTALL] Deleted profile/saves folder: {}",
                        pdir.display()
                    ));
                }
            }
        }

        let mut deleted_regs = 0usize;
        for key in &m.registry_keys {
            if !is_safe_reg_delete_key(key) {
                continue;
            }
            for view in ["/reg:32", "/reg:64"] {
                if Command::new("reg")
                    .args(["delete", key, "/f", view])
                    .creation_flags(CREATE_NO_WINDOW)
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
                {
                    deleted_regs += 1;
                }
            }
        }
        if deleted_regs > 0 {
            logs.push(format!(
                "[UNINSTALL] Removed {deleted_regs} registered game registry key view(s)."
            ));
        }
    } else {
        logs.push("[UNINSTALL] Kept user profile, saves, and settings intact.".into());
    }

    // 4. Remove Windows Settings -> Apps uninstall entry & manifest file
    if !m.uninstall_reg_key.is_empty() {
        let _ = Command::new("reg")
            .args(["delete", &m.uninstall_reg_key, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    }
    let mpath = manifests_dir().join(format!("{}.manifest", m.id));
    let _ = fs::remove_file(mpath);
    logs.push(format!("[DONE] '{}' uninstalled cleanly.", m.display_name));
    logs
}

pub fn quick_dir_size_bytes(dirs: &[PathBuf]) -> u64 {
    let mut total = 0u64;
    for d in dirs {
        if !d.exists() {
            continue;
        }
        for e in WalkDir::new(d).max_depth(4).into_iter().flatten() {
            if e.file_type().is_file() {
                total += e.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }
    total
}
