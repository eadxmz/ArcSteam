use crc32fast::Hasher as CrcHasher;
use md5::{Digest, Md5};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumKind {
    Md5,
    Sfv,
}

#[derive(Debug, Clone)]
pub struct ChecksumTask {
    pub kind: ChecksumKind,
    pub expected_hex: String,
    pub display_name: String,
    pub full_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileVerifyOutcome {
    Ok(String),
    Missing(String),
    Corrupt {
        file: String,
        expected: String,
        actual: String,
    },
}

#[derive(Debug, Default, Clone)]
pub struct VerifyProgress {
    pub running: bool,
    pub total: usize,
    pub completed: usize,
    pub ok_count: usize,
    pub missing_count: usize,
    pub corrupt_count: usize,
    pub manifest_found: String,
    pub results: Vec<FileVerifyOutcome>,
}

/// Discovers `.md5` and `.sfv` manifest files inside a repack or installed game folder
/// (including FitGirl's `MD5/` subfolder) and parses all entries.
pub fn discover_checksum_tasks(root: &Path) -> (Vec<String>, Vec<ChecksumTask>) {
    let mut manifests = Vec::new();
    let mut tasks = Vec::new();

    for entry in WalkDir::new(root).max_depth(3).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();

        if ext != "md5" && ext != "sfv" {
            continue;
        }
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };
        let parent = path.parent().unwrap_or(root);
        manifests.push(
            path.strip_prefix(root)
                .unwrap_or(path)
                .display()
                .to_string(),
        );

        for raw in content.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
                continue;
            }
            if ext == "md5" {
                if line.len() > 33 && line[..32].chars().all(|c| c.is_ascii_hexdigit()) {
                    let expected = line[..32].to_ascii_lowercase();
                    let rel = line[32..].trim().trim_start_matches('*').trim();
                    if !rel.is_empty() {
                        let resolved = resolve_manifest_path(root, parent, rel);
                        tasks.push(ChecksumTask {
                            kind: ChecksumKind::Md5,
                            expected_hex: expected,
                            display_name: rel.to_string(),
                            full_path: resolved,
                        });
                    }
                }
            } else if ext == "sfv" {
                if let Some((rel, crc)) = line.rsplit_once(char::is_whitespace) {
                    let crc = crc.trim();
                    let rel = rel.trim();
                    if crc.len() == 8 && crc.chars().all(|c| c.is_ascii_hexdigit()) && !rel.is_empty() {
                        let resolved = resolve_manifest_path(root, parent, rel);
                        tasks.push(ChecksumTask {
                            kind: ChecksumKind::Sfv,
                            expected_hex: crc.to_ascii_lowercase(),
                            display_name: rel.to_string(),
                            full_path: resolved,
                        });
                    }
                }
            }
        }
    }

    (manifests, tasks)
}

fn resolve_manifest_path(root: &Path, manifest_dir: &Path, rel: &str) -> PathBuf {
    let cleaned = rel.replace('/', "\\");
    let candidate = manifest_dir.join(&cleaned);
    if candidate.exists() {
        return candidate;
    }
    let from_root = root.join(cleaned.trim_start_matches("..\\"));
    if from_root.exists() {
        return from_root;
    }
    candidate
}

fn hash_file(task: &ChecksumTask, cancel: &AtomicBool) -> Option<FileVerifyOutcome> {
    if cancel.load(Ordering::Relaxed) {
        return None;
    }
    if !task.full_path.exists() {
        return Some(FileVerifyOutcome::Missing(task.display_name.clone()));
    }
    let Ok(mut f) = File::open(&task.full_path) else {
        return Some(FileVerifyOutcome::Missing(task.display_name.clone()));
    };
    let mut buf = vec![0u8; 2 * 1024 * 1024];

    let actual = match task.kind {
        ChecksumKind::Md5 => {
            let mut hasher = Md5::new();
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return None;
                }
                let Ok(n) = f.read(&mut buf) else {
                    return Some(FileVerifyOutcome::Corrupt {
                        file: task.display_name.clone(),
                        expected: task.expected_hex.clone(),
                        actual: "READ_ERROR".into(),
                    });
                };
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            let digest = hasher.finalize();
            digest.iter().map(|b| format!("{b:02x}")).collect::<String>()
        }
        ChecksumKind::Sfv => {
            let mut hasher = CrcHasher::new();
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return None;
                }
                let Ok(n) = f.read(&mut buf) else {
                    return Some(FileVerifyOutcome::Corrupt {
                        file: task.display_name.clone(),
                        expected: task.expected_hex.clone(),
                        actual: "READ_ERROR".into(),
                    });
                };
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            format!("{:08x}", hasher.finalize())
        }
    };

    if actual == task.expected_hex {
        Some(FileVerifyOutcome::Ok(task.display_name.clone()))
    } else {
        Some(FileVerifyOutcome::Corrupt {
            file: task.display_name.clone(),
            expected: task.expected_hex.clone(),
            actual,
        })
    }
}

/// Spawns multi-threaded checksum verification across all logical CPU cores.
pub fn spawn_verify_thread(
    root: PathBuf,
    progress: Arc<Mutex<VerifyProgress>>,
    cancel: Arc<AtomicBool>,
) {
    cancel.store(false, Ordering::Relaxed);
    std::thread::spawn(move || {
        let (manifests, tasks) = discover_checksum_tasks(&root);
        let total = tasks.len();
        {
            let mut p = progress.lock().unwrap();
            p.running = true;
            p.total = total;
            p.completed = 0;
            p.ok_count = 0;
            p.missing_count = 0;
            p.corrupt_count = 0;
            p.manifest_found = if manifests.is_empty() {
                "No .md5 or .sfv manifest found in folder".into()
            } else {
                manifests.join(", ")
            };
            p.results.clear();
        }

        if total > 0 {
            let workers = std::thread::available_parallelism()
                .map(|n| n.get().clamp(1, 8))
                .unwrap_or(4);
            let next_idx = AtomicUsize::new(0);

            std::thread::scope(|s| {
                for _ in 0..workers {
                    s.spawn(|| loop {
                        if cancel.load(Ordering::Relaxed) {
                            break;
                        }
                        let i = next_idx.fetch_add(1, Ordering::Relaxed);
                        if i >= total {
                            break;
                        }
                        if let Some(outcome) = hash_file(&tasks[i], &cancel) {
                            let mut p = progress.lock().unwrap();
                            p.completed += 1;
                            match &outcome {
                                FileVerifyOutcome::Ok(_) => p.ok_count += 1,
                                FileVerifyOutcome::Missing(_) => p.missing_count += 1,
                                FileVerifyOutcome::Corrupt { .. } => p.corrupt_count += 1,
                            }
                            p.results.push(outcome);
                        }
                    });
                }
            });
        }

        let mut p = progress.lock().unwrap();
        p.running = false;
    });
}
