use anyhow::{Context, Result};
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

#[derive(Debug, Default, Clone)]
pub struct ZstdProgress {
    pub running: bool,
    pub pct: f32,
    pub status: String,
}

struct CountingReader<R> {
    inner: R,
    read_bytes: u64,
    total_bytes: u64,
    progress: Arc<Mutex<ZstdProgress>>,
    cancel: Arc<AtomicBool>,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "Cancelled by user"));
        }
        let n = self.inner.read(buf)?;
        self.read_bytes += n as u64;
        if self.total_bytes > 0 {
            if let Ok(mut p) = self.progress.lock() {
                p.pct = (self.read_bytes as f32 / self.total_bytes as f32).clamp(0.0, 1.0);
            }
        }
        Ok(n)
    }
}

/// Compresses an installed game folder into a single multi-threaded `.tar.zst` Fast-Archive
/// that extracts at 500+ MB/s on SSDs.
pub fn spawn_zstd_pack(
    src_dir: PathBuf,
    dst_archive: PathBuf,
    level: i32,
    progress: Arc<Mutex<ZstdProgress>>,
    cancel: Arc<AtomicBool>,
) {
    cancel.store(false, Ordering::Relaxed);
    std::thread::spawn(move || {
        {
            let mut p = progress.lock().unwrap();
            p.running = true;
            p.pct = 0.0;
            p.status = "Scanning game folder...".into();
        }
        let res = run_pack(&src_dir, &dst_archive, level, &progress, &cancel);
        let mut p = progress.lock().unwrap();
        p.running = false;
        match res {
            Ok(msg) => {
                p.pct = 1.0;
                p.status = msg;
            }
            Err(e) => {
                p.status = format!("Error: {e:#}");
            }
        }
    });
}

fn run_pack(
    src_dir: &PathBuf,
    dst_archive: &PathBuf,
    level: i32,
    progress: &Arc<Mutex<ZstdProgress>>,
    cancel: &Arc<AtomicBool>,
) -> Result<String> {
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    for entry in WalkDir::new(src_dir).into_iter().flatten() {
        if entry.file_type().is_file() {
            let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
            total_bytes += len;
            files.push((entry.into_path(), len));
        }
    }
    if files.is_empty() {
        anyhow::bail!("Source folder has no files to compress");
    }

    let out_file = File::create(dst_archive)
        .with_context(|| format!("Failed to create {}", dst_archive.display()))?;
    let threads = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4);

    let mut encoder = zstd::stream::write::Encoder::new(out_file, level.clamp(1, 15))?;
    let _ = encoder.multithread(threads);
    let mut tar_builder = tar::Builder::new(encoder);

    let mut done_bytes = 0u64;
    for (file_path, len) in files {
        if cancel.load(Ordering::Relaxed) {
            anyhow::bail!("Cancelled by user");
        }
        let rel = file_path.strip_prefix(src_dir).unwrap_or(&file_path);
        {
            let mut p = progress.lock().unwrap();
            p.status = format!("Packing {}", rel.display());
            if total_bytes > 0 {
                p.pct = (done_bytes as f32 / total_bytes as f32).clamp(0.0, 0.99);
            }
        }
        tar_builder.append_path_with_name(&file_path, rel)?;
        done_bytes += len;
    }

    let encoder = tar_builder.into_inner()?;
    encoder.finish()?;
    let final_size = std::fs::metadata(dst_archive).map(|m| m.len()).unwrap_or(0);
    let ratio = if total_bytes > 0 {
        (final_size as f64 / total_bytes as f64) * 100.0
    } else {
        100.0
    };
    Ok(format!(
        "Packed cleanly -> {} ({:.1}% of original size)",
        dst_archive.display(),
        ratio
    ))
}

/// Extracts a `.tar.zst` Fast-Archive at full SSD/CPU speed.
pub fn spawn_zstd_unpack(
    src_archive: PathBuf,
    dst_dir: PathBuf,
    progress: Arc<Mutex<ZstdProgress>>,
    cancel: Arc<AtomicBool>,
) {
    cancel.store(false, Ordering::Relaxed);
    std::thread::spawn(move || {
        {
            let mut p = progress.lock().unwrap();
            p.running = true;
            p.pct = 0.0;
            p.status = format!("Extracting {}...", src_archive.display());
        }
        let res = (|| -> Result<()> {
            std::fs::create_dir_all(&dst_dir)?;
            let total_bytes = std::fs::metadata(&src_archive)?.len();
            let file = File::open(&src_archive)?;
            let counting = CountingReader {
                inner: file,
                read_bytes: 0,
                total_bytes,
                progress: progress.clone(),
                cancel: cancel.clone(),
            };
            let decoder = zstd::stream::read::Decoder::new(counting)?;
            let mut archive = tar::Archive::new(decoder);
            archive.unpack(&dst_dir)?;
            Ok(())
        })();

        let mut p = progress.lock().unwrap();
        p.running = false;
        match res {
            Ok(()) => {
                p.pct = 1.0;
                p.status = format!("Extracted cleanly to {}", dst_dir.display());
            }
            Err(e) => {
                p.status = format!("Error: {e:#}");
            }
        }
    });
}
