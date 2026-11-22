use anyhow::{Context, Result};
use librqbit::Api;
use std::collections::HashMap;
use std::io::SeekFrom;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt};
use tokio::runtime::Handle;
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
    WideNameInfo,
};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::{FspError, Result as FspResult, U16CStr};

const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC000_0034u32 as i32;
const STATUS_IO_DEVICE_ERROR: i32 = 0xC000_0185u32 as i32;
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

const LOCAL_CACHE_WINDOW: usize = 4 * 1024 * 1024;
const SWARM_READAHEAD_BYTES: u64 = 32 * 1024 * 1024;
const SWARM_READAHEAD_CHUNK: usize = 1024 * 1024;

pub trait AsyncReadSeek: AsyncRead + AsyncSeek + Send {}
impl<T: AsyncRead + AsyncSeek + Send> AsyncReadSeek for T {}

type BoxedStream = Pin<Box<dyn AsyncReadSeek>>;

#[derive(Clone, Debug)]
pub struct VirtualTorrentFile {
    pub file_id: usize,
    pub virtual_name: String,
    pub size: u64,
}

pub struct TorrentStreamFs {
    pub api: Arc<Api>,
    pub torrent_id: usize,
    pub rt: Handle,
    pub files: Arc<HashMap<String, VirtualTorrentFile>>,
    pub dir_buffer: DirBuffer,
}

pub struct CachedStreamState {
    stream: BoxedStream,
    cache_start: u64,
    cache_buf: Vec<u8>,
}

pub struct OpenVirtualHandle {
    pub file: Option<VirtualTorrentFile>,
    pub state: Option<Mutex<CachedStreamState>>,
    pub frontier: Arc<AtomicU64>,
    pub closed: Arc<AtomicBool>,
}

impl Drop for OpenVirtualHandle {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
    }
}

impl TorrentStreamFs {
    pub fn new(
        api: Arc<Api>,
        torrent_id: usize,
        rt: Handle,
        entries: Vec<VirtualTorrentFile>,
    ) -> Self {
        let mut map = HashMap::new();
        for f in entries {
            let key = f
                .virtual_name
                .replace('/', "\\")
                .trim_start_matches('\\')
                .to_ascii_lowercase();
            map.insert(key, f);
        }

        Self {
            api,
            torrent_id,
            rt,
            files: Arc::new(map),
            dir_buffer: DirBuffer::new(),
        }
    }

    async fn prime_range(&self, file_id: usize, start: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let mut stream = self
            .api
            .api_stream(self.torrent_id.into(), file_id)
            .await
            .with_context(|| format!("Failed to open FileStream for file_id={file_id}"))?;

        stream.seek(SeekFrom::Start(start)).await?;
        let mut scratch = vec![0u8; 256 * 1024];
        let mut remaining = len;
        while remaining > 0 {
            let to_read = (remaining as usize).min(scratch.len());
            let n = stream.read(&mut scratch[..to_read]).await?;
            if n == 0 {
                break;
            }
            remaining -= n as u64;
        }
        Ok(())
    }

    /// Pre-fetches the final 16 MB EOF directory footer AND the opening 8 MB contiguous
    /// header window so FreeArc solid blocks begin decompressing without cold-start stalls.
    pub async fn prime_eof_and_head(&self, file_id: usize, total_size: u64) -> Result<()> {
        if total_size == 0 {
            return Ok(());
        }
        let tail = (16 * 1024 * 1024u64).min(total_size);
        let tail_start = total_size.saturating_sub(tail);
        self.prime_range(file_id, tail_start, total_size - tail_start)
            .await?;

        let head = (8 * 1024 * 1024u64).min(total_size);
        self.prime_range(file_id, 0, head).await?;
        Ok(())
    }

    fn spawn_contiguous_readahead(
        &self,
        file_id: usize,
        total_size: u64,
        frontier: Arc<AtomicU64>,
        closed: Arc<AtomicBool>,
    ) {
        let api = self.api.clone();
        let torrent_id = self.torrent_id;
        self.rt.spawn(async move {
            let Ok(mut pf_stream) = api.api_stream(torrent_id.into(), file_id).await else {
                return;
            };
            let mut prefetch_pos: u64 = 0;
            let mut scratch = vec![0u8; SWARM_READAHEAD_CHUNK];

            while !closed.load(Ordering::Relaxed) {
                let cursor = frontier.load(Ordering::Relaxed);
                let horizon = cursor.saturating_add(SWARM_READAHEAD_BYTES).min(total_size);

                if prefetch_pos < cursor || prefetch_pos > horizon {
                    prefetch_pos = cursor.min(total_size);
                    if pf_stream.seek(SeekFrom::Start(prefetch_pos)).await.is_err() {
                        break;
                    }
                }

                if prefetch_pos < horizon {
                    let want = ((horizon - prefetch_pos) as usize).min(scratch.len());
                    match pf_stream.read(&mut scratch[..want]).await {
                        Ok(0) => {
                            prefetch_pos = total_size;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                        Ok(n) => {
                            prefetch_pos = prefetch_pos.saturating_add(n as u64);
                        }
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(150)).await;
                        }
                    }
                } else {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                }
            }
        });
    }

    fn lookup(&self, file_name: &U16CStr) -> Option<&VirtualTorrentFile> {
        let key = file_name
            .to_string_lossy()
            .trim_start_matches('\\')
            .to_ascii_lowercase();
        self.files.get(&key)
    }
}

impl FileSystemContext for TorrentStreamFs {
    type FileContext = OpenVirtualHandle;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [std::ffi::c_void]>,
        _resolve_reparse_points: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> FspResult<FileSecurity> {
        let path = file_name.to_string_lossy();
        let is_root = path == "\\" || path.is_empty();
        if !is_root && self.lookup(file_name).is_none() {
            return Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND));
        }
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: if is_root {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_READONLY
            },
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> FspResult<Self::FileContext> {
        let path = file_name.to_string_lossy();
        if path == "\\" || path.is_empty() {
            file_info.as_mut().file_attributes = FILE_ATTRIBUTE_DIRECTORY;
            return Ok(OpenVirtualHandle {
                file: None,
                state: None,
                frontier: Arc::new(AtomicU64::new(0)),
                closed: Arc::new(AtomicBool::new(false)),
            });
        }
        if let Some(vf) = self.lookup(file_name) {
            let fi = file_info.as_mut();
            fi.file_attributes = FILE_ATTRIBUTE_READONLY;
            fi.file_size = vf.size;
            fi.allocation_size = (vf.size + 4095) & !4095;

            let raw_stream = self
                .rt
                .block_on(self.api.api_stream(self.torrent_id.into(), vf.file_id))
                .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;

            let frontier = Arc::new(AtomicU64::new(0));
            let closed = Arc::new(AtomicBool::new(false));
            self.spawn_contiguous_readahead(vf.file_id, vf.size, frontier.clone(), closed.clone());

            let cached = CachedStreamState {
                stream: Box::pin(raw_stream),
                cache_start: 0,
                cache_buf: Vec::new(),
            };

            Ok(OpenVirtualHandle {
                file: Some(vf.clone()),
                state: Some(Mutex::new(cached)),
                frontier,
                closed,
            })
        } else {
            Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND))
        }
    }

    fn close(&self, context: Self::FileContext) {
        context.closed.store(true, Ordering::Relaxed);
    }

    fn get_file_info(&self, context: &Self::FileContext, file_info: &mut FileInfo) -> FspResult<()> {
        if let Some(vf) = &context.file {
            file_info.file_attributes = FILE_ATTRIBUTE_READONLY;
            file_info.file_size = vf.size;
            file_info.allocation_size = (vf.size + 4095) & !4095;
        } else {
            file_info.file_attributes = FILE_ATTRIBUTE_DIRECTORY;
        }
        Ok(())
    }

    fn read(&self, context: &Self::FileContext, buffer: &mut [u8], offset: u64) -> FspResult<u32> {
        let (Some(vf), Some(state_mtx)) = (&context.file, &context.state) else {
            return Ok(0);
        };
        if offset >= vf.size || buffer.is_empty() {
            return Ok(0);
        }

        let target_len = ((vf.size - offset) as usize).min(buffer.len());
        context
            .frontier
            .store(offset.saturating_add(target_len as u64), Ordering::Relaxed);

        let mut state_guard = state_mtx
            .lock()
            .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;
        let CachedStreamState {
            stream,
            cache_start,
            cache_buf,
        } = &mut *state_guard;

        let req_end = offset + target_len as u64;
        let cache_end = *cache_start + cache_buf.len() as u64;

        if offset >= *cache_start && req_end <= cache_end {
            let local_start = (offset - *cache_start) as usize;
            buffer[..target_len].copy_from_slice(&cache_buf[local_start..local_start + target_len]);
            return Ok(target_len as u32);
        }

        let fetch_len = target_len
            .max(LOCAL_CACHE_WINDOW)
            .min((vf.size - offset) as usize);
        cache_buf.resize(fetch_len, 0);

        let filled = self
            .rt
            .block_on(async {
                stream.seek(SeekFrom::Start(offset)).await?;
                let mut total = 0usize;
                while total < fetch_len {
                    let n = stream.read(&mut cache_buf[total..fetch_len]).await?;
                    if n == 0 {
                        break;
                    }
                    total += n;
                }
                Ok::<usize, std::io::Error>(total)
            })
            .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;

        cache_buf.truncate(filled);
        *cache_start = offset;

        let to_copy = target_len.min(filled);
        buffer[..to_copy].copy_from_slice(&cache_buf[..to_copy]);
        Ok(to_copy as u32)
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> FspResult<u32> {
        if context.file.is_some() {
            return Ok(0);
        }
        if let Ok(lock) = self.dir_buffer.acquire(marker.is_none(), None) {
            for vf in self.files.values() {
                let mut info = DirInfo::<255>::new();
                if info.set_name(&vf.virtual_name).is_ok() {
                    let fi = info.file_info_mut();
                    fi.file_attributes = FILE_ATTRIBUTE_READONLY;
                    fi.file_size = vf.size;
                    fi.allocation_size = (vf.size + 4095) & !4095;
                    if lock.write(&mut info).is_err() {
                        break;
                    }
                }
            }
        }
        Ok(self.dir_buffer.read(marker, buffer))
    }
}

pub fn mount_virtual_drive(
    drive_letter: &str,
    fs: TorrentStreamFs,
) -> Result<FileSystemHost<TorrentStreamFs>> {
    let mut params = VolumeParams::new();
    params
        .filesystem_name("ArcSteamFS")
        .sector_size(4096)
        .sectors_per_allocation_unit(1)
        .max_component_length(255)
        .irp_timeout(600_000)
        .file_info_timeout(5_000);

    let mut host: FileSystemHost<TorrentStreamFs> =
        FileSystemHost::<TorrentStreamFs>::new(params, fs)
            .map_err(|e| anyhow::anyhow!("WinFsp FileSystemHost::new failed: {e:?}"))?;
    host.mount(drive_letter)
        .map_err(|e| anyhow::anyhow!("WinFsp mount({drive_letter}) failed: {e:?}"))?;
    host.start()
        .map_err(|e| anyhow::anyhow!("WinFsp start() failed: {e:?}"))?;
    Ok(host)
}
