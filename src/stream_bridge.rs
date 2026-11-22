use anyhow::{Context, Result};
use reqwest::blocking::Client;
use reqwest::header::RANGE;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
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

#[derive(Clone, Debug)]
pub struct VirtualTorrentFile {
    pub file_id: usize,
    pub virtual_name: String, // Flat or relative path inside Z:\
    pub size: u64,
}

pub struct TorrentStreamFs {
    pub base_stream_url: String, // e.g. "http://127.0.0.1:49210/torrents/0/stream"
    pub client: Client,
    pub files: Arc<HashMap<String, VirtualTorrentFile>>,
    pub dir_buffer: DirBuffer,
}

pub struct OpenVirtualHandle {
    pub file: Option<VirtualTorrentFile>, // None => root directory
}

impl TorrentStreamFs {
    pub fn new(base_stream_url: String, entries: Vec<VirtualTorrentFile>) -> Result<Self> {
        let mut map = HashMap::new();
        for f in entries {
            let key = f
                .virtual_name
                .replace('/', "\\")
                .trim_start_matches('\\')
                .to_ascii_lowercase();
            map.insert(key, f);
        }

        // Long timeout so slow torrent peers never trigger a premature HTTP read error.
        let client = Client::builder()
            .timeout(Duration::from_secs(540))
            .pool_max_idle_per_host(16)
            .build()?;

        Ok(Self {
            base_stream_url,
            client,
            files: Arc::new(map),
            dir_buffer: DirBuffer::new(),
        })
    }

    /// Pre-fetches the final 16 MB of a FreeArc (.bin / .doi) or 7z/ZIP archive
    /// so unarc.exe reads the EOF directory footer instantaneously without stalling.
    pub fn prime_eof_footer(&self, file_id: usize, total_size: u64) -> Result<()> {
        if total_size == 0 {
            return Ok(());
        }
        let tail = 16 * 1024 * 1024u64;
        let start = total_size.saturating_sub(tail);
        let end = total_size.saturating_sub(1);
        let url = format!("{}/{}", self.base_stream_url, file_id);
        let _ = self
            .client
            .get(&url)
            .header(RANGE, format!("bytes={start}-{end}"))
            .send()
            .with_context(|| format!("EOF tail-prime failed for file_id={file_id}"))?;
        Ok(())
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
            return Ok(OpenVirtualHandle { file: None });
        }
        if let Some(vf) = self.lookup(file_name) {
            let fi = file_info.as_mut();
            fi.file_attributes = FILE_ATTRIBUTE_READONLY;
            fi.file_size = vf.size;
            fi.allocation_size = (vf.size + 4095) & !4095;
            Ok(OpenVirtualHandle {
                file: Some(vf.clone()),
            })
        } else {
            Err(FspError::NTSTATUS(STATUS_OBJECT_NAME_NOT_FOUND))
        }
    }

    fn close(&self, _context: Self::FileContext) {}

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

    /// Blocks transparently until librqbit fetches and SHA-1 verifies the requested byte range.
    fn read(&self, context: &Self::FileContext, buffer: &mut [u8], offset: u64) -> FspResult<u32> {
        let Some(vf) = &context.file else {
            return Ok(0);
        };
        if offset >= vf.size || buffer.is_empty() {
            return Ok(0);
        }
        let end = (offset + buffer.len() as u64 - 1).min(vf.size - 1);
        let url = format!("{}/{}", self.base_stream_url, vf.file_id);

        let resp = self
            .client
            .get(&url)
            .header(RANGE, format!("bytes={offset}-{end}"))
            .send()
            .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;

        let bytes = resp
            .bytes()
            .map_err(|_| FspError::NTSTATUS(STATUS_IO_DEVICE_ERROR))?;

        let n = bytes.len().min(buffer.len());
        buffer[..n].copy_from_slice(&bytes[..n]);
        Ok(n as u32)
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
        if let Ok(mut lock) = self.dir_buffer.acquire(marker.is_none(), None) {
            for vf in self.files.values() {
                let mut info = DirInfo::<255>::new();
                if info.set_name(&vf.virtual_name).is_ok() {
                    let fi = info.file_info_mut();
                    fi.file_attributes = FILE_ATTRIBUTE_READONLY;
                    fi.file_size = vf.size;
                    fi.allocation_size = (vf.size + 4095) & !4095;
                    if !lock.write(&mut info) {
                        break;
                    }
                }
            }
        }
        Ok(self.dir_buffer.read(marker, buffer))
    }
}

/// Mounts the demand-paged virtual drive (e.g., "Z:") with a 10-minute IRP timeout
/// so slow swarms never cause Windows I/O timeout errors inside unarc.exe.
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
        .irp_timeout(600_000) // 10 minutes max IRP wait
        .file_info_timeout(5_000);

    let mut host = FileSystemHost::new(params, fs)
        .map_err(|e| anyhow::anyhow!("WinFsp FileSystemHost::new failed: {e:?}"))?;
    host.mount(drive_letter)
        .map_err(|e| anyhow::anyhow!("WinFsp mount({drive_letter}) failed: {e:?}"))?;
    host.start()
        .map_err(|e| anyhow::anyhow!("WinFsp start() failed: {e:?}"))?;
    Ok(host)
}
