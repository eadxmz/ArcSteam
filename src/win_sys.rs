use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use sysinfo::System;

const ES_CONTINUOUS: u32 = 0x8000_0000;
const ES_SYSTEM_REQUIRED: u32 = 0x0000_0001;
const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
const SW_SHOWNORMAL: i32 = 1;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetThreadExecutionState(es_flags: u32) -> u32;
    fn GetDiskFreeSpaceExW(
        lp_directory_name: *const u16,
        lp_free_bytes_available_to_caller: *mut u64,
        lp_total_number_of_bytes: *mut u64,
        lp_total_number_of_free_bytes: *mut u64,
    ) -> i32;
    fn CreateJobObjectW(lp_job_attributes: *const c_void, lp_name: *const u16) -> isize;
    fn AssignProcessToJobObject(h_job: isize, h_process: isize) -> i32;
    fn TerminateJobObject(h_job: isize, u_exit_code: u32) -> i32;
    fn OpenProcess(dw_desired_access: u32, b_inherit_handle: i32, dw_process_id: u32) -> isize;
    fn CloseHandle(h_object: isize) -> i32;
    fn GetModuleHandleA(lp_module_name: *const i8) -> isize;
    fn GetProcAddress(h_module: isize, lp_proc_name: *const i8) -> *const c_void;
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn IsUserAnAdmin() -> i32;
    fn ShellExecuteW(
        hwnd: isize,
        lp_operation: *const u16,
        lp_file: *const u16,
        lp_parameters: *const u16,
        lp_directory: *const u16,
        n_show_cmd: i32,
    ) -> isize;
}

type NtProcessFn = unsafe extern "system" fn(isize) -> i32;

fn to_wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Returns true if ArcSteam is running with Administrator privileges.
pub fn is_elevated() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

/// Checks whether WinFsp runtime DLL is installed on the machine.
pub fn is_winfsp_installed() -> bool {
    Path::new(r"C:\Program Files (x86)\WinFsp\bin\winfsp-x64.dll").exists()
        || Path::new(r"C:\Program Files\WinFsp\bin\winfsp-x64.dll").exists()
}


/// Opens a web URL in the user's default browser.
pub fn open_url(url: &str) {
    let verb = to_wide("open");
    let target = to_wide(url);
    unsafe {
        ShellExecuteW(
            0,
            verb.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// Opens a folder or file in Windows Explorer.
pub fn open_in_explorer(path: &Path) {
    let _ = std::fs::create_dir_all(path);
    let verb = to_wide("open");
    let target = to_wide(&path.display().to_string());
    unsafe {
        ShellExecuteW(
            0,
            verb.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// Relaunches the current arcsteam.exe with UAC elevation ("runas").
pub fn relaunch_as_admin() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let verb = to_wide("runas");
    let file = to_wide(&exe.display().to_string());
    let ret = unsafe {
        ShellExecuteW(
            0,
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    ret > 32
}

/// Queries free disk bytes available on the volume hosting `path` (walking up if path doesn't exist yet).
pub fn free_disk_bytes(path: &Path) -> Option<u64> {
    let mut probe = Some(path);
    let existing = loop {
        match probe {
            Some(p) if p.exists() => break p,
            Some(p) => probe = p.parent(),
            None => return None,
        }
    };
    let wide = to_wide(&existing.display().to_string());
    let mut avail: u64 = 0;
    let mut total: u64 = 0;
    let mut free: u64 = 0;
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut avail, &mut total, &mut free) };
    if ok != 0 { Some(avail) } else { None }
}

/// RAII guard that prevents Windows from sleeping during active extraction/streaming.
pub struct KeepAwakeGuard;

impl KeepAwakeGuard {
    pub fn activate() -> Self {
        unsafe {
            SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
        }
        Self
    }
}

impl Drop for KeepAwakeGuard {
    fn drop(&mut self) {
        unsafe {
            SetThreadExecutionState(ES_CONTINUOUS);
        }
    }
}

/// Win32 Job Object handle that groups an unpacker and all its spawned workers
/// (cls-srep, srep64, xtool, lolz) so Cancel kills the entire tree cleanly.
pub struct JobHandle {
    raw: isize,
}

impl JobHandle {
    pub fn new() -> Option<Self> {
        let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if h == 0 { None } else { Some(Self { raw: h }) }
    }

    pub fn assign_child(&self, child: &Child) -> bool {
        let proc_handle = child.as_raw_handle() as isize;
        unsafe { AssignProcessToJobObject(self.raw, proc_handle) != 0 }
    }

    pub fn terminate_all(&self) {
        if self.raw != 0 {
            unsafe {
                TerminateJobObject(self.raw, 1);
            }
        }
    }
}

impl Drop for JobHandle {
    fn drop(&mut self) {
        if self.raw != 0 {
            unsafe {
                CloseHandle(self.raw);
            }
            self.raw = 0;
        }
    }
}

/// Collects `root_pid` and all recursive descendant PIDs using sysinfo.
pub fn collect_process_tree(sys: &System, root_pid: u32) -> Vec<u32> {
    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    for (pid, proc_) in sys.processes() {
        if let Some(parent) = proc_.parent() {
            children_map
                .entry(parent.as_u32())
                .or_default()
                .push(pid.as_u32());
        }
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut result = Vec::new();
    queue.push_back(root_pid);

    while let Some(curr) = queue.pop_front() {
        if visited.insert(curr) {
            result.push(curr);
            if let Some(kids) = children_map.get(&curr) {
                for &k in kids {
                    queue.push_back(k);
                }
            }
        }
    }
    result
}

/// Suspends or resumes an entire unpacker process tree (unarc + srep64 + xtool + lolz)
/// using ntdll's NtSuspendProcess / NtResumeProcess.
pub fn set_process_tree_paused(root_pid: u32, pause: bool) -> usize {
    if root_pid == 0 {
        return 0;
    }
    let fn_name = if pause {
        b"NtSuspendProcess\0".as_ptr() as *const i8
    } else {
        b"NtResumeProcess\0".as_ptr() as *const i8
    };

    let nt_fn: Option<NtProcessFn> = unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll == 0 {
            None
        } else {
            let ptr = GetProcAddress(ntdll, fn_name);
            if ptr.is_null() {
                None
            } else {
                Some(std::mem::transmute::<*const c_void, NtProcessFn>(ptr))
            }
        }
    };

    let Some(func) = nt_fn else {
        return 0;
    };

    let sys = System::new_all();
    let pids = collect_process_tree(&sys, root_pid);
    let mut touched = 0usize;

    for pid in pids {
        unsafe {
            let h = OpenProcess(PROCESS_SUSPEND_RESUME, 0, pid);
            if h != 0 {
                if func(h) == 0 {
                    touched += 1;
                }
                CloseHandle(h);
            }
        }
    }
    touched
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostQueueAction {
    DoNothing,
    SleepPc,
    ShutdownPc,
}

impl PostQueueAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::DoNothing => "Do Nothing",
            Self::SleepPc => "Sleep PC",
            Self::ShutdownPc => "Shutdown PC (30s delay)",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DoNothing => "none",
            Self::SleepPc => "sleep",
            Self::ShutdownPc => "shutdown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "sleep" => Self::SleepPc,
            "shutdown" => Self::ShutdownPc,
            _ => Self::DoNothing,
        }
    }
}

pub fn execute_post_queue_action(action: PostQueueAction) {
    match action {
        PostQueueAction::DoNothing => {}
        PostQueueAction::SleepPc => {
            let _ = Command::new("rundll32.exe")
                .args(["powrprof.dll,SetSuspendState", "0,1,0"])
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();
        }
        PostQueueAction::ShutdownPc => {
            let _ = Command::new("shutdown")
                .args([
                    "/s",
                    "/t",
                    "30",
                    "/c",
                    "ArcSteam queue completed. Shutting down in 30 seconds.",
                ])
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();
        }
    }
}


/// Silently installs the built-in signed WinFsp MSI (prompts UAC once if not elevated; no reboot required).
pub fn install_embedded_winfsp(msi_path: &Path) -> bool {
    if !msi_path.exists() {
        return false;
    }
    let esc = msi_path.display().to_string().replace('\'', "''");
    let ps_cmd = if is_elevated() {
        format!(
            "$p = Start-Process msiexec.exe -Wait -PassThru -ArgumentList '/i','\"{esc}\"','/qn','/norestart'; exit $p.ExitCode"
        )
    } else {
        format!(
            "$p = Start-Process msiexec.exe -Verb RunAs -Wait -PassThru -ArgumentList '/i','\"{esc}\"','/qn','/norestart'; exit $p.ExitCode"
        )
    };
    Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// RAII guard that switches Windows to the High Performance power plan while unpacking
/// to prevent CPU frequency scaling/core parking between compression blocks, then restores
/// the previous scheme cleanly on exit or cancel.
pub struct HighPerformanceGuard {
    prev_guid: Option<String>,
}

impl HighPerformanceGuard {
    pub fn activate() -> Self {
        let prev_guid = Command::new("powercfg")
            .args(["/getactivescheme"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()
            .and_then(|out| {
                let s = String::from_utf8_lossy(&out.stdout);
                let re = regex::Regex::new(
                    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                )
                .ok()?;
                re.find(&s).map(|m| m.as_str().to_string())
            });

        const HIGH_PERF_GUID: &str = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
        let ok = Command::new("powercfg")
            .args(["/setactive", HIGH_PERF_GUID])
            .creation_flags(CREATE_NO_WINDOW)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if ok {
            Self { prev_guid }
        } else {
            Self { prev_guid: None }
        }
    }
}

impl Drop for HighPerformanceGuard {
    fn drop(&mut self) {
        if let Some(ref guid) = self.prev_guid {
            let _ = Command::new("powercfg")
                .args(["/setactive", guid])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
    }
}

/// Checks whether essential 32-bit legacy game runtimes (DirectX June 2010 & VC++ 2010 x86)
/// are present in C:\Windows\SysWOW64. Missing these causes splash-screen hangs (Far Cry 3)
/// or 0xc0000142 startup crashes on modern Windows 10/11 installs.
pub fn check_legacy_game_runtimes() -> Vec<&'static str> {
    let mut missing = Vec::new();
    let wow64 = Path::new(r"C:\Windows\SysWOW64");
    if wow64.is_dir() {
        if !wow64.join("d3dx9_43.dll").exists() || !wow64.join("d3dx11_43.dll").exists() {
            missing.push("DirectX End-User Runtime (June 2010) [d3dx9_43.dll / d3dx11_43.dll]");
        }
        if !wow64.join("msvcr100.dll").exists() {
            missing.push("Visual C++ 2010 x86 Runtime [msvcr100.dll]");
        }
    }
    missing
}

/// Detects whether the drive hosting `path` is an SSD/NVMe (safe for parallel archive reads)
/// vs a spinning HDD / USB external drive (where sequential reading avoids read-head thrashing).
pub fn is_source_ssd(path: &Path) -> bool {
    let s = path.display().to_string();
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[1] != b':' {
        return false;
    }
    let letter = (bytes[0] as char).to_ascii_uppercase();
    let ps = format!(
        "$d = Get-Partition -DriveLetter '{letter}' -ErrorAction SilentlyContinue | Get-Disk -ErrorAction SilentlyContinue; \
         if ($null -eq $d) {{ 'UNKNOWN'; exit }} \
         $pd = Get-PhysicalDisk -ErrorAction SilentlyContinue | Where-Object {{ $_.DeviceId -eq [string]$d.Number }} | Select-Object -First 1; \
         $mt = if ($pd) {{ [string]$pd.MediaType }} else {{ 'Unspecified' }}; \
         $bt = [string]$d.BusType; \
         Write-Output \"$mt|$bt\""
    );
    let Ok(out) = Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    else {
        return false;
    };
    let info = String::from_utf8_lossy(&out.stdout).trim().to_ascii_uppercase();
    if info.starts_with("SSD|") || info.starts_with("SCM|") {
        return true;
    }
    if info.starts_with("HDD|") {
        return false;
    }
    // Unspecified media type: NVMe is always solid-state; USB bridges default to sequential (safe for external HDDs)
    info.contains("|NVME")
}

/// Notifies Windows Explorer & Start Menu that shortcuts/folders changed so stale icons clear immediately.
pub fn notify_shell_changed() {
    let ps = "Add-Type -Namespace Win32 -Name Shell -MemberDefinition \
              '[DllImport(\"shell32.dll\")] public static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);'; \
              [Win32.Shell]::SHChangeNotify(0x08000000, 0x0000, [IntPtr]::Zero, [IntPtr]::Zero)";
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command", ps])
        .creation_flags(CREATE_NO_WINDOW)
        .status();
}
