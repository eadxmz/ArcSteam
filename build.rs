use std::fs;
use std::path::PathBuf;

fn main() {
    winfsp::build::winfsp_link_delayload();

    // 1. Embed Windows .exe icon + requireAdministrator UAC manifest
    //    (required by FitGirl/DODI CLS plugins like cls-magic2l/cls-srep for Global\ shared memory,
    //     plus automatic Defender Boost & WinFsp virtual drive mounting)
    println!("cargo:rerun-if-changed=assets/icon.ico");
    let mut res = winresource::WindowsResource::new();
    if std::path::Path::new("assets/icon.ico").exists() {
        res.set_icon("assets/icon.ico");
    }
    res.set("ProductName", "ArcSteam");
    res.set("FileDescription", "ArcSteam — Live Stream & Turbo Repack Installer");
    res.set_manifest(
        r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>"#,
    );
    if let Err(e) = res.compile() {
        println!("cargo:warning=Failed to compile Windows resource/manifest: {e}");
    }

    // 2. Embed any helper binaries placed in bundled_tools/ directly into arcsteam.exe
    println!("cargo:rerun-if-changed=bundled_tools");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    let gen_path = out_dir.join("embedded_tools_gen.rs");
    let bundled_dir = PathBuf::from("bundled_tools");

    let mut entries = String::new();
    if bundled_dir.is_dir() {
        let mut files: Vec<PathBuf> = fs::read_dir(&bundled_dir)
            .ok()
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect();
        files.sort();

        for path in files {
            if let (Some(fname), Ok(canon)) = (
                path.file_name().and_then(|n| n.to_str()),
                fs::canonicalize(&path),
            ) {
                let clean = canon.display().to_string();
                let clean = clean.strip_prefix(r"\\?\").unwrap_or(&clean);
                entries.push_str(&format!(
                    "    (\"{fname}\", include_bytes!(r#\"{clean}\"#)),\n"
                ));
            }
        }
    }

    let generated = format!(
        "pub const EMBEDDED_TOOLS: &[(&str, &[u8])] = &[\n{entries}];\n"
    );
    fs::write(&gen_path, generated).expect("Failed to write embedded_tools_gen.rs");
}
