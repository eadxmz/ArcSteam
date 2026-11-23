use crate::optimizer;
use crate::win_sys::PostQueueAction;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub local_source: PathBuf,
    pub download_cache_dir: PathBuf,
    pub temp_ssd_dir: PathBuf,
    pub target_game_dir: PathBuf,
    pub virtual_drive: String,
    pub live_install_while_dl: bool,
    pub defender_bypass: bool,
    pub replay_registry: bool,
    pub create_shortcuts: bool,
    pub create_start_menu: bool,
    pub start_menu_folder: String,
    pub auto_clean_temp: bool,
    pub auto_ram: bool,
    pub srep_ram_mb: u64,
    pub post_queue_action: PostQueueAction,
}

fn default_downloads_cache() -> PathBuf {
    if let Some(profile) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(profile).join("Downloads").join("ArcSteam");
    }
    PathBuf::from(r"C:\ArcSteam\Downloads")
}

fn default_temp_dir() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("ArcSteam").join("Temp");
    }
    PathBuf::from(r"C:\ArcSteam\Temp")
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            local_source: PathBuf::new(),
            download_cache_dir: default_downloads_cache(),
            temp_ssd_dir: default_temp_dir(),
            target_game_dir: PathBuf::from(r"C:\Games"),
            virtual_drive: "Z:".into(),
            live_install_while_dl: true,
            defender_bypass: true,
            replay_registry: true,
            create_shortcuts: true,
            create_start_menu: true,
            start_menu_folder: String::new(),
            auto_clean_temp: true,
            auto_ram: true,
            srep_ram_mb: optimizer::optimal_srep_ram_mb(),
            post_queue_action: PostQueueAction::DoNothing,
        }
    }
}

fn config_path() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        let dir = PathBuf::from(local).join("ArcSteam");
        let _ = fs::create_dir_all(&dir);
        return dir.join("config.ini");
    }
    PathBuf::from("arcsteam_config.ini")
}

impl AppConfig {
    pub fn load() -> Self {
        let mut cfg = Self::default();
        let Ok(content) = fs::read_to_string(config_path()) else {
            return cfg;
        };
        let mut migrated = false;
        for line in content.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let val = v.trim();
            match k.trim() {
                "local_source" if !val.is_empty() => {
                    if val.to_ascii_lowercase().contains("after neet") {
                        migrated = true;
                    } else {
                        cfg.local_source = PathBuf::from(val);
                    }
                }
                "download_cache_dir" if !val.is_empty() => {
                    if val.eq_ignore_ascii_case(r"G:\ArcSteamCache") {
                        migrated = true;
                    } else {
                        cfg.download_cache_dir = PathBuf::from(val);
                    }
                }
                "temp_ssd_dir" if !val.is_empty() => cfg.temp_ssd_dir = PathBuf::from(val),
                "target_game_dir" if !val.is_empty() => cfg.target_game_dir = PathBuf::from(val),
                "virtual_drive" if !val.is_empty() => cfg.virtual_drive = val.to_string(),
                "live_install_while_dl" => cfg.live_install_while_dl = val == "true",
                "defender_bypass" => cfg.defender_bypass = val == "true",
                "replay_registry" => cfg.replay_registry = val == "true",
                "create_shortcuts" => cfg.create_shortcuts = val == "true",
                "create_start_menu" => cfg.create_start_menu = val == "true",
                "start_menu_folder" => cfg.start_menu_folder = val.to_string(),
                "auto_clean_temp" => cfg.auto_clean_temp = val == "true",
                "auto_ram" => cfg.auto_ram = val == "true",
                "srep_ram_mb" => {
                    if let Ok(n) = val.parse::<u64>() {
                        cfg.srep_ram_mb = n.clamp(1024, 16384);
                    }
                }
                "post_queue_action" => cfg.post_queue_action = PostQueueAction::parse(val),
                _ => {}
            }
        }
        if migrated {
            cfg.save();
        }
        cfg
    }

    pub fn save(&self) {
        let data = format!(
            "local_source={}\ndownload_cache_dir={}\ntemp_ssd_dir={}\ntarget_game_dir={}\nvirtual_drive={}\nlive_install_while_dl={}\ndefender_bypass={}\nreplay_registry={}\ncreate_shortcuts={}\ncreate_start_menu={}\nstart_menu_folder={}\nauto_clean_temp={}\nauto_ram={}\nsrep_ram_mb={}\npost_queue_action={}\n",
            self.local_source.display(),
            self.download_cache_dir.display(),
            self.temp_ssd_dir.display(),
            self.target_game_dir.display(),
            self.virtual_drive,
            self.live_install_while_dl,
            self.defender_bypass,
            self.replay_registry,
            self.create_shortcuts,
            self.create_start_menu,
            self.start_menu_folder,
            self.auto_clean_temp,
            self.auto_ram,
            self.srep_ram_mb,
            self.post_queue_action.as_str(),
        );
        let _ = fs::write(config_path(), data);
    }
}
