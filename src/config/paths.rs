use std::path::PathBuf;

pub const DEFAULT_CONFIG_DIR: &str = env!("RIDENTD_CONFIG_DIR");

pub fn system_config_path() -> PathBuf {
    PathBuf::from(DEFAULT_CONFIG_DIR).join("oidentd.conf")
}

pub fn masquerade_config_path() -> PathBuf {
    PathBuf::from(DEFAULT_CONFIG_DIR).join("oidentd_masq.conf")
}
