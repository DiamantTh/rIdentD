use std::path::Path;

use super::Config;

#[derive(Debug, Clone, Default)]
pub struct TomlConfig {
    pub config: Config,
}

pub fn load_toml_config(_path: &Path) -> std::io::Result<TomlConfig> {
    Ok(TomlConfig::default())
}
