pub mod legacy;
pub mod paths;
pub mod toml;

#[derive(Debug, Clone)]
pub struct Config {
    pub os: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            os: "UNIX".to_string(),
        }
    }
}
