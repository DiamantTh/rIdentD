use std::env;

fn main() {
    let config_dir = match env::var("RIDENTD_CONFIG_DIR") {
        Ok(value) => value,
        Err(_) => {
            let prefix = env::var("RIDENTD_PREFIX").unwrap_or_else(|_| "/".to_string());
            let trimmed = prefix.trim_end_matches('/');
            format!("{trimmed}/etc/rIdentD")
        }
    };

    println!("cargo:rustc-env=RIDENTD_CONFIG_DIR={config_dir}");
}
