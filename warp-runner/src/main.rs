extern crate dirs;
#[macro_use]
extern crate log;
extern crate simple_logger;

use log::Level;
use std::env;
use std::error::Error;
use std::ffi::*;
use std::fs;
use std::io;
use std::path::*;
use std::process;

mod executor;
mod extractor;

static TARGET_FILE_NAME_BUF: &'static [u8] = b"tVQhhsFFlGGD3oWV4lEPST8I8FEPP54IM0q7daes4E1y3p2U2wlJRYmWmjPYfkhZ0PlT14Ls0j8fdDkoj33f2BlRJavLj3mWGibJsGt5uLAtrCDtvxikZ8UX2mQDCrgE\0";
static TARGET_HASH_VALUE_BUF: &'static [u8] = b"A2owjjTtZOpeQ4GdoXtrqzJ7dHGMnR3bbVGWRQqiiYkGI2eSN4PHXFoKbu5mqkNUliudXUOn0cgaN87WAuakXrD9k3yEdpSItXKXO3wdfWqJe4aISzSrOfm7gXCchXI5\0";

fn target_file_name() -> &'static str {
    let nul_pos = TARGET_FILE_NAME_BUF
        .iter()
        .position(|elem| *elem == b'\0')
        .expect("TARGET_FILE_NAME_BUF has no NUL terminator");

    let slice = &TARGET_FILE_NAME_BUF[..(nul_pos + 1)];
    CStr::from_bytes_with_nul(slice)
        .expect("Can't convert TARGET_FILE_NAME_BUF slice to CStr")
        .to_str()
        .expect("Can't convert TARGET_FILE_NAME_BUF CStr to str")
}

fn target_hash_value() -> &'static str {
    let nul_pos = TARGET_HASH_VALUE_BUF
        .iter()
        .position(|elem| *elem == b'\0')
        .expect("TARGET_HASH_VALUE_BUF has no NUL terminator");

    let slice = &TARGET_HASH_VALUE_BUF[..(nul_pos + 1)];
    CStr::from_bytes_with_nul(slice)
        .expect("Can't convert TARGET_HASH_VALUE_BUF slice to CStr")
        .to_str()
        .expect("Can't convert TARGET_HASH_VALUE_BUF CStr to str")
}

fn cache_path(target: &str) -> PathBuf {
    dirs::data_local_dir()
        .expect("No data local dir found")
        .join("warp")
        .join("packages")
        .join(target)
}

// 在 extract 函数中保存哈希值
fn extract(exe_path: &Path, cache_path: &Path, hash_path: &Path) -> io::Result<()> {
    fs::remove_dir_all(cache_path).ok();
    extractor::extract_to(exe_path, cache_path)?;

    let hash = target_hash_value();
    fs::write(hash_path, hash)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    if env::var("WARP_TRACE").is_ok() {
        simple_logger::init_with_level(Level::Trace)?;
    }

    let self_path = env::current_exe()?;
    let self_file_name = self_path.file_name().unwrap();
    let cache_dir = cache_path(&self_file_name.to_string_lossy());
    let hash_path = cache_path(&format!("{}.hash", self_file_name.to_string_lossy()));

    trace!("self_path={:?}", self_path);
    trace!("self_file_name={:?}", self_file_name);
    trace!("cache_dir={:?}", cache_dir);
    trace!("hash_path={:?}", hash_path);

    let target_file_name = target_file_name();
    let target_path = cache_dir.join(target_file_name);

    trace!("target_exec={:?}", target_file_name);
    trace!("target_path={:?}", target_path);

    // 在检查缓存时比较哈希值
    match fs::metadata(&cache_dir) {
        Ok(_) => {
            let current_hash = target_hash_value();
            if let Ok(saved_hash) = fs::read_to_string(&hash_path) {
                if saved_hash == current_hash && target_path.exists() {
                    trace!("cache is up-to-date");
                } else {
                    trace!("cache is outdated or target missing");
                    extract(&self_path, &cache_dir, &hash_path)?;
                }
            } else {
                trace!("hash file missing, re-extracting");
                extract(&self_path, &cache_dir, &hash_path)?;
            }
        }
        Err(_) => {
            trace!("cache not found");
            extract(&self_path, &cache_dir, &hash_path)?;
        }
    }

    let exit_code = executor::execute(&target_path)?;
    process::exit(exit_code);
}
