extern crate clap;
extern crate dirs;
extern crate flate2;
#[macro_use]
extern crate lazy_static;
extern crate reqwest;
extern crate tar;
extern crate tempdir;

use clap::{App, AppSettings, Arg};
use flate2::Compression;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::io::{Read, copy};
use std::path::Path;
use std::process;
use tempdir::TempDir;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const AUTHOR: &str = env!("CARGO_PKG_AUTHORS");
const VERSION: &str = env!("CARGO_PKG_VERSION");

const RUNNER_MAGIC: &[u8] = b"tVQhhsFFlGGD3oWV4lEPST8I8FEPP54IM0q7daes4E1y3p2U2wlJRYmWmjPYfkhZ0PlT14Ls0j8fdDkoj33f2BlRJavLj3mWGibJsGt5uLAtrCDtvxikZ8UX2mQDCrgE\0";
const HASH_RUNNER_MAGIC: &[u8] = b"A2owjjTtZOpeQ4GdoXtrqzJ7dHGMnR3bbVGWRQqiiYkGI2eSN4PHXFoKbu5mqkNUliudXUOn0cgaN87WAuakXrD9k3yEdpSItXKXO3wdfWqJe4aISzSrOfm7gXCchXI5\0";

const RUNNER_LINUX_X64: &[u8] = include_bytes!("../../target/x86_64-unknown-linux-gnu/release/warp-runner");
// const RUNNER_MACOS_X64: &[u8] = include_bytes!("../../target/x86_64-apple-darwin/release/warp-runner");
const RUNNER_WINDOWS_X64: &[u8] =
    include_bytes!("../../target/x86_64-pc-windows-gnu/release/warp-runner.exe");

lazy_static! {
    static ref RUNNER_BY_ARCH: HashMap<&'static str, &'static [u8]> = {
        let mut m = HashMap::new();
        m.insert("linux-x64", RUNNER_LINUX_X64);
        // m.insert("macos-x64", RUNNER_MACOS_X64);
        m.insert("windows-x64", RUNNER_WINDOWS_X64);
        m
    };
}

/// Print a message to stderr and exit with error code 1
macro_rules! bail {
    () => (process::exit(1));
    ($($arg:tt)*) => ({
        eprint!("{}\n", format_args!($($arg)*));
        process::exit(1);
    })
}

fn replace_magic(buf: &mut Vec<u8>, magic: &[u8], target_value: &str) -> io::Result<Vec<u8>> {
    // 将正确的目标可执行文件名称设置到本地 magic buffer 中
    let magic_len = magic.len();
    let mut new_magic = vec![0; magic_len];
    new_magic[..target_value.len()].clone_from_slice(target_value.as_bytes());

    // 在 runner 可执行文件中找到 magic buffer offset
    let mut offs_opt = None;
    for (i, chunk) in buf.windows(magic_len).enumerate() {
        if chunk == magic {
            offs_opt = Some(i);
            break;
        }
    }

    if offs_opt.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "no magic found inside runner",
        ));
    }

    // 将 magic 替换为指向目标可执行文件的新 magic
    let offs = offs_opt.unwrap();
    buf[offs..offs + magic_len].clone_from_slice(&new_magic);

    Ok(buf.clone())
}

fn patch_runner(arch: &str, exec_name: &str, hash_value: &str) -> io::Result<Vec<u8>> {
    // 读取内存中的运行程序可执行文件
    let runner_contents = RUNNER_BY_ARCH.get(arch).unwrap();
    let mut buf = runner_contents.to_vec();

    buf = replace_magic(&mut buf, RUNNER_MAGIC, exec_name)?;
    buf = replace_magic(&mut buf, HASH_RUNNER_MAGIC, hash_value)?;

    Ok(buf)
}

fn create_tgz(dir: &Path, out: &Path) -> io::Result<()> {
    let f = fs::File::create(out)?;
    let gz = GzEncoder::new(f, Compression::best());
    let mut tar = tar::Builder::new(gz);
    tar.follow_symlinks(false);
    tar.append_dir_all(".", dir)?;
    Ok(())
}

#[cfg(target_family = "unix")]
fn create_app_file(out: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o755)
        .open(out)
}

#[cfg(target_family = "windows")]
fn create_app_file(out: &Path) -> io::Result<File> {
    fs::OpenOptions::new().create(true).write(true).open(out)
}

fn create_app(runner_buf: &Vec<u8>, tgz_path: &Path, out: &Path) -> io::Result<()> {
    let mut outf = create_app_file(out)?;
    let mut tgzf = fs::File::open(tgz_path)?;
    outf.write_all(runner_buf)?;
    copy(&mut tgzf, &mut outf)?;
    Ok(())
}

/// 计算目录的哈希值
fn hash_directory(dir: &Path) -> io::Result<String> {
    let mut hasher = Sha256::new();
    hash_directory_recursive(dir, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

/// 递归地计算目录中所有文件的哈希值
fn hash_directory_recursive(dir: &Path, hasher: &mut Sha256) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            hash_directory_recursive(&path, hasher)?;
        } else {
            let mut file = File::open(&path)?;
            let mut buffer = [0; 1024];
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = App::new(APP_NAME)
        .settings(&[AppSettings::ArgRequiredElseHelp, AppSettings::ColoredHelp])
        .version(VERSION)
        .author(AUTHOR)
        .about("Create self-contained single binary application")
        .arg(
            Arg::with_name("arch")
                .short("a")
                .long("arch")
                .value_name("arch")
                .help(&format!(
                    "Sets the architecture. Supported: {:?}",
                    RUNNER_BY_ARCH.keys()
                ))
                .display_order(1)
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("input_dir")
                .short("i")
                .long("input_dir")
                .value_name("input_dir")
                .help("Sets the input directory containing the application and dependencies")
                .display_order(2)
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("exec")
                .short("e")
                .long("exec")
                .value_name("exec")
                .help("Sets the application executable file name")
                .display_order(3)
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("output")
                .short("o")
                .long("output")
                .value_name("output")
                .help("Sets the resulting self-contained application file name")
                .display_order(4)
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let arch = args.value_of("arch").unwrap();
    if !RUNNER_BY_ARCH.contains_key(&arch) {
        bail!(
            "Unknown architecture specified: {}, supported: {:?}",
            arch,
            RUNNER_BY_ARCH.keys()
        );
    }

    let input_dir = Path::new(args.value_of("input_dir").unwrap());
    if fs::metadata(input_dir).is_err() {
        bail!("Cannot access specified input directory {:?}", input_dir);
    }

    // 计算 input_dir 的哈希值
    let hash = hash_directory(input_dir)?;
    println!("Hash of input directory: {}", hash);

    let exec_name = args.value_of("exec").unwrap();
    if exec_name.len() >= RUNNER_MAGIC.len() {
        bail!("Executable name is too long, please consider using a shorter name");
    }

    let exec_path = Path::new(input_dir).join(exec_name);
    match fs::metadata(&exec_path) {
        Err(_) => {
            bail!("Cannot find file {:?}", exec_path);
        }
        Ok(metadata) => {
            if !metadata.is_file() {
                bail!("{:?} isn't a file", exec_path);
            }
        }
    }

    let runner_buf = patch_runner(&arch, &exec_name, &*hash)?;

    println!("Compressing input directory {:?}...", input_dir);
    let tmp_dir = TempDir::new(APP_NAME)?;
    let tgz_path = tmp_dir.path().join("input.tgz");
    create_tgz(&input_dir, &tgz_path)?;

    let exec_name = Path::new(args.value_of("output").unwrap());
    println!(
        "Creating self-contained application binary {:?}...",
        exec_name
    );
    create_app(&runner_buf, &tgz_path, &exec_name)?;

    println!("All done");
    Ok(())
}
