// ====================
// ====================
// インポート部
// ====================
// ====================
use anyhow::Result as R;
use clap::Parser;
use inquire::Select;
use log::*;
use regex::Regex;
use serde::de::Error;
use serde::{Deserialize, Serialize};
use simple_logger::SimpleLogger;
use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows::core::PCWSTR;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::CREATE_NEW_CONSOLE;
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE,
};

// ====================
// ====================
// 構造体定義部
// ====================
// ====================

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long)]
    config_file: PathBuf,
    #[arg(short, long, default_value = "eec", required = false)]
    exec_path: PathBuf,

    #[arg(long, required = false)]
    arg0_program: Option<PathBuf>,
    #[arg(short, long, required = false)]
    arg1_program_args: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TempData {
    parent_pid: u32,
    child_pid: u32,
    config_file: String,
    program: String,
    program_args: Vec<String>,
}

// ====================
// 環境変数用構造体
// ====================
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum EnvVar {
    Single(Vec<String>),
    Multiple(String, Vec<String>),
}

// ====================
// 環境設定用構造体
// ====================
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    paths: Vec<String>,
    envs: Vec<EnvVar>,
}

// ====================
// tomlファイルを開き、Config構造体を返す関数
// ====================
fn read_toml<P>(filename: P) -> Result<Config, toml::de::Error>
where
    P: AsRef<Path>,
{
    let mut file = File::open(filename).map_err(|e| toml::de::Error::custom(e.to_string()))?;
    let mut contents = String::new();
    io::Read::read_to_string(&mut file, &mut contents).unwrap();
    toml::de::from_str(&contents)
}

// ====================
// 指定の文字で一致の一時ファイルをリストで返す関数
// ====================
fn get_temp_lists(s: &str) -> R<Vec<PathBuf>> {
    let temp_dir = env::temp_dir();
    let mut temp_paths = Vec::new();
    let mut found_temp_paths = Vec::new();
    // temp_dir がディレクトリであるか確認
    if temp_dir.is_dir() {
        for entry in fs::read_dir(temp_dir)? {
            let entry = entry?;
            let path = entry.path();

            // ファイルのみを対象
            if path.is_file() {
                temp_paths.push(path);
            }
        }
    } else {
        return Err(anyhow::anyhow!("The specified path is not a directory."));
    }
    debug!("temp_paths: {:?}", temp_paths);
    // 一致確認
    if !temp_paths.is_empty() {
        for path in &temp_paths {
            if let Some(path_str) = path.to_str() {
                if path_str.contains(s) {
                    debug!("Found: {}", path_str);
                    found_temp_paths.push(path.clone());
                } else {
                    debug!("Not found.");
                }
            } else {
                return Err(anyhow::anyhow!("Invalid path: {:?}", path));
            }
        }
    }

    Ok(found_temp_paths)
}
// ====================
// pidが有効なプロセスかどうかboolを返す関数
// ====================
fn process_exists(pid: u32) -> R<bool> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        if !handle.0.is_null() {
            let _ = CloseHandle(handle)?; // ハンドルリーク防止
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ====================
// プロセスをkillさせ,成功の有無をboolで返す関数
// ====================
pub fn kill_process(pid: u32) -> R<bool> {
    unsafe {
        // プロセスを終了させるためのアクセス権で開く
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        if handle != HANDLE(std::ptr::null_mut()) {
            // 終了コード 1 を渡してプロセスを強制終了
            let _ = TerminateProcess(handle, 1)?;
            CloseHandle(handle)?; // ハンドルを忘れず閉じる
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ====================
// pidからプロセス名を取得して R<Option<String>> で返す関数（QueryFullProcessImageNameW 使用）
// ====================
fn get_process_name(pid: u32) -> R<Option<String>> {
    unsafe {
        let process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        if process_handle.0.is_null() {
            return Ok(None);
        }

        let mut buffer = vec![0u16; 1024];
        let mut size = buffer.len() as u32;

        let ok = QueryFullProcessImageNameW(
            process_handle,
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
            PWSTR(buffer.as_mut_ptr()),
            &mut size,
        )?;

        let _ = CloseHandle(process_handle);

        if size == 0 {
            return Ok(None);
        }

        buffer.truncate(size as usize);
        let full_path = OsString::from_wide(&buffer).to_string_lossy().into_owned();

        // ファイル名だけ欲しい場合は以下を追加
        let file_name = std::path::Path::new(&full_path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned());

        Ok(file_name)
    }
}

// ====================
// 入力に含まれる環境変数等、キャプチャーしてStringを返す関数
// ====================
fn expand_env_variables(input: &str) -> String {
    let re = Regex::new(r"\$\(([^)]+)\)").unwrap();
    re.replace_all(input, |caps: &regex::Captures| {
        env::var(&caps[1]).unwrap_or_else(|_| "".to_string())
    })
    .to_string()
}
// ====================
// expand_env_variablesのVec版
// ====================
fn expand_env_variables_vec(inputs: &[String]) -> Vec<String> {
    inputs.iter().map(|s| expand_env_variables(s)).collect()
}

// ====================
// 環境変数を空にする関数（現在のプロセスに直接適用）
// ====================
pub fn apply_env_removal(config: &Config) {
    // PATH環境変数から指定されたパスだけ除外
    if let Ok(current_path) = env::var("PATH") {
        let mut paths: Vec<String> = env::split_paths(&current_path)
            .map(|p| p.to_string_lossy().to_string())
            .collect();
        let expanded_paths = expand_env_variables_vec(&config.paths);

        // プロジェクトルート、target/debug、target/release、target/debug/depsを除外
        const PROJECT_ROOT: &str = env!("PROJECT_ROOT");
        let project_root_path = Path::new(&PROJECT_ROOT);
        debug!("PROJECT_ROOT: {:?}", project_root_path);
        // std::thread::sleep(std::time::Duration::from_millis(10000));

        let target_debug = project_root_path.join("target").join("debug");
        let target_release = project_root_path.join("target").join("release");
        let target_debug_deps = target_debug.join("deps");

        // 除外すべきパスのリストを作成
        let mut exclude_paths = vec![
            target_debug.to_string_lossy().to_string(),
            target_debug_deps.to_string_lossy().to_string(),
        ];
        // rustc --print sysroot で Rust ツールチェインの sysroot パスを取得
        if let Ok(sysroot_output) = std::process::Command::new("rustc")
            .args(&["--print", "sysroot"])
            .output()
        {
            if sysroot_output.status.success() {
                let sysroot = String::from_utf8_lossy(&sysroot_output.stdout)
                    .trim()
                    .to_string();

                // rustc -vV で host ターゲット名を取得
                if let Ok(version_output) =
                    std::process::Command::new("rustc").args(&["-vV"]).output()
                {
                    if version_output.status.success() {
                        let version_info = String::from_utf8_lossy(&version_output.stdout);
                        if let Some(host_line) =
                            version_info.lines().find(|line| line.starts_with("host: "))
                        {
                            let host_target = host_line.trim_start_matches("host: ").trim();

                            // sysroot/lib/rustlib/<host>/lib を除外対象に追加
                            let rustlib_lib = Path::new(&sysroot)
                                .join("lib")
                                .join("rustlib")
                                .join(host_target)
                                .join("lib");
                            exclude_paths.push(rustlib_lib.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }

        // paths から除外する
        paths.retain(|p| {
            !exclude_paths
                .iter()
                .any(|exclude_path| p.contains(exclude_path))
        });
        paths.retain(|p| {
            let expand_paths = &expand_env_variables(p);
            let p_norm = Path::new(expand_paths);
            !expanded_paths
                .iter()
                .any(|remove_path| Path::new(remove_path) == p_norm)
        });

        // 新しい PATH を再構成して設定
        if let Ok(new_path) = env::join_paths(paths.iter()) {
            env::set_var("PATH", new_path);
        } else {
            // join_paths が失敗したら PATH を空にする
            env::set_var("PATH", "");
        }
    }
    // 指定されたキーの環境変数を空文字に設定（削除の代わり）
    for env_var in &config.envs {
        match env_var {
            EnvVar::Single(keys) => {
                for key in keys {
                    env::set_var(key, ""); // 削除ではなく空文字に
                }
            }
            EnvVar::Multiple(key, _values) => {
                env::set_var(key, ""); // 同上
            }
        }
    }
}

// ====================
// eec_<program>_<xxx>.tmp の形式から <program> を抽出する関数
// ====================
fn extract_name_from_filename(file_name: &str) -> Option<&str> {
    let parts: Vec<&str> = file_name.split('_').collect();
    if parts.len() >= 3 && parts[0] == "eec" {
        Some(parts[1])
    } else {
        None
    }
}

// ====================
// 重複している <name> に対応するファイルがあれば選択させて、選ばれたファイルを返す
// ====================
fn select_from_duplicated(paths: &Vec<PathBuf>) -> Option<PathBuf> {
    let mut name_map: HashMap<String, Vec<(PathBuf, TempData)>> = HashMap::new();

    for path in paths {
        let bin = fs::read(path).ok()?;
        let data: TempData = bincode::deserialize(&bin).ok()?; // VecじゃなくTempDataに変更！

        if let Some(file_name) = path.file_name().and_then(|f| f.to_str()) {
            if let Some(name) = extract_name_from_filename(file_name) {
                name_map
                    .entry(name.to_string())
                    .or_default()
                    .push((path.clone(), data));
            }
        }
    }

    let duplicated: Vec<(String, Vec<(PathBuf, TempData)>)> = name_map
        .into_iter()
        .filter(|(_name, entries)| entries.len() > 1)
        .collect();

    if duplicated.is_empty() {
        return None;
    }

    let mut display_map: HashMap<String, PathBuf> = HashMap::new();
    let mut options: Vec<String> = Vec::new();

    for (name, group) in duplicated {
        for (path, data) in group {
            let display = format!("PID: {} | FILE: {}", data.child_pid, path.display());
            display_map.insert(display.clone(), path.clone());
            options.push(display);
        }
    }

    let selected = Select::new(
        "外部プログラムが重複しています。下記から選んでください：",
        options,
    )
    .prompt()
    .ok()?;

    display_map.get(&selected).cloned()
}

// ====================
// メイン関数
// ====================
fn main() -> R<()> {
    #[cfg(debug_assertions)]
    let _ = SimpleLogger::new().init();
    let args = Args::parse();
    /*
    // env-execが作成した一時ファイルリストを取得
    let temp_lists = get_temp_lists("eec_")?;
    select_from_duplicated(&temp_lists);
    */

    let mut temp_lists = get_temp_lists("eec_")?;
    // 重複一時ファイルをユーザーに選択させる
    if let Some(selected) = select_from_duplicated(&temp_lists) {
        // 重複名グループの名前を抽出
        let selected_name = selected
            .file_name()
            .and_then(|f| f.to_str())
            .and_then(|s| extract_name_from_filename(s))
            .map(|s| s.to_string());
        // 選択されたファイル名以外の重複ファイル名を除去
        if let Some(name) = selected_name {
            // 残すべきPathBuf（selected）以外の、同じ<name>のものを削除
            temp_lists.retain(|p| {
                let fname = p.file_name().and_then(|f| f.to_str());
                if let Some(fname) = fname {
                    if let Some(n) = extract_name_from_filename(fname) {
                        // <name>が一致して、選ばれたやつじゃなければ除外
                        return n != name || *p == selected;
                    }
                }
                true
            });

            // selected を追加
            if !temp_lists.contains(&selected) {
                temp_lists.push(selected);
            }
        }
    }

    // 取得した一時ファイルごとに処理
    for (i, temp_file) in temp_lists.iter().enumerate() {
        // 一時ファイル(バイナリファイル)から構造体にマップして取得
        let temp_binary_data: Vec<u8> = fs::read(temp_file)?;
        let temp_data: TempData = bincode::deserialize(&temp_binary_data)?;
        debug!("Read temp_data[{}]: {:?}", i, temp_data);
        // 親プロセスと子プロセスの両方の有効性を返すローカル関数
        let parent_and_child_exists = |pid1: u32, pid2: u32| -> R<(bool, bool)> {
            let mut pid1_is_exist = false;
            let mut pid2_is_exist = false;
            if process_exists(pid1)? {
                pid1_is_exist = true
            }
            if process_exists(pid2)? {
                pid2_is_exist = true
            }
            Ok((pid1_is_exist, pid2_is_exist))
        };
        let (pid1_is_exist, pid2_is_exist) =
            parent_and_child_exists(temp_data.parent_pid, temp_data.child_pid)?;
        // 親プロセスと子プロセス両方が有効の場合のみ処理
        if pid1_is_exist && pid2_is_exist {
            let _parent_process_name = if let Some(name) = get_process_name(temp_data.parent_pid)? {
                name.clone()
            } else {
                String::new()
            };
            let parent_process_name = if let Some((name, _)) = _parent_process_name.rsplit_once('.')
            {
                name.to_string()
            } else {
                String::new()
            };
            let child_process_name = if let Some(name) = get_process_name(temp_data.child_pid)? {
                name.clone()
            } else {
                String::new()
            };
            debug!(
                "Temp data[{}] -> parent process name: {}",
                i, parent_process_name
            );
            debug!(
                "Temp data[{}] -> child process name: {}",
                i, child_process_name
            );

            if parent_process_name == "eec" {
                let env_exec_path = &args.exec_path;

                let is_program_valid = if let Ok(_) = Command::new(env_exec_path).output() {
                    true
                } else {
                    false
                };
                if !is_program_valid {
                    return Err(anyhow::anyhow!(
                        "This program is invalid: {:?}",
                        env_exec_path
                    ));
                }

                // env-exec作成の一時ファイルから環境設定ファイルを取得
                let temp_config_file = match read_toml(&temp_data.config_file) {
                    Ok(c) => c,
                    Err(err) => return Err(anyhow::anyhow!("{}", err)),
                };

                // env-exec-restartのプログラム引数から環境設定ファイルを取得
                let config_path = Path::new(&args.config_file);

                if !config_path.is_file() {
                    return Err(anyhow::anyhow!(
                        "The configuration file was not found or is not a valid file: {}",
                        config_path.display()
                    ));
                }

                let args_config_path = match fs::canonicalize(config_path) {
                    Ok(config) => config,
                    Err(err) => return Err(anyhow::anyhow!("{}", err)),
                };

                // env-execのプロセスを終了
                let _ = kill_process(temp_data.parent_pid)?;

                let program = if args.arg0_program.is_some() {
                    args.arg0_program.clone().unwrap()
                } else {
                    PathBuf::from(temp_data.program)
                };
                let program_args = if args.arg1_program_args.is_some() {
                    args.arg1_program_args.clone().unwrap()
                } else {
                    temp_data.program_args.clone()
                };
                let mut cmd = Command::new(env_exec_path);
                debug!("config: {:?}", temp_config_file);
                apply_env_removal(&temp_config_file);
                cmd.creation_flags(CREATE_NEW_CONSOLE.0)
                    .arg("run")
                    .arg("--config-file")
                    .arg(&args_config_path)
                    .arg("--program")
                    .arg(program)
                    .arg("--")
                    .args(program_args)
                    .spawn()?;
                if let Err(e) = std::fs::remove_file(&temp_file) {
                    return Err(anyhow::anyhow!("Failed to delete temp file: {}", e));
                }
                // env-execが起動した外部プログラムを終了
                let _ = kill_process(temp_data.child_pid)?;
            } else {
            }
        }
    }

    Ok(())
}
