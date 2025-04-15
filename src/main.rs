// ====================
// ====================
// インポート部
// ====================
// ====================
use anyhow::Result as R;
use clap::{Parser, Subcommand};
use inquire::Select;
use log::*;
use serde::{Deserialize, Serialize};
use simple_logger::SimpleLogger;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};
use windows::core::PCWSTR;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot;
use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameW};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ,
};
use windows::Win32::System::Threading::{CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_CONSOLE};
// ====================
// ====================
// 構造体定義部
// ====================
// ====================

#[derive(Debug, Parser)]
struct Args {
    #[arg(short, long)]
    config_file: String,
    #[arg(short, long)]
    all: bool,
    #[arg(short, long)]
    list: bool,
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
        eprintln!("The specified path is not a directory.");
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
                eprintln!("Invalid path: {:?}", path);
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
// メイン関数
// ====================
fn main() -> R<()> {
    #[cfg(debug_assertions)]
    let _ = SimpleLogger::new().init();
    let args = Args::parse();
    let temp_lists = get_temp_lists("env-exec_")?;

    for (i, temp_file) in temp_lists.iter().enumerate() {
        let temp_binary_data: Vec<u8> = fs::read(temp_file)?;
        let temp_data: TempData = bincode::deserialize(&temp_binary_data)?;
        debug!("Read temp_data[{}]: {:?}", i, temp_data);
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
        if pid1_is_exist && pid2_is_exist {
            let parent_process_name = if let Some(name) = get_process_name(temp_data.parent_pid)? {
                name.clone()
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
            if parent_process_name == "env-exec.exe" {
                // env-execのプロセスを終了
                let _ = kill_process(temp_data.parent_pid)?;
                let config_file = fs::canonicalize(&args.config_file)?;
                let cmd = Command::new("env-exec")
                    .creation_flags(CREATE_NEW_CONSOLE.0)
                    .arg(&config_file)
                    .arg(temp_data.program)
                    .args(temp_data.program_args)
                    .spawn()?;
                if let Err(e) = std::fs::remove_file(&temp_file) {
                    error!("Failed to delete temp file: {}", e);
                }
                // env-execが起動した外部プログラムを終了
                let _ = kill_process(temp_data.child_pid)?;
            } else {
            }
        }
    }

    /*
        let options = vec![
            "name: C:/Users/osakana/test-config1.toml ppid: 3104230",
            "name: C:/Users/osakana/test-config2.toml ppid: 3204024",
            "name: C:/Users/osakana/test-config3.toml ppid: 3205204",
        ];
        let ans = Select::new("該当プロセスが3個見つかりました。", options).prompt();
    */
    Ok(())
}
