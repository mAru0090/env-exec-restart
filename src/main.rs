use clap::{Parser,Subcommand};
use anyhow::Result as R;

/**
	== usage ==
	env-exec-restart.exe [OPTIONS] --env-file <ENV_FILE>
**/


#[derive(Debug,Parser)]
struct Args {
	#[arg(short,long)]
	env_file:String,
	#[arg(short,long)]
	all:bool,
	#[arg(short,long)]
	list:bool,
}
fn main() -> R<()> {
    Args::parse();
    println!("Hello, world!");
    Ok(())
}
