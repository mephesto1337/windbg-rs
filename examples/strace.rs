use clap::{Parser, Subcommand};
use windows::core::Result;

use debugger::{debuggee::LoadDll, debugger::ContinueEvent, Debuggee, Debugger};

#[derive(Debug, Parser)]
pub struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Attach {
        pid: u32,
    },
    Spawn {
        exec: String,
        #[clap(short, long)]
        args: Option<String>,
    },
}

const CREATEFILEW_OFFSET: usize = 0x000250F0;

struct Strace;

impl Debugger for Strace {
    fn on_dll_load(
        &mut self,
        debuggee: &mut Debuggee,
        _pid: u32,
        _tid: u32,
        load: LoadDll,
    ) -> Result<ContinueEvent> {
        let Some(filename) = load.filename.as_ref() else {
            return Ok(ContinueEvent::default());
        };
        if !filename.eq_ignore_ascii_case(r"C:\Windows\System32\KernelBase.dll") {
            return Ok(ContinueEvent::default());
        }

        debuggee.add_breakpoint(load.base_addr + CREATEFILEW_OFFSET)?;

        Ok(ContinueEvent::default())
    }

    fn on_breakpoint(
        &mut self,
        debuggee: &mut Debuggee,
        _pid: u32,
        _tid: u32,
        addr: usize,
    ) -> Result<ContinueEvent> {
        log::info!("Hit BP CreateFileW at {addr:x}");
        let filename_addr = debuggee.get_registers()?.cx;
        if let Ok(filename) = debuggee.read_string(filename_addr, true) {
            log::info!("Opening filename {filename:?}");
        } else {
            log::info!("Opening filename unknown file");
        }
        Ok(ContinueEvent::default())
    }
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();
    let mut debuggee = match args.cmd {
        Command::Attach { pid } => Debuggee::attach_pid(pid)?,
        Command::Spawn { exec, args } => Debuggee::spawn(exec, args.unwrap_or_default())?,
    };
    log::info!("Debuggee = {debuggee:?}");
    let mut debugger = Strace;

    debuggee.run(&mut debugger)?;

    Ok(())
}
