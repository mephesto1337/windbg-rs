use clap::{Parser, Subcommand};
use windows::core::Result;

use debugger::{
    debuggee::{Exception, ExceptionCode, ExceptionInfo, LoadDll},
    debugger::ContinueEvent,
    Debuggee, Debugger,
};

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

#[derive(Debug)]
struct Strace;

impl Debugger for Strace {
    fn on_dll_load(&mut self, debuggee: &mut Debuggee, load: LoadDll) -> Result<ContinueEvent> {
        let Some(filename) = load.filename.as_ref() else {
            return Ok(ContinueEvent::default());
        };
        if !filename.eq_ignore_ascii_case(r"C:\Windows\System32\KernelBase.dll") {
            return Ok(ContinueEvent::default());
        }

        debuggee.add_breakpoint(load.base_addr + CREATEFILEW_OFFSET)?;

        Ok(ContinueEvent::default())
    }

    fn on_breakpoint(&mut self, debuggee: &mut Debuggee, addr: usize) -> Result<ContinueEvent> {
        tracing::info!("Hit BP CreateFileW at {addr:x}");
        let filename_addr = debuggee.get_registers()?.cx;
        if let Ok(filename) = debuggee.read_string(filename_addr, true) {
            println!("Opening filename {filename:?}");
        }
        Ok(ContinueEvent::default())
    }

    fn on_exception(&mut self, debuggee: &mut Debuggee, e: ExceptionInfo) -> Result<ContinueEvent> {
        if !e.first_chance {
            return Ok(ContinueEvent::StopDebugging);
        }

        let Some(Exception {
            code: ExceptionCode::AccessViolation,
            address,
            ..
        }) = e.chain.first()
        else {
            return Ok(ContinueEvent::StopDebugging);
        };

        let mut buf = [0u8; 16];
        let n = debuggee.read_memory(*address - 3, &mut buf[..])?;
        tracing::error!("0x{address:x}: {buf:x?}", buf = &buf[..n]);
        Ok(ContinueEvent::Continue)
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let mut debuggee = match args.cmd {
        Command::Attach { pid } => Debuggee::attach_pid(pid)?,
        Command::Spawn { exec, args } => Debuggee::spawn(exec, args.unwrap_or_default())?,
    };
    tracing::info!("Debuggee = {debuggee:?}");
    let mut debugger = Strace;

    debuggee.run(&mut debugger)?;

    Ok(())
}
