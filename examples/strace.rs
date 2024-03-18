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
const CREATEFILEA_OFFSET: usize = 0x00024F90;

#[derive(Debug, Default)]
struct Strace {
    createfilea: usize,
    createfilew: usize,
    exception_counter: usize,
}

impl Debugger for Strace {
    fn on_dll_load(&mut self, debuggee: &mut Debuggee, load: LoadDll) -> Result<ContinueEvent> {
        let Some(filename) = load.filename.as_ref() else {
            return Ok(ContinueEvent::default());
        };
        if !filename.eq_ignore_ascii_case(r"C:\Windows\System32\KernelBase.dll") {
            return Ok(ContinueEvent::default());
        }

        self.createfilea = load.base_addr + CREATEFILEA_OFFSET;
        self.createfilew = load.base_addr + CREATEFILEW_OFFSET;

        debuggee.add_breakpoint(self.createfilea)?;
        debuggee.add_breakpoint(self.createfilew)?;

        Ok(ContinueEvent::default())
    }

    fn on_breakpoint(&mut self, debuggee: &mut Debuggee, addr: usize) -> Result<ContinueEvent> {
        let filename_addr = debuggee.get_registers()?.cx;
        let maybe_filename = if addr == self.createfilea {
            debuggee.read_string(filename_addr, false).ok()
        } else if addr == self.createfilew {
            debuggee.read_string(filename_addr, true).ok()
        } else {
            None
        };
        if let Some(filename) = maybe_filename {
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
        self.exception_counter += 1;
        if self.exception_counter > 3 {
            return Ok(ContinueEvent::StopDebugging);
        }

        let mut buf = [0u8; 16];
        debuggee.read_memory(*address - 3, &mut buf[..])?;
        tracing::error!("0x{address:x}: {buf:x?}", buf = &buf[..]);
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
    let mut debugger = Strace::default();

    debuggee.run(&mut debugger)?;

    Ok(())
}
