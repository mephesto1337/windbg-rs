use core::fmt;

use clap::{Parser, Subcommand};
use windows::core::Result;

use debugger::{
    breakpoint::Breakpoint,
    debuggee::{Exception, ExceptionInfo, LoadDll},
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

#[derive(Default)]
struct CreateFile {
    exception_counter: usize,
    opened_handle: Option<String>,
}

impl fmt::Debug for CreateFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateFile")
            .field("ec", &self.exception_counter)
            .finish_non_exhaustive()
    }
}

impl Debugger for CreateFile {
    fn on_dll_load(&mut self, debuggee: &mut Debuggee, load: LoadDll) -> Result<ContinueEvent> {
        let Some(filename) = load.filename.as_ref() else {
            return Ok(ContinueEvent::default());
        };
        if !filename.eq_ignore_ascii_case(r"C:\Windows\System32\KernelBase.dll") {
            return Ok(ContinueEvent::default());
        }

        let createfilea = debuggee
            .resolv("CreateFileA")
            .expect("CreateFileA should be present in kernelbase");
        let createfilew = debuggee
            .resolv("CreateFileW")
            .expect("CreateFileA should be present in kernelbase");

        debuggee
            .add_breakpoint_by_addr(createfilea)?
            .set_label("createfilea");
        debuggee
            .add_breakpoint_by_addr(createfilew)?
            .set_label("createfilew");

        Ok(ContinueEvent::default())
    }

    fn on_breakpoint(&mut self, debuggee: &mut Debuggee, bp: &Breakpoint) -> Result<ContinueEvent> {
        if let Some(filename) = self.opened_handle.take() {
            let regs = debuggee.get_registers()?;
            let handle = regs.ax;
            println!("Opened {filename:?} with 0x{handle:x}");
            return Ok(ContinueEvent::default());
        }

        let filename_addr = debuggee.get_registers()?.cx;
        let symbol = debuggee.lookup_addr(bp.addr());
        let maybe_filename = if symbol.eq_ignore_ascii_case("createfilea") {
            debuggee.read_string(filename_addr, false).ok()
        } else if symbol.eq_ignore_ascii_case("createfilew") {
            debuggee.read_string(filename_addr, true).ok()
        } else {
            None
        };
        if let Some(filename) = maybe_filename {
            let ra = unsafe { debuggee.get_return_address() }?;
            debuggee.add_breakpoint_by_addr(ra)?.set_one_shot();
            tracing::info!("Added breakpoint on return address of {:?}", bp.label());
            self.opened_handle = Some(filename);
        }
        Ok(ContinueEvent::default())
    }

    fn on_exception(&mut self, debuggee: &mut Debuggee, e: ExceptionInfo) -> Result<ContinueEvent> {
        if !e.first_chance {
            return Ok(ContinueEvent::StopDebugging);
        }

        let Some(Exception { code, address, .. }) = e.chain.first() else {
            unreachable!("Exception chain has at least 1 exception");
        };

        if code.other().is_some() {
            // CLR exceptions
            return Ok(ContinueEvent::ExceptionNotHandled);
        }

        self.exception_counter += 1;
        if self.exception_counter > 3 {
            return Ok(ContinueEvent::StopDebugging);
        }

        let mut buf = [0u8; 16];
        debuggee.read_memory(*address - 3, &mut buf[..])?;
        let symbol = debuggee.lookup_addr(*address);
        tracing::error!("{symbol}: {buf:x?}", buf = &buf[..]);
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
    let mut debugger = CreateFile::default();

    debuggee.run(&mut debugger)?;

    Ok(())
}
