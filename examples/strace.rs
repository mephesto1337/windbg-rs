use core::fmt;

use clap::{Parser, Subcommand};
use windows::core::Result;

use debugger::{
    breakpoint::Breakpoint,
    debuggee::{LoadDll},
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

// const ARGS_COUNT_MAX: usize = 4;

#[derive(Default)]
struct Strace;

impl fmt::Debug for Strace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Strace").finish_non_exhaustive()
    }
}

impl Debugger for Strace {
    fn on_dll_load(&mut self, debuggee: &mut Debuggee, load: LoadDll) -> Result<ContinueEvent> {
        let Some(filename) = load.filename.as_ref() else {
            return Ok(ContinueEvent::default());
        };
        if !filename.eq_ignore_ascii_case(r"C:\Windows\System32\ntdll.dll") {
            return Ok(ContinueEvent::default());
        }

        let Some(ntdll) = debuggee
            .modules()
            .iter()
            .find(|img| img.name().eq_ignore_ascii_case("ntdll.dll"))
        else {
            return Ok(ContinueEvent::default());
        };
        let addrs = ntdll.symbols().filter_map(|(a, n)| n.starts_with("Nt").then_some(a)).collect::<Vec<_>>();

        for addr in addrs {
            debuggee.add_breakpoint(addr)?;
        }

        Ok(ContinueEvent::default())
    }

    fn on_breakpoint(&mut self, debuggee: &mut Debuggee, bp: Breakpoint) -> Result<ContinueEvent> {
        let regs = debuggee.get_registers()?;
        let symbol = debuggee.lookup_addr(bp.addr());
        let (arg0, arg1, arg2, arg3) = (regs.cx, regs.dx, regs.r8, regs.r9);

        println!("{symbol}({arg0:x}, {arg1:x}, {arg2:x}, {arg3:x})");
        Ok(ContinueEvent::default())
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
