use core::fmt;

use clap::{Parser, Subcommand};
use windows::core::Result;

use debugger::{
    breakpoint::Breakpoint, debuggee::LoadDll, debugger::ContinueEvent, Debuggee, Debugger,
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
const DLL_NAME: &str = "kernelbase.dll";

fn match_dll_name(filename: &str) -> bool {
    let basename = filename
        .rsplit_once('\\')
        .map(|(_, b)| b)
        .unwrap_or(filename);
    basename.eq_ignore_ascii_case(DLL_NAME)
}

#[derive(Default)]
struct Strace;

impl fmt::Debug for Strace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Strace").finish_non_exhaustive()
    }
}

impl Strace {
    fn trace_dll<F>(debuggee: &mut Debuggee, name: &str, filter: F) -> Result<()>
    where
        F: Fn(&str) -> bool,
    {
        let Some(dll) = debuggee
            .modules()
            .iter()
            .find(|img| img.name().eq_ignore_ascii_case(name))
        else {
            return Ok(());
        };
        let addrs = dll
            .symbols()
            .filter_map(|(a, n)| filter(n).then_some(a))
            .collect::<Vec<_>>();

        tracing::debug!("BP: {addrs:x?}");
        debuggee.add_breakpoints(addrs.into_iter())?;

        Ok(())
    }
}

impl Debugger for Strace {
    fn on_dll_load(&mut self, debuggee: &mut Debuggee, load: LoadDll) -> Result<ContinueEvent> {
        let Some(filename) = load.filename.as_deref() else {
            return Ok(ContinueEvent::Continue);
        };
        if !match_dll_name(filename) {
            return Ok(ContinueEvent::Continue);
        }
        Self::trace_dll(debuggee, DLL_NAME, |n: &str| n.contains("File"))?;
        Ok(ContinueEvent::Continue)
    }

    fn on_breakpoint(&mut self, debuggee: &mut Debuggee, bp: &Breakpoint) -> Result<ContinueEvent> {
        let regs = debuggee.get_registers()?;
        let symbol = debuggee.lookup_addr(bp.addr());
        let mut stack = regs.open_stack(debuggee)?;
        let (arg0, arg1, arg2, arg3) = (
            regs.get_arg(&mut stack, 0)?,
            regs.get_arg(&mut stack, 1)?,
            regs.get_arg(&mut stack, 2)?,
            regs.get_arg(&mut stack, 3)?,
        );

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
