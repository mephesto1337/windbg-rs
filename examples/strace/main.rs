use std::{
    collections::HashMap,
    fmt::{self, Write},
};

use clap::{Parser, Subcommand};
use windows::core::Result;

use debugger::{
    breakpoint::Breakpoint, debuggee::LoadDll, debugger::ContinueEvent, Debuggee, Debugger,
};

mod handlers;

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

const ARGS_COUNT_MAX: usize = 4;
const DLL_NAME: &str = "kernelbase.dll";

fn match_dll_name(filename: &str) -> bool {
    let basename = filename
        .rsplit_once('\\')
        .map(|(_, b)| b)
        .unwrap_or(filename);
    basename.eq_ignore_ascii_case(DLL_NAME)
}

#[derive(Default)]
struct Strace {
    args: HashMap<(String, u32), [usize; ARGS_COUNT_MAX]>,
    args_handler: HashMap<&'static str, Box<dyn Fn(&mut Debuggee, &[usize], usize) -> Result<()>>>,
}

impl fmt::Debug for Strace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Strace").finish_non_exhaustive()
    }
}

impl Strace {
    fn trace_dll<F>(&mut self, debuggee: &mut Debuggee, name: &str, filter: F) -> Result<()>
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
        let symbols = dll
            .symbols()
            .filter_map(|(a, n)| filter(n).then_some((a, n.to_owned())))
            .collect::<Vec<_>>();

        self.args.reserve(symbols.len());
        for (addr, sym) in symbols {
            debuggee.add_breakpoint(addr)?.set_label(sym);
        }

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
        self.trace_dll(debuggee, DLL_NAME, |n: &str| n.contains("File"))?;
        Ok(ContinueEvent::Continue)
    }

    fn on_breakpoint(&mut self, debuggee: &mut Debuggee, bp: &Breakpoint) -> Result<ContinueEvent> {
        let regs = debuggee.get_registers()?;
        let Some(label) = bp.label() else {
            tracing::warn!("No label for bp {bp:?}");
            return Ok(ContinueEvent::Continue);
        };
        let key = (label.into(), debuggee.tid());

        if bp.is_one_shot() {
            let Some(args) = self.args.remove(&key) else {
                tracing::warn!("No args for call to {label}");
                return Ok(ContinueEvent::Continue);
            };
            let ret = regs.ax;
            if let Some(cb) = self.args_handler.get(label) {
                cb(debuggee, &args[..], ret)?;
            } else {
                let mut args_str = String::new();
                let mut first = "";
                for a in args {
                    write!(&mut args_str, "{first}{a:x}").unwrap();
                    first = ", ";
                }
                println!("{label}({args_str}) = {ret:x}");
            }
        } else {
            let mut stack = regs.open_stack(debuggee)?;
            let mut args = [0; ARGS_COUNT_MAX];
            for (idx, arg) in args.iter_mut().enumerate() {
                *arg = regs.get_arg(&mut stack, idx)?;
            }
            self.args.insert(key, args);

            let ra = unsafe { debuggee.get_return_address() }?;
            tracing::debug!("Setting breakpoint on return of {label}: 0x{ra:x}");
            debuggee
                .add_breakpoint(&ra)?
                .set_one_shot()
                .set_label(label.to_owned());
        }

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

    debugger
        .args_handler
        .insert("CreateFileW", Box::new(handlers::createfilew));
    debugger
        .args_handler
        .insert("FindFirstFileW", Box::new(handlers::findfirstfilew));
    debugger
        .args_handler
        .insert("GetModuleFileNameW", Box::new(handlers::getmodulefilenamew));

    debuggee.run(&mut debugger)?;

    Ok(())
}
