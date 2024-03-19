use windows::{core::Result, Win32::System::Threading::GetThreadId};

use super::{ContinueEvent, DebugEvent, Debuggee, Debugger};
use crate::utils::OwnedHandle;

// mod breakpoint;
// mod exception;

#[tracing::instrument(skip(debuggee), fields(pid = debuggee.pid()))]
pub(super) fn run<D>(debuggee: &mut Debuggee, debugger: &mut D) -> Result<ContinueEvent>
where
    D: Debugger,
{
    let raw_event = debuggee.wait_for_event(None)?;
    let (pid, tid) = (raw_event.dwProcessId, raw_event.dwThreadId);
    debug_assert!(pid == debuggee.pid());
    debuggee.current_tid = tid;
    let event = DebugEvent::new(debuggee.h_proc.0, raw_event)?;
    let action = match event {
        DebugEvent::Exception(e) => exception::handle(debuggee, debugger, e)?,
        DebugEvent::CreateThread((handle, info)) => {
            let tid = unsafe { GetThreadId(handle) };
            tracing::info!("New thread #{tid:x} with func {:x}", info.start_address);
            debuggee.tids.push((tid, OwnedHandle(handle)));
            debugger.on_thread_create(debuggee, info)?
        }
        DebugEvent::CreateProcess(info) => {
            if let Some(image_name) = info.image_name.as_ref() {
                tracing::info!("New process {image_name}");
            } else {
                tracing::info!("New process with unknown image");
            }
            debugger.on_process_create(debuggee, info)?
        }
        DebugEvent::ExitThread(code) => {
            tracing::info!("Thread exiting with code 0x{code:x}");
            debuggee.check_handles(tid);
            debugger.on_thread_exit(debuggee, code)?
        }
        DebugEvent::ExitProcess(code) => {
            tracing::info!("Process exitting with code 0x{code:x}");
            debugger.on_process_exit(debuggee, code)?;
            ContinueEvent::StopDebugging
        }
        DebugEvent::LoadDll(load_dll) => {
            if let Some(filename) = load_dll.filename.as_ref() {
                tracing::info!("Loading DLL {filename} at 0x{:x}", load_dll.base_addr);
            } else {
                tracing::info!("Loading DLL at 0x{:x}", load_dll.base_addr);
            }
            let _ = debuggee.add_image(load_dll.base_addr)?;
            debugger.on_dll_load(debuggee, load_dll)?
        }
        DebugEvent::UnloadDll(base_addr) => {
            tracing::info!("Unloadind dll at 0x{base_addr:x}");
            debuggee.remove_image(base_addr);
            debugger.on_dll_unload(debuggee, base_addr)?
        }
        DebugEvent::DebugString(s) => {
            if !s.is_empty() {
                tracing::info!("Got string from debuggee: {s:?}");
                debugger.on_debug_string(debuggee, s)?
            } else {
                tracing::trace!("Got empty string from debuggee");
                ContinueEvent::default()
            }
        }
        DebugEvent::Rip(rip) => {
            tracing::info!("Got rip: {rip:?}");
            debugger.on_rip(debuggee, rip)?
        }
    };
    Ok(action)
}
