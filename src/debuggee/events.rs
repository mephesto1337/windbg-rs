use crate::utils::{read_string_utf16, read_string_utf8};
use windows::{
    core::{Error, Result},
    Win32::{
        Foundation::{ERROR_INVALID_DATA, HANDLE},
        System::Diagnostics::Debug::{
            CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, DEBUG_EVENT_CODE,
            EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
            LOAD_DLL_DEBUG_EVENT, OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT, UNLOAD_DLL_DEBUG_EVENT,
        },
    },
};

mod exception;
pub use exception::{Exception, ExceptionCode, ExceptionInfo};

mod create_thread;
pub use create_thread::CreateThreadInfo;

mod create_process;
pub use create_process::CreateProcessInfo;

mod load_dll;
pub use load_dll::LoadDll;

mod rip;
pub use rip::Rip;

#[derive(Debug, PartialEq, Eq)]
pub enum DebugEvent {
    Exception(ExceptionInfo),
    CreateThread((HANDLE, CreateThreadInfo)),
    CreateProcess(CreateProcessInfo),
    ExitThread(u32),
    ExitProcess(u32),
    LoadDll(LoadDll),
    UnloadDll(usize),
    DebugString(String),
    Rip(Rip),
}

impl DebugEvent {
    pub(super) fn new(handle: HANDLE, value: DEBUG_EVENT) -> Result<Self> {
        let ret = match value.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => {
                let except = unsafe { value.u.Exception };
                Self::Exception(except.into())
            }
            CREATE_THREAD_DEBUG_EVENT => {
                let thread_info = unsafe { value.u.CreateThread };
                Self::CreateThread((thread_info.hThread, thread_info.into()))
            }
            CREATE_PROCESS_DEBUG_EVENT => {
                let process_info = unsafe { value.u.CreateProcessInfo };
                Self::CreateProcess(process_info.into())
            }
            EXIT_THREAD_DEBUG_EVENT => {
                let code = unsafe { value.u.ExitThread }.dwExitCode;
                Self::ExitThread(code)
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                let code = unsafe { value.u.ExitProcess }.dwExitCode;
                Self::ExitProcess(code)
            }
            LOAD_DLL_DEBUG_EVENT => {
                let load_dll = unsafe { value.u.LoadDll };
                Self::LoadDll(load_dll.into())
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                let unload_dll = unsafe { value.u.UnloadDll };
                Self::UnloadDll(unload_dll.lpBaseOfDll as usize)
            }
            OUTPUT_DEBUG_STRING_EVENT => {
                let output_debug_string = unsafe { value.u.DebugString };
                let maybe_str = if output_debug_string.fUnicode != 0 {
                    read_string_utf16(handle, output_debug_string.lpDebugStringData.0 as usize)
                } else {
                    read_string_utf8(handle, output_debug_string.lpDebugStringData.0 as usize)
                };
                Self::DebugString(maybe_str.unwrap_or_default())
            }
            RIP_EVENT => {
                let rip = unsafe { value.u.RipInfo };
                Self::Rip(rip.into())
            }
            DEBUG_EVENT_CODE(c) => {
                return Err(Error::new(
                    ERROR_INVALID_DATA.into(),
                    format!("Invalid debug error code: 0x{c:x}"),
                ));
            }
        };
        Ok(ret)
    }
}
