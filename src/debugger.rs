use windows::{
    core::Result,
    Win32::Foundation::{DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, DBG_REPLY_LATER, NTSTATUS},
};

use crate::debuggee::{CreateProcessInfo, CreateThreadInfo, Debuggee, ExceptionInfo, LoadDll, Rip};

#[derive(Debug, PartialEq, Eq, Copy, Clone, Default)]
pub enum ContinueEvent {
    #[default]
    Continue,
    ExceptionNotHandled,
    ReplyLater,
    StopDebugging,
}

impl ContinueEvent {
    pub(crate) fn as_ntstatus(&self) -> NTSTATUS {
        match self {
            Self::Continue => DBG_CONTINUE,
            Self::ExceptionNotHandled => DBG_EXCEPTION_NOT_HANDLED,
            Self::ReplyLater => DBG_REPLY_LATER,
            _ => unreachable!(),
        }
    }
}

pub trait Debugger: std::fmt::Debug {
    fn on_exception(&mut self, debuggee: &mut Debuggee, e: ExceptionInfo) -> Result<ContinueEvent> {
        let _ = (debuggee, e);
        Ok(ContinueEvent::StopDebugging)
    }

    fn on_thread_create(
        &mut self,
        debuggee: &mut Debuggee,
        info: CreateThreadInfo,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, info);
        Ok(ContinueEvent::default())
    }

    fn on_process_create(
        &mut self,
        debuggee: &mut Debuggee,
        info: CreateProcessInfo,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, info);
        Ok(ContinueEvent::default())
    }

    fn on_thread_exit(&mut self, debuggee: &mut Debuggee, code: u32) -> Result<ContinueEvent> {
        let _ = (debuggee, code);
        Ok(ContinueEvent::default())
    }

    fn on_process_exit(&mut self, debuggee: &mut Debuggee, code: u32) -> Result<ContinueEvent> {
        let _ = (debuggee, code);
        Ok(ContinueEvent::default())
    }

    fn on_dll_load(&mut self, debuggee: &mut Debuggee, load: LoadDll) -> Result<ContinueEvent> {
        let _ = (debuggee, load);
        Ok(ContinueEvent::default())
    }

    fn on_dll_unload(
        &mut self,
        debuggee: &mut Debuggee,
        base_addr: usize,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, base_addr);
        Ok(ContinueEvent::default())
    }

    fn on_debug_string(&mut self, debuggee: &mut Debuggee, s: String) -> Result<ContinueEvent> {
        let _ = (debuggee, s);
        Ok(ContinueEvent::default())
    }

    fn on_rip(&mut self, debuggee: &mut Debuggee, rip: Rip) -> Result<ContinueEvent> {
        let _ = (debuggee, rip);
        Ok(ContinueEvent::default())
    }

    fn on_breakpoint(&mut self, debuggee: &mut Debuggee, addr: usize) -> Result<ContinueEvent> {
        let _ = (debuggee, addr);
        Ok(ContinueEvent::default())
    }
}
