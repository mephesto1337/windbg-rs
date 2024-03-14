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

pub trait Debugger {
    fn on_exception(
        &mut self,
        debuggee: &mut Debuggee,
        pid: u32,
        tid: u32,
        e: ExceptionInfo,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, pid, tid, e);
        Ok(ContinueEvent::default())
    }

    fn on_thread_create(
        &mut self,
        debuggee: &mut Debuggee,
        pid: u32,
        tid: u32,
        info: CreateThreadInfo,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, pid, tid, info);
        Ok(ContinueEvent::default())
    }

    fn on_process_create(
        &mut self,
        debuggee: &mut Debuggee,
        pid: u32,
        tid: u32,
        info: CreateProcessInfo,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, pid, tid, info);
        Ok(ContinueEvent::default())
    }

    fn on_thread_exit(
        &mut self,
        debuggee: &mut Debuggee,
        pid: u32,
        tid: u32,
        code: u32,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, pid, tid, code);
        Ok(ContinueEvent::default())
    }

    fn on_process_exit(
        &mut self,
        debuggee: &mut Debuggee,
        pid: u32,
        tid: u32,
        code: u32,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, pid, tid, code);
        Ok(ContinueEvent::default())
    }

    fn on_dll_load(
        &mut self,
        debuggee: &mut Debuggee,
        pid: u32,
        tid: u32,
        load: LoadDll,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, pid, tid, load);
        Ok(ContinueEvent::default())
    }

    fn on_dll_unload(
        &mut self,
        debuggee: &mut Debuggee,
        pid: u32,
        tid: u32,
        base_addr: usize,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, pid, tid, base_addr);
        Ok(ContinueEvent::default())
    }

    fn on_debug_string(
        &mut self,
        debuggee: &mut Debuggee,
        pid: u32,
        tid: u32,
        s: String,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, pid, tid, s);
        Ok(ContinueEvent::default())
    }

    fn on_rip(
        &mut self,
        debuggee: &mut Debuggee,
        pid: u32,
        tid: u32,
        rip: Rip,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, pid, tid, rip);
        Ok(ContinueEvent::default())
    }

    fn on_breakpoint(
        &mut self,
        debuggee: &mut Debuggee,
        pid: u32,
        tid: u32,
        addr: usize,
    ) -> Result<ContinueEvent> {
        let _ = (debuggee, pid, tid, addr);
        Ok(ContinueEvent::default())
    }
}
