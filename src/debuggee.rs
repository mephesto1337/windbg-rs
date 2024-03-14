use std::{
    ffi::{c_void, CString},
    fmt,
    marker::PhantomData,
    mem::{size_of, MaybeUninit},
    ptr::{addr_of, addr_of_mut},
    time::Duration,
};

use windows::{
    core::{Error, Result, PCSTR, PSTR},
    Win32::{
        Foundation::{GetHandleInformation, BOOL, ERROR_INVALID_DATA, ERROR_NOT_FOUND, HANDLE},
        System::{
            Diagnostics::{
                Debug::{
                    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop,
                    DebugBreakProcess, GetThreadContext, WaitForDebugEvent, WriteProcessMemory,
                    DEBUG_EVENT,
                },
                ToolHelp::{
                    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
                },
            },
            Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_READWRITE},
            Threading::{
                CreateProcessA, GetThreadId, OpenProcess, OpenThread, CREATE_NEW_CONSOLE,
                CREATE_NEW_PROCESS_GROUP, DEBUG_ONLY_THIS_PROCESS, INFINITE, PROCESS_ALL_ACCESS,
                PROCESS_INFORMATION, STARTUPINFOA, THREAD_ALL_ACCESS,
            },
        },
    },
};

use crate::{
    debugger::{ContinueEvent, Debugger},
    process::Process,
    utils::{read_memory, read_string_utf16, read_string_utf8, OwnedHandle},
    Registers,
};

pub struct Debuggee {
    proc: Process,
    h_proc: OwnedHandle,
    tids: Vec<(u32, OwnedHandle)>,
    current_tid: u32,
    breakpoints: Vec<(usize, [u8; 4])>,
    _not_send: PhantomData<*mut ()>,
}

mod events;
pub use events::{CreateProcessInfo, CreateThreadInfo, DebugEvent, ExceptionInfo, LoadDll, Rip};
use events::{Exception, ExceptionCode};

impl fmt::Debug for Debuggee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Debuggee")
            .field("proc", &self.proc)
            .finish_non_exhaustive()
    }
}

impl Drop for Debuggee {
    fn drop(&mut self) {
        let _ = unsafe { DebugActiveProcessStop(self.proc.pid()) };
    }
}

impl Debuggee {
    fn open_threads(pid: u32) -> Result<Vec<(u32, OwnedHandle)>> {
        let h_snap = OwnedHandle(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid) }?);
        let mut te = unsafe {
            let mut buf = MaybeUninit::uninit();
            Thread32First(h_snap.0, buf.as_mut_ptr())?;
            buf.assume_init()
        };

        let mut tids = Vec::new();
        loop {
            if te.th32OwnerProcessID == pid {
                if let Ok(h_thread) =
                    unsafe { OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID) }
                {
                    tids.push((te.th32ThreadID, OwnedHandle(h_thread)));
                };
            }

            if unsafe { Thread32Next(h_snap.0, addr_of_mut!(te)) }.is_err() {
                break;
            }
        }

        Ok(tids)
    }

    fn from_proc(proc: Process, handle: Option<HANDLE>) -> Result<Self> {
        let h_proc = match handle {
            Some(h) => h,
            None => unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, proc.pid()) }?,
        };
        unsafe { DebugActiveProcess(proc.pid()) }?;
        unsafe { DebugBreakProcess(h_proc) }?;
        let tids = Self::open_threads(proc.pid())?;

        Ok(Self {
            proc,
            h_proc: OwnedHandle(h_proc),
            tids,
            current_tid: 0,
            breakpoints: Default::default(),
            _not_send: PhantomData,
        })
    }

    pub fn attach_pid(pid: u32) -> Result<Self> {
        let proc = Process::new(pid)?;
        Self::from_proc(proc, None)
    }

    pub fn attach_image(name: impl AsRef<str>) -> Result<Self> {
        let name = name.as_ref();
        let procs = Process::all()?;
        for proc in procs {
            if proc.image() == name {
                return Self::from_proc(proc, None);
            }
        }
        Err(Error::new(
            ERROR_NOT_FOUND.into(),
            format!("Could not find process with specified image: {name:?}"),
        ))
    }

    pub fn spawn(filename: impl Into<Vec<u8>>, args: impl Into<Vec<u8>>) -> Result<Self> {
        let application_name = CString::new(filename).map_err(|_| {
            Error::new(
                ERROR_INVALID_DATA.into(),
                "Cannot construct filename from buffer",
            )
        })?;
        let args = CString::new(args).map_err(|_| {
            Error::new(
                ERROR_INVALID_DATA.into(),
                "Cannot construct args from buffer",
            )
        })?;
        let startup_info = STARTUPINFOA {
            cb: size_of::<STARTUPINFOA>() as u32,
            ..Default::default()
        };
        let PROCESS_INFORMATION {
            hProcess,
            hThread,
            dwProcessId,
            dwThreadId,
        } = unsafe {
            let mut process_infomation_buf = MaybeUninit::uninit();
            let args_ptr = args.into_raw();
            let ret = CreateProcessA(
                PCSTR(application_name.as_ptr().cast()),
                PSTR(args_ptr.cast()),
                None,
                None,
                BOOL(0),
                CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP | DEBUG_ONLY_THIS_PROCESS,
                None,
                PCSTR::from_raw("C:\\Windows\\System32\0".as_ptr()),
                addr_of!(startup_info),
                process_infomation_buf.as_mut_ptr(),
            );
            let _ = CString::from_raw(args_ptr);
            log::debug!("CreateProcess: {ret:?}");
            ret?;
            process_infomation_buf.assume_init()
        };

        Ok(Self {
            proc: Process {
                id: dwProcessId,
                image: application_name.into_string().unwrap(),
            },
            h_proc: OwnedHandle(hProcess),
            tids: vec![(dwThreadId, OwnedHandle(hThread))],
            current_tid: dwThreadId,
            breakpoints: Vec::new(),
            _not_send: PhantomData,
        })
    }

    fn wait_for_event(&mut self, timeout: Option<Duration>) -> Result<DEBUG_EVENT> {
        let mut debug_event = MaybeUninit::uninit();
        let timeout = timeout
            .and_then(|d| d.as_millis().try_into().ok())
            .unwrap_or(INFINITE);
        unsafe { WaitForDebugEvent(debug_event.as_mut_ptr(), timeout) }?;
        Ok(unsafe { debug_event.assume_init() })
    }

    fn continue_debug_event(&mut self, pid: u32, tid: u32, action: ContinueEvent) -> Result<()> {
        unsafe { ContinueDebugEvent(pid, tid, action.as_ntstatus()) }?;
        Ok(())
    }

    pub fn read_memory(&mut self, addr: usize, buf: &mut [u8]) -> Result<usize> {
        read_memory(self.h_proc.0, addr, buf)
    }

    pub fn write_memory(&mut self, addr: usize, buf: &[u8]) -> Result<usize> {
        let mut bytes_written = 0;
        log::trace!("Try to write {n} bytes at {addr:x}", n = buf.len());
        unsafe {
            WriteProcessMemory(
                self.h_proc.0,
                addr as *const c_void,
                buf.as_ptr().cast(),
                buf.len(),
                Some(addr_of_mut!(bytes_written)),
            )
        }?;

        Ok(bytes_written)
    }

    pub fn write_all_memory(&mut self, mut addr: usize, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            let n = self.write_memory(addr, buf)?;
            addr += n;
            buf = &buf[n..];
        }

        Ok(())
    }

    pub fn read_string(&mut self, addr: usize, is_unicode: bool) -> Result<String> {
        if is_unicode {
            read_string_utf16(self.h_proc.0, addr)
        } else {
            read_string_utf8(self.h_proc.0, addr)
        }
    }

    pub fn read_memory_exact(&mut self, mut addr: usize, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            let n = self.read_memory(addr, buf)?;
            addr += n;
            buf = &mut buf[n..];
        }

        Ok(())
    }

    pub fn get_thread_handle(&self, tid: Option<u32>) -> Option<HANDLE> {
        let tid = tid.unwrap_or(self.current_tid);
        self.tids
            .iter()
            .find_map(|(id, oh)| (*id == tid).then_some(oh.0))
    }

    fn check_handles(&mut self, tid: u32) {
        log::debug!("tid passed: 0x{tid:x}");
        let tids = std::mem::take(&mut self.tids);
        self.tids = tids
            .into_iter()
            .filter_map(|(tid, handle)| {
                let mut flags = 0;
                match unsafe { GetHandleInformation(handle.0, addr_of_mut!(flags)) } {
                    Ok(_) => {
                        log::debug!("Handle for tid 0x{tid:x} is still valid");
                        Some((tid, handle))
                    }
                    Err(_) => {
                        log::debug!("Handle for tid 0x{tid:x} is not valid anymore");
                        None
                    }
                }
            })
            .collect();
    }

    pub fn run<D>(&mut self, dbg: &mut D) -> Result<()>
    where
        D: Debugger,
    {
        loop {
            let raw_event = self.wait_for_event(None)?;
            let (pid, tid) = (raw_event.dwProcessId, raw_event.dwThreadId);
            self.current_tid = tid;
            let event = DebugEvent::new(self.h_proc.0, raw_event)?;
            let action = match event {
                DebugEvent::Exception(e) => {
                    if let Some(Exception {
                        code: ExceptionCode::Breakpoint,
                        address,
                        ..
                    }) = e.chain.first()
                    {
                        log::debug!("BP: {:x?}", &self.breakpoints[..]);
                        if let Some(opcodes) = self
                            .breakpoints
                            .iter()
                            .find_map(|(addr, opcodes)| (addr == address).then_some(opcodes))
                            .copied()
                        {
                            log::info!("Got expected breakpoint at {address:x?}");
                            let addr = *address;
                            let mut orig = [0; 4];
                            self.restore_opcodes(addr, &opcodes[..], Some(&mut orig[..]))?;
                            let action = dbg.on_breakpoint(self, pid, tid, *address)?;
                            self.restore_opcodes(addr, &orig[..], None)?;
                            action
                        } else {
                            log::info!("Got unexpected breakpoint at {address:x?}");
                            dbg.on_breakpoint(self, pid, tid, *address)?
                        }
                    } else {
                        log::info!("Got exception: {e:x?}");
                        dbg.on_exception(self, pid, tid, e)?;
                        break;
                    }
                }
                DebugEvent::CreateThread((handle, info)) => {
                    let tid = unsafe { GetThreadId(handle) };
                    log::info!("New thread #{tid:x} with func {:x}", info.start_address);
                    self.tids.push((tid, OwnedHandle(handle)));
                    dbg.on_thread_create(self, pid, tid, info)?
                }
                DebugEvent::CreateProcess(info) => {
                    if let Some(image_name) = info.image_name.as_ref() {
                        log::info!("New process {image_name}");
                    } else {
                        log::info!("New process with unknown image");
                    }
                    dbg.on_process_create(self, pid, tid, info)?
                }
                DebugEvent::ExitThread(code) => {
                    log::info!("Thread exiting with code 0x{code:x}");
                    self.check_handles(tid);
                    dbg.on_thread_exit(self, pid, tid, code)?
                }
                DebugEvent::ExitProcess(code) => {
                    log::info!("Process exitting with code 0x{code:x}");
                    dbg.on_process_exit(self, pid, tid, code)?;
                    break;
                }
                DebugEvent::LoadDll(load_dll) => {
                    if let Some(filename) = load_dll.filename.as_ref() {
                        log::info!("Loading DLL {filename} at 0x{:x}", load_dll.base_addr);
                    } else {
                        log::info!("Loading DLL at 0x{:x}", load_dll.base_addr);
                    }
                    dbg.on_dll_load(self, pid, tid, load_dll)?
                }
                DebugEvent::UnloadDll(base_addr) => {
                    log::info!("Unloadind dll at 0x{base_addr:x}");
                    dbg.on_dll_unload(self, pid, tid, base_addr)?
                }
                DebugEvent::DebugString(s) => {
                    if !s.is_empty() {
                        log::info!("Got string from debuggee: {s:?}");
                        dbg.on_debug_string(self, pid, tid, s)?
                    } else {
                        log::trace!("Got empty string from debuggee");
                        ContinueEvent::default()
                    }
                }
                DebugEvent::Rip(rip) => {
                    log::info!("Got rip: {rip:?}");
                    dbg.on_rip(self, pid, tid, rip)?
                }
            };

            if matches!(action, ContinueEvent::StopDebugging) {
                log::info!("Stopping debugger loop");
                break;
            }

            self.continue_debug_event(pid, tid, action)?;
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        unsafe { DebugBreakProcess(self.h_proc.0) }
    }

    fn change_protect(
        &mut self,
        addr: usize,
        prot: PAGE_PROTECTION_FLAGS,
    ) -> Result<PAGE_PROTECTION_FLAGS> {
        const PAGE_SIZE: usize = 0x1000;
        let base_addr = (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let old_protections = unsafe {
            let mut old_protections_buf = MaybeUninit::uninit();
            VirtualProtectEx(
                self.h_proc.0,
                base_addr as *const c_void,
                PAGE_SIZE,
                prot,
                old_protections_buf.as_mut_ptr(),
            )?;
            old_protections_buf.assume_init()
        };
        log::trace!("Change protection of {addr:x} from {old_protections:?} to {prot:?}");
        Ok(old_protections)
    }

    pub fn add_breakpoint(&mut self, addr: usize) -> Result<usize> {
        let id = self.breakpoints.len();
        let mut opcodes = [0u8; 4];
        const BREAK_OPCODE: u8 = 0xcc;

        let break_opcodes = [BREAK_OPCODE; 1];

        self.restore_opcodes(addr, &break_opcodes[..], Some(&mut opcodes[..]))?;

        let old_protections = self.change_protect(addr, PAGE_READWRITE)?;
        self.write_all_memory(addr, &break_opcodes[..])?;
        self.change_protect(addr, old_protections)?;
        self.breakpoints.push((addr, opcodes));

        log::info!("Added breakpoint #{id} at 0x{addr:x}");
        Ok(id)
    }

    fn restore_opcodes(
        &mut self,
        addr: usize,
        opcodes: &[u8],
        orig: Option<&mut [u8]>,
    ) -> Result<()> {
        log::trace!("Setting memory to RW");
        let old_protections = self.change_protect(addr, PAGE_READWRITE)?;
        if let Some(orig) = orig {
            log::trace!("Saving original content ({} bytes)", orig.len());
            self.read_memory_exact(addr, orig)?;
        }
        self.write_all_memory(addr, opcodes)?;
        log::trace!("Setting memory to original protection {old_protections:?}");
        self.change_protect(addr, old_protections)?;
        Ok(())
    }

    pub fn remove_breakpoint(&mut self, id: usize) -> Result<()> {
        if id >= self.breakpoints.len() {
            return Ok(());
        }

        let (addr, opcodes) = self.breakpoints.remove(id);
        self.restore_opcodes(addr, &opcodes[..], None)?;
        log::info!("Removed breakpoint #{id} at 0x{addr:x}");
        Ok(())
    }

    pub fn get_registers(&mut self) -> Result<Registers> {
        let Some(handle) = self.get_thread_handle(None) else {
            return Err(Error::new(
                ERROR_INVALID_DATA.into(),
                "No handle for current thread",
            ));
        };
        let context = unsafe {
            let mut buf = MaybeUninit::uninit();
            GetThreadContext(handle, buf.as_mut_ptr())?;
            buf.assume_init()
        };
        Ok(context.into())
    }

    /// SAFETY:
    /// * must be called at the first instruction of a function in order to have a significant
    ///   result
    pub unsafe fn get_return_address(&mut self) -> Result<usize> {
        let regs = self.get_registers()?;
        let mut saved_ip = 0usize.to_ne_bytes();
        self.read_memory_exact(regs.sp, &mut saved_ip[..])?;
        Ok(usize::from_ne_bytes(saved_ip))
    }
}
