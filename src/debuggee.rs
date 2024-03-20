use std::{
    ffi::{c_void, CString},
    fmt,
    io::{Read, Seek, SeekFrom, Write},
    marker::PhantomData,
    mem::{size_of, MaybeUninit},
    ops::{Deref, DerefMut},
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
                    DebugBreakProcess, FlushInstructionCache, GetThreadContext, SetThreadContext,
                    WaitForDebugEvent, CONTEXT, DEBUG_EVENT,
                },
                ToolHelp::{
                    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD,
                },
            },
            Threading::{
                CreateProcessA, GetThreadId, OpenProcess, OpenThread, CREATE_NEW_CONSOLE,
                CREATE_NEW_PROCESS_GROUP, DEBUG_ONLY_THIS_PROCESS, INFINITE, PROCESS_ALL_ACCESS,
                PROCESS_INFORMATION, STARTUPINFOA, THREAD_ALL_ACCESS,
            },
        },
    },
};

use crate::{
    breakpoint::{Breakpoint, Breakpoints, BREAKPOINT_SIZE, BREAK_OPCODES},
    debugger::{ContinueEvent, Debugger},
    process::Process,
    registers::EFlags,
    symbols::Image,
    utils::{
        memory::{self as mem, get_protection, page_start, PAGE_SIZE},
        strings::{read_string_utf16, read_string_utf8},
        OwnedHandle,
    },
    Disassembler, Registers,
};

#[cfg(target_arch = "x86_64")]
mod constants {
    use windows::Win32::System::Diagnostics::Debug::{CONTEXT_ALL_AMD64, CONTEXT_FLAGS};
    pub(super) const CONTEXT_ALL: CONTEXT_FLAGS = CONTEXT_ALL_AMD64;
}
#[cfg(target_arch = "x86")]
mod constants {
    use capstone::arch::x86::ArchMode;
    use windows::Win32::System::Diagnostics::Debug::{CONTEXT_ALL_X86, CONTEXT_FLAGS};
    pub(super) const CONTEXT_ALL: CONTEXT_FLAGS = CONTEXT_ALL_X86;
    pub(super) const CAPSTONE_MODE: ArchMode = ArchMode::Mode32;
}

use self::constants::*;

pub struct Debuggee {
    proc: Process,
    h_proc: OwnedHandle,
    tids: Vec<(u32, OwnedHandle)>,
    current_tid: u32,
    breakpoints: Breakpoints,
    prev_breakpoint_addr: usize,
    breakpoint_action: Option<ContinueEvent>,
    modules: Vec<Image>,
    _not_send: PhantomData<*mut ()>,
}

mod events;
pub use events::{
    CreateProcessInfo, CreateThreadInfo, DebugEvent, Exception, ExceptionCode, ExceptionInfo,
    LoadDll, Rip,
};

mod memory;
pub use memory::{ReadOnlyMemory, ReadWriteMemory};

#[repr(align(16))]
struct Context(CONTEXT);

impl Deref for Context {
    type Target = CONTEXT;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Context {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Debug for Debuggee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Debuggee")
            .field("pid", &self.pid())
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

    fn build(
        proc: Process,
        handle: OwnedHandle,
        tids: Vec<(u32, OwnedHandle)>,
        current_tid: u32,
    ) -> Result<Self> {
        let main_module = Image::from_file(proc.image())?;
        Ok(Self {
            proc,
            h_proc: handle,
            tids,
            current_tid,
            breakpoints: Default::default(),
            modules: vec![main_module],
            breakpoint_action: None,
            prev_breakpoint_addr: 0,
            _not_send: PhantomData,
        })
    }

    fn from_proc(proc: Process, handle: Option<HANDLE>) -> Result<Self> {
        let h_proc = OwnedHandle(match handle {
            Some(h) => h,
            None => unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, proc.pid()) }?,
        });
        unsafe { DebugActiveProcess(proc.pid()) }?;
        unsafe { DebugBreakProcess(h_proc.0) }?;
        let tids = Self::open_threads(proc.pid())?;

        Self::build(proc, h_proc, tids, 0)
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
            tracing::debug!("CreateProcess: {ret:?}");
            ret?;
            process_infomation_buf.assume_init()
        };

        Self::build(
            Process {
                id: dwProcessId,
                image: application_name.into_string().unwrap(),
            },
            OwnedHandle(hProcess),
            vec![(dwThreadId, OwnedHandle(hThread))],
            dwThreadId,
        )
    }

    fn wait_for_event(&mut self, timeout: Option<Duration>) -> Result<DEBUG_EVENT> {
        let mut debug_event = MaybeUninit::uninit();
        let timeout = timeout
            .and_then(|d| d.as_millis().try_into().ok())
            .unwrap_or(INFINITE);
        unsafe { WaitForDebugEvent(debug_event.as_mut_ptr(), timeout) }?;
        Ok(unsafe { debug_event.assume_init() })
    }

    pub fn modules(&self) -> &[Image] {
        &self.modules[..]
    }

    pub fn pid(&self) -> u32 {
        self.proc.pid()
    }

    pub fn tid(&self) -> u32 {
        self.current_tid
    }

    fn continue_debug_event(&mut self, pid: u32, tid: u32, action: ContinueEvent) -> Result<()> {
        unsafe { ContinueDebugEvent(pid, tid, action.as_ntstatus()) }?;
        Ok(())
    }

    pub fn write_memory(&mut self, mut addr: usize, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            let n = mem::write(self.h_proc.0, addr, buf)?;
            addr += n;
            buf = &buf[n..];
        }

        Ok(())
    }

    #[tracing::instrument(skip(self), level = "debug", ret)]
    pub fn read_string(&mut self, addr: usize, is_unicode: bool) -> Result<String> {
        if is_unicode {
            read_string_utf16(self.h_proc.0, addr)
        } else {
            read_string_utf8(self.h_proc.0, addr)
        }
    }

    pub fn read_memory(&mut self, mut addr: usize, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            let n = mem::read(self.h_proc.0, addr, buf)?;
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

    #[tracing::instrument(skip(self))]
    fn check_handles(&mut self, tid: u32) {
        let tids = std::mem::take(&mut self.tids);
        self.tids = tids
            .into_iter()
            .filter_map(|(tid, handle)| {
                let mut flags = 0;
                match unsafe { GetHandleInformation(handle.0, addr_of_mut!(flags)) } {
                    Ok(_) => {
                        tracing::trace!("Handle for tid 0x{tid:x} is still valid");
                        Some((tid, handle))
                    }
                    Err(_) => {
                        tracing::trace!("Handle for tid 0x{tid:x} is not valid anymore");
                        None
                    }
                }
            })
            .collect();
    }

    #[tracing::instrument(skip(self, dbg), ret)]
    fn handle_breakpoint<D>(
        &mut self,
        dbg: &mut D,
        addr: usize,
        first: bool,
    ) -> Result<ContinueEvent>
    where
        D: Debugger,
    {
        tracing::trace!("BP: {:x?}", &self.breakpoints);
        let symbol = self.lookup_addr(addr);
        if let Some(bp) = self.breakpoints.get_by_addr(addr).cloned() {
            tracing::info!("Got expected breakpoint at {symbol}");
            let mut orig = [0; BREAKPOINT_SIZE];
            self.restore_opcodes(addr, bp.saved_bc(), Some(&mut orig[..]))?;
            let mut regs = self.get_registers()?;
            tracing::debug!(
                "Setting back IP from {ip:x} to {addr:x} (-{n})",
                ip = regs.ip,
                n = regs.ip - addr
            );
            regs.ip = addr;
            self.set_registers(regs)?;
            let action = dbg.on_breakpoint(self, &bp)?;
            if bp.is_one_shot() {
                tracing::debug!("Removing one-shot BP at {:x}", bp.addr());
                self.remove_breakpoint(bp.id())?;
            }
            self.breakpoint_action = Some(action);
            self.single_step()?;
            // self.restore_opcodes(addr, &orig[..], None)?;
            Ok(ContinueEvent::Continue)
        } else {
            tracing::warn!("Got unexpected breakpoint at {symbol}");
            Ok(ContinueEvent::default())
        }
    }

    #[tracing::instrument(skip_all, level = "debug")]
    fn handle_exception<D>(&mut self, dbg: &mut D, e: ExceptionInfo) -> Result<ContinueEvent>
    where
        D: Debugger,
    {
        match e.chain.first() {
            Some(Exception {
                code: ExceptionCode::Breakpoint,
                address,
                ..
            }) if e.first_chance => {
                self.prev_breakpoint_addr = *address;
                self.handle_breakpoint(dbg, *address, e.first_chance)
            }
            Some(Exception {
                code: ExceptionCode::SingleStep,
                address,
                ..
            }) => {
                if self.breakpoint_action.is_some() {
                    tracing::debug!("got SingleStep exception at 0x{address:x}");
                    if self.prev_breakpoint_addr == 0 {
                        tracing::warn!(
                            address,
                            prev_breakpoint_addr = self.prev_breakpoint_addr,
                            "Single step was {n} bytes?!",
                            n = address - self.prev_breakpoint_addr,
                        );
                        return Ok(ContinueEvent::default());
                    }
                    self.write_memory(self.prev_breakpoint_addr, &BREAK_OPCODES[..])?;
                    self.prev_breakpoint_addr = 0;
                    Ok(ContinueEvent::default())
                } else {
                    tracing::debug!("Single step from 0x{address:x}");
                    Ok(ContinueEvent::default())
                }
            }
            _ => {
                tracing::info!("Got exception: {e:x?}");
                dbg.on_exception(self, e)
            }
        }
    }

    #[tracing::instrument(name = "run", skip(self), fields(pid = self.pid()))]
    pub fn run_inner<D>(&mut self, dbg: &mut D) -> Result<ContinueEvent>
    where
        D: Debugger,
    {
        let raw_event = self.wait_for_event(None)?;
        let (pid, tid) = (raw_event.dwProcessId, raw_event.dwThreadId);
        debug_assert!(pid == self.pid());
        self.current_tid = tid;
        let event = DebugEvent::new(self.h_proc.0, raw_event)?;
        let action = match event {
            DebugEvent::Exception(e) => self.handle_exception(dbg, e)?,
            DebugEvent::CreateThread((handle, info)) => {
                let tid = unsafe { GetThreadId(handle) };
                tracing::info!("New thread #{tid:x} with func {:x}", info.start_address);
                self.tids.push((tid, OwnedHandle(handle)));
                dbg.on_thread_create(self, info)?
            }
            DebugEvent::CreateProcess(info) => {
                if let Some(image_name) = info.image_name.as_ref() {
                    tracing::info!("New process {image_name}");
                } else {
                    tracing::info!("New process with unknown image");
                }
                dbg.on_process_create(self, info)?
            }
            DebugEvent::ExitThread(code) => {
                tracing::info!("Thread exiting with code 0x{code:x}");
                self.check_handles(tid);
                dbg.on_thread_exit(self, code)?
            }
            DebugEvent::ExitProcess(code) => {
                tracing::info!("Process exitting with code 0x{code:x}");
                dbg.on_process_exit(self, code)?;
                ContinueEvent::StopDebugging
            }
            DebugEvent::LoadDll(load_dll) => {
                if let Some(filename) = load_dll.filename.as_ref() {
                    tracing::info!("Loading DLL {filename} at 0x{:x}", load_dll.base_addr);
                } else {
                    tracing::info!("Loading DLL at 0x{:x}", load_dll.base_addr);
                }
                let _ = self.add_image(load_dll.base_addr);
                dbg.on_dll_load(self, load_dll)?
            }
            DebugEvent::UnloadDll(base_addr) => {
                tracing::info!("Unloadind dll at 0x{base_addr:x}");
                self.remove_image(base_addr);
                dbg.on_dll_unload(self, base_addr)?
            }
            DebugEvent::DebugString(s) => {
                if !s.is_empty() {
                    tracing::info!("Got string from debuggee: {s:?}");
                    dbg.on_debug_string(self, s)?
                } else {
                    tracing::trace!("Got empty string from debuggee");
                    ContinueEvent::default()
                }
            }
            DebugEvent::Rip(rip) => {
                tracing::info!("Got rip: {rip:?}");
                dbg.on_rip(self, rip)?
            }
        };
        Ok(action)
    }

    #[tracing::instrument(skip(self), level = "trace", ret)]
    fn add_image(&mut self, base_addr: usize) -> Result<()> {
        let image = Image::build(self.h_proc.0, base_addr)?;
        match self
            .modules
            .binary_search_by(|img| img.base_addr().cmp(&base_addr))
        {
            Ok(idx) => {
                tracing::warn!(
                    "Confict between images {img1} and {image}",
                    img1 = &self.modules[idx]
                );
                self.modules[idx] = image;
            }
            Err(idx) => {
                self.modules.insert(idx, image);
            }
        }
        Ok(())
    }

    fn remove_image(&mut self, base_addr: usize) {
        if let Ok(idx) = self
            .modules
            .binary_search_by(|img| img.base_addr().cmp(&base_addr))
        {
            self.modules.remove(idx);
        }
    }

    pub fn run<D>(&mut self, dbg: &mut D) -> Result<()>
    where
        D: Debugger,
    {
        while let Ok(action) = self.run_inner(dbg) {
            if matches!(action, ContinueEvent::StopDebugging) {
                tracing::info!("Stopping debugger loop");
                break;
            }

            self.continue_debug_event(self.pid(), self.tid(), action)?;
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        unsafe { DebugBreakProcess(self.h_proc.0) }
    }

    pub fn get_readonly_memory(&self, addr: usize, size: usize) -> Result<ReadOnlyMemory> {
        ReadOnlyMemory::new(addr, size, self.h_proc.0)
    }

    pub fn get_readwrite_memory(&self, addr: usize, size: usize) -> Result<ReadWriteMemory> {
        ReadWriteMemory::new(addr, size, self.h_proc.0)
    }

    pub fn add_breakpoint_by_addr(&mut self, addr: usize) -> Result<&mut Breakpoint> {
        let mut mw = memory::ReadWriteMemory::new(addr, BREAKPOINT_SIZE, self.h_proc.0)?;
        self.breakpoints.add(&mut mw)
    }

    pub fn add_breakpoint(&mut self, addr_or_symbol: &str) -> Result<&mut Breakpoint> {
        let (addr, symbol) = if let Some(addr) = self.resolv(addr_or_symbol) {
            (addr, addr_or_symbol.into())
        } else if let Ok(addr) = usize::from_str_radix(addr_or_symbol, 16) {
            (addr, self.lookup_addr(addr))
        } else {
            return Err(Error::new(
                ERROR_INVALID_DATA.into(),
                "Could not resolv symbol",
            ));
        };
        let bp = self.add_breakpoint_by_addr(addr)?;
        tracing::debug!("Added breakpoint #{id} at {symbol}", id = bp.id());
        Ok(bp)
    }

    pub fn add_breakpoints(&mut self, addrs: impl Iterator<Item = usize>) -> Result<()> {
        let mut addrs: Vec<_> = addrs.collect();
        addrs.sort();
        tracing::debug!("addrs = {addrs:x?}");
        let mut addrs = &addrs[..];
        while !addrs.is_empty() {
            let start_addr = addrs.first().copied().map(page_start).unwrap();
            let end_offset = addrs
                .iter()
                .position(|&a| a >= (start_addr + PAGE_SIZE))
                .unwrap_or(addrs.len());
            let mut mw = self.get_readwrite_memory(start_addr, PAGE_SIZE)?;
            self.breakpoints.add_many(&mut mw, &addrs[..end_offset])?;
            addrs = &addrs[end_offset..];
        }
        Ok(())
    }

    #[tracing::instrument(skip_all, level = "trace", ret)]
    fn restore_opcodes(
        &mut self,
        addr: usize,
        opcodes: &[u8],
        orig: Option<&mut [u8]>,
    ) -> Result<()> {
        let mut mem = self.get_readwrite_memory(addr, opcodes.len())?;
        if let Some(orig) = orig {
            mem.read_exact(orig)?;
            mem.seek(SeekFrom::Start(0))?;
            mem.write_all(opcodes)?;
            tracing::trace!("Changing {orig:x?} to {opcodes:x?} at 0x{addr:x}");
        } else {
            mem.write_all(opcodes)?;
            tracing::trace!("Changing opcodes at 0x{addr:x} to {opcodes:x?}");
        }
        unsafe {
            FlushInstructionCache(self.h_proc.0, Some(addr as *const c_void), opcodes.len())
        }?;
        Ok(())
    }

    pub fn remove_breakpoint(&mut self, id: usize) -> Result<()> {
        let Some(bp) = self.breakpoints.get(id) else {
            return Ok(());
        };
        let mut mw = memory::ReadWriteMemory::new(bp.addr(), BREAKPOINT_SIZE, self.h_proc.0)?;
        self.breakpoints.remove(&mut mw, id)
    }

    fn get_current_thread_handle(&self) -> Result<HANDLE> {
        self.get_thread_handle(None).ok_or(Error::new(
            ERROR_INVALID_DATA.into(),
            "No handle for current thread",
        ))
    }

    fn get_current_context(&self) -> Result<Context> {
        let handle = self.get_current_thread_handle()?;

        let mut context = Context(CONTEXT {
            ContextFlags: CONTEXT_ALL,
            ..Default::default()
        });
        unsafe { GetThreadContext(handle, addr_of_mut!(context.0)) }?;
        Ok(context)
    }

    #[tracing::instrument(skip_all, ret, level = "trace")]
    fn set_current_context(&self, context: &Context) -> Result<()> {
        let handle = self.get_current_thread_handle()?;
        tracing::trace!("Elfags = {}", EFlags::from_context(&context.0));
        unsafe { SetThreadContext(handle, addr_of!(context.0)) }?;
        Ok(())
    }

    #[tracing::instrument(skip(self), ret, level = "trace")]
    pub fn get_registers(&mut self) -> Result<Registers> {
        let context = self.get_current_context()?;
        let regs = context.0.into();
        Ok(regs)
    }

    #[tracing::instrument(skip_all, ret, level = "trace")]
    pub fn set_registers(&mut self, registers: Registers) -> Result<Registers> {
        let context = Context(registers.into());
        self.set_current_context(&context)?;
        Ok(context.0.into())
    }

    /// # Safety
    /// * must be called at the first instruction of a function in order to have a significant
    ///   result
    #[tracing::instrument(skip(self), level = "trace", ret)]
    pub unsafe fn get_return_address(&mut self) -> Result<usize> {
        let regs = self.get_registers()?;
        let mut saved_ip = 0usize.to_ne_bytes();
        self.read_memory(regs.sp, &mut saved_ip[..])?;
        Ok(usize::from_ne_bytes(saved_ip))
    }

    #[tracing::instrument(skip(self), level = "debug", ret)]
    pub fn single_step(&mut self) -> Result<usize> {
        let mut context = self.get_current_context()?;
        let ip = context.Rip as usize;
        if tracing::enabled!(tracing::Level::TRACE) {
            let mut nxt_instructions = [0u8; 8];
            let prot = get_protection(self.h_proc.0, ip)?;
            self.read_memory(ip, &mut nxt_instructions[..])?;
            let insts = Disassembler::new().disasm(&nxt_instructions[..], ip)?;
            tracing::trace!("Single step at 0x{ip:x} ({prot:?}):\n{insts}");
        }
        context.EFlags |= EFlags::TF.bits();
        self.set_current_context(&context)?;
        Ok(ip)
    }

    fn is_call_instruction(&self, bc: &[u8]) -> bool {
        let disas = Disassembler::new();
        disas.is_next_mnemonic(bc, |ins| ins == "call")
    }

    #[tracing::instrument(skip(self), level = "debug", ret)]
    pub fn step_over(&mut self) -> Result<()> {
        let mut ip = self.single_step()?;
        let mut instructions = [0u8; 8];
        for _ in 0..10 {
            self.read_memory(ip, &mut instructions[..])?;
            if self.is_call_instruction(&instructions[..]) {
                break;
            }
            self.continue_debug_event(self.pid(), self.tid(), ContinueEvent::Continue)?;
            ip = self.single_step()?;
        }
        Ok(())
    }

    pub fn resolv(&self, symbol: &str) -> Option<usize> {
        match symbol.split_once('!') {
            Some((module_name, symbol)) => {
                let module = self
                    .modules
                    .iter()
                    .find(|img| img.name().eq_ignore_ascii_case(module_name))?;
                module.resolv(symbol)
            }
            None => self.modules.iter().find_map(|img| img.resolv(symbol)),
        }
    }

    pub fn lookup_addr(&self, addr: usize) -> String {
        self.modules
            .iter()
            .find_map(|img| img.lookup_addr(addr))
            .unwrap_or_else(|| format!("0x{addr:x}"))
    }
}
