use std::{
    fmt,
    io::{Read, Seek, SeekFrom},
    mem::size_of,
};

use windows::{core::Result, Win32::System::Diagnostics::Debug::CONTEXT};

use crate::{debuggee::ReadOnlyMemory, utils::hex::Hex, Debuggee};

mod eflags;
pub use eflags::EFlags;

#[derive(Clone)]
pub struct Registers {
    pub ip: usize,
    pub ax: usize,
    pub bx: usize,
    pub cx: usize,
    pub dx: usize,
    pub si: usize,
    pub di: usize,
    pub sp: usize,
    pub bp: usize,
    pub flags: EFlags,

    #[cfg(target_arch = "x86_64")]
    pub r8: usize,
    #[cfg(target_arch = "x86_64")]
    pub r9: usize,
    #[cfg(target_arch = "x86_64")]
    pub r10: usize,
    #[cfg(target_arch = "x86_64")]
    pub r11: usize,
    #[cfg(target_arch = "x86_64")]
    pub r12: usize,
    #[cfg(target_arch = "x86_64")]
    pub r13: usize,
    #[cfg(target_arch = "x86_64")]
    pub r14: usize,
    #[cfg(target_arch = "x86_64")]
    pub r15: usize,

    raw_context: CONTEXT,
}

impl fmt::Debug for Registers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg_struct = f.debug_struct("Registers");
        dbg_struct
            .field("ip", &Hex(self.ip))
            .field("ax", &Hex(self.ax))
            .field("bx", &Hex(self.bx))
            .field("cx", &Hex(self.cx))
            .field("dx", &Hex(self.dx))
            .field("si", &Hex(self.si))
            .field("di", &Hex(self.di))
            .field("sp", &Hex(self.sp))
            .field("bp", &Hex(self.bp))
            .field("flags", &self.flags);

        #[cfg(target_arch = "x86_64")]
        {
            dbg_struct
                .field("r8", &Hex(self.r8))
                .field("r9", &Hex(self.r9))
                .field("r10", &Hex(self.r10))
                .field("r11", &Hex(self.r11))
                .field("r12", &Hex(self.r12))
                .field("r13", &Hex(self.r13))
                .field("r14", &Hex(self.r14))
                .field("r15", &Hex(self.r15));
        }

        dbg_struct.finish()
    }
}

impl PartialEq for Registers {
    fn eq(&self, other: &Self) -> bool {
        self.ip == other.ip
            && self.ax == other.ax
            && self.bx == other.bx
            && self.cx == other.cx
            && self.dx == other.dx
            && self.si == other.si
            && self.di == other.di
            && self.sp == other.sp
            && self.bp == other.bp
            && self.flags == other.flags
            && self.r8 == other.r8
            && self.r9 == other.r9
            && self.r10 == other.r10
            && self.r11 == other.r11
            && self.r12 == other.r12
            && self.r13 == other.r13
            && self.r14 == other.r14
            && self.r15 == other.r15
    }
}

impl Eq for Registers {}

impl From<CONTEXT> for Registers {
    fn from(value: CONTEXT) -> Self {
        Self {
            ip: value.Rip as usize,
            ax: value.Rax as usize,
            bx: value.Rbx as usize,
            cx: value.Rcx as usize,
            dx: value.Rdx as usize,
            si: value.Rsi as usize,
            di: value.Rdi as usize,
            sp: value.Rsp as usize,
            bp: value.Rbp as usize,
            flags: EFlags::from_bits(value.EFlags).unwrap(),
            #[cfg(target_arch = "x86_64")]
            r8: value.R8 as usize,
            #[cfg(target_arch = "x86_64")]
            r9: value.R9 as usize,
            #[cfg(target_arch = "x86_64")]
            r10: value.R10 as usize,
            #[cfg(target_arch = "x86_64")]
            r11: value.R11 as usize,
            #[cfg(target_arch = "x86_64")]
            r12: value.R12 as usize,
            #[cfg(target_arch = "x86_64")]
            r13: value.R13 as usize,
            #[cfg(target_arch = "x86_64")]
            r14: value.R14 as usize,
            #[cfg(target_arch = "x86_64")]
            r15: value.R15 as usize,

            raw_context: value,
        }
    }
}

impl From<Registers> for CONTEXT {
    fn from(value: Registers) -> Self {
        let mut context = value.raw_context;
        context.Rip = value.ip as u64;
        context.Rax = value.ax as u64;
        context.Rbx = value.bx as u64;
        context.Rcx = value.cx as u64;
        context.Rdx = value.dx as u64;
        context.Rsi = value.si as u64;
        context.Rdi = value.di as u64;
        context.Rsp = value.sp as u64;
        context.Rbp = value.bp as u64;
        context.EFlags = value.flags.bits();
        #[cfg(target_arch = "x86_64")]
        {
            context.R8 = value.r8 as u64;
            context.R9 = value.r9 as u64;
            context.R10 = value.r10 as u64;
            context.R11 = value.r11 as u64;
            context.R12 = value.r12 as u64;
            context.R13 = value.r13 as u64;
            context.R14 = value.r14 as u64;
            context.R15 = value.r15 as u64;
        }
        context
    }
}

impl Registers {
    #[cfg(target_arch = "x86_64")]
    pub fn get_arg(&self, stack: &mut ReadOnlyMemory, idx: usize) -> Result<usize> {
        match idx {
            0 => Ok(self.cx),
            1 => Ok(self.dx),
            2 => Ok(self.r8),
            3 => Ok(self.r9),
            _ => {
                let offset = (idx - 3) * size_of::<u64>();
                let mut arg = 0u64.to_ne_bytes();
                stack.seek(SeekFrom::Start(offset as u64))?;
                stack.read_exact(&mut arg[..])?;
                Ok(u64::from_ne_bytes(arg) as usize)
            }
        }
    }

    #[cfg(target_arch = "x86")]
    fn get_arg(&self, stack: &mut ReadOnlyMemory, idx: usize) -> Result<usize> {
        let offset = (idx + 1) * size_of::<u32>();
        let mut arg = 0u32.to_ne_bytes();
        stack.seek(SeekFrom::Start(offset as u64))?;
        stack.read_exact(&mut arg[..])?;
        Ok(u32::from_ne_bytes(arg) as usize)
    }

    pub fn open_stack(&self, debuggee: &Debuggee) -> Result<ReadOnlyMemory> {
        const STACK_SIZE: usize = 16 * size_of::<usize>();
        debuggee.get_readonly_memory(self.sp, STACK_SIZE)
    }
}
