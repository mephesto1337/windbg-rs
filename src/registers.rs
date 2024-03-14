use windows::Win32::System::Diagnostics::Debug::CONTEXT;

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub flags: usize,

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
}

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
            flags: value.EFlags as usize,
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
        }
    }
}
