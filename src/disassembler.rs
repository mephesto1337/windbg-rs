use capstone::{
    arch::{x86::ArchSyntax, BuildsCapstone, BuildsCapstoneSyntax},
    Capstone,
};
use std::fmt::Write;
use windows::{
    core::{Error, Result},
    Win32::Foundation::ERROR_INVALID_DATA,
};

#[cfg(target_arch = "x86_64")]
mod constants {
    use capstone::arch::x86::ArchMode;
    pub(super) const CAPSTONE_MODE: ArchMode = ArchMode::Mode64;
}
#[cfg(target_arch = "x86")]
mod constants {
    use capstone::arch::x86::ArchMode;
    pub(super) const CAPSTONE_MODE: ArchMode = ArchMode::Mode32;
}

use self::constants::*;

pub struct Disassembler {
    cs: Capstone,
}

impl Default for Disassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Disassembler {
    pub fn new() -> Self {
        let cs = Capstone::new()
            .x86()
            .mode(CAPSTONE_MODE)
            .syntax(ArchSyntax::Intel)
            .detail(true)
            .build()
            .expect("Invalid builtin paramaters for Capstone");
        Self { cs }
    }

    pub fn disasm_count(&self, bc: &[u8], addr: usize, count: usize) -> Result<String> {
        let insts = self
            .cs
            .disasm_count(bc, addr as u64, count)
            .map_err(|_| Error::new(ERROR_INVALID_DATA.into(), "Cannot disassemble buffer"))?;
        let mut s = String::new();
        for i in insts.iter() {
            write!(&mut s, "{i}\n").unwrap();
        }
        Ok(s)
    }

    pub fn disasm(&self, bc: &[u8], addr: usize) -> Result<String> {
        let insts = self
            .cs
            .disasm_all(bc, addr as u64)
            .map_err(|_| Error::new(ERROR_INVALID_DATA.into(), "Cannot disassemble buffer"))?;
        let mut s = String::new();
        for i in insts.iter() {
            write!(&mut s, "{i}\n").unwrap();
        }
        Ok(s)
    }

    pub fn is_next_mnemonic<F>(&self, bc: &'_ [u8], f: F) -> bool
    where
        F: FnOnce(&str) -> bool,
    {
        let Ok(insts) = self.cs.disasm_count(bc, 0, 1) else {
            return false;
        };
        let Some(first) = insts.first() else {
            return false;
        };
        let Some(mnemonic) = first.mnemonic() else {
            return false;
        };
        f(mnemonic)
    }
}
