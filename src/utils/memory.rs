use bitflags::bitflags;
use core::fmt;
use std::{
    ffi::c_void,
    mem::{size_of_val, MaybeUninit},
    ptr::addr_of_mut,
};
use windows::{
    core::Result,
    Win32::{
        Foundation::{ERROR_PARTIAL_COPY, HANDLE},
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            Memory::{
                VirtualProtectEx, VirtualQueryEx, PAGE_EXECUTE, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS,
                PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
            },
        },
    },
};

pub const PAGE_SIZE: usize = 0x1000;

pub const fn page_start(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

pub const fn page_end(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct PageProtection: u32 {
        const NONE = 0;
        const COPY = 0b1000;
        const READ = 0b0100;
        const WRITE = 0b0010;
        const EXECUTE = 0b0001;

        const EXECUTE_WRITE_COPY = 0b1111;
        const READ_EXECUTE = 0b0101;
        const READ_WRITE = 0b0110;
        const READ_WRITE_EXECUTE = 0b0111;
        const WRITE_COPY = 0b1110;
    }
}

impl fmt::Display for PageProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = "";
        for (name, flag) in self.iter_names() {
            if self.contains(flag) {
                write!(f, "{sep}{name}")?;
                sep = "|";
            }
        }
        Ok(())
    }
}

impl From<PageProtection> for PAGE_PROTECTION_FLAGS {
    fn from(value: PageProtection) -> Self {
        match value {
            PageProtection::EXECUTE => PAGE_EXECUTE,
            PageProtection::READ_EXECUTE => PAGE_EXECUTE_READ,
            PageProtection::READ => PAGE_READONLY,
            PageProtection::READ_WRITE => PAGE_READWRITE,
            PageProtection::READ_WRITE_EXECUTE => PAGE_EXECUTE_READWRITE,
            PageProtection::WRITE_COPY => PAGE_WRITECOPY,
            PageProtection::EXECUTE_WRITE_COPY => PAGE_EXECUTE_WRITECOPY,
            PageProtection::NONE => PAGE_NOACCESS,
            _ => unreachable!(),
        }
    }
}

impl From<PAGE_PROTECTION_FLAGS> for PageProtection {
    fn from(value: PAGE_PROTECTION_FLAGS) -> Self {
        match value {
            PAGE_EXECUTE => Self::EXECUTE,
            PAGE_EXECUTE_READ => Self::READ_EXECUTE,
            PAGE_READONLY => Self::READ,
            PAGE_READWRITE => Self::READ_WRITE,
            PAGE_EXECUTE_READWRITE => Self::READ_WRITE_EXECUTE,
            PAGE_WRITECOPY => Self::WRITE_COPY,
            PAGE_EXECUTE_WRITECOPY => Self::EXECUTE_WRITE_COPY,
            PAGE_NOACCESS => Self::NONE,
            PAGE_PROTECTION_FLAGS(x) => unreachable!("Invalid PAGE_PROTECTION_FLAGS value 0x{x:x}"),
        }
    }
}

#[tracing::instrument(level = "trace", ret)]
pub fn change_protect(
    handle: HANDLE,
    addr: usize,
    size: usize,
    prot: PageProtection,
) -> Result<PageProtection> {
    let start_addr = page_start(addr);
    let page_count = (page_end(addr + size) - start_addr) / PAGE_SIZE;

    let old_protections = unsafe {
        let mut old_protections_buf = MaybeUninit::uninit();
        VirtualProtectEx(
            handle,
            addr as *const c_void,
            PAGE_SIZE * page_count,
            prot.into(),
            old_protections_buf.as_mut_ptr(),
        )?;
        old_protections_buf.assume_init()
    };
    let old_protections = old_protections.into();
    Ok(old_protections)
}

#[tracing::instrument(skip(buf), level = "trace")]
pub fn read(handle: HANDLE, addr: usize, buf: &mut [u8]) -> Result<usize> {
    let mut bytes_read = 0;
    let ret = unsafe {
        ReadProcessMemory(
            handle,
            addr as *const c_void,
            buf.as_mut_ptr().cast(),
            buf.len(),
            Some(addr_of_mut!(bytes_read)),
        )
    };

    match ret {
        Ok(_) => Ok(bytes_read),
        Err(e) if e.code() == ERROR_PARTIAL_COPY.into() => Ok(bytes_read),
        Err(e) => Err(e),
    }
}

#[tracing::instrument(skip(buf), level = "trace")]
pub fn write(handle: HANDLE, addr: usize, buf: &[u8]) -> Result<usize> {
    let mut bytes_written = 0;
    unsafe {
        WriteProcessMemory(
            handle,
            addr as *const c_void,
            buf.as_ptr().cast(),
            buf.len(),
            Some(addr_of_mut!(bytes_written)),
        )
    }?;

    Ok(bytes_written)
}

#[tracing::instrument(level = "trace", ret)]
pub fn get_protection(handle: HANDLE, addr: usize) -> Result<PageProtection> {
    let mut memory_info_buf = MaybeUninit::uninit();
    let size = unsafe {
        VirtualQueryEx(
            handle,
            Some(page_start(addr) as *const c_void),
            memory_info_buf.as_mut_ptr(),
            size_of_val(&memory_info_buf),
        )
    };
    if size == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let memory_info = unsafe { memory_info_buf.assume_init() };
    Ok(memory_info.Protect.into())
}
