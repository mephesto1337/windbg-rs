use std::{
    ffi::c_void,
    mem::{size_of_val, MaybeUninit},
    ptr::addr_of_mut,
};

use windows::{
    core::Result,
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            Memory::{
                VirtualProtectEx, VirtualQueryEx, PAGE_EXECUTE, PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_PROTECTION_FLAGS,
                PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
            },
        },
    },
};

pub const PAGE_SIZE: usize = 0x1000;

const fn page_start(addr: usize) -> usize {
    addr & !(PAGE_SIZE - 1)
}

const fn page_end(addr: usize) -> usize {
    (addr + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PageProtection {
    ExecuteOnly,
    ExecuteWriteCopy,
    ReadExecute,
    ReadOnly,
    ReadWrite,
    ReadWriteExecute,
    WriteCopy,
}

impl From<PageProtection> for PAGE_PROTECTION_FLAGS {
    fn from(value: PageProtection) -> Self {
        match value {
            PageProtection::ExecuteOnly => PAGE_EXECUTE,
            PageProtection::ReadExecute => PAGE_EXECUTE_READ,
            PageProtection::ReadOnly => PAGE_READONLY,
            PageProtection::ReadWrite => PAGE_READWRITE,
            PageProtection::ReadWriteExecute => PAGE_EXECUTE_READWRITE,
            PageProtection::WriteCopy => PAGE_WRITECOPY,
            PageProtection::ExecuteWriteCopy => PAGE_EXECUTE_WRITECOPY,
        }
    }
}

impl From<PAGE_PROTECTION_FLAGS> for PageProtection {
    fn from(value: PAGE_PROTECTION_FLAGS) -> Self {
        match value {
            PAGE_EXECUTE => Self::ExecuteOnly,
            PAGE_EXECUTE_READ => Self::ReadExecute,
            PAGE_READONLY => Self::ReadOnly,
            PAGE_READWRITE => Self::ReadWrite,
            PAGE_EXECUTE_READWRITE => Self::ReadWriteExecute,
            PAGE_WRITECOPY => Self::WriteCopy,
            PAGE_EXECUTE_WRITECOPY => Self::ExecuteWriteCopy,
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
    tracing::trace!("Change protection of {start_addr:x} from {old_protections:?} to {prot:?}");
    Ok(old_protections)
}

#[tracing::instrument(skip(buf), level = "trace")]
pub fn read(handle: HANDLE, addr: usize, buf: &mut [u8]) -> Result<usize> {
    let mut bytes_read = 0;
    unsafe {
        ReadProcessMemory(
            handle,
            addr as *const c_void,
            buf.as_mut_ptr().cast(),
            buf.len(),
            Some(addr_of_mut!(bytes_read)),
        )
    }?;

    Ok(bytes_read)
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
