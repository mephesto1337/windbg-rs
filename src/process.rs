use std::{
    borrow::Cow,
    mem::{size_of, size_of_val, MaybeUninit},
    ptr,
};
use windows::{
    core::Result,
    Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            ProcessStatus::{EnumProcessModules, EnumProcesses, GetModuleFileNameExA},
            Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
        },
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub(crate) id: u32,
    pub(crate) image: String,
}

pub(crate) fn get_image_name(handle: HANDLE) -> Result<String> {
    let mut module = MaybeUninit::uninit();
    let mut needed = 0;
    unsafe {
        EnumProcessModules(
            handle,
            module.as_mut_ptr(),
            size_of_val(&module) as u32,
            ptr::addr_of_mut!(needed),
        )
    }?;
    assert_eq!(needed, size_of_val(&module) as u32);
    let module = unsafe { module.assume_init() };

    let mut filename = Vec::with_capacity(1024);
    unsafe {
        let buf = std::slice::from_raw_parts_mut(filename.as_mut_ptr(), filename.capacity());
        let size = GetModuleFileNameExA(handle, module, buf);
        assert!(size < buf.len() as u32);
        filename.set_len(size as usize);
    };

    Ok(match String::from_utf8_lossy(&filename[..]) {
        Cow::Borrowed(_) => unsafe { String::from_utf8_unchecked(filename) },
        Cow::Owned(o) => o,
    })
}

impl Process {
    fn all_pids() -> Result<Vec<u32>> {
        let mut proc_ids = Vec::with_capacity(1024);
        let mut proc_ids_size = 0;
        loop {
            let cb = proc_ids.capacity() * size_of::<u32>();
            unsafe {
                EnumProcesses(
                    proc_ids.as_mut_ptr(),
                    cb as u32,
                    ptr::addr_of_mut!(proc_ids_size),
                )
            }?;
            let proc_count = proc_ids_size as usize / size_of::<u32>();
            if proc_count == proc_ids.capacity() {
                proc_ids.reserve(proc_count + 1024);
            } else {
                unsafe { proc_ids.set_len(proc_count) };
                break Ok(proc_ids);
            }
        }
    }

    fn get_image(pid: u32) -> Result<String> {
        let desired_access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
        let handle = unsafe { OpenProcess(desired_access, false, pid) }?;
        let maybe_image_name = get_image_name(handle);
        let _ = unsafe { CloseHandle(handle) };
        maybe_image_name
    }

    pub fn new(id: u32) -> Result<Self> {
        let image = Self::get_image(id)?;
        Ok(Self { id, image })
    }

    pub fn all() -> Result<Vec<Self>> {
        Ok(Self::all_pids()?
            .iter()
            .filter_map(|&pid| Self::new(pid).ok())
            .collect())
    }

    pub fn pid(&self) -> u32 {
        self.id
    }

    pub fn image(&self) -> &str {
        self.image.as_str()
    }
}
