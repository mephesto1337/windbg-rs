use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Memory::{UnmapViewOfFile, MEMORY_MAPPED_VIEW_ADDRESS},
};

pub struct OwnedHandle(pub HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub struct OwnedView(pub MEMORY_MAPPED_VIEW_ADDRESS);

impl Drop for OwnedView {
    fn drop(&mut self) {
        if !self.0.Value.is_null() {
            let _ = unsafe { UnmapViewOfFile(self.0) };
        }
    }
}

pub fn read_into_unitialized<E, F>(buf_vec: &mut Vec<u8>, mut f: F) -> Result<usize, E>
where
    F: FnMut(&mut [u8]) -> Result<usize, E>,
{
    let old_len = buf_vec.len();
    let uninit_buf = buf_vec.spare_capacity_mut();
    if uninit_buf.is_empty() {
        return Ok(0);
    }
    let buf: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(uninit_buf.as_mut_ptr().cast(), uninit_buf.len()) };
    let n = f(buf)?;
    unsafe {
        buf_vec.set_len(old_len + n);
    }
    Ok(n)
}

pub mod filenames;
pub mod hex;
pub mod memory;
pub mod strings;
