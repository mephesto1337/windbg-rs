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

pub mod filenames;
pub mod memory;
pub mod strings;
