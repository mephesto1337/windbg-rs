use std::ptr;
use windows::{
    core::{Error, Result, PCSTR},
    Win32::{
        Foundation::{ERROR_NOT_FOUND, HANDLE},
        Storage::FileSystem::{GetFileSize, GetLogicalDriveStringsA, QueryDosDeviceA},
        System::{
            Memory::{CreateFileMappingA, MapViewOfFile, FILE_MAP_READ, PAGE_READONLY},
            ProcessStatus::GetMappedFileNameA,
            Threading::GetCurrentProcess,
        },
    },
};

use super::{OwnedHandle, OwnedView};

#[tracing::instrument(level = "trace")]
pub fn get_filename_from_handle(handle: HANDLE) -> Result<String> {
    let mut high = 0;
    let low = unsafe { GetFileSize(handle, Some(ptr::addr_of_mut!(high))) };

    if low == 0 && high == 0 {
        // Empty file, cannot go on
        return Err(Error::new(
            ERROR_NOT_FOUND.into(),
            "Cannot retrieve filename from an empty file",
        ));
    }

    let mapping =
        OwnedHandle(unsafe { CreateFileMappingA(handle, None, PAGE_READONLY, 0, 1, None) }?);

    let mem = unsafe { MapViewOfFile(mapping.0, FILE_MAP_READ, 0, 0, 1) };
    if mem.Value.is_null() {
        return Err(Error::new(
            ERROR_NOT_FOUND.into(),
            "Cannot create a valid MapViewOfFile",
        ));
    }
    let mem = OwnedView(mem);

    let mut buf = vec![0u8; 1024];
    let n = unsafe { GetMappedFileNameA(GetCurrentProcess(), mem.0.Value, &mut buf[..]) };
    if n < 1 {
        return Err(Error::new(
            ERROR_NOT_FOUND.into(),
            "Cannot retrieve mapped filename",
        ));
    }
    buf.truncate(n as usize);
    let fullname = unsafe { String::from_utf8_unchecked(buf) };
    Ok(get_device_mapping(&fullname).unwrap_or(fullname))
}

pub fn get_device_mapping(device: impl AsRef<str>) -> Option<String> {
    let device = device.as_ref();
    let mut drive_letters = [0u8; 27];
    let n = unsafe { GetLogicalDriveStringsA(Some(&mut drive_letters[..])) } as usize;
    if n == 0 {
        return None;
    }

    let mut device_name = *b" :\0";
    for dl in &drive_letters[..n] {
        device_name[0] = *dl;
        let mut raw_dev_path = [0u8; 256];
        let n = unsafe {
            QueryDosDeviceA(
                PCSTR::from_raw(device_name.as_ptr()),
                Some(&mut raw_dev_path[..]),
            )
        } as usize;
        if n <= 2 {
            continue;
        }

        let dev_path = unsafe { std::str::from_utf8_unchecked(&raw_dev_path[..(n - 2)]) };
        if let Some(path) = device.strip_prefix(dev_path) {
            return Some(format!("{}:{path}", unsafe {
                char::from_u32_unchecked(*dl as u32)
            }));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use windows::{
        core::PCSTR,
        Win32::{
            Foundation::GENERIC_READ,
            Storage::FileSystem::{
                CreateFileA, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ, OPEN_EXISTING,
            },
        },
    };

    #[test]
    fn get_filename_from_handle() {
        let filename = r"C:\WINDOWS\SYSTEM32\CMD.EXE";
        let c_filename = CString::new(filename).unwrap();
        let handle = unsafe {
            CreateFileA(
                PCSTR::from_raw(c_filename.as_ptr().cast()),
                GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        }
        .unwrap();
        let filename2 = super::get_filename_from_handle(handle).unwrap();
        assert!(filename.eq_ignore_ascii_case(&filename2));
    }
}
