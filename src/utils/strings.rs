use std::{borrow::Cow, mem::size_of};

use super::read_memory;
use windows::{
    core::{Error, Result},
    Win32::Foundation::{ERROR_NOT_FOUND, HANDLE},
};

macro_rules! impl_read_null_terminated_buffer {
    ($name:ident, $type:ty) => {
        fn $name(handle: HANDLE, mut addr: usize) -> Result<Vec<$type>> {
            let mut null_terminated_buf = Vec::with_capacity(256);
            let mut bytes_read = 0;
            const MAX_READ_SIZE: usize = 0x1000;

            loop {
                if bytes_read >= MAX_READ_SIZE {
                    return Err(Error::new(
                        ERROR_NOT_FOUND.into(),
                        "Could not find null terminator",
                    ));
                }
                let uninit_buf = null_terminated_buf.spare_capacity_mut();
                let buf: &mut [u8] = unsafe {
                    std::slice::from_raw_parts_mut(
                        uninit_buf.as_mut_ptr().cast(),
                        uninit_buf.len() * size_of::<$type>(),
                    )
                };
                let n = read_memory(handle, addr, buf)?;
                bytes_read += n;
                addr += n;
                if let Some(index) = null_terminated_buf
                    .iter()
                    .enumerate()
                    .skip(bytes_read / size_of::<$type>())
                    .find_map(|(i, &b)| (b == 0).then_some(i))
                {
                    // Null terminator is _NOT_ included
                    null_terminated_buf.truncate(index);
                    return Ok(null_terminated_buf);
                }
            }
        }
    };
}

impl_read_null_terminated_buffer!(read_string_u8, u8);
impl_read_null_terminated_buffer!(read_string_u16, u16);

pub fn read_string_utf8(handle: HANDLE, addr: usize) -> Result<String> {
    let buf = read_string_u8(handle, addr)?;
    Ok(match String::from_utf8(buf) {
        Ok(s) => s,
        Err(e) => {
            let buf = e.into_bytes();
            match String::from_utf8_lossy(&buf[..(buf.len() - 1)]) {
                Cow::Borrowed(_) => {
                    unreachable!("String is supposed not to be valid UTF-8")
                }
                Cow::Owned(o) => o,
            }
        }
    })
}

pub fn read_string_utf16(handle: HANDLE, addr: usize) -> Result<String> {
    let buf = read_string_u16(handle, addr)?;
    Ok(String::from_utf16_lossy(&buf[..]))
}
