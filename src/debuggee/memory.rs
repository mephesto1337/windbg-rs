use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    ops::Neg,
};
use windows::{core::Result, Win32::Foundation::HANDLE};

use crate::utils::memory::{self, change_protect, get_protection, PageProtection};

#[derive(Debug)]
struct Memory {
    start: usize,
    size: usize,
    offset: usize,
    handle: HANDLE,
    old_prot: Option<PageProtection>,
}

impl Memory {
    pub fn addr(&self) -> usize {
        self.start + self.offset
    }

    fn new(start: usize, size: usize, handle: HANDLE, prot: PageProtection) -> Result<Self> {
        let cur_prot = get_protection(handle, start)?;
        let old_prot = if cur_prot & prot == prot {
            None
        } else {
            Some(change_protect(handle, start, size, prot)?)
        };

        Ok(Self {
            start,
            size,
            offset: 0,
            handle,
            old_prot,
        })
    }
}

#[derive(Debug)]
pub struct ReadOnlyMemory(Memory);

impl ReadOnlyMemory {
    pub(super) fn new(start: usize, size: usize, handle: HANDLE) -> Result<Self> {
        let mem = Memory::new(start, size, handle, PageProtection::READ)?;
        Ok(Self(mem))
    }

    pub fn addr(&self) -> usize {
        self.0.addr()
    }
}

#[derive(Debug)]
pub struct ReadWriteMemory(Memory);

impl ReadWriteMemory {
    pub(super) fn new(start: usize, size: usize, handle: HANDLE) -> Result<Self> {
        let mem = Memory::new(start, size, handle, PageProtection::READ_WRITE)?;
        Ok(Self(mem))
    }

    pub fn addr(&self) -> usize {
        self.0.addr()
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        if let Some(prot) = self.old_prot.take() {
            let _ = change_protect(self.handle, self.start, self.size, prot);
        }
    }
}

impl Read for Memory {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        if self.offset >= self.size {
            return Ok(0);
        }
        let max_read = self.size - self.offset;
        if buf.len() > max_read {
            buf = &mut buf[..max_read];
        }

        let n = memory::read(self.handle, self.start + self.offset, buf)
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        self.offset += n;
        Ok(n)
    }
}

impl Write for Memory {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        if self.offset >= self.size {
            return Ok(0);
        }
        let max_write = self.size - self.offset;
        if buf.len() > max_write {
            buf = &buf[..max_write];
        }

        let n = memory::write(self.handle, self.start + self.offset, buf)
            .map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        self.offset += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for ReadOnlyMemory {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Read for ReadWriteMemory {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for ReadWriteMemory {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Seek for Memory {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(o) => {
                if o > self.size as u64 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "offset is out of bounds",
                    ));
                }
                self.offset = o as usize;
            }
            SeekFrom::End(o) => {
                if o < 0 {
                    let o: u64 = o.neg().try_into().expect("o should be positive");
                    self.offset = self.size.checked_sub(o as usize).ok_or(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Cannot go before start",
                    ))?;
                } else if o == 0 {
                    self.offset = self.size;
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Cannot go past end",
                    ));
                }
            }
            SeekFrom::Current(o) => {
                if o < 0 {
                    let o: u64 = o.neg().try_into().expect("o should be positive");
                    self.offset = self
                        .offset
                        .checked_sub(o.try_into().unwrap_or(usize::MAX))
                        .ok_or(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Cannot go before start",
                        ))?;
                } else if o == 0 {
                    // Nothing
                } else {
                    let o: u64 = o.try_into().expect("o should be positive");
                    self.offset = self
                        .offset
                        .saturating_add(o.try_into().unwrap_or(usize::MAX));
                    if self.offset > self.size {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Cannot go past end",
                        ));
                    }
                }
            }
        }
        Ok(self.offset as u64)
    }
}

impl Seek for ReadOnlyMemory {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}

impl Seek for ReadWriteMemory {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.0.seek(pos)
    }
}
