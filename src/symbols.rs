use core::fmt;
use std::path::Path;

use windows::{core::Result, Win32::Foundation::HANDLE};

use crate::utils::{
    memory::{self, PAGE_SIZE},
    read_into_unitialized,
};

use self::pe::ImageHeader;

mod pe;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Image {
    name: String,
    header: ImageHeader,
    symbols: Vec<(usize, String)>,
    base_addr: usize,
    end_addr: usize,
}

impl fmt::Display for Image {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}(0x{:x})", self.name, self.base_addr)
    }
}

impl Image {
    pub(crate) fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let buf = std::fs::read(path)?;
        Self::build_inner(&buf[..], None, 0)
    }

    pub(crate) fn build(handle: HANDLE, base_addr: usize) -> Result<Self> {
        let mut pe = Vec::with_capacity(PAGE_SIZE);

        read_into_unitialized(&mut pe, |buf: &mut [u8]| -> Result<usize> {
            memory::read(handle, base_addr, buf)
        })?;
        let hdr = pe::parse_headers(&pe[..])?;
        let total_size = hdr.optional_header.size_of_image();
        if total_size > pe.len() {
            let additional = total_size - pe.len();
            pe.reserve(additional);
            let base_addr = base_addr + pe.len();
            read_into_unitialized(&mut pe, |buf: &mut [u8]| -> Result<usize> {
                memory::read(handle, base_addr, &mut buf[..additional])
            })?;
        }

        Self::build_inner(&pe[..], Some(hdr), base_addr)
    }

    fn build_inner(buf: &[u8], hdr: Option<ImageHeader>, mut base_addr: usize) -> Result<Self> {
        let header = match hdr {
            Some(h) => h,
            None => pe::parse_headers(buf)?,
        };
        let (name, symbols) = pe::parse_symbols(buf, &header)?;

        if base_addr == 0 {
            base_addr = header.optional_header.image_base();
        }

        Ok(Self {
            name,
            symbols,
            base_addr,
            end_addr: base_addr + header.optional_header.size_of_image(),
            header,
        })
    }

    pub fn resolv(&self, symbol: &str) -> Option<usize> {
        self.symbols.iter().find_map(|(addr, name)| {
            name.eq_ignore_ascii_case(symbol)
                .then_some(self.base_addr + *addr)
        })
    }

    pub fn lookup_addr(&self, addr: usize) -> Option<String> {
        if !self.contains(addr) {
            return None;
        }

        let addr = addr - self.base_addr;
        Some(match self.symbols.binary_search_by(|x| x.0.cmp(&addr)) {
            Ok(idx) => self.symbols[idx].1.clone(),
            Err(idx) => {
                assert!(idx > 1);
                let (s_addr, s_name) = &self.symbols[idx - 1];
                format!(
                    "{module}!{s_name}+0x{offset:x}",
                    module = self.name(),
                    offset = addr - *s_addr
                )
            }
        })
    }

    pub fn header(&self) -> &ImageHeader {
        &self.header
    }

    pub fn base_addr(&self) -> usize {
        self.base_addr
    }

    pub fn contains(&self, addr: usize) -> bool {
        self.base_addr <= addr && addr < self.end_addr
    }
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}
