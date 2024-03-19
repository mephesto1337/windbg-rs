use std::{ffi::CStr, mem::size_of};
use windows::{
    core::{Error, Result},
    Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_DATA, ERROR_UNSUPPORTED_TYPE},
};

const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

/// Nt DOS header
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: u32,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader32 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub base_of_data: u32,
    pub image_base: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u32,
    pub size_of_stack_commit: u32,
    pub size_of_heap_reserve: u32,
    pub size_of_heap_commit: u32,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionalHeader {
    OptionalHeader32(OptionalHeader32),
    OptionalHeader64(OptionalHeader64),
}

impl OptionalHeader {
    pub fn size_of_image(&self) -> usize {
        (match self {
            OptionalHeader::OptionalHeader32(ref o32) => o32.size_of_image,
            OptionalHeader::OptionalHeader64(ref o64) => o64.size_of_image,
        }) as usize
    }

    pub fn image_base(&self) -> usize {
        match self {
            OptionalHeader::OptionalHeader32(ref o32) => o32.image_base as usize,
            OptionalHeader::OptionalHeader64(ref o64) => o64.image_base as usize,
        }
    }

    pub fn entry_point(&self) -> usize {
        match self {
            OptionalHeader::OptionalHeader32(ref o32) => o32.address_of_entry_point as usize,
            OptionalHeader::OptionalHeader64(ref o64) => o64.address_of_entry_point as usize,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ImageNtHeader {
    signature: u32,
    file_header: FileHeader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageHeader {
    pub signature: u32,
    pub file_header: FileHeader,
    pub optional_header: OptionalHeader,
}

macro_rules! from_buffer {
    ($input:expr, $type:ty, $count:expr) => {{
        fn func(input: &[u8], count: usize) -> windows::core::Result<(&[$type], &[u8])> {
            let size = size_of::<$type>() * count;
            if input.len() < size {
                Err(Error::new(
                    ERROR_INSUFFICIENT_BUFFER.into(),
                    concat!(
                        "Buffer is too small for [",
                        stringify!($type),
                        "; ",
                        stringify!($count),
                        "]"
                    ),
                ))
            } else {
                let s: &[$type] =
                    unsafe { std::slice::from_raw_parts(input.as_ptr().cast(), count) };
                Ok((s, &input[size..]))
            }
        }
        func($input, $count as usize)
    }};
    ($input:expr, $type:ty) => {{
        fn func(input: &[u8]) -> windows::core::Result<(&$type, &[u8])> {
            let size = size_of::<$type>();
            if input.len() < size {
                Err(Error::new(
                    ERROR_INSUFFICIENT_BUFFER.into(),
                    concat!("Buffer is too small for ", stringify!($type)),
                ))
            } else {
                let s: &$type = unsafe { &*input.as_ptr().cast() };
                Ok((s, &input[size..]))
            }
        }
        func($input)
    }};
}

pub fn parse_headers(input: &[u8]) -> Result<ImageHeader> {
    let (dos_header, _) = from_buffer!(input, DosHeader)?;
    if dos_header.e_magic != u16::from_ne_bytes(*b"MZ") {
        return Err(Error::new(
            ERROR_INVALID_DATA.into(),
            "Invalid magic for DOS header",
        ));
    }

    let (nt_header, input_opt_header) =
        from_buffer!(&input[dos_header.e_lfanew as usize..], ImageNtHeader)?;
    if nt_header.signature != u32::from_ne_bytes(*b"PE\0\0") {
        return Err(Error::new(
            ERROR_INVALID_DATA.into(),
            "Invalid magic for NT header",
        ));
    }

    let file_header = nt_header.file_header.clone();
    let optional_header = match file_header.machine {
        IMAGE_FILE_MACHINE_I386 => {
            let (opt, _) = from_buffer!(input_opt_header, OptionalHeader32)?;
            if opt.magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC {
                return Err(Error::new(
                    ERROR_INVALID_DATA.into(),
                    "Invalud magic for Optional header 32",
                ));
            }
            OptionalHeader::OptionalHeader32(opt.clone())
        }
        IMAGE_FILE_MACHINE_AMD64 => {
            let (opt, _) = from_buffer!(input_opt_header, OptionalHeader64)?;
            if opt.magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC {
                return Err(Error::new(
                    ERROR_INVALID_DATA.into(),
                    "Invalud magic for Optional header 64",
                ));
            }
            OptionalHeader::OptionalHeader64(opt.clone())
        }
        _ => {
            return Err(Error::new(
                ERROR_UNSUPPORTED_TYPE.into(),
                "Only i386 and amd64 optional headers are supported",
            ));
        }
    };

    Ok(ImageHeader {
        signature: nt_header.signature,
        file_header,
        optional_header,
    })
}

pub fn parse_symbols(input: &[u8], hdr: &ImageHeader) -> Result<(String, Vec<(usize, String)>)> {
    let export_table_info = match hdr.optional_header {
        OptionalHeader::OptionalHeader32(ref o32) => {
            &o32.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        }
        OptionalHeader::OptionalHeader64(ref o64) => {
            &o64.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        }
    };

    if export_table_info.virtual_address == 0 {
        return Ok((
            String::new(),
            vec![(hdr.optional_header.entry_point(), "_entry".into())],
        ));
    }

    let export_tables_buf =
        &input[export_table_info.virtual_address as usize..][..export_table_info.size as usize];
    let (export_table, _) = from_buffer!(export_tables_buf, ImageExportDirectory)?;

    let mut symbols = Vec::with_capacity(export_table.number_of_names as usize + 1);
    symbols.push((hdr.optional_header.entry_point(), "_entry".into()));

    let module_name =
        unsafe { ::std::ffi::CStr::from_ptr(input[export_table.name as usize..].as_ptr().cast()) }
            .to_string_lossy()
            .into_owned();

    let (ordinals, _) = from_buffer!(
        &input[export_table.address_of_name_ordinals as usize..],
        u16,
        export_table.number_of_names
    )?;
    let (name_indexes, _) = from_buffer!(
        &input[export_table.address_of_names as usize..],
        u32,
        export_table.number_of_names
    )?;
    let (func_addresses, _) = from_buffer!(
        &input[export_table.address_of_functions as usize..],
        u32,
        export_table.number_of_functions
    )?;

    let export_table_start = export_table_info.virtual_address as usize;
    let export_table_end = export_table_start + export_table_info.size as usize;
    let is_forwarded = |addr: usize| export_table_start <= addr && addr < export_table_end;

    for (idx, addr) in func_addresses.iter().map(|a| *a as usize).enumerate() {
        if is_forwarded(addr) {
            continue;
        }
        let Some(name_index) = ordinals.iter().position(|&o| o as usize == idx) else {
            continue;
        };

        let name =
            unsafe { CStr::from_ptr(input[name_indexes[name_index] as usize..].as_ptr().cast()) }
                .to_string_lossy()
                .into_owned();
        symbols.push((addr, name));
    }

    symbols.sort_unstable_by(|a, b| a.0.cmp(&b.0));

    Ok((module_name, symbols))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let content = std::fs::read(r"C:\windows\system32\kernel32.dll").unwrap();
        let hdr = super::parse_headers(&content[..]).unwrap();
        eprintln!("{hdr:#x?}");
        let symbols = super::parse_symbols(&content[..], &hdr).unwrap();
        eprintln!("{symbols:#x?}");
    }
}
