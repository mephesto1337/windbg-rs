use std::{
    fmt::{self, Write},
    mem::{size_of, MaybeUninit},
};
use windows::{core::Result, Win32::Storage::FileSystem::WIN32_FIND_DATAW};

use debugger::Debuggee;

#[derive(Clone, Copy, PartialEq, Eq)]
enum StringMode {
    Unicode,
    Ansi,
}

impl fmt::Display for StringMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unicode => f.write_char('W'),
            Self::Ansi => f.write_char('A'),
        }
    }
}

macro_rules! impl_handler {
    ($func:ident ( $($tail:tt)* )) => {
        pub(super) fn $func(debuggee: &mut Debuggee, args: &[usize], ret: usize) -> Result<()> {
            impl_handler!(__priv_expand_args $($tail)* ,);
            let mut buf = format!("{}(", stringify!($func));

            impl_handler!(__priv_expand_fmt (&mut buf), $($tail)*);
            println!("{buf}) = 0x{ret:x}");
            Ok(())
        }
    };
    (__priv_expand_fmt) => {};
    (__priv_expand_fmt $buf:expr, $name:ident : ptr $type:path, $($tail:tt)*) => {
        write!($buf, concat!("{", stringify!($name), ":x?}, "));
        impl_handler!(__priv_expand_fmt $buf, $($tail)*);
    };
    (__priv_expand_fmt $name:ident : string , $($tail:tt)*) => {
        write!($buf, concat!("{", stringify!($name), "}, "));
        impl_handler!(__priv_expand_fmt $buf, $($tail)*);
    };
    (__priv_expand_fmt $name:ident : $type:ty, $($tail:tt)*) => {
        write!($buf, concat!("{", stringify!($name), ":x?}, "));
        impl_handler!(__priv_expand_fmt $buf, $($tail)*);
    };
    (__priv_expand_args $($tail:tt)*) => {
        impl_handler!(__priv_count 0 , $($tail)*);
    };
    (__priv_count $count:expr ) => {};
    (__priv_count $count:expr , ) => {};
    (__priv_count $count:expr , $name:ident : ptr $type:path , $($tail:tt)*) => {
        let $name = deref_struct<$type>(debuggee, args[$count])?;
        impl_handler!(__priv_count $count + 1 , $($tail)*);
    };
    (__priv_count $count:expr , $name:ident : string , $($tail:tt)*) => {
        let $name = debuggee.read_string(args[$count], true)?;
        impl_handler!(__priv_count $count + 1 , $($tail)*);
    };
    (__priv_count $count:expr , $name:ident : $type:ty , $($tail:tt)*) => {
        let $name = args[$count] as $type;
        impl_handler!(__priv_count $count + 1 , $($tail)*);
    };
}

impl_handler!(CreateFileW ( filename : string, desired_access : u32, share_mode : u32));

fn deref_struct<T: Sized>(debuggee: &mut Debuggee, addr: usize) -> Result<T> {
    let mut strct = MaybeUninit::<T>::uninit();
    let buf: &mut [u8] =
        unsafe { std::slice::from_raw_parts_mut(strct.as_mut_ptr().cast(), size_of::<T>()) };
    debuggee.read_memory(addr, buf)?;
    drop(buf);
    Ok(unsafe { strct.assume_init() })
}

fn createfile(mode: StringMode, debuggee: &mut Debuggee, args: &[usize], ret: usize) -> Result<()> {
    let filename = debuggee.read_string(args[0], mode == StringMode::Unicode)?;
    let desired_access = args[1];
    let share_mode = args[2];
    println!("CreateFile{mode}({filename:?}, {desired_access:x}, {share_mode:x}, ...) = 0x{ret:x}");
    Ok(())
}

pub(super) fn createfilea(debuggee: &mut Debuggee, args: &[usize], ret: usize) -> Result<()> {
    createfile(StringMode::Ansi, debuggee, args, ret)
}

pub(super) fn createfilew(debuggee: &mut Debuggee, args: &[usize], ret: usize) -> Result<()> {
    createfile(StringMode::Unicode, debuggee, args, ret)
}

pub(super) fn findfirstfilew(debuggee: &mut Debuggee, args: &[usize], ret: usize) -> Result<()> {
    let filename = debuggee.read_string(args[0], true)?;
    let ffd = deref_struct::<WIN32_FIND_DATAW>(debuggee, args[1])?;
    println!("FindFirstFileW({filename:?}, {ffd:x?}) = 0x{ret:x}");
    Ok(())
}

pub(super) fn getfileattributesw(
    debuggee: &mut Debuggee,
    args: &[usize],
    ret: usize,
) -> Result<()> {
    let filename = debuggee.read_string(args[0], true)?;
    println!("GetFileAttributesW({filename:?}) = 0x{ret:x}");
    Ok(())
}

pub(super) fn getmodulefilenamew(
    debuggee: &mut Debuggee,
    args: &[usize],
    ret: usize,
) -> Result<()> {
    let module = args[0];
    let filename = debuggee.read_string(args[1], true)?;
    let size = args[2];
    println!("GetModuleFileNameW({module:x}, {filename:?}, {size}) = 0x{ret:x}");
    Ok(())
}

pub(super) fn getfiletype(debuggee: &mut Debuggee, args: &[usize], ret: usize) -> Result<()> {
    let handle = args[0];
    println!("GetFileType({handle:x}) = 0x{ret:x}");
    Ok(())
}
