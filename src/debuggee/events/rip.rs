use windows::Win32::{
    Foundation::WIN32_ERROR,
    System::Diagnostics::Debug::{RIP_INFO, RIP_INFO_TYPE, SLE_ERROR, SLE_MINORERROR, SLE_WARNING},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rip {
    Error,
    MinorError,
    Warning,
    WinError(WIN32_ERROR),
}

impl From<RIP_INFO> for Rip {
    fn from(value: RIP_INFO) -> Self {
        match value.dwType {
            SLE_ERROR => Self::Error,
            SLE_MINORERROR => Self::MinorError,
            SLE_WARNING => Self::Warning,
            RIP_INFO_TYPE(0) => Self::WinError(WIN32_ERROR(value.dwError)),
            RIP_INFO_TYPE(val) => unreachable!("Invalid RIP_INFO_TYPE: {val}"),
        }
    }
}
