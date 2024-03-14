use windows::Win32::System::Diagnostics::Debug::LOAD_DLL_DEBUG_INFO;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadDll {
    pub filename: Option<String>,
    pub base_addr: usize,
}

impl From<LOAD_DLL_DEBUG_INFO> for LoadDll {
    fn from(value: LOAD_DLL_DEBUG_INFO) -> Self {
        Self {
            filename: crate::utils::get_filename_from_handle(value.hFile).ok(),
            base_addr: value.lpBaseOfDll as usize,
        }
    }
}
