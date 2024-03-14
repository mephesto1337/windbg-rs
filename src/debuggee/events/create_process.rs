use windows::Win32::System::Diagnostics::Debug::CREATE_PROCESS_DEBUG_INFO;

use crate::{process::get_image_name, utils::get_filename_from_handle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateProcessInfo {
    pub image_name: Option<String>,
}

impl From<CREATE_PROCESS_DEBUG_INFO> for CreateProcessInfo {
    fn from(value: CREATE_PROCESS_DEBUG_INFO) -> Self {
        Self {
            image_name: get_filename_from_handle(value.hProcess)
                .or_else(|_| get_image_name(value.hProcess))
                .ok(),
        }
    }
}
