use windows::Win32::System::Diagnostics::Debug::CREATE_THREAD_DEBUG_INFO;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateThreadInfo {
    pub local_base: usize,
    pub start_address: usize,
}

impl From<CREATE_THREAD_DEBUG_INFO> for CreateThreadInfo {
    fn from(value: CREATE_THREAD_DEBUG_INFO) -> Self {
        Self {
            local_base: value.lpThreadLocalBase as usize,
            start_address: value.lpStartAddress.map(|a| a as usize).unwrap_or(0),
        }
    }
}
