pub mod debuggee;
pub mod debugger;
pub mod process;
mod registers;

pub use debuggee::Debuggee;
pub use debugger::Debugger;
pub use registers::Registers;

pub(crate) mod utils;
