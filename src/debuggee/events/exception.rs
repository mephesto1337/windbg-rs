use std::ptr;
use windows::Win32::{
    Foundation::{
        EXCEPTION_ACCESS_VIOLATION, EXCEPTION_ARRAY_BOUNDS_EXCEEDED, EXCEPTION_BREAKPOINT,
        EXCEPTION_DATATYPE_MISALIGNMENT, EXCEPTION_FLT_DENORMAL_OPERAND,
        EXCEPTION_FLT_DIVIDE_BY_ZERO, EXCEPTION_FLT_INEXACT_RESULT,
        EXCEPTION_FLT_INVALID_OPERATION, EXCEPTION_FLT_OVERFLOW, EXCEPTION_FLT_STACK_CHECK,
        EXCEPTION_FLT_UNDERFLOW, EXCEPTION_GUARD_PAGE, EXCEPTION_ILLEGAL_INSTRUCTION,
        EXCEPTION_INT_DIVIDE_BY_ZERO, EXCEPTION_INT_OVERFLOW, EXCEPTION_INVALID_DISPOSITION,
        EXCEPTION_INVALID_HANDLE, EXCEPTION_IN_PAGE_ERROR, EXCEPTION_NONCONTINUABLE_EXCEPTION,
        EXCEPTION_POSSIBLE_DEADLOCK, EXCEPTION_PRIV_INSTRUCTION, EXCEPTION_SINGLE_STEP,
        EXCEPTION_SPAPI_UNRECOVERABLE_STACK_OVERFLOW, EXCEPTION_STACK_OVERFLOW, NTSTATUS,
    },
    System::Diagnostics::Debug::{EXCEPTION_DEBUG_INFO, EXCEPTION_RECORD},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExceptionCode {
    AccessViolation,
    ArrayBoundsExceeded,
    Breakpoint,
    DatatypeMisalignment,
    FltDenormalOperand,
    FltDivideByZero,
    FltInexactResult,
    FltInvalidOperation,
    FltOverflow,
    FltStackCheck,
    FltUnderflow,
    GuardPage,
    IllegalInstruction,
    IntDivideByZero,
    IntOverflow,
    InvalidDisposition,
    InvalidHandle,
    InPageError,
    NonContinuableException,
    PossibleDeadlock,
    PrivInstruction,
    SingleStep,
    SpapiUnrecoverableStackOverflow,
    StackOverflow,
    Other(NTSTATUS),
}

impl ExceptionCode {
    pub fn other(&self) -> Option<i32> {
        match self {
            Self::Other(NTSTATUS(c)) => Some(*c),
            _ => None,
        }
    }
}

impl From<NTSTATUS> for ExceptionCode {
    fn from(code: NTSTATUS) -> Self {
        match code {
            EXCEPTION_ACCESS_VIOLATION => Self::AccessViolation,
            EXCEPTION_ARRAY_BOUNDS_EXCEEDED => Self::ArrayBoundsExceeded,
            EXCEPTION_BREAKPOINT => Self::Breakpoint,
            EXCEPTION_DATATYPE_MISALIGNMENT => Self::DatatypeMisalignment,
            EXCEPTION_FLT_DENORMAL_OPERAND => Self::FltDenormalOperand,
            EXCEPTION_FLT_DIVIDE_BY_ZERO => Self::FltDivideByZero,
            EXCEPTION_FLT_INEXACT_RESULT => Self::FltInexactResult,
            EXCEPTION_FLT_INVALID_OPERATION => Self::FltInvalidOperation,
            EXCEPTION_FLT_OVERFLOW => Self::FltOverflow,
            EXCEPTION_FLT_STACK_CHECK => Self::FltStackCheck,
            EXCEPTION_FLT_UNDERFLOW => Self::FltUnderflow,
            EXCEPTION_GUARD_PAGE => Self::GuardPage,
            EXCEPTION_ILLEGAL_INSTRUCTION => Self::IllegalInstruction,
            EXCEPTION_INT_DIVIDE_BY_ZERO => Self::IntDivideByZero,
            EXCEPTION_INT_OVERFLOW => Self::IntOverflow,
            EXCEPTION_INVALID_DISPOSITION => Self::InvalidDisposition,
            EXCEPTION_INVALID_HANDLE => Self::InvalidHandle,
            EXCEPTION_IN_PAGE_ERROR => Self::InPageError,
            EXCEPTION_NONCONTINUABLE_EXCEPTION => Self::NonContinuableException,
            EXCEPTION_POSSIBLE_DEADLOCK => Self::PossibleDeadlock,
            EXCEPTION_PRIV_INSTRUCTION => Self::PrivInstruction,
            EXCEPTION_SINGLE_STEP => Self::SingleStep,
            EXCEPTION_SPAPI_UNRECOVERABLE_STACK_OVERFLOW => Self::SpapiUnrecoverableStackOverflow,
            EXCEPTION_STACK_OVERFLOW => Self::StackOverflow,
            _ => Self::Other(code),
        }
    }
}

impl From<u32> for ExceptionCode {
    fn from(value: u32) -> Self {
        NTSTATUS(value as i32).into()
    }
}
#[derive(Debug, PartialEq, Eq)]

pub struct ExceptionInfo {
    pub chain: Vec<Exception>,
    pub first_chance: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Exception {
    pub code: ExceptionCode,
    pub flags: u32,
    pub address: usize,
    pub parameters: Vec<usize>,
}

impl Exception {
    fn from(value: EXCEPTION_RECORD) -> (Self, *const EXCEPTION_RECORD) {
        let parameters = value
            .ExceptionInformation
            .iter()
            .copied()
            .take(value.NumberParameters as usize)
            .collect();

        (
            Self {
                code: value.ExceptionCode.into(),
                flags: value.ExceptionFlags,
                address: value.ExceptionAddress as usize,
                parameters,
            },
            value.ExceptionRecord.cast_const(),
        )
    }
}

impl From<EXCEPTION_DEBUG_INFO> for ExceptionInfo {
    fn from(value: EXCEPTION_DEBUG_INFO) -> Self {
        let mut chain = Vec::with_capacity(1);
        let first_chance = value.dwFirstChance != 0;
        let mut e = value.ExceptionRecord;
        loop {
            let (cur, nxt) = Exception::from(e);
            chain.push(cur);
            if nxt.is_null() {
                break;
            }
            e = unsafe { ptr::read(nxt) };
        }

        Self {
            chain,
            first_chance,
        }
    }
}
