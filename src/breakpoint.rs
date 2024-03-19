use std::io::{Read, Seek, SeekFrom, Write};

use windows::core::Result;

use crate::debuggee::ReadWriteMemory;

pub const BREAKPOINT_SIZE: usize = 1;
pub const BREAK_OPCODES: [u8; BREAKPOINT_SIZE] = [0xcc];

#[derive(Debug, Clone, Copy)]
pub struct Breakpoint {
    pub(crate) addr: usize,
    pub(crate) saved_bc: [u8; BREAKPOINT_SIZE],
    pub(crate) one_shot: bool,
}

impl Breakpoint {
    pub fn addr(&self) -> usize {
        self.addr
    }
    pub fn saved_bc(&self) -> [u8; BREAKPOINT_SIZE] {
        self.saved_bc
    }
    pub fn is_one_shot(&self) -> bool {
        self.one_shot
    }
    pub fn set_one_shot(&mut self) {
        self.one_shot = true
    }
}

#[derive(Debug, Clone, Default)]
pub struct Breakpoints {
    bp: Vec<Option<Breakpoint>>,
}

impl Breakpoints {
    #[tracing::instrument(skip(self), ret)]
    pub fn add(&mut self, mem: &mut ReadWriteMemory) -> Result<usize> {
        let mut saved_bc = [0u8; BREAKPOINT_SIZE];

        let addr = mem.addr();
        mem.read_exact(&mut saved_bc[..])?;
        mem.seek(SeekFrom::Start(0))?;
        mem.write(&BREAK_OPCODES[..])?;

        let (id, bp) = self.alloc_bp();
        bp.addr = addr;
        bp.saved_bc.copy_from_slice(&saved_bc);
        tracing::info!("Added breakpoint #{id} at 0x{addr:x}");
        Ok(id)
    }

    fn alloc_bp(&mut self) -> (usize, &mut Breakpoint) {
        let idx = match self
            .bp
            .iter()
            .enumerate()
            .find_map(|(idx, val)| val.is_none().then_some(idx))
        {
            Some(idx) => idx,
            None => {
                let idx = self.bp.len();
                self.bp.push(None);
                idx
            }
        };
        let bp = Breakpoint {
            one_shot: false,
            addr: 0,
            saved_bc: [0u8; BREAKPOINT_SIZE],
        };
        let place = unsafe { self.bp.get_unchecked_mut(idx) };
        *place = Some(bp);
        (idx, unsafe { place.as_mut().unwrap_unchecked() })
    }

    #[tracing::instrument(skip(self), ret)]
    pub fn remove(&mut self, mem: &mut ReadWriteMemory, id: usize) -> Result<()> {
        let Some(Breakpoint { addr, saved_bc, .. }) = self.bp.get_mut(id).and_then(|x| x.take())
        else {
            return Ok(());
        };

        assert_eq!(addr as u64, mem.stream_position().unwrap());
        mem.write_all(&saved_bc[..])?;
        tracing::info!("Removed breakpoint #{id} at 0x{addr:x}");
        Ok(())
    }

    pub fn get(&self, id: usize) -> Option<&Breakpoint> {
        self.bp.get(id).and_then(|bp| bp.as_ref())
    }

    pub fn get_by_addr(&self, addr: usize) -> Option<&Breakpoint> {
        self.bp
            .iter()
            .filter_map(|b| b.as_ref())
            .find(|&b| b.addr == addr)
    }
}
