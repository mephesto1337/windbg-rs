use std::{
    borrow::Cow,
    io::{Read, Seek, SeekFrom, Write},
};

use windows::core::Result;

use crate::debuggee::ReadWriteMemory;

pub const BREAKPOINT_SIZE: usize = 1;
pub const BREAK_OPCODES: [u8; BREAKPOINT_SIZE] = [0xcc];

#[derive(Debug, Clone)]
pub struct Breakpoint {
    id: usize,
    addr: usize,
    saved_bc: [u8; BREAKPOINT_SIZE],
    one_shot: bool,
    label: Option<Cow<'static, str>>,
}

impl Breakpoint {
    pub fn id(&self) -> usize {
        self.id
    }
    pub fn set_label(&mut self, label: impl Into<Cow<'static, str>>) -> &mut Self {
        self.label = Some(label.into());
        self
    }
    pub fn label(&self) -> Option<&str> {
        self.label.as_ref().map(|s| s.as_ref())
    }
    pub fn addr(&self) -> usize {
        self.addr
    }
    pub fn saved_bc(&self) -> &[u8] {
        &self.saved_bc[..]
    }
    pub fn is_one_shot(&self) -> bool {
        self.one_shot
    }
    pub fn set_one_shot(&mut self) -> &mut Self {
        self.one_shot = true;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct Breakpoints {
    bp: Vec<Option<Breakpoint>>,
}

impl Breakpoints {
    #[tracing::instrument(skip_all, fields(addr = mem.addr()))]
    pub fn add(&mut self, mem: &mut ReadWriteMemory) -> Result<&mut Breakpoint> {
        let mut saved_bc = [0u8; BREAKPOINT_SIZE];

        let offset = mem.stream_position()?;
        let addr = mem.addr();
        mem.read_exact(&mut saved_bc[..])?;
        mem.seek(SeekFrom::Start(offset))?;
        mem.write(&BREAK_OPCODES[..])?;

        let bp = self.alloc_bp();
        bp.addr = addr;
        bp.saved_bc.copy_from_slice(&saved_bc);
        tracing::debug!(
            "Added breakpoint #{id} at 0x{addr:x} ({saved_bc:x?} -> {:x?})",
            &BREAK_OPCODES,
            id = bp.id()
        );
        Ok(bp)
    }

    #[tracing::instrument(skip(self), fields(addr = mem.addr()), ret)]
    pub fn add_many(&mut self, mem: &mut ReadWriteMemory, addrs: &[usize]) -> Result<()> {
        mem.seek(SeekFrom::Start(0))?;
        let start_addr = mem.addr() as u64;

        for addr in addrs {
            let offset = *addr as u64 - start_addr;
            mem.seek(SeekFrom::Start(offset))?;
            assert_eq!(mem.addr(), *addr);
            self.add(mem)?;
        }
        Ok(())
    }

    fn alloc_bp(&mut self) -> &mut Breakpoint {
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
            id: idx,
            one_shot: false,
            addr: 0,
            saved_bc: [0u8; BREAKPOINT_SIZE],
            label: None,
        };
        let place = unsafe { self.bp.get_unchecked_mut(idx) };
        *place = Some(bp);
        unsafe { place.as_mut().unwrap_unchecked() }
    }

    #[tracing::instrument(skip(self, mem), fields(addr = mem.addr()), ret)]
    pub fn remove(&mut self, mem: &mut ReadWriteMemory, id: usize) -> Result<()> {
        let Some(Breakpoint { addr, saved_bc, .. }) = self.bp.get_mut(id).and_then(|x| x.take())
        else {
            return Ok(());
        };

        assert_eq!(addr, mem.addr());
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
