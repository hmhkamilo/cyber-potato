//! Bus and memory subsystem for cyber-rs.

/// Hardware bus abstraction for memory access and I/O port delegation.
pub trait Bus {
    /// Read 8-bit byte from physical memory address.
    fn read_u8(&mut self, addr: u32) -> u8;

    /// Write 8-bit byte to physical memory address.
    fn write_u8(&mut self, addr: u32, val: u8);

    /// Read little-endian 16-bit word from physical memory address.
    fn read_u16(&mut self, addr: u32) -> u16 {
        let b0 = self.read_u8(addr) as u16;
        let b1 = self.read_u8(addr.wrapping_add(1)) as u16;
        b0 | (b1 << 8)
    }

    /// Write little-endian 16-bit word to physical memory address.
    fn write_u16(&mut self, addr: u32, val: u16) {
        self.write_u8(addr, val as u8);
        self.write_u8(addr.wrapping_add(1), (val >> 8) as u8);
    }

    /// Read little-endian 32-bit dword from physical memory address.
    fn read_u32(&mut self, addr: u32) -> u32 {
        let w0 = self.read_u16(addr) as u32;
        let w1 = self.read_u16(addr.wrapping_add(2)) as u32;
        w0 | (w1 << 16)
    }

    /// Write little-endian 32-bit dword to physical memory address.
    fn write_u32(&mut self, addr: u32, val: u32) {
        self.write_u16(addr, val as u16);
        self.write_u16(addr.wrapping_add(2), (val >> 16) as u16);
    }

    /// Port input (I/O space). Returns 0 by default if unhandled.
    fn port_in(&mut self, _port: u16, _size: u8) -> u32 {
        0
    }

    /// Port output (I/O space).
    fn port_out(&mut self, _port: u16, _val: u32, _size: u8) {}
}

/// Flat RAM implementation (1 MB standard DOS real mode + optional HMA).
#[derive(Clone, Debug)]
pub struct FlatMemory {
    pub data: Vec<u8>,
    pub a20_mask: u32,
}

impl FlatMemory {
    /// Create new memory buffer initialized with given size (default 1 MB).
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0; size],
            a20_mask: 0x001F_FFFF, // A20 enabled by default (1 MB + HMA)
        }
    }

    /// Create standard 1 MB real-mode memory.
    pub fn new_1mb() -> Self {
        Self::new(1024 * 1024)
    }

    /// Set A20 gate mask (e.g. 0x000F_FFFF for 1 MB wrapping, 0x001F_FFFF for enabled).
    pub fn set_a20_enabled(&mut self, enabled: bool) {
        self.a20_mask = if enabled { 0x001F_FFFF } else { 0x000F_FFFF };
    }

    #[inline(always)]
    fn translate(&self, addr: u32) -> usize {
        let masked = (addr & self.a20_mask) as usize;
        if masked < self.data.len() {
            masked
        } else {
            masked % self.data.len()
        }
    }
}

impl Default for FlatMemory {
    fn default() -> Self {
        Self::new_1mb()
    }
}

impl Bus for FlatMemory {
    #[inline(always)]
    fn read_u8(&mut self, addr: u32) -> u8 {
        let idx = self.translate(addr);
        self.data[idx]
    }

    #[inline(always)]
    fn write_u8(&mut self, addr: u32, val: u8) {
        let idx = self.translate(addr);
        self.data[idx] = val;
    }
}
