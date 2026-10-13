//! 16-bit real-mode (8086/80286/80386 real mode) x86 CPU core.
//! Pure standard library implementation with zero external crate dependencies.

use crate::bus::Bus;

/// EFLAGS bit masks
pub const FLAG_CF: u32 = 1 << 0;
pub const FLAG_PF: u32 = 1 << 2;
pub const FLAG_AF: u32 = 1 << 4;
pub const FLAG_ZF: u32 = 1 << 6;
pub const FLAG_SF: u32 = 1 << 7;
pub const FLAG_TF: u32 = 1 << 8;
pub const FLAG_IF: u32 = 1 << 9;
pub const FLAG_DF: u32 = 1 << 10;
pub const FLAG_OF: u32 = 1 << 11;

/// CPU Fault conditions
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    DivideError,
    InvalidOpcode(u8),
    GeneralProtectionFault(u16),
    StackFault,
    BoundsCheck,
}

/// Execution step result for delegating hardware / system calls outside the CPU
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepResult {
    /// Normal instruction execution completed
    Ok,
    /// Software interrupt triggered (e.g. int 21h, int 10h, int 33h)
    Int(u8),
    /// Port input requested by instruction (e.g. in al, dx)
    PortIn { port: u16, size: u8 },
    /// Port output requested by instruction (e.g. out dx, al)
    PortOut { port: u16, val: u32, size: u8 },
    /// CPU executed HLT instruction
    Halt,
    /// CPU Fault occurred
    Fault(Fault),
}

/// CPU Register State
#[derive(Clone, Debug)]
pub struct Cpu {
    // 32-bit General Purpose Registers
    pub eax: u32,
    pub ecx: u32,
    pub edx: u32,
    pub ebx: u32,
    pub esp: u32,
    pub ebp: u32,
    pub esi: u32,
    pub edi: u32,

    // Segment Registers
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub ss: u16,
    pub fs: u16,
    pub gs: u16,

    // Instruction Pointer
    pub ip: u16,

    // Flags
    pub eflags: u32,

    // Halt state
    pub halted: bool,
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

// Parity table for fast parity flag computation
const PARITY_TABLE: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < 256 {
        let mut bits = i;
        let mut count = 0;
        while bits > 0 {
            if bits & 1 == 1 {
                count += 1;
            }
            bits >>= 1;
        }
        table[i] = (count % 2) == 0;
        i += 1;
    }
    table
};

impl Cpu {
    /// Create new CPU initialized to 16-bit real-mode defaults
    pub fn new() -> Self {
        Self {
            eax: 0,
            ecx: 0,
            edx: 0,
            ebx: 0,
            esp: 0,
            ebp: 0,
            esi: 0,
            edi: 0,
            cs: 0,
            ds: 0,
            es: 0,
            ss: 0,
            fs: 0,
            gs: 0,
            ip: 0,
            eflags: 0x0000_0002, // Bit 1 is always 1 on x86
            halted: false,
        }
    }

    // 16-bit Register Views
    #[inline(always)] pub fn ax(&self) -> u16 { self.eax as u16 }
    #[inline(always)] pub fn cx(&self) -> u16 { self.ecx as u16 }
    #[inline(always)] pub fn dx(&self) -> u16 { self.edx as u16 }
    #[inline(always)] pub fn bx(&self) -> u16 { self.ebx as u16 }
    #[inline(always)] pub fn sp(&self) -> u16 { self.esp as u16 }
    #[inline(always)] pub fn bp(&self) -> u16 { self.ebp as u16 }
    #[inline(always)] pub fn si(&self) -> u16 { self.esi as u16 }
    #[inline(always)] pub fn di(&self) -> u16 { self.edi as u16 }

    #[inline(always)] pub fn set_ax(&mut self, v: u16) { self.eax = (self.eax & 0xFFFF_0000) | (v as u32); }
    #[inline(always)] pub fn set_cx(&mut self, v: u16) { self.ecx = (self.ecx & 0xFFFF_0000) | (v as u32); }
    #[inline(always)] pub fn set_dx(&mut self, v: u16) { self.edx = (self.edx & 0xFFFF_0000) | (v as u32); }
    #[inline(always)] pub fn set_bx(&mut self, v: u16) { self.ebx = (self.ebx & 0xFFFF_0000) | (v as u32); }
    #[inline(always)] pub fn set_sp(&mut self, v: u16) { self.esp = (self.esp & 0xFFFF_0000) | (v as u32); }
    #[inline(always)] pub fn set_bp(&mut self, v: u16) { self.ebp = (self.ebp & 0xFFFF_0000) | (v as u32); }
    #[inline(always)] pub fn set_si(&mut self, v: u16) { self.esi = (self.esi & 0xFFFF_0000) | (v as u32); }
    #[inline(always)] pub fn set_di(&mut self, v: u16) { self.edi = (self.edi & 0xFFFF_0000) | (v as u32); }

    // 8-bit Register Views
    #[inline(always)] pub fn al(&self) -> u8 { self.eax as u8 }
    #[inline(always)] pub fn cl(&self) -> u8 { self.ecx as u8 }
    #[inline(always)] pub fn dl(&self) -> u8 { self.edx as u8 }
    #[inline(always)] pub fn bl(&self) -> u8 { self.ebx as u8 }
    #[inline(always)] pub fn ah(&self) -> u8 { (self.eax >> 8) as u8 }
    #[inline(always)] pub fn ch(&self) -> u8 { (self.ecx >> 8) as u8 }
    #[inline(always)] pub fn dh(&self) -> u8 { (self.edx >> 8) as u8 }
    #[inline(always)] pub fn bh(&self) -> u8 { (self.ebx >> 8) as u8 }

    #[inline(always)] pub fn set_al(&mut self, v: u8) { self.eax = (self.eax & 0xFFFF_FF00) | (v as u32); }
    #[inline(always)] pub fn set_cl(&mut self, v: u8) { self.ecx = (self.ecx & 0xFFFF_FF00) | (v as u32); }
    #[inline(always)] pub fn set_dl(&mut self, v: u8) { self.edx = (self.edx & 0xFFFF_FF00) | (v as u32); }
    #[inline(always)] pub fn set_bl(&mut self, v: u8) { self.ebx = (self.ebx & 0xFFFF_FF00) | (v as u32); }
    #[inline(always)] pub fn set_ah(&mut self, v: u8) { self.eax = (self.eax & 0xFFFF_00FF) | ((v as u32) << 8); }
    #[inline(always)] pub fn set_ch(&mut self, v: u8) { self.ecx = (self.ecx & 0xFFFF_00FF) | ((v as u32) << 8); }
    #[inline(always)] pub fn set_dh(&mut self, v: u8) { self.edx = (self.edx & 0xFFFF_00FF) | ((v as u32) << 8); }
    #[inline(always)] pub fn set_bh(&mut self, v: u8) { self.ebx = (self.ebx & 0xFFFF_00FF) | ((v as u32) << 8); }

    // Index-based Register Access
    #[inline(always)]
    pub fn reg8(&self, idx: usize) -> u8 {
        match idx & 7 {
            0 => self.al(), 1 => self.cl(), 2 => self.dl(), 3 => self.bl(),
            4 => self.ah(), 5 => self.ch(), 6 => self.dh(), 7 => self.bh(),
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    pub fn set_reg8(&mut self, idx: usize, v: u8) {
        match idx & 7 {
            0 => self.set_al(v), 1 => self.set_cl(v), 2 => self.set_dl(v), 3 => self.set_bl(v),
            4 => self.set_ah(v), 5 => self.set_ch(v), 6 => self.set_dh(v), 7 => self.set_bh(v),
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    pub fn reg16(&self, idx: usize) -> u16 {
        match idx & 7 {
            0 => self.ax(), 1 => self.cx(), 2 => self.dx(), 3 => self.bx(),
            4 => self.sp(), 5 => self.bp(), 6 => self.si(), 7 => self.di(),
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    pub fn set_reg16(&mut self, idx: usize, v: u16) {
        match idx & 7 {
            0 => self.set_ax(v), 1 => self.set_cx(v), 2 => self.set_dx(v), 3 => self.set_bx(v),
            4 => self.set_sp(v), 5 => self.set_bp(v), 6 => self.set_si(v), 7 => self.set_di(v),
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    pub fn reg32(&self, idx: usize) -> u32 {
        match idx & 7 {
            0 => self.eax, 1 => self.ecx, 2 => self.edx, 3 => self.ebx,
            4 => self.esp, 5 => self.ebp, 6 => self.esi, 7 => self.edi,
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    pub fn set_reg32(&mut self, idx: usize, v: u32) {
        match idx & 7 {
            0 => self.eax = v, 1 => self.ecx = v, 2 => self.edx = v, 3 => self.ebx = v,
            4 => self.esp = v, 5 => self.ebp = v, 6 => self.esi = v, 7 => self.edi = v,
            _ => unreachable!(),
        }
    }

    // Segment Register Access
    #[inline(always)]
    pub fn sreg(&self, idx: usize) -> u16 {
        match idx {
            0 => self.es, 1 => self.cs, 2 => self.ss, 3 => self.ds,
            4 => self.fs, 5 => self.gs,
            _ => self.ds,
        }
    }

    #[inline(always)]
    pub fn set_sreg(&mut self, idx: usize, v: u16) {
        match idx {
            0 => self.es = v, 1 => self.cs = v, 2 => self.ss = v, 3 => self.ds = v,
            4 => self.fs = v, 5 => self.gs = v,
            _ => {}
        }
    }

    // Flag Accessors
    #[inline(always)] pub fn flags(&self) -> u16 { (self.eflags & 0xFFFF) as u16 }
    #[inline(always)] pub fn set_flags(&mut self, v: u16) { self.eflags = (self.eflags & 0xFFFF_0000) | ((v as u32) | 2); }

    #[inline(always)] pub fn cf(&self) -> bool { (self.eflags & FLAG_CF) != 0 }
    #[inline(always)] pub fn pf(&self) -> bool { (self.eflags & FLAG_PF) != 0 }
    #[inline(always)] pub fn af(&self) -> bool { (self.eflags & FLAG_AF) != 0 }
    #[inline(always)] pub fn zf(&self) -> bool { (self.eflags & FLAG_ZF) != 0 }
    #[inline(always)] pub fn sf(&self) -> bool { (self.eflags & FLAG_SF) != 0 }
    #[inline(always)] pub fn tf(&self) -> bool { (self.eflags & FLAG_TF) != 0 }
    #[inline(always)] pub fn if_flag(&self) -> bool { (self.eflags & FLAG_IF) != 0 }
    #[inline(always)] pub fn df(&self) -> bool { (self.eflags & FLAG_DF) != 0 }
    #[inline(always)] pub fn of(&self) -> bool { (self.eflags & FLAG_OF) != 0 }

    #[inline(always)] pub fn set_cf(&mut self, b: bool) { if b { self.eflags |= FLAG_CF; } else { self.eflags &= !FLAG_CF; } }
    #[inline(always)] pub fn set_pf(&mut self, b: bool) { if b { self.eflags |= FLAG_PF; } else { self.eflags &= !FLAG_PF; } }
    #[inline(always)] pub fn set_af(&mut self, b: bool) { if b { self.eflags |= FLAG_AF; } else { self.eflags &= !FLAG_AF; } }
    #[inline(always)] pub fn set_zf(&mut self, b: bool) { if b { self.eflags |= FLAG_ZF; } else { self.eflags &= !FLAG_ZF; } }
    #[inline(always)] pub fn set_sf(&mut self, b: bool) { if b { self.eflags |= FLAG_SF; } else { self.eflags &= !FLAG_SF; } }
    #[inline(always)] pub fn set_tf(&mut self, b: bool) { if b { self.eflags |= FLAG_TF; } else { self.eflags &= !FLAG_TF; } }
    #[inline(always)] pub fn set_if(&mut self, b: bool) { if b { self.eflags |= FLAG_IF; } else { self.eflags &= !FLAG_IF; } }
    #[inline(always)] pub fn set_df(&mut self, b: bool) { if b { self.eflags |= FLAG_DF; } else { self.eflags &= !FLAG_DF; } }
    #[inline(always)] pub fn set_of(&mut self, b: bool) { if b { self.eflags |= FLAG_OF; } else { self.eflags &= !FLAG_OF; } }

    // Arithmetic Flag Updaters
    pub fn update_flags_add8(&mut self, a: u8, b: u8, c_in: u8) -> u8 {
        let sum = (a as u32) + (b as u32) + (c_in as u32);
        let res = sum as u8;
        self.set_cf(sum > 0xFF);
        self.set_af(((a ^ b ^ res) & 0x10) != 0);
        self.set_zf(res == 0);
        self.set_sf((res & 0x80) != 0);
        self.set_pf(PARITY_TABLE[res as usize]);
        self.set_of(((a ^ res) & (b ^ res) & 0x80) != 0);
        res
    }

    pub fn update_flags_add16(&mut self, a: u16, b: u16, c_in: u16) -> u16 {
        let sum = (a as u32) + (b as u32) + (c_in as u32);
        let res = sum as u16;
        self.set_cf(sum > 0xFFFF);
        self.set_af(((a ^ b ^ res) & 0x10) != 0);
        self.set_zf(res == 0);
        self.set_sf((res & 0x8000) != 0);
        self.set_pf(PARITY_TABLE[(res & 0xFF) as usize]);
        self.set_of(((a ^ res) & (b ^ res) & 0x8000) != 0);
        res
    }

    pub fn update_flags_add32(&mut self, a: u32, b: u32, c_in: u32) -> u32 {
        let sum = (a as u64) + (b as u64) + (c_in as u64);
        let res = sum as u32;
        self.set_cf(sum > 0xFFFF_FFFF);
        self.set_af(((a ^ b ^ res) & 0x10) != 0);
        self.set_zf(res == 0);
        self.set_sf((res & 0x8000_0000) != 0);
        self.set_pf(PARITY_TABLE[(res & 0xFF) as usize]);
        self.set_of(((a ^ res) & (b ^ res) & 0x8000_0000) != 0);
        res
    }

    pub fn update_flags_sub8(&mut self, a: u8, b: u8, b_in: u8) -> u8 {
        let diff = (a as i32) - (b as i32) - (b_in as i32);
        let res = diff as u8;
        self.set_cf((a as u32) < ((b as u32) + (b_in as u32)));
        self.set_af(((a ^ b ^ res) & 0x10) != 0);
        self.set_zf(res == 0);
        self.set_sf((res & 0x80) != 0);
        self.set_pf(PARITY_TABLE[res as usize]);
        self.set_of(((a ^ b) & (a ^ res) & 0x80) != 0);
        res
    }

    pub fn update_flags_sub16(&mut self, a: u16, b: u16, b_in: u16) -> u16 {
        let diff = (a as i32) - (b as i32) - (b_in as i32);
        let res = diff as u16;
        self.set_cf((a as u32) < ((b as u32) + (b_in as u32)));
        self.set_af(((a ^ b ^ res) & 0x10) != 0);
        self.set_zf(res == 0);
        self.set_sf((res & 0x8000) != 0);
        self.set_pf(PARITY_TABLE[(res & 0xFF) as usize]);
        self.set_of(((a ^ b) & (a ^ res) & 0x8000) != 0);
        res
    }

    pub fn update_flags_sub32(&mut self, a: u32, b: u32, b_in: u32) -> u32 {
        let diff = (a as i64) - (b as i64) - (b_in as i64);
        let res = diff as u32;
        self.set_cf((a as u64) < ((b as u64) + (b_in as u64)));
        self.set_af(((a ^ b ^ res) & 0x10) != 0);
        self.set_zf(res == 0);
        self.set_sf((res & 0x8000_0000) != 0);
        self.set_pf(PARITY_TABLE[(res & 0xFF) as usize]);
        self.set_of(((a ^ b) & (a ^ res) & 0x8000_0000) != 0);
        res
    }

    pub fn update_flags_logic8(&mut self, res: u8) {
        self.set_cf(false);
        self.set_of(false);
        self.set_af(false);
        self.set_zf(res == 0);
        self.set_sf((res & 0x80) != 0);
        self.set_pf(PARITY_TABLE[res as usize]);
    }

    pub fn update_flags_logic16(&mut self, res: u16) {
        self.set_cf(false);
        self.set_of(false);
        self.set_af(false);
        self.set_zf(res == 0);
        self.set_sf((res & 0x8000) != 0);
        self.set_pf(PARITY_TABLE[(res & 0xFF) as usize]);
    }

    pub fn update_flags_logic32(&mut self, res: u32) {
        self.set_cf(false);
        self.set_of(false);
        self.set_af(false);
        self.set_zf(res == 0);
        self.set_sf((res & 0x8000_0000) != 0);
        self.set_pf(PARITY_TABLE[(res & 0xFF) as usize]);
    }

    pub fn update_flags_inc8(&mut self, a: u8) -> u8 {
        let res = a.wrapping_add(1);
        self.set_af((a & 0x0F) == 0x0F);
        self.set_zf(res == 0);
        self.set_sf((res & 0x80) != 0);
        self.set_pf(PARITY_TABLE[res as usize]);
        self.set_of(a == 0x7F);
        res
    }

    pub fn update_flags_inc16(&mut self, a: u16) -> u16 {
        let res = a.wrapping_add(1);
        self.set_af((a & 0x0F) == 0x0F);
        self.set_zf(res == 0);
        self.set_sf((res & 0x8000) != 0);
        self.set_pf(PARITY_TABLE[(res & 0xFF) as usize]);
        self.set_of(a == 0x7FFF);
        res
    }

    pub fn update_flags_inc32(&mut self, a: u32) -> u32 {
        let res = a.wrapping_add(1);
        self.set_af((a & 0x0F) == 0x0F);
        self.set_zf(res == 0);
        self.set_sf((res & 0x8000_0000) != 0);
        self.set_pf(PARITY_TABLE[(res & 0xFF) as usize]);
        self.set_of(a == 0x7FFF_FFFF);
        res
    }

    pub fn update_flags_dec8(&mut self, a: u8) -> u8 {
        let res = a.wrapping_sub(1);
        self.set_af((a & 0x0F) == 0);
        self.set_zf(res == 0);
        self.set_sf((res & 0x80) != 0);
        self.set_pf(PARITY_TABLE[res as usize]);
        self.set_of(a == 0x80);
        res
    }

    pub fn update_flags_dec16(&mut self, a: u16) -> u16 {
        let res = a.wrapping_sub(1);
        self.set_af((a & 0x0F) == 0);
        self.set_zf(res == 0);
        self.set_sf((res & 0x8000) != 0);
        self.set_pf(PARITY_TABLE[(res & 0xFF) as usize]);
        self.set_of(a == 0x8000);
        res
    }

    pub fn update_flags_dec32(&mut self, a: u32) -> u32 {
        let res = a.wrapping_sub(1);
        self.set_af((a & 0x0F) == 0);
        self.set_zf(res == 0);
        self.set_sf((res & 0x8000_0000) != 0);
        self.set_pf(PARITY_TABLE[(res & 0xFF) as usize]);
        self.set_of(a == 0x8000_0000);
        res
    }

    // Stack Operations
    pub fn push16(&mut self, bus: &mut impl Bus, val: u16) {
        let sp = self.sp().wrapping_sub(2);
        self.set_sp(sp);
        let linear = ((self.ss as u32) << 4).wrapping_add(sp as u32);
        bus.write_u16(linear, val);
    }

    pub fn pop16(&mut self, bus: &mut impl Bus) -> u16 {
        let sp = self.sp();
        let linear = ((self.ss as u32) << 4).wrapping_add(sp as u32);
        let val = bus.read_u16(linear);
        self.set_sp(sp.wrapping_add(2));
        val
    }

    pub fn push32(&mut self, bus: &mut impl Bus, val: u32) {
        let sp = self.sp().wrapping_sub(4);
        self.set_sp(sp);
        let linear = ((self.ss as u32) << 4).wrapping_add(sp as u32);
        bus.write_u32(linear, val);
    }

    pub fn pop32(&mut self, bus: &mut impl Bus) -> u32 {
        let sp = self.sp();
        let linear = ((self.ss as u32) << 4).wrapping_add(sp as u32);
        let val = bus.read_u32(linear);
        self.set_sp(sp.wrapping_add(4));
        val
    }

    // Instruction Fetching
    #[inline(always)]
    pub fn fetch_u8(&mut self, bus: &mut impl Bus) -> u8 {
        let linear = ((self.cs as u32) << 4).wrapping_add(self.ip as u32);
        self.ip = self.ip.wrapping_add(1);
        bus.read_u8(linear)
    }

    #[inline(always)]
    pub fn fetch_u16(&mut self, bus: &mut impl Bus) -> u16 {
        let b0 = self.fetch_u8(bus) as u16;
        let b1 = self.fetch_u8(bus) as u16;
        b0 | (b1 << 8)
    }

    #[inline(always)]
    pub fn fetch_u32(&mut self, bus: &mut impl Bus) -> u32 {
        let w0 = self.fetch_u16(bus) as u32;
        let w1 = self.fetch_u16(bus) as u32;
        w0 | (w1 << 16)
    }

    // 16-bit ModR/M Resolution
    pub fn resolve_modrm16(&mut self, bus: &mut impl Bus, modrm: u8, seg_override: Option<u16>) -> EffectiveAddress {
        let mode = modrm >> 6;
        let rm = modrm & 7;

        if mode == 3 {
            return EffectiveAddress::Register(rm);
        }

        let (base, def_seg) = match rm {
            0 => (self.bx().wrapping_add(self.si()), self.ds),
            1 => (self.bx().wrapping_add(self.di()), self.ds),
            2 => (self.bp().wrapping_add(self.si()), self.ss),
            3 => (self.bp().wrapping_add(self.di()), self.ss),
            4 => (self.si(), self.ds),
            5 => (self.di(), self.ds),
            6 => {
                if mode == 0 {
                    let disp16 = self.fetch_u16(bus);
                    return EffectiveAddress::Memory(self.calc_linear(seg_override.unwrap_or(self.ds), disp16));
                } else {
                    (self.bp(), self.ss)
                }
            }
            7 => (self.bx(), self.ds),
            _ => unreachable!(),
        };

        let disp: u16 = match mode {
            0 => 0,
            1 => (self.fetch_u8(bus) as i8) as u16,
            2 => self.fetch_u16(bus),
            _ => unreachable!(),
        };

        let offset = base.wrapping_add(disp);
        let seg = seg_override.unwrap_or(def_seg);
        EffectiveAddress::Memory(self.calc_linear(seg, offset))
    }

    #[inline(always)]
    pub fn calc_linear(&self, seg: u16, offset: u16) -> u32 {
        ((seg as u32) << 4).wrapping_add(offset as u32)
    }

    // Single Instruction Step Execution
    pub fn step(&mut self, bus: &mut impl Bus) -> StepResult {
        if self.halted {
            return StepResult::Halt;
        }

        let start_ip = self.ip;

        let mut seg_override = None;
        let mut op32 = false;
        let mut rep_prefix = None;

        // Prefix Loop
        let opcode = loop {
            let b = self.fetch_u8(bus);
            match b {
                0x26 => seg_override = Some(self.es),
                0x2E => seg_override = Some(self.cs),
                0x36 => seg_override = Some(self.ss),
                0x3E => seg_override = Some(self.ds),
                0x64 => seg_override = Some(self.fs),
                0x65 => seg_override = Some(self.gs),
                0x66 => op32 = !op32,
                0x67 => {} // 67h address size override (no-op in 16-bit cybersphere)
                0xF2 | 0xF3 => rep_prefix = Some(b),
                _ => break b,
            }
        };

        self.execute_opcode(bus, opcode, seg_override, op32, rep_prefix, start_ip)
    }

    fn execute_opcode(
        &mut self,
        bus: &mut impl Bus,
        opcode: u8,
        seg_override: Option<u16>,
        op32: bool,
        rep_prefix: Option<u8>,
        start_ip: u16,
    ) -> StepResult {
        match opcode {
            // NOP / XCHG ax, ax
            0x90 => StepResult::Ok,

            // 0x0F Escape: Two-Byte Opcodes
            0x0F => self.execute_0f(bus, seg_override, op32),

            // ADD
            0x00 => self.exec_alu_rm_r_8(bus, seg_override, |cpu, a, b| cpu.update_flags_add8(a, b, 0)),
            0x01 => self.exec_alu_rm_r_16_32(bus, seg_override, op32, |cpu, a, b| cpu.update_flags_add16(a, b, 0), |cpu, a, b| cpu.update_flags_add32(a, b, 0)),
            0x02 => self.exec_alu_r_rm_8(bus, seg_override, |cpu, a, b| cpu.update_flags_add8(a, b, 0)),
            0x03 => self.exec_alu_r_rm_16_32(bus, seg_override, op32, |cpu, a, b| cpu.update_flags_add16(a, b, 0), |cpu, a, b| cpu.update_flags_add32(a, b, 0)),
            0x04 => { let imm = self.fetch_u8(bus); let res = self.update_flags_add8(self.al(), imm, 0); self.set_al(res); StepResult::Ok }
            0x05 => {
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.eax = self.update_flags_add32(self.eax, imm, 0);
                } else {
                    let imm = self.fetch_u16(bus);
                    let res = self.update_flags_add16(self.ax(), imm, 0);
                    self.set_ax(res);
                }
                StepResult::Ok
            }

            // PUSH/POP Segment Registers
            0x06 => { self.push16(bus, self.es); StepResult::Ok }
            0x07 => { self.es = self.pop16(bus); StepResult::Ok }
            0x0E => { self.push16(bus, self.cs); StepResult::Ok }
            0x16 => { self.push16(bus, self.ss); StepResult::Ok }
            0x17 => { self.ss = self.pop16(bus); StepResult::Ok }
            0x1E => { self.push16(bus, self.ds); StepResult::Ok }
            0x1F => { self.ds = self.pop16(bus); StepResult::Ok }

            // OR
            0x08 => self.exec_alu_rm_r_8(bus, seg_override, |cpu, a, b| { let res = a | b; cpu.update_flags_logic8(res); res }),
            0x09 => self.exec_alu_rm_r_16_32(bus, seg_override, op32, |cpu, a, b| { let res = a | b; cpu.update_flags_logic16(res); res }, |cpu, a, b| { let res = a | b; cpu.update_flags_logic32(res); res }),
            0x0A => self.exec_alu_r_rm_8(bus, seg_override, |cpu, a, b| { let res = a | b; cpu.update_flags_logic8(res); res }),
            0x0B => self.exec_alu_r_rm_16_32(bus, seg_override, op32, |cpu, a, b| { let res = a | b; cpu.update_flags_logic16(res); res }, |cpu, a, b| { let res = a | b; cpu.update_flags_logic32(res); res }),
            0x0C => { let imm = self.fetch_u8(bus); let res = self.al() | imm; self.update_flags_logic8(res); self.set_al(res); StepResult::Ok }
            0x0D => {
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.eax |= imm;
                    self.update_flags_logic32(self.eax);
                } else {
                    let imm = self.fetch_u16(bus);
                    let res = self.ax() | imm;
                    self.update_flags_logic16(res);
                    self.set_ax(res);
                }
                StepResult::Ok
            }

            // ADC
            0x10 => { let cf = if self.cf() { 1 } else { 0 }; self.exec_alu_rm_r_8(bus, seg_override, move |cpu, a, b| cpu.update_flags_add8(a, b, cf)) }
            0x11 => { let cf = if self.cf() { 1 } else { 0 }; self.exec_alu_rm_r_16_32(bus, seg_override, op32, move |cpu, a, b| cpu.update_flags_add16(a, b, cf as u16), move |cpu, a, b| cpu.update_flags_add32(a, b, cf as u32)) }
            0x12 => { let cf = if self.cf() { 1 } else { 0 }; self.exec_alu_r_rm_8(bus, seg_override, move |cpu, a, b| cpu.update_flags_add8(a, b, cf)) }
            0x13 => { let cf = if self.cf() { 1 } else { 0 }; self.exec_alu_r_rm_16_32(bus, seg_override, op32, move |cpu, a, b| cpu.update_flags_add16(a, b, cf as u16), move |cpu, a, b| cpu.update_flags_add32(a, b, cf as u32)) }
            0x14 => { let cf = if self.cf() { 1 } else { 0 }; let imm = self.fetch_u8(bus); let res = self.update_flags_add8(self.al(), imm, cf); self.set_al(res); StepResult::Ok }
            0x15 => {
                let cf = if self.cf() { 1 } else { 0 };
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.eax = self.update_flags_add32(self.eax, imm, cf);
                } else {
                    let imm = self.fetch_u16(bus);
                    let res = self.update_flags_add16(self.ax(), imm, cf as u16);
                    self.set_ax(res);
                }
                StepResult::Ok
            }

            // SBB
            0x18 => { let cf = if self.cf() { 1 } else { 0 }; self.exec_alu_rm_r_8(bus, seg_override, move |cpu, a, b| cpu.update_flags_sub8(a, b, cf)) }
            0x19 => { let cf = if self.cf() { 1 } else { 0 }; self.exec_alu_rm_r_16_32(bus, seg_override, op32, move |cpu, a, b| cpu.update_flags_sub16(a, b, cf as u16), move |cpu, a, b| cpu.update_flags_sub32(a, b, cf as u32)) }
            0x1A => { let cf = if self.cf() { 1 } else { 0 }; self.exec_alu_r_rm_8(bus, seg_override, move |cpu, a, b| cpu.update_flags_sub8(a, b, cf)) }
            0x1B => { let cf = if self.cf() { 1 } else { 0 }; self.exec_alu_r_rm_16_32(bus, seg_override, op32, move |cpu, a, b| cpu.update_flags_sub16(a, b, cf as u16), move |cpu, a, b| cpu.update_flags_sub32(a, b, cf as u32)) }
            0x1C => { let cf = if self.cf() { 1 } else { 0 }; let imm = self.fetch_u8(bus); let res = self.update_flags_sub8(self.al(), imm, cf); self.set_al(res); StepResult::Ok }
            0x1D => {
                let cf = if self.cf() { 1 } else { 0 };
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.eax = self.update_flags_sub32(self.eax, imm, cf);
                } else {
                    let imm = self.fetch_u16(bus);
                    let res = self.update_flags_sub16(self.ax(), imm, cf as u16);
                    self.set_ax(res);
                }
                StepResult::Ok
            }

            // AND
            0x20 => self.exec_alu_rm_r_8(bus, seg_override, |cpu, a, b| { let res = a & b; cpu.update_flags_logic8(res); res }),
            0x21 => self.exec_alu_rm_r_16_32(bus, seg_override, op32, |cpu, a, b| { let res = a & b; cpu.update_flags_logic16(res); res }, |cpu, a, b| { let res = a & b; cpu.update_flags_logic32(res); res }),
            0x22 => self.exec_alu_r_rm_8(bus, seg_override, |cpu, a, b| { let res = a & b; cpu.update_flags_logic8(res); res }),
            0x23 => self.exec_alu_r_rm_16_32(bus, seg_override, op32, |cpu, a, b| { let res = a & b; cpu.update_flags_logic16(res); res }, |cpu, a, b| { let res = a & b; cpu.update_flags_logic32(res); res }),
            0x24 => { let imm = self.fetch_u8(bus); let res = self.al() & imm; self.update_flags_logic8(res); self.set_al(res); StepResult::Ok }
            0x25 => {
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.eax &= imm;
                    self.update_flags_logic32(self.eax);
                } else {
                    let imm = self.fetch_u16(bus);
                    let res = self.ax() & imm;
                    self.update_flags_logic16(res);
                    self.set_ax(res);
                }
                StepResult::Ok
            }

            // SUB
            0x28 => self.exec_alu_rm_r_8(bus, seg_override, |cpu, a, b| cpu.update_flags_sub8(a, b, 0)),
            0x29 => self.exec_alu_rm_r_16_32(bus, seg_override, op32, |cpu, a, b| cpu.update_flags_sub16(a, b, 0), |cpu, a, b| cpu.update_flags_sub32(a, b, 0)),
            0x2A => self.exec_alu_r_rm_8(bus, seg_override, |cpu, a, b| cpu.update_flags_sub8(a, b, 0)),
            0x2B => self.exec_alu_r_rm_16_32(bus, seg_override, op32, |cpu, a, b| cpu.update_flags_sub16(a, b, 0), |cpu, a, b| cpu.update_flags_sub32(a, b, 0)),
            0x2C => { let imm = self.fetch_u8(bus); let res = self.update_flags_sub8(self.al(), imm, 0); self.set_al(res); StepResult::Ok }
            0x2D => {
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.eax = self.update_flags_sub32(self.eax, imm, 0);
                } else {
                    let imm = self.fetch_u16(bus);
                    let res = self.update_flags_sub16(self.ax(), imm, 0);
                    self.set_ax(res);
                }
                StepResult::Ok
            }

            // XOR
            0x30 => self.exec_alu_rm_r_8(bus, seg_override, |cpu, a, b| { let res = a ^ b; cpu.update_flags_logic8(res); res }),
            0x31 => self.exec_alu_rm_r_16_32(bus, seg_override, op32, |cpu, a, b| { let res = a ^ b; cpu.update_flags_logic16(res); res }, |cpu, a, b| { let res = a ^ b; cpu.update_flags_logic32(res); res }),
            0x32 => self.exec_alu_r_rm_8(bus, seg_override, |cpu, a, b| { let res = a ^ b; cpu.update_flags_logic8(res); res }),
            0x33 => self.exec_alu_r_rm_16_32(bus, seg_override, op32, |cpu, a, b| { let res = a ^ b; cpu.update_flags_logic16(res); res }, |cpu, a, b| { let res = a ^ b; cpu.update_flags_logic32(res); res }),
            0x34 => { let imm = self.fetch_u8(bus); let res = self.al() ^ imm; self.update_flags_logic8(res); self.set_al(res); StepResult::Ok }
            0x35 => {
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.eax ^= imm;
                    self.update_flags_logic32(self.eax);
                } else {
                    let imm = self.fetch_u16(bus);
                    let res = self.ax() ^ imm;
                    self.update_flags_logic16(res);
                    self.set_ax(res);
                }
                StepResult::Ok
            }

            // CMP
            0x38 => { self.exec_alu_rm_r_8(bus, seg_override, |cpu, a, b| { cpu.update_flags_sub8(a, b, 0); a }); StepResult::Ok }
            0x39 => { self.exec_alu_rm_r_16_32(bus, seg_override, op32, |cpu, a, b| { cpu.update_flags_sub16(a, b, 0); a }, |cpu, a, b| { cpu.update_flags_sub32(a, b, 0); a }); StepResult::Ok }
            0x3A => { self.exec_alu_r_rm_8(bus, seg_override, |cpu, a, b| { cpu.update_flags_sub8(a, b, 0); a }); StepResult::Ok }
            0x3B => { self.exec_alu_r_rm_16_32(bus, seg_override, op32, |cpu, a, b| { cpu.update_flags_sub16(a, b, 0); a }, |cpu, a, b| { cpu.update_flags_sub32(a, b, 0); a }); StepResult::Ok }
            0x3C => { let imm = self.fetch_u8(bus); self.update_flags_sub8(self.al(), imm, 0); StepResult::Ok }
            0x3D => {
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.update_flags_sub32(self.eax, imm, 0);
                } else {
                    let imm = self.fetch_u16(bus);
                    self.update_flags_sub16(self.ax(), imm, 0);
                }
                StepResult::Ok
            }

            // INC Reg 16/32
            0x40..=0x47 => {
                let reg = (opcode & 7) as usize;
                if op32 {
                    let v = self.reg32(reg);
                    let res = self.update_flags_inc32(v);
                    self.set_reg32(reg, res);
                } else {
                    let v = self.reg16(reg);
                    let res = self.update_flags_inc16(v);
                    self.set_reg16(reg, res);
                }
                StepResult::Ok
            }

            // DEC Reg 16/32
            0x48..=0x4F => {
                let reg = (opcode & 7) as usize;
                if op32 {
                    let v = self.reg32(reg);
                    let res = self.update_flags_dec32(v);
                    self.set_reg32(reg, res);
                } else {
                    let v = self.reg16(reg);
                    let res = self.update_flags_dec16(v);
                    self.set_reg16(reg, res);
                }
                StepResult::Ok
            }

            // PUSH Reg 16/32
            0x50..=0x57 => {
                let reg = (opcode & 7) as usize;
                if op32 {
                    let v = self.reg32(reg);
                    self.push32(bus, v);
                } else {
                    let v = self.reg16(reg);
                    self.push16(bus, v);
                }
                StepResult::Ok
            }

            // POP Reg 16/32
            0x58..=0x5F => {
                let reg = (opcode & 7) as usize;
                if op32 {
                    let v = self.pop32(bus);
                    self.set_reg32(reg, v);
                } else {
                    let v = self.pop16(bus);
                    self.set_reg16(reg, v);
                }
                StepResult::Ok
            }

            // PUSHA / PUSHAD
            0x60 => {
                if op32 {
                    let temp_esp = self.esp;
                    let (eax, ecx, edx, ebx, ebp, esi, edi) = (self.eax, self.ecx, self.edx, self.ebx, self.ebp, self.esi, self.edi);
                    self.push32(bus, eax);
                    self.push32(bus, ecx);
                    self.push32(bus, edx);
                    self.push32(bus, ebx);
                    self.push32(bus, temp_esp);
                    self.push32(bus, ebp);
                    self.push32(bus, esi);
                    self.push32(bus, edi);
                } else {
                    let temp_sp = self.sp();
                    let (ax, cx, dx, bx, bp, si, di) = (self.ax(), self.cx(), self.dx(), self.bx(), self.bp(), self.si(), self.di());
                    self.push16(bus, ax);
                    self.push16(bus, cx);
                    self.push16(bus, dx);
                    self.push16(bus, bx);
                    self.push16(bus, temp_sp);
                    self.push16(bus, bp);
                    self.push16(bus, si);
                    self.push16(bus, di);
                }
                StepResult::Ok
            }

            // POPA / POPAD
            0x61 => {
                if op32 {
                    self.edi = self.pop32(bus);
                    self.esi = self.pop32(bus);
                    self.ebp = self.pop32(bus);
                    let _ = self.pop32(bus); // skip ESP
                    self.ebx = self.pop32(bus);
                    self.edx = self.pop32(bus);
                    self.ecx = self.pop32(bus);
                    self.eax = self.pop32(bus);
                } else {
                    let di = self.pop16(bus); self.set_di(di);
                    let si = self.pop16(bus); self.set_si(si);
                    let bp = self.pop16(bus); self.set_bp(bp);
                    let _ = self.pop16(bus); // skip SP
                    let bx = self.pop16(bus); self.set_bx(bx);
                    let dx = self.pop16(bus); self.set_dx(dx);
                    let cx = self.pop16(bus); self.set_cx(cx);
                    let ax = self.pop16(bus); self.set_ax(ax);
                }
                StepResult::Ok
            }

            // PUSH imm16/imm32
            0x68 => {
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.push32(bus, imm);
                } else {
                    let imm = self.fetch_u16(bus);
                    self.push16(bus, imm);
                }
                StepResult::Ok
            }

            // IMUL r16/32, r/m, imm16/32
            0x69 => {
                let modrm = self.fetch_u8(bus);
                let reg = ((modrm >> 3) & 7) as usize;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let v = self.read_ea32(bus, ea);
                    let imm = self.fetch_u32(bus) as i32 as i64;
                    let prod = (v as i32 as i64).wrapping_mul(imm);
                    let res = prod as u32;
                    self.set_reg32(reg, res);
                    let overflow = prod != (res as i32 as i64);
                    self.set_cf(overflow);
                    self.set_of(overflow);
                } else {
                    let v = self.read_ea16(bus, ea);
                    let imm = self.fetch_u16(bus) as i16 as i32;
                    let prod = (v as i16 as i32).wrapping_mul(imm);
                    let res = prod as u16;
                    self.set_reg16(reg, res);
                    let overflow = prod != (res as i16 as i32);
                    self.set_cf(overflow);
                    self.set_of(overflow);
                }
                StepResult::Ok
            }

            // PUSH imm8 (sign extended)
            0x6A => {
                let imm = self.fetch_u8(bus) as i8;
                if op32 {
                    self.push32(bus, imm as i32 as u32);
                } else {
                    self.push16(bus, imm as i16 as u16);
                }
                StepResult::Ok
            }

            // IMUL r16/32, r/m, imm8 (sign extended)
            0x6B => {
                let modrm = self.fetch_u8(bus);
                let reg = ((modrm >> 3) & 7) as usize;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                let imm = (self.fetch_u8(bus) as i8) as i32;
                if op32 {
                    let v = self.read_ea32(bus, ea);
                    let prod = (v as i32 as i64).wrapping_mul(imm as i64);
                    let res = prod as u32;
                    self.set_reg32(reg, res);
                    let overflow = prod != (res as i32 as i64);
                    self.set_cf(overflow);
                    self.set_of(overflow);
                } else {
                    let v = self.read_ea16(bus, ea);
                    let prod = (v as i16 as i32).wrapping_mul(imm);
                    let res = prod as u16;
                    self.set_reg16(reg, res);
                    let overflow = prod != (res as i16 as i32);
                    self.set_cf(overflow);
                    self.set_of(overflow);
                }
                StepResult::Ok
            }

            // Jcc Short
            0x70..=0x7F => {
                let disp = (self.fetch_u8(bus) as i8) as i16 as u16;
                let cond = self.eval_cond(opcode & 0x0F);
                if cond {
                    self.ip = self.ip.wrapping_add(disp);
                }
                StepResult::Ok
            }

            // Group 1: ALU r/m, imm
            0x80 | 0x82 => {
                let modrm = self.fetch_u8(bus);
                let op_type = (modrm >> 3) & 7;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                let imm = self.fetch_u8(bus);
                let v = self.read_ea8(bus, ea);
                let res = self.exec_group1_8(op_type, v, imm);
                if op_type != 7 { // CMP does not write back
                    self.write_ea8(bus, ea, res);
                }
                StepResult::Ok
            }
            0x81 => {
                let modrm = self.fetch_u8(bus);
                let op_type = (modrm >> 3) & 7;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let imm = self.fetch_u32(bus);
                    let v = self.read_ea32(bus, ea);
                    let res = self.exec_group1_32(op_type, v, imm);
                    if op_type != 7 {
                        self.write_ea32(bus, ea, res);
                    }
                } else {
                    let imm = self.fetch_u16(bus);
                    let v = self.read_ea16(bus, ea);
                    let res = self.exec_group1_16(op_type, v, imm);
                    if op_type != 7 {
                        self.write_ea16(bus, ea, res);
                    }
                }
                StepResult::Ok
            }
            0x83 => {
                let modrm = self.fetch_u8(bus);
                let op_type = (modrm >> 3) & 7;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                let imm8 = self.fetch_u8(bus) as i8;
                if op32 {
                    let imm = imm8 as i32 as u32;
                    let v = self.read_ea32(bus, ea);
                    let res = self.exec_group1_32(op_type, v, imm);
                    if op_type != 7 {
                        self.write_ea32(bus, ea, res);
                    }
                } else {
                    let imm = imm8 as i16 as u16;
                    let v = self.read_ea16(bus, ea);
                    let res = self.exec_group1_16(op_type, v, imm);
                    if op_type != 7 {
                        self.write_ea16(bus, ea, res);
                    }
                }
                StepResult::Ok
            }

            // TEST r/m, r
            0x84 => {
                let modrm = self.fetch_u8(bus);
                let reg = self.reg8(((modrm >> 3) & 7) as usize);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                let v = self.read_ea8(bus, ea);
                self.update_flags_logic8(v & reg);
                StepResult::Ok
            }
            0x85 => {
                let modrm = self.fetch_u8(bus);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let reg = self.reg32(((modrm >> 3) & 7) as usize);
                    let v = self.read_ea32(bus, ea);
                    self.update_flags_logic32(v & reg);
                } else {
                    let reg = self.reg16(((modrm >> 3) & 7) as usize);
                    let v = self.read_ea16(bus, ea);
                    self.update_flags_logic16(v & reg);
                }
                StepResult::Ok
            }

            // XCHG r/m, r
            0x86 => {
                let modrm = self.fetch_u8(bus);
                let reg_idx = ((modrm >> 3) & 7) as usize;
                let reg_val = self.reg8(reg_idx);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                let rm_val = self.read_ea8(bus, ea);
                self.set_reg8(reg_idx, rm_val);
                self.write_ea8(bus, ea, reg_val);
                StepResult::Ok
            }
            0x87 => {
                let modrm = self.fetch_u8(bus);
                let reg_idx = ((modrm >> 3) & 7) as usize;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let reg_val = self.reg32(reg_idx);
                    let rm_val = self.read_ea32(bus, ea);
                    self.set_reg32(reg_idx, rm_val);
                    self.write_ea32(bus, ea, reg_val);
                } else {
                    let reg_val = self.reg16(reg_idx);
                    let rm_val = self.read_ea16(bus, ea);
                    self.set_reg16(reg_idx, rm_val);
                    self.write_ea16(bus, ea, reg_val);
                }
                StepResult::Ok
            }

            // MOV r/m, r
            0x88 => {
                let modrm = self.fetch_u8(bus);
                let reg_val = self.reg8(((modrm >> 3) & 7) as usize);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                self.write_ea8(bus, ea, reg_val);
                StepResult::Ok
            }
            0x89 => {
                let modrm = self.fetch_u8(bus);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let reg_val = self.reg32(((modrm >> 3) & 7) as usize);
                    self.write_ea32(bus, ea, reg_val);
                } else {
                    let reg_val = self.reg16(((modrm >> 3) & 7) as usize);
                    self.write_ea16(bus, ea, reg_val);
                }
                StepResult::Ok
            }

            // MOV r, r/m
            0x8A => {
                let modrm = self.fetch_u8(bus);
                let reg_idx = ((modrm >> 3) & 7) as usize;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                let v = self.read_ea8(bus, ea);
                self.set_reg8(reg_idx, v);
                StepResult::Ok
            }
            0x8B => {
                let modrm = self.fetch_u8(bus);
                let reg_idx = ((modrm >> 3) & 7) as usize;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let v = self.read_ea32(bus, ea);
                    self.set_reg32(reg_idx, v);
                } else {
                    let v = self.read_ea16(bus, ea);
                    self.set_reg16(reg_idx, v);
                }
                StepResult::Ok
            }

            // MOV r/m16, sreg
            0x8C => {
                let modrm = self.fetch_u8(bus);
                let sreg_val = self.sreg(((modrm >> 3) & 7) as usize);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                self.write_ea16(bus, ea, sreg_val);
                StepResult::Ok
            }

            // LEA r16/32, m
            0x8D => {
                let modrm = self.fetch_u8(bus);
                let reg_idx = ((modrm >> 3) & 7) as usize;
                let ea = self.resolve_modrm16(bus, modrm, None);
                let offset = match ea {
                    EffectiveAddress::Memory(linear) => (linear & 0xFFFF) as u16,
                    EffectiveAddress::Register(_) => return StepResult::Fault(Fault::InvalidOpcode(0x8D)),
                };
                if op32 {
                    self.set_reg32(reg_idx, offset as u32);
                } else {
                    self.set_reg16(reg_idx, offset);
                }
                StepResult::Ok
            }

            // MOV sreg, r/m16
            0x8E => {
                let modrm = self.fetch_u8(bus);
                let sreg_idx = ((modrm >> 3) & 7) as usize;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                let v = self.read_ea16(bus, ea);
                self.set_sreg(sreg_idx, v);
                StepResult::Ok
            }

            // POP r/m16/32
            0x8F => {
                let modrm = self.fetch_u8(bus);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let v = self.pop32(bus);
                    self.write_ea32(bus, ea, v);
                } else {
                    let v = self.pop16(bus);
                    self.write_ea16(bus, ea, v);
                }
                StepResult::Ok
            }

            // XCHG ax/eax, reg
            0x91..=0x97 => {
                let reg = (opcode & 7) as usize;
                if op32 {
                    let tmp = self.eax;
                    self.eax = self.reg32(reg);
                    self.set_reg32(reg, tmp);
                } else {
                    let tmp = self.ax();
                    let v = self.reg16(reg);
                    self.set_ax(v);
                    self.set_reg16(reg, tmp);
                }
                StepResult::Ok
            }

            // CBW / CWDE
            0x98 => {
                if op32 {
                    self.eax = (self.ax() as i16 as i32) as u32;
                } else {
                    let ax = (self.al() as i8 as i16) as u16;
                    self.set_ax(ax);
                }
                StepResult::Ok
            }

            // CWD / CDQ
            0x99 => {
                if op32 {
                    self.edx = if (self.eax & 0x8000_0000) != 0 { 0xFFFF_FFFF } else { 0 };
                } else {
                    let dx = if (self.ax() & 0x8000) != 0 { 0xFFFF } else { 0 };
                    self.set_dx(dx);
                }
                StepResult::Ok
            }

            // CALL Far
            0x9A => {
                let new_ip = self.fetch_u16(bus);
                let new_cs = self.fetch_u16(bus);
                let cur_cs = self.cs;
                let cur_ip = self.ip;
                self.push16(bus, cur_cs);
                self.push16(bus, cur_ip);
                self.cs = new_cs;
                self.ip = new_ip;
                StepResult::Ok
            }

            // PUSHF / POPF
            0x9C => {
                if op32 { self.push32(bus, self.eflags); } else { self.push16(bus, self.flags()); }
                StepResult::Ok
            }
            0x9D => {
                if op32 { let f = self.pop32(bus); self.eflags = (f & 0x003F_7FD5) | 2; }
                else { let f = self.pop16(bus); self.set_flags(f); }
                StepResult::Ok
            }

            // SAHF / LAHF
            0x9E => {
                let ah = self.ah();
                let f = (self.flags() & 0xFF02) | (ah as u16 & 0x00D7);
                self.set_flags(f);
                StepResult::Ok
            }
            0x9F => {
                let f = (self.flags() & 0x00D7) as u8;
                self.set_ah(f | 2);
                StepResult::Ok
            }

            // MOV AL/AX/EAX, [disp16] and vice versa
            0xA0 => {
                let disp = self.fetch_u16(bus);
                let linear = self.calc_linear(seg_override.unwrap_or(self.ds), disp);
                self.set_al(bus.read_u8(linear));
                StepResult::Ok
            }
            0xA1 => {
                let disp = self.fetch_u16(bus);
                let linear = self.calc_linear(seg_override.unwrap_or(self.ds), disp);
                if op32 { self.eax = bus.read_u32(linear); } else { let v = bus.read_u16(linear); self.set_ax(v); }
                StepResult::Ok
            }
            0xA2 => {
                let disp = self.fetch_u16(bus);
                let linear = self.calc_linear(seg_override.unwrap_or(self.ds), disp);
                bus.write_u8(linear, self.al());
                StepResult::Ok
            }
            0xA3 => {
                let disp = self.fetch_u16(bus);
                let linear = self.calc_linear(seg_override.unwrap_or(self.ds), disp);
                if op32 { bus.write_u32(linear, self.eax); } else { bus.write_u16(linear, self.ax()); }
                StepResult::Ok
            }

            // String Instructions
            0xA4 => self.exec_movs(bus, seg_override, rep_prefix, 1, start_ip),
            0xA5 => self.exec_movs(bus, seg_override, rep_prefix, if op32 { 4 } else { 2 }, start_ip),
            0xAA => self.exec_stos(bus, rep_prefix, 1, start_ip),
            0xAB => self.exec_stos(bus, rep_prefix, if op32 { 4 } else { 2 }, start_ip),
            0xAC => self.exec_lods(bus, seg_override, 1),
            0xAD => self.exec_lods(bus, seg_override, if op32 { 4 } else { 2 }),
            0xAE => self.exec_scas(bus, rep_prefix, 1, start_ip),
            0xAF => self.exec_scas(bus, rep_prefix, if op32 { 4 } else { 2 }, start_ip),

            // TEST AL/AX/EAX, imm
            0xA8 => { let imm = self.fetch_u8(bus); self.update_flags_logic8(self.al() & imm); StepResult::Ok }
            0xA9 => {
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.update_flags_logic32(self.eax & imm);
                } else {
                    let imm = self.fetch_u16(bus);
                    self.update_flags_logic16(self.ax() & imm);
                }
                StepResult::Ok
            }

            // MOV r8, imm8
            0xB0..=0xB7 => {
                let reg = (opcode & 7) as usize;
                let imm = self.fetch_u8(bus);
                self.set_reg8(reg, imm);
                StepResult::Ok
            }

            // MOV r16/32, imm16/32
            0xB8..=0xBF => {
                let reg = (opcode & 7) as usize;
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.set_reg32(reg, imm);
                } else {
                    let imm = self.fetch_u16(bus);
                    self.set_reg16(reg, imm);
                }
                StepResult::Ok
            }

            // Shifts: Group 2
            0xC0 => self.exec_shift_group2_8(bus, seg_override, ShiftCount::Imm8),
            0xC1 => self.exec_shift_group2_16_32(bus, seg_override, op32, ShiftCount::Imm8),
            0xD0 => self.exec_shift_group2_8(bus, seg_override, ShiftCount::One),
            0xD1 => self.exec_shift_group2_16_32(bus, seg_override, op32, ShiftCount::One),
            0xD2 => self.exec_shift_group2_8(bus, seg_override, ShiftCount::Cl),
            0xD3 => self.exec_shift_group2_16_32(bus, seg_override, op32, ShiftCount::Cl),

            // RET Near
            0xC2 => { let imm = self.fetch_u16(bus); self.ip = self.pop16(bus); self.set_sp(self.sp().wrapping_add(imm)); StepResult::Ok }
            0xC3 => { self.ip = self.pop16(bus); StepResult::Ok }

            // LES / LDS
            0xC4 => self.exec_load_far_pointer(bus, seg_override, 0), // ES
            0xC5 => self.exec_load_far_pointer(bus, seg_override, 3), // DS

            // MOV r/m, imm
            0xC6 => {
                let modrm = self.fetch_u8(bus);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                let imm = self.fetch_u8(bus);
                self.write_ea8(bus, ea, imm);
                StepResult::Ok
            }
            0xC7 => {
                let modrm = self.fetch_u8(bus);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let imm = self.fetch_u32(bus);
                    self.write_ea32(bus, ea, imm);
                } else {
                    let imm = self.fetch_u16(bus);
                    self.write_ea16(bus, ea, imm);
                }
                StepResult::Ok
            }

            // RET Far
            0xCA => { let imm = self.fetch_u16(bus); self.ip = self.pop16(bus); self.cs = self.pop16(bus); self.set_sp(self.sp().wrapping_add(imm)); StepResult::Ok }
            0xCB => { self.ip = self.pop16(bus); self.cs = self.pop16(bus); StepResult::Ok }

            // INT
            0xCC => StepResult::Int(3),
            0xCD => { let vec = self.fetch_u8(bus); StepResult::Int(vec) }

            // IRET
            0xCF => {
                self.ip = self.pop16(bus);
                self.cs = self.pop16(bus);
                let f = self.pop16(bus);
                self.set_flags(f);
                StepResult::Ok
            }

            // LOOP / JCXZ
            0xE0 => { // LOOPNE / LOOPNZ
                let disp = (self.fetch_u8(bus) as i8) as i16 as u16;
                let cx = self.cx().wrapping_sub(1);
                self.set_cx(cx);
                if cx != 0 && !self.zf() { self.ip = self.ip.wrapping_add(disp); }
                StepResult::Ok
            }
            0xE1 => { // LOOPE / LOOPZ
                let disp = (self.fetch_u8(bus) as i8) as i16 as u16;
                let cx = self.cx().wrapping_sub(1);
                self.set_cx(cx);
                if cx != 0 && self.zf() { self.ip = self.ip.wrapping_add(disp); }
                StepResult::Ok
            }
            0xE2 => { // LOOP
                let disp = (self.fetch_u8(bus) as i8) as i16 as u16;
                let cx = self.cx().wrapping_sub(1);
                self.set_cx(cx);
                if cx != 0 { self.ip = self.ip.wrapping_add(disp); }
                StepResult::Ok
            }
            0xE3 => { // JCXZ
                let disp = (self.fetch_u8(bus) as i8) as i16 as u16;
                if self.cx() == 0 { self.ip = self.ip.wrapping_add(disp); }
                StepResult::Ok
            }

            // IN / OUT Imm
            0xE4 => { let port = self.fetch_u8(bus) as u16; StepResult::PortIn { port, size: 1 } }
            0xE5 => { let port = self.fetch_u8(bus) as u16; StepResult::PortIn { port, size: if op32 { 4 } else { 2 } } }
            0xE6 => { let port = self.fetch_u8(bus) as u16; StepResult::PortOut { port, val: self.al() as u32, size: 1 } }
            0xE7 => { let port = self.fetch_u8(bus) as u16; StepResult::PortOut { port, val: if op32 { self.eax } else { self.ax() as u32 }, size: if op32 { 4 } else { 2 } } }

            // CALL / JMP Direct
            0xE8 => {
                let disp = self.fetch_u16(bus);
                let ret_ip = self.ip;
                self.push16(bus, ret_ip);
                self.ip = self.ip.wrapping_add(disp);
                StepResult::Ok
            }
            0xE9 => {
                let disp = self.fetch_u16(bus);
                self.ip = self.ip.wrapping_add(disp);
                StepResult::Ok
            }
            0xEA => {
                let new_ip = self.fetch_u16(bus);
                let new_cs = self.fetch_u16(bus);
                self.ip = new_ip;
                self.cs = new_cs;
                StepResult::Ok
            }
            0xEB => {
                let disp = (self.fetch_u8(bus) as i8) as i16 as u16;
                self.ip = self.ip.wrapping_add(disp);
                StepResult::Ok
            }

            // IN / OUT DX
            0xEC => StepResult::PortIn { port: self.dx(), size: 1 },
            0xED => StepResult::PortIn { port: self.dx(), size: if op32 { 4 } else { 2 } },
            0xEE => StepResult::PortOut { port: self.dx(), val: self.al() as u32, size: 1 },
            0xEF => StepResult::PortOut { port: self.dx(), val: if op32 { self.eax } else { self.ax() as u32 }, size: if op32 { 4 } else { 2 } },

            // HLT / CMC / Flags
            0xF4 => { self.halted = true; StepResult::Halt }
            0xF5 => { let c = !self.cf(); self.set_cf(c); StepResult::Ok }
            0xF8 => { self.set_cf(false); StepResult::Ok }
            0xF9 => { self.set_cf(true); StepResult::Ok }
            0xFA => { self.set_if(false); StepResult::Ok }
            0xFB => { self.set_if(true); StepResult::Ok }
            0xFC => { self.set_df(false); StepResult::Ok }
            0xFD => { self.set_df(true); StepResult::Ok }

            // Group 3: F6 / F7
            0xF6 => self.exec_group3_8(bus, seg_override),
            0xF7 => self.exec_group3_16_32(bus, seg_override, op32),

            // Group 4: FE
            0xFE => {
                let modrm = self.fetch_u8(bus);
                let op_type = (modrm >> 3) & 7;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                match op_type {
                    0 => { let v = self.read_ea8(bus, ea); let res = self.update_flags_inc8(v); self.write_ea8(bus, ea, res); StepResult::Ok }
                    1 => { let v = self.read_ea8(bus, ea); let res = self.update_flags_dec8(v); self.write_ea8(bus, ea, res); StepResult::Ok }
                    _ => StepResult::Fault(Fault::InvalidOpcode(0xFE)),
                }
            }

            // Group 5: FF
            0xFF => self.exec_group5(bus, seg_override, op32),

            _ => StepResult::Fault(Fault::InvalidOpcode(opcode)),
        }
    }

    // 0x0F Two-Byte Opcode Execution
    fn execute_0f(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, op32: bool) -> StepResult {
        let op2 = self.fetch_u8(bus);
        match op2 {
            // Jcc Near
            0x80..=0x8F => {
                let disp = self.fetch_u16(bus);
                let cond = self.eval_cond(op2 & 0x0F);
                if cond {
                    self.ip = self.ip.wrapping_add(disp);
                }
                StepResult::Ok
            }

            // PUSH / POP FS
            0xA0 => { self.push16(bus, self.fs); StepResult::Ok }
            0xA1 => { self.fs = self.pop16(bus); StepResult::Ok }

            // BT r/m, r
            0xA3 => {
                let modrm = self.fetch_u8(bus);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let bit_idx = self.reg32(((modrm >> 3) & 7) as usize) & 31;
                    let val = self.read_ea32(bus, ea);
                    self.set_cf((val & (1 << bit_idx)) != 0);
                } else {
                    let bit_idx = self.reg16(((modrm >> 3) & 7) as usize) & 15;
                    let val = self.read_ea16(bus, ea);
                    self.set_cf((val & (1 << bit_idx)) != 0);
                }
                StepResult::Ok
            }

            // PUSH / POP GS
            0xA8 => { self.push16(bus, self.gs); StepResult::Ok }
            0xA9 => { self.gs = self.pop16(bus); StepResult::Ok }

            // BTS r/m, r
            0xAB => {
                let modrm = self.fetch_u8(bus);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let bit_idx = self.reg32(((modrm >> 3) & 7) as usize) & 31;
                    let val = self.read_ea32(bus, ea);
                    self.set_cf((val & (1 << bit_idx)) != 0);
                    self.write_ea32(bus, ea, val | (1 << bit_idx));
                } else {
                    let bit_idx = self.reg16(((modrm >> 3) & 7) as usize) & 15;
                    let val = self.read_ea16(bus, ea);
                    self.set_cf((val & (1 << bit_idx)) != 0);
                    self.write_ea16(bus, ea, val | (1 << bit_idx));
                }
                StepResult::Ok
            }

            // IMUL r, r/m
            0xAF => {
                let modrm = self.fetch_u8(bus);
                let reg_idx = ((modrm >> 3) & 7) as usize;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let a = self.reg32(reg_idx) as i32 as i64;
                    let b = self.read_ea32(bus, ea) as i32 as i64;
                    let prod = a.wrapping_mul(b);
                    let res = prod as u32;
                    self.set_reg32(reg_idx, res);
                    let overflow = prod != (res as i32 as i64);
                    self.set_cf(overflow);
                    self.set_of(overflow);
                } else {
                    let a = self.reg16(reg_idx) as i16 as i32;
                    let b = self.read_ea16(bus, ea) as i16 as i32;
                    let prod = a.wrapping_mul(b);
                    let res = prod as u16;
                    self.set_reg16(reg_idx, res);
                    let overflow = prod != (res as i16 as i32);
                    self.set_cf(overflow);
                    self.set_of(overflow);
                }
                StepResult::Ok
            }

            // BTR r/m, r
            0xB3 => {
                let modrm = self.fetch_u8(bus);
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                if op32 {
                    let bit_idx = self.reg32(((modrm >> 3) & 7) as usize) & 31;
                    let val = self.read_ea32(bus, ea);
                    self.set_cf((val & (1 << bit_idx)) != 0);
                    self.write_ea32(bus, ea, val & !(1 << bit_idx));
                } else {
                    let bit_idx = self.reg16(((modrm >> 3) & 7) as usize) & 15;
                    let val = self.read_ea16(bus, ea);
                    self.set_cf((val & (1 << bit_idx)) != 0);
                    self.write_ea16(bus, ea, val & !(1 << bit_idx));
                }
                StepResult::Ok
            }

            // LSS / LFS / LGS
            0xB2 => self.exec_load_far_pointer(bus, seg_override, 2), // SS
            0xB4 => self.exec_load_far_pointer(bus, seg_override, 4), // FS
            0xB5 => self.exec_load_far_pointer(bus, seg_override, 5), // GS

            // Group 8: BT / BTS / BTR / BTC r/m, imm8
            0xBA => {
                let modrm = self.fetch_u8(bus);
                let op_type = (modrm >> 3) & 7;
                let ea = self.resolve_modrm16(bus, modrm, seg_override);
                let bit_imm = self.fetch_u8(bus);
                if op32 {
                    let bit_idx = (bit_imm & 31) as u32;
                    let val = self.read_ea32(bus, ea);
                    self.set_cf((val & (1 << bit_idx)) != 0);
                    match op_type {
                        4 => {} // BT
                        5 => self.write_ea32(bus, ea, val | (1 << bit_idx)), // BTS
                        6 => self.write_ea32(bus, ea, val & !(1 << bit_idx)), // BTR
                        7 => self.write_ea32(bus, ea, val ^ (1 << bit_idx)), // BTC
                        _ => return StepResult::Fault(Fault::InvalidOpcode(0xBA)),
                    }
                } else {
                    let bit_idx = (bit_imm & 15) as u16;
                    let val = self.read_ea16(bus, ea);
                    self.set_cf((val & (1 << bit_idx)) != 0);
                    match op_type {
                        4 => {} // BT
                        5 => self.write_ea16(bus, ea, val | (1 << bit_idx)), // BTS
                        6 => self.write_ea16(bus, ea, val & !(1 << bit_idx)), // BTR
                        7 => self.write_ea16(bus, ea, val ^ (1 << bit_idx)), // BTC
                        _ => return StepResult::Fault(Fault::InvalidOpcode(0xBA)),
                    }
                }
                StepResult::Ok
            }

            _ => StepResult::Fault(Fault::InvalidOpcode(op2)),
        }
    }

    // Condition Code Evaluator
    #[inline(always)]
    fn eval_cond(&self, c: u8) -> bool {
        match c {
            0 => self.of(),                     // O
            1 => !self.of(),                    // NO
            2 => self.cf(),                     // B / C / NAE
            3 => !self.cf(),                    // AE / NB / NC
            4 => self.zf(),                     // E / Z
            5 => !self.zf(),                    // NE / NZ
            6 => self.cf() || self.zf(),        // BE / NA
            7 => !self.cf() && !self.zf(),      // A / NBE
            8 => self.sf(),                     // S
            9 => !self.sf(),                    // NS
            10 => self.pf(),                    // P / PE
            11 => !self.pf(),                   // NP / PO
            12 => self.sf() != self.of(),       // L / NGE
            13 => self.sf() == self.of(),       // GE / NL
            14 => self.zf() || (self.sf() != self.of()), // LE / NG
            15 => !self.zf() && (self.sf() == self.of()), // G / NLE
            _ => unreachable!(),
        }
    }

    // String Op Implementations
    fn exec_movs(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, rep: Option<u8>, size: usize, start_ip: u16) -> StepResult {
        if rep.is_some() && self.cx() == 0 {
            return StepResult::Ok;
        }

        let df = self.df();
        let src_seg = seg_override.unwrap_or(self.ds);
        let dst_seg = self.es;
        let src = self.calc_linear(src_seg, self.si());
        let dst = self.calc_linear(dst_seg, self.di());

        match size {
            1 => {
                let b = bus.read_u8(src);
                bus.write_u8(dst, b);
                self.set_si(if df { self.si().wrapping_sub(1) } else { self.si().wrapping_add(1) });
                self.set_di(if df { self.di().wrapping_sub(1) } else { self.di().wrapping_add(1) });
            }
            2 => {
                let w = bus.read_u16(src);
                bus.write_u16(dst, w);
                self.set_si(if df { self.si().wrapping_sub(2) } else { self.si().wrapping_add(2) });
                self.set_di(if df { self.di().wrapping_sub(2) } else { self.di().wrapping_add(2) });
            }
            4 => {
                let d = bus.read_u32(src);
                bus.write_u32(dst, d);
                self.set_si(if df { self.si().wrapping_sub(4) } else { self.si().wrapping_add(4) });
                self.set_di(if df { self.di().wrapping_sub(4) } else { self.di().wrapping_add(4) });
            }
            _ => unreachable!(),
        }

        if rep.is_some() {
            let next_cx = self.cx().wrapping_sub(1);
            self.set_cx(next_cx);
            if next_cx != 0 {
                self.ip = start_ip;
            }
        }
        StepResult::Ok
    }

    fn exec_stos(&mut self, bus: &mut impl Bus, rep: Option<u8>, size: usize, start_ip: u16) -> StepResult {
        if rep.is_some() && self.cx() == 0 {
            return StepResult::Ok;
        }

        let df = self.df();
        let dst_seg = self.es;
        let dst = self.calc_linear(dst_seg, self.di());
        match size {
            1 => {
                bus.write_u8(dst, self.al());
                self.set_di(if df { self.di().wrapping_sub(1) } else { self.di().wrapping_add(1) });
            }
            2 => {
                bus.write_u16(dst, self.ax());
                self.set_di(if df { self.di().wrapping_sub(2) } else { self.di().wrapping_add(2) });
            }
            4 => {
                bus.write_u32(dst, self.eax);
                self.set_di(if df { self.di().wrapping_sub(4) } else { self.di().wrapping_add(4) });
            }
            _ => unreachable!(),
        }

        if rep.is_some() {
            let next_cx = self.cx().wrapping_sub(1);
            self.set_cx(next_cx);
            if next_cx != 0 {
                self.ip = start_ip;
            }
        }
        StepResult::Ok
    }

    fn exec_lods(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, size: usize) -> StepResult {
        let df = self.df();
        let src_seg = seg_override.unwrap_or(self.ds);
        let src = self.calc_linear(src_seg, self.si());
        match size {
            1 => {
                self.set_al(bus.read_u8(src));
                self.set_si(if df { self.si().wrapping_sub(1) } else { self.si().wrapping_add(1) });
            }
            2 => {
                self.set_ax(bus.read_u16(src));
                self.set_si(if df { self.si().wrapping_sub(2) } else { self.si().wrapping_add(2) });
            }
            4 => {
                self.eax = bus.read_u32(src);
                self.set_si(if df { self.si().wrapping_sub(4) } else { self.si().wrapping_add(4) });
            }
            _ => unreachable!(),
        }
        StepResult::Ok
    }

    fn exec_scas(&mut self, bus: &mut impl Bus, rep: Option<u8>, size: usize, start_ip: u16) -> StepResult {
        if rep.is_some() && self.cx() == 0 {
            return StepResult::Ok;
        }

        let df = self.df();
        let dst_seg = self.es;
        let dst = self.calc_linear(dst_seg, self.di());
        match size {
            1 => {
                let v = bus.read_u8(dst);
                self.update_flags_sub8(self.al(), v, 0);
                self.set_di(if df { self.di().wrapping_sub(1) } else { self.di().wrapping_add(1) });
            }
            2 => {
                let v = bus.read_u16(dst);
                self.update_flags_sub16(self.ax(), v, 0);
                self.set_di(if df { self.di().wrapping_sub(2) } else { self.di().wrapping_add(2) });
            }
            4 => {
                let v = bus.read_u32(dst);
                self.update_flags_sub32(self.eax, v, 0);
                self.set_di(if df { self.di().wrapping_sub(4) } else { self.di().wrapping_add(4) });
            }
            _ => unreachable!(),
        }

        if let Some(r) = rep {
            let next_cx = self.cx().wrapping_sub(1);
            self.set_cx(next_cx);
            let terminate = (r == 0xF3 && !self.zf()) || (r == 0xF2 && self.zf()) || next_cx == 0;
            if !terminate {
                self.ip = start_ip;
            }
        }
        StepResult::Ok
    }

    // Helper functions for effective address read/write
    #[inline(always)]
    fn read_ea8(&self, bus: &mut impl Bus, ea: EffectiveAddress) -> u8 {
        match ea {
            EffectiveAddress::Register(r) => self.reg8(r as usize),
            EffectiveAddress::Memory(linear) => bus.read_u8(linear),
        }
    }

    #[inline(always)]
    fn write_ea8(&mut self, bus: &mut impl Bus, ea: EffectiveAddress, val: u8) {
        match ea {
            EffectiveAddress::Register(r) => self.set_reg8(r as usize, val),
            EffectiveAddress::Memory(linear) => bus.write_u8(linear, val),
        }
    }

    #[inline(always)]
    fn read_ea16(&self, bus: &mut impl Bus, ea: EffectiveAddress) -> u16 {
        match ea {
            EffectiveAddress::Register(r) => self.reg16(r as usize),
            EffectiveAddress::Memory(linear) => bus.read_u16(linear),
        }
    }

    #[inline(always)]
    fn write_ea16(&mut self, bus: &mut impl Bus, ea: EffectiveAddress, val: u16) {
        match ea {
            EffectiveAddress::Register(r) => self.set_reg16(r as usize, val),
            EffectiveAddress::Memory(linear) => bus.write_u16(linear, val),
        }
    }

    #[inline(always)]
    fn read_ea32(&self, bus: &mut impl Bus, ea: EffectiveAddress) -> u32 {
        match ea {
            EffectiveAddress::Register(r) => self.reg32(r as usize),
            EffectiveAddress::Memory(linear) => bus.read_u32(linear),
        }
    }

    #[inline(always)]
    fn write_ea32(&mut self, bus: &mut impl Bus, ea: EffectiveAddress, val: u32) {
        match ea {
            EffectiveAddress::Register(r) => self.set_reg32(r as usize, val),
            EffectiveAddress::Memory(linear) => bus.write_u32(linear, val),
        }
    }

    // Load Far Pointer (LES, LDS, LSS, LFS, LGS)
    fn exec_load_far_pointer(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, target_sreg: usize) -> StepResult {
        let modrm = self.fetch_u8(bus);
        let reg_idx = ((modrm >> 3) & 7) as usize;
        let ea = self.resolve_modrm16(bus, modrm, seg_override);
        let linear = match ea {
            EffectiveAddress::Memory(l) => l,
            EffectiveAddress::Register(_) => return StepResult::Fault(Fault::InvalidOpcode(0xC5)),
        };
        let offset = bus.read_u16(linear);
        let seg = bus.read_u16(linear.wrapping_add(2));
        self.set_reg16(reg_idx, offset);
        self.set_sreg(target_sreg, seg);
        StepResult::Ok
    }

    // Group 1 helpers
    fn exec_group1_8(&mut self, op: u8, a: u8, b: u8) -> u8 {
        match op {
            0 => self.update_flags_add8(a, b, 0),
            1 => { let res = a | b; self.update_flags_logic8(res); res }
            2 => { let cf = if self.cf() { 1 } else { 0 }; self.update_flags_add8(a, b, cf) }
            3 => { let cf = if self.cf() { 1 } else { 0 }; self.update_flags_sub8(a, b, cf) }
            4 => { let res = a & b; self.update_flags_logic8(res); res }
            5 => self.update_flags_sub8(a, b, 0),
            6 => { let res = a ^ b; self.update_flags_logic8(res); res }
            7 => { self.update_flags_sub8(a, b, 0); a }
            _ => unreachable!(),
        }
    }

    fn exec_group1_16(&mut self, op: u8, a: u16, b: u16) -> u16 {
        match op {
            0 => self.update_flags_add16(a, b, 0),
            1 => { let res = a | b; self.update_flags_logic16(res); res }
            2 => { let cf = if self.cf() { 1 } else { 0 }; self.update_flags_add16(a, b, cf) }
            3 => { let cf = if self.cf() { 1 } else { 0 }; self.update_flags_sub16(a, b, cf) }
            4 => { let res = a & b; self.update_flags_logic16(res); res }
            5 => self.update_flags_sub16(a, b, 0),
            6 => { let res = a ^ b; self.update_flags_logic16(res); res }
            7 => { self.update_flags_sub16(a, b, 0); a }
            _ => unreachable!(),
        }
    }

    fn exec_group1_32(&mut self, op: u8, a: u32, b: u32) -> u32 {
        match op {
            0 => self.update_flags_add32(a, b, 0),
            1 => { let res = a | b; self.update_flags_logic32(res); res }
            2 => { let cf = if self.cf() { 1 } else { 0 }; self.update_flags_add32(a, b, cf) }
            3 => { let cf = if self.cf() { 1 } else { 0 }; self.update_flags_sub32(a, b, cf) }
            4 => { let res = a & b; self.update_flags_logic32(res); res }
            5 => self.update_flags_sub32(a, b, 0),
            6 => { let res = a ^ b; self.update_flags_logic32(res); res }
            7 => { self.update_flags_sub32(a, b, 0); a }
            _ => unreachable!(),
        }
    }

    // Generic ALU r/m, r and r, r/m helpers
    fn exec_alu_rm_r_8<F>(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, f: F) -> StepResult
    where F: FnOnce(&mut Cpu, u8, u8) -> u8 {
        let modrm = self.fetch_u8(bus);
        let reg = self.reg8(((modrm >> 3) & 7) as usize);
        let ea = self.resolve_modrm16(bus, modrm, seg_override);
        let rm_val = self.read_ea8(bus, ea);
        let res = f(self, rm_val, reg);
        self.write_ea8(bus, ea, res);
        StepResult::Ok
    }

    fn exec_alu_r_rm_8<F>(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, f: F) -> StepResult
    where F: FnOnce(&mut Cpu, u8, u8) -> u8 {
        let modrm = self.fetch_u8(bus);
        let reg_idx = ((modrm >> 3) & 7) as usize;
        let reg_val = self.reg8(reg_idx);
        let ea = self.resolve_modrm16(bus, modrm, seg_override);
        let rm_val = self.read_ea8(bus, ea);
        let res = f(self, reg_val, rm_val);
        self.set_reg8(reg_idx, res);
        StepResult::Ok
    }

    fn exec_alu_rm_r_16_32<F16, F32>(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, op32: bool, f16: F16, f32: F32) -> StepResult
    where F16: FnOnce(&mut Cpu, u16, u16) -> u16, F32: FnOnce(&mut Cpu, u32, u32) -> u32 {
        let modrm = self.fetch_u8(bus);
        let ea = self.resolve_modrm16(bus, modrm, seg_override);
        if op32 {
            let reg = self.reg32(((modrm >> 3) & 7) as usize);
            let rm_val = self.read_ea32(bus, ea);
            let res = f32(self, rm_val, reg);
            self.write_ea32(bus, ea, res);
        } else {
            let reg = self.reg16(((modrm >> 3) & 7) as usize);
            let rm_val = self.read_ea16(bus, ea);
            let res = f16(self, rm_val, reg);
            self.write_ea16(bus, ea, res);
        }
        StepResult::Ok
    }

    fn exec_alu_r_rm_16_32<F16, F32>(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, op32: bool, f16: F16, f32: F32) -> StepResult
    where F16: FnOnce(&mut Cpu, u16, u16) -> u16, F32: FnOnce(&mut Cpu, u32, u32) -> u32 {
        let modrm = self.fetch_u8(bus);
        let reg_idx = ((modrm >> 3) & 7) as usize;
        let ea = self.resolve_modrm16(bus, modrm, seg_override);
        if op32 {
            let reg_val = self.reg32(reg_idx);
            let rm_val = self.read_ea32(bus, ea);
            let res = f32(self, reg_val, rm_val);
            self.set_reg32(reg_idx, res);
        } else {
            let reg_val = self.reg16(reg_idx);
            let rm_val = self.read_ea16(bus, ea);
            let res = f16(self, reg_val, rm_val);
            self.set_reg16(reg_idx, res);
        }
        StepResult::Ok
    }

    // Shift Group 2 Execution
    fn exec_shift_group2_8(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, cnt: ShiftCount) -> StepResult {
        let modrm = self.fetch_u8(bus);
        let op_type = (modrm >> 3) & 7;
        let ea = self.resolve_modrm16(bus, modrm, seg_override);
        let count = match cnt {
            ShiftCount::One => 1,
            ShiftCount::Cl => self.cl() & 31,
            ShiftCount::Imm8 => self.fetch_u8(bus) & 31,
        };
        if count == 0 {
            return StepResult::Ok;
        }

        let val = self.read_ea8(bus, ea);
        let res = match op_type {
            4 => { // SHL / SAL
                let mut v = val as u32;
                let mut last_cf = false;
                for _ in 0..count {
                    last_cf = (v & 0x80) != 0;
                    v = (v << 1) & 0xFF;
                }
                self.set_cf(last_cf);
                if count == 1 {
                    self.set_of(((v >> 7) & 1) != (if last_cf { 1 } else { 0 }));
                }
                self.update_flags_logic8(v as u8);
                self.set_cf(last_cf);
                v as u8
            }
            5 => { // SHR
                let mut v = val;
                let mut last_cf = false;
                for _ in 0..count {
                    last_cf = (v & 1) != 0;
                    v >>= 1;
                }
                self.set_cf(last_cf);
                if count == 1 {
                    self.set_of((val & 0x80) != 0);
                }
                self.update_flags_logic8(v);
                self.set_cf(last_cf);
                v
            }
            7 => { // SAR
                let mut v = val as i8;
                let mut last_cf = false;
                for _ in 0..count {
                    last_cf = (v & 1) != 0;
                    v >>= 1;
                }
                self.set_cf(last_cf);
                if count == 1 {
                    self.set_of(false);
                }
                self.update_flags_logic8(v as u8);
                self.set_cf(last_cf);
                v as u8
            }
            _ => return StepResult::Fault(Fault::InvalidOpcode(0xD0)),
        };
        self.write_ea8(bus, ea, res);
        StepResult::Ok
    }

    fn exec_shift_group2_16_32(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, op32: bool, cnt: ShiftCount) -> StepResult {
        let modrm = self.fetch_u8(bus);
        let op_type = (modrm >> 3) & 7;
        let ea = self.resolve_modrm16(bus, modrm, seg_override);
        let count = match cnt {
            ShiftCount::One => 1,
            ShiftCount::Cl => self.cl() & 31,
            ShiftCount::Imm8 => self.fetch_u8(bus) & 31,
        };
        if count == 0 {
            return StepResult::Ok;
        }

        if op32 {
            let val = self.read_ea32(bus, ea);
            let res = match op_type {
                4 => { // SHL
                    let mut v = val as u64;
                    let mut last_cf = false;
                    for _ in 0..count {
                        last_cf = (v & 0x8000_0000) != 0;
                        v = (v << 1) & 0xFFFF_FFFF;
                    }
                    self.set_cf(last_cf);
                    if count == 1 {
                        self.set_of(((v >> 31) & 1) != (if last_cf { 1 } else { 0 }));
                    }
                    self.update_flags_logic32(v as u32);
                    self.set_cf(last_cf);
                    v as u32
                }
                5 => { // SHR
                    let mut v = val;
                    let mut last_cf = false;
                    for _ in 0..count {
                        last_cf = (v & 1) != 0;
                        v >>= 1;
                    }
                    self.set_cf(last_cf);
                    if count == 1 {
                        self.set_of((val & 0x8000_0000) != 0);
                    }
                    self.update_flags_logic32(v);
                    self.set_cf(last_cf);
                    v
                }
                7 => { // SAR
                    let mut v = val as i32;
                    let mut last_cf = false;
                    for _ in 0..count {
                        last_cf = (v & 1) != 0;
                        v >>= 1;
                    }
                    self.set_cf(last_cf);
                    if count == 1 {
                        self.set_of(false);
                    }
                    self.update_flags_logic32(v as u32);
                    self.set_cf(last_cf);
                    v as u32
                }
                _ => return StepResult::Fault(Fault::InvalidOpcode(0xD1)),
            };
            self.write_ea32(bus, ea, res);
        } else {
            let val = self.read_ea16(bus, ea);
            let res = match op_type {
                4 => { // SHL
                    let mut v = val as u32;
                    let mut last_cf = false;
                    for _ in 0..count {
                        last_cf = (v & 0x8000) != 0;
                        v = (v << 1) & 0xFFFF;
                    }
                    self.set_cf(last_cf);
                    if count == 1 {
                        self.set_of(((v >> 15) & 1) != (if last_cf { 1 } else { 0 }));
                    }
                    self.update_flags_logic16(v as u16);
                    self.set_cf(last_cf);
                    v as u16
                }
                5 => { // SHR
                    let mut v = val;
                    let mut last_cf = false;
                    for _ in 0..count {
                        last_cf = (v & 1) != 0;
                        v >>= 1;
                    }
                    self.set_cf(last_cf);
                    if count == 1 {
                        self.set_of((val & 0x8000) != 0);
                    }
                    self.update_flags_logic16(v);
                    self.set_cf(last_cf);
                    v
                }
                7 => { // SAR
                    let mut v = val as i16;
                    let mut last_cf = false;
                    for _ in 0..count {
                        last_cf = (v & 1) != 0;
                        v >>= 1;
                    }
                    self.set_cf(last_cf);
                    if count == 1 {
                        self.set_of(false);
                    }
                    self.update_flags_logic16(v as u16);
                    self.set_cf(last_cf);
                    v as u16
                }
                _ => return StepResult::Fault(Fault::InvalidOpcode(0xD1)),
            };
            self.write_ea16(bus, ea, res);
        }
        StepResult::Ok
    }

    // Group 3 Execution (TEST, NOT, NEG, MUL, IMUL, DIV, IDIV)
    fn exec_group3_8(&mut self, bus: &mut impl Bus, seg_override: Option<u16>) -> StepResult {
        let modrm = self.fetch_u8(bus);
        let op_type = (modrm >> 3) & 7;
        let ea = self.resolve_modrm16(bus, modrm, seg_override);
        match op_type {
            0 | 1 => { // TEST r/m8, imm8
                let imm = self.fetch_u8(bus);
                let v = self.read_ea8(bus, ea);
                self.update_flags_logic8(v & imm);
            }
            2 => { // NOT
                let v = self.read_ea8(bus, ea);
                self.write_ea8(bus, ea, !v);
            }
            3 => { // NEG
                let v = self.read_ea8(bus, ea);
                let res = self.update_flags_sub8(0, v, 0);
                self.set_cf(v != 0);
                self.write_ea8(bus, ea, res);
            }
            4 => { // MUL AL * r/m8 -> AX
                let v = self.read_ea8(bus, ea) as u16;
                let prod = (self.al() as u16) * v;
                self.set_ax(prod);
                let cf_of = (prod & 0xFF00) != 0;
                self.set_cf(cf_of);
                self.set_of(cf_of);
            }
            5 => { // IMUL AL * r/m8 -> AX
                let v = self.read_ea8(bus, ea) as i8 as i16;
                let prod = (self.al() as i8 as i16) * v;
                self.set_ax(prod as u16);
                let cf_of = prod != (prod as i8 as i16);
                self.set_cf(cf_of);
                self.set_of(cf_of);
            }
            6 => { // DIV AX / r/m8 -> AL (quot), AH (rem)
                let divisor = self.read_ea8(bus, ea) as u16;
                if divisor == 0 {
                    return StepResult::Fault(Fault::DivideError);
                }
                let quot = self.ax() / divisor;
                let rem = self.ax() % divisor;
                if quot > 0xFF {
                    return StepResult::Fault(Fault::DivideError);
                }
                self.set_al(quot as u8);
                self.set_ah(rem as u8);
            }
            7 => { // IDIV AX / r/m8 -> AL (quot), AH (rem)
                let divisor = self.read_ea8(bus, ea) as i8 as i16;
                if divisor == 0 {
                    return StepResult::Fault(Fault::DivideError);
                }
                let quot = (self.ax() as i16) / divisor;
                let rem = (self.ax() as i16) % divisor;
                if quot > 127 || quot < -128 {
                    return StepResult::Fault(Fault::DivideError);
                }
                self.set_al(quot as i8 as u8);
                self.set_ah(rem as i8 as u8);
            }
            _ => unreachable!(),
        }
        StepResult::Ok
    }

    fn exec_group3_16_32(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, op32: bool) -> StepResult {
        let modrm = self.fetch_u8(bus);
        let op_type = (modrm >> 3) & 7;
        let ea = self.resolve_modrm16(bus, modrm, seg_override);
        if op32 {
            match op_type {
                0 | 1 => { // TEST
                    let imm = self.fetch_u32(bus);
                    let v = self.read_ea32(bus, ea);
                    self.update_flags_logic32(v & imm);
                }
                2 => { // NOT
                    let v = self.read_ea32(bus, ea);
                    self.write_ea32(bus, ea, !v);
                }
                3 => { // NEG
                    let v = self.read_ea32(bus, ea);
                    let res = self.update_flags_sub32(0, v, 0);
                    self.set_cf(v != 0);
                    self.write_ea32(bus, ea, res);
                }
                4 => { // MUL EAX * r/m32 -> EDX:EAX
                    let v = self.read_ea32(bus, ea) as u64;
                    let prod = (self.eax as u64) * v;
                    self.eax = prod as u32;
                    self.edx = (prod >> 32) as u32;
                    let cf_of = self.edx != 0;
                    self.set_cf(cf_of);
                    self.set_of(cf_of);
                }
                5 => { // IMUL
                    let v = self.read_ea32(bus, ea) as i32 as i64;
                    let prod = (self.eax as i32 as i64) * v;
                    self.eax = prod as u32;
                    self.edx = (prod >> 32) as u32;
                    let cf_of = prod != (prod as i32 as i64);
                    self.set_cf(cf_of);
                    self.set_of(cf_of);
                }
                6 => { // DIV EDX:EAX / r/m32
                    let divisor = self.read_ea32(bus, ea) as u64;
                    if divisor == 0 {
                        return StepResult::Fault(Fault::DivideError);
                    }
                    let num = ((self.edx as u64) << 32) | (self.eax as u64);
                    let quot = num / divisor;
                    let rem = num % divisor;
                    if quot > 0xFFFF_FFFF {
                        return StepResult::Fault(Fault::DivideError);
                    }
                    self.eax = quot as u32;
                    self.edx = rem as u32;
                }
                7 => { // IDIV
                    let divisor = self.read_ea32(bus, ea) as i32 as i64;
                    if divisor == 0 {
                        return StepResult::Fault(Fault::DivideError);
                    }
                    let num = (((self.edx as u64) << 32) | (self.eax as u64)) as i64;
                    let quot = num / divisor;
                    let rem = num % divisor;
                    if quot > 0x7FFF_FFFF || quot < -0x8000_0000 {
                        return StepResult::Fault(Fault::DivideError);
                    }
                    self.eax = quot as i32 as u32;
                    self.edx = rem as i32 as u32;
                }
                _ => unreachable!(),
            }
        } else {
            match op_type {
                0 | 1 => { // TEST
                    let imm = self.fetch_u16(bus);
                    let v = self.read_ea16(bus, ea);
                    self.update_flags_logic16(v & imm);
                }
                2 => { // NOT
                    let v = self.read_ea16(bus, ea);
                    self.write_ea16(bus, ea, !v);
                }
                3 => { // NEG
                    let v = self.read_ea16(bus, ea);
                    let res = self.update_flags_sub16(0, v, 0);
                    self.set_cf(v != 0);
                    self.write_ea16(bus, ea, res);
                }
                4 => { // MUL AX * r/m16 -> DX:AX
                    let v = self.read_ea16(bus, ea) as u32;
                    let prod = (self.ax() as u32) * v;
                    self.set_ax(prod as u16);
                    self.set_dx((prod >> 16) as u16);
                    let cf_of = self.dx() != 0;
                    self.set_cf(cf_of);
                    self.set_of(cf_of);
                }
                5 => { // IMUL
                    let v = self.read_ea16(bus, ea) as i16 as i32;
                    let prod = (self.ax() as i16 as i32) * v;
                    self.set_ax(prod as u16);
                    self.set_dx((prod >> 16) as u16);
                    let cf_of = prod != (prod as i16 as i32);
                    self.set_cf(cf_of);
                    self.set_of(cf_of);
                }
                6 => { // DIV DX:AX / r/m16
                    let divisor = self.read_ea16(bus, ea) as u32;
                    if divisor == 0 {
                        return StepResult::Fault(Fault::DivideError);
                    }
                    let num = ((self.dx() as u32) << 16) | (self.ax() as u32);
                    let quot = num / divisor;
                    let rem = num % divisor;
                    if quot > 0xFFFF {
                        return StepResult::Fault(Fault::DivideError);
                    }
                    self.set_ax(quot as u16);
                    self.set_dx(rem as u16);
                }
                7 => { // IDIV
                    let divisor = self.read_ea16(bus, ea) as i16 as i32;
                    if divisor == 0 {
                        return StepResult::Fault(Fault::DivideError);
                    }
                    let num = (((self.dx() as u32) << 16) | (self.ax() as u32)) as i32;
                    let quot = num / divisor;
                    let rem = num % divisor;
                    if quot > 32767 || quot < -32768 {
                        return StepResult::Fault(Fault::DivideError);
                    }
                    self.set_ax(quot as i16 as u16);
                    self.set_dx(rem as i16 as u16);
                }
                _ => unreachable!(),
            }
        }
        StepResult::Ok
    }

    // Group 5 Execution (INC, DEC, CALL, CALL Far, JMP, JMP Far, PUSH)
    fn exec_group5(&mut self, bus: &mut impl Bus, seg_override: Option<u16>, op32: bool) -> StepResult {
        let modrm = self.fetch_u8(bus);
        let op_type = (modrm >> 3) & 7;
        let ea = self.resolve_modrm16(bus, modrm, seg_override);
        match op_type {
            0 => { // INC r/m
                if op32 {
                    let v = self.read_ea32(bus, ea);
                    let res = self.update_flags_inc32(v);
                    self.write_ea32(bus, ea, res);
                } else {
                    let v = self.read_ea16(bus, ea);
                    let res = self.update_flags_inc16(v);
                    self.write_ea16(bus, ea, res);
                }
            }
            1 => { // DEC r/m
                if op32 {
                    let v = self.read_ea32(bus, ea);
                    let res = self.update_flags_dec32(v);
                    self.write_ea32(bus, ea, res);
                } else {
                    let v = self.read_ea16(bus, ea);
                    let res = self.update_flags_dec16(v);
                    self.write_ea16(bus, ea, res);
                }
            }
            2 => { // CALL Near Indirect
                let new_ip = self.read_ea16(bus, ea);
                let ret_ip = self.ip;
                self.push16(bus, ret_ip);
                self.ip = new_ip;
            }
            3 => { // CALL Far Indirect
                let linear = match ea {
                    EffectiveAddress::Memory(l) => l,
                    _ => return StepResult::Fault(Fault::InvalidOpcode(0xFF)),
                };
                let new_ip = bus.read_u16(linear);
                let new_cs = bus.read_u16(linear.wrapping_add(2));
                let cur_cs = self.cs;
                let cur_ip = self.ip;
                self.push16(bus, cur_cs);
                self.push16(bus, cur_ip);
                self.cs = new_cs;
                self.ip = new_ip;
            }
            4 => { // JMP Near Indirect
                let new_ip = self.read_ea16(bus, ea);
                self.ip = new_ip;
            }
            5 => { // JMP Far Indirect
                let linear = match ea {
                    EffectiveAddress::Memory(l) => l,
                    _ => return StepResult::Fault(Fault::InvalidOpcode(0xFF)),
                };
                let new_ip = bus.read_u16(linear);
                let new_cs = bus.read_u16(linear.wrapping_add(2));
                self.ip = new_ip;
                self.cs = new_cs;
            }
            6 => { // PUSH r/m
                if op32 {
                    let v = self.read_ea32(bus, ea);
                    self.push32(bus, v);
                } else {
                    let v = self.read_ea16(bus, ea);
                    self.push16(bus, v);
                }
            }
            _ => return StepResult::Fault(Fault::InvalidOpcode(0xFF)),
        }
        StepResult::Ok
    }
}

/// Address resolved from ModR/M byte
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EffectiveAddress {
    Register(u8),
    Memory(u32),
}

enum ShiftCount {
    One,
    Cl,
    Imm8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::FlatMemory;

    #[test]
    fn test_add_sub_flags() {
        let mut cpu = Cpu::new();

        // 5 + 3 = 8
        let res = cpu.update_flags_add8(5, 3, 0);
        assert_eq!(res, 8);
        assert!(!cpu.cf());
        assert!(!cpu.zf());
        assert!(!cpu.sf());

        // 5 - 5 = 0
        let res = cpu.update_flags_sub8(5, 5, 0);
        assert_eq!(res, 0);
        assert!(!cpu.cf());
        assert!(cpu.zf());
        assert!(!cpu.sf());

        // 3 - 5 = 254 (borrow)
        let res = cpu.update_flags_sub8(3, 5, 0);
        assert_eq!(res, 254);
        assert!(cpu.cf());
        assert!(!cpu.zf());
        assert!(cpu.sf());
    }

    #[test]
    fn test_mov_and_add_execution() {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();

        // Code: mov ax, 0x1234; add ax, 0x1111
        // B8 34 12
        // 05 11 11
        mem.write_u8(0, 0xB8);
        mem.write_u8(1, 0x34);
        mem.write_u8(2, 0x12);
        mem.write_u8(3, 0x05);
        mem.write_u8(4, 0x11);
        mem.write_u8(5, 0x11);

        assert_eq!(cpu.step(&mut mem), StepResult::Ok);
        assert_eq!(cpu.ax(), 0x1234);

        assert_eq!(cpu.step(&mut mem), StepResult::Ok);
        assert_eq!(cpu.ax(), 0x2345);
        assert_eq!(cpu.ip, 6);
    }
}
