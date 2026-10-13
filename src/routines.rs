//! Hand-rewritten native Rust routines for Cybersphere (Milestone M5).
//!
//! Each routine is implemented as an idiomatic, plain typed Rust function
//! with a documented contract, accompanied by a hook adapter that precisely
//! reproduces x86 register, flag, and memory side effects.

use crate::bus::Bus;
use crate::cpu::Cpu;

// ============================================================================
// Routine 1: PRNG (`0x4506`)
// ============================================================================

/// Linear congruential generator (LCG) step used for all in-game pseudo-random numbers.
///
/// Multiplies 16-bit `seed` by multiplier `0x24A1` and adds increment `0x24DF`
/// modulo 65536. Masks result with `0x7FFF` to produce a 15-bit non-negative
/// dividend, then divides by `modulus` (stored in `BX`).
///
/// # Arguments
/// * `seed`: Current 16-bit PRNG seed from `DS:0x70C2`
/// * `modulus`: Divisor / range bound (must be > 0)
///
/// # Returns
/// * `(new_seed, quotient, remainder)`
#[inline]
pub fn prng_step(seed: u16, modulus: u16) -> (u16, u16, u16) {
    let new_seed = seed.wrapping_mul(0x24A1).wrapping_add(0x24DF);
    let dividend = (new_seed & 0x7FFF) as u32;
    let divisor = modulus as u32;
    let quot = (dividend / divisor) as u16;
    let rem = (dividend % divisor) as u16;
    (new_seed, quot, rem)
}

/// Native hook adapter for PRNG at `CS:0x4506`.
pub fn hook_prng(cpu: &mut Cpu, bus: &mut impl Bus) -> bool {
    let bx = cpu.bx();
    if bx == 0 {
        return false;
    }
    let ds_base = (cpu.ds as u32) << 4;
    let seed = bus.read_u16(ds_base + 0x70C2);
    let (new_seed, quot, rem) = prng_step(seed, bx);
    bus.write_u16(ds_base + 0x70C2, new_seed);

    cpu.set_ax(quot);
    cpu.set_dx(rem);
    cpu.set_cx(0x24A1);

    // `and ax, 0x7fff` clears CF, OF, AF; sets ZF, PF, SF
    let and_res = new_seed & 0x7FFF;
    cpu.update_flags_logic16(and_res);

    // Pop return IP from stack
    let ss_linear = (cpu.ss as u32) << 4;
    let sp = cpu.sp();
    let ret_ip = bus.read_u16(ss_linear + sp as u32);
    cpu.set_sp(sp.wrapping_add(2));
    cpu.ip = ret_ip;
    true
}

// ============================================================================
// Routine 2: Paddle Bounce Angle (`0x3477`)
// ============================================================================

/// Computes deflection angle relative to paddle center upon ball contact.
///
/// Adds 8-pixel center offset (`0x200` subpixels) to `ball_x`, subtracts `paddle_x`,
/// shifts down to pixels, and computes deflection relative to paddle center:
/// - Normal paddle: `angle = 2 * (x_offset - 28)`
/// - Wide paddle:   `angle = 1.5 * (x_offset - 38)`
/// Clamps angle to signed range `[-52, +52]` (`0xCC` to `0x34`).
///
/// # Arguments
/// * `ball_x`: 1/64th fixed-point ball X position (read from `[bx]`)
/// * `paddle_x`: 1/64th fixed-point paddle X position (read from `[DS:0x8778]`)
/// * `is_wide`: Wide paddle flag (read from `[DS:0x877A]`)
///
/// # Returns
/// * `(clamped_angle_u16, was_wide, pre_clamp_al)`
#[inline]
pub fn calculate_paddle_bounce_angle(ball_x: u16, paddle_x: u16, is_wide: bool) -> (u16, bool, u8) {
    let delta = (ball_x.wrapping_add(0x200).wrapping_sub(paddle_x) >> 6) as i16;
    let raw: i8 = if is_wide {
        let diff = (delta.wrapping_sub(38)) as i8;
        let prod = (diff as i16) * 3;
        (prod as i8) >> 1
    } else {
        let diff = (delta.wrapping_sub(28)) as i8;
        diff << 1
    };
    let pre_clamp = if raw < -52 { -52i8 as u8 } else { raw as u8 };
    let clamped: i8 = if (pre_clamp as i8) > 52 { 52 } else { pre_clamp as i8 };
    ((clamped as u8) as u16, is_wide, pre_clamp)
}

/// Native hook adapter for paddle bounce angle calculation at `CS:0x3477`.
pub fn hook_paddle_bounce_angle(cpu: &mut Cpu, bus: &mut impl Bus) -> bool {
    let ds_base = (cpu.ds as u32) << 4;
    let ball_ptr = cpu.bx();
    let ball_x = bus.read_u16(ds_base + ball_ptr as u32);
    let paddle_x = bus.read_u16(ds_base + 0x8778);
    let is_wide = bus.read_u16(ds_base + 0x877A) != 0;

    let (angle_u16, was_wide, pre_clamp_al) = calculate_paddle_bounce_angle(ball_x, paddle_x, is_wide);
    bus.write_u16(ds_base + (ball_ptr as u32) + 4, angle_u16);
    cpu.set_ax(angle_u16);
    if was_wide {
        cpu.set_dl(3);
    }

    // Status flags set by `cmp al, 0x34` (where al was pre_clamp_al)
    cpu.update_flags_sub8(pre_clamp_al, 0x34, 0);

    // Pop return IP from stack
    let ss_linear = (cpu.ss as u32) << 4;
    let sp = cpu.sp();
    let ret_ip = bus.read_u16(ss_linear + sp as u32);
    cpu.set_sp(sp.wrapping_add(2));
    cpu.ip = ret_ip;
    true
}

// ============================================================================
// Routine 3: Sine / Cosine Step Lookup & Step Integration (`0x34B7`)
// ============================================================================

/// Evaluates trigonometry step displacements from 256-byte sine lookup table.
///
/// Angle quadrature:
/// - Sine:   `sine_table[angle]`
/// - Cosine: `sine_table[(angle - 0x40) & 0xFF]`
/// Displacements scaled by speed: `(val * speed + 0x20) >> 6`.
///
/// # Arguments
/// * `angle`: 8-bit heading angle
/// * `speed`: 16-bit ball speed
/// * `sine_table`: 256 signed bytes table
///
/// # Returns
/// * `(step_x, step_y)` in 1/64th fixed-point pixels
#[inline]
pub fn trig_step(angle: u8, speed: i16, sine_table: &[i8; 256]) -> (i16, i16) {
    let sin_val = sine_table[angle as usize] as i16;
    let cos_val = sine_table[angle.wrapping_sub(0x40) as usize] as i16;
    let step_x = ((sin_val * speed).wrapping_add(0x20)) >> 6;
    let step_y = ((cos_val * speed).wrapping_add(0x20)) >> 6;
    (step_x, step_y)
}

pub fn hook_test_ball_step_collision(cpu: &mut Cpu, bus: &mut impl Bus) -> bool {
    hook_test_ball_step_collision_ext(cpu, bus, None)
}

/// Native hook adapter for ball step displacement and collision test at `CS:0x34B7`.
pub fn hook_test_ball_step_collision_ext(
    cpu: &mut Cpu,
    bus: &mut impl Bus,
    mut hit_counter: Option<&mut u64>,
) -> bool {
    let ds_base = (cpu.ds as u32) << 4;
    let bx_val = cpu.bx();
    let di_val = cpu.di();

    bus.write_u16(ds_base + 0x871A, 0);
    bus.write_u16(ds_base + 0x871C, 0);
    bus.write_u16(ds_base + 0x871E, 0);

    let ball_x = bus.read_u16(ds_base + bx_val as u32);
    bus.write_u16(ds_base + 0x868A, ball_x);

    let angle = bus.read_u16(ds_base + bx_val as u32 + 4) as u8;
    let speed = bus.read_u16(ds_base + bx_val as u32 + 6) as i16;

    if di_val != 2 {
        let sin_byte = bus.read_u8(ds_base + 0x59A4 + angle as u32) as i8 as i16;
        let prod_x = (sin_byte as i32) * (speed as i32);
        cpu.set_dx((prod_x >> 16) as u16);
        let step_x = ((prod_x as i16).wrapping_add(0x20)) >> 6;
        let mut new_x = ball_x.wrapping_add(step_x as u16);
        if (new_x as i16) <= 0 {
            new_x = new_x.wrapping_add(0x4DC0);
            bus.write_u16(ds_base + 0x8724, 1);
        }
        if (new_x as i16) >= 0x4E00 {
            new_x = new_x.wrapping_sub(0x4DC0);
            bus.write_u16(ds_base + 0x8724, 1);
        }
        bus.write_u16(ds_base + 0x868A, new_x);
        if di_val == 0 {
            bus.write_u16(ds_base + bx_val as u32, new_x);
        }
    }

    let ball_y = bus.read_u16(ds_base + bx_val as u32 + 2);
    bus.write_u16(ds_base + 0x868C, ball_y);

    if di_val == 1 {
        // Test brick grid hit
        exec_grid_hit_quad(cpu, bus, di_val, hit_counter.as_deref_mut());
    } else {
        let cos_byte = bus.read_u8(ds_base + 0x59A4 + (angle.wrapping_sub(0x40)) as u32) as i8 as i16;
        let prod_y = (cos_byte as i32) * (speed as i32);
        cpu.set_dx((prod_y >> 16) as u16);
        let step_y = ((prod_y as i16).wrapping_add(0x20)) >> 6;
        let new_y = ball_y.wrapping_add(step_y as u16);

        if (new_y as i16) < 0x3000 {
            bus.write_u16(ds_base + 0x868C, new_y);
            if di_val == 0 {
                bus.write_u16(ds_base + bx_val as u32 + 2, new_y);
                cpu.set_ax(new_y);
                cpu.set_cx(speed as u16);
                cpu.set_dx((prod_y >> 16) as u16);
                cpu.esi = 0x59A4 + ((angle.wrapping_sub(0x40) as u32) & 0xFF);
                cpu.edi = 0;
                cpu.update_flags_sub16(0, 0, 0);
            } else {
                exec_grid_hit_quad(cpu, bus, di_val, hit_counter.as_deref_mut());
            }
        } else {
            // Ball fell off screen into death plane - delegate to guest code or reproduce
            bus.write_u16(ds_base + bx_val as u32 + 6, 0x000C);
            let ds_seed = bus.read_u16(ds_base + 0x70C2);
            let (new_seed, _, rem) = prng_step(ds_seed, 0x54);
            bus.write_u16(ds_base + 0x70C2, new_seed);
            let new_angle = rem.wrapping_sub(0x2A);
            bus.write_u16(ds_base + bx_val as u32 + 4, new_angle);
            bus.write_u16(ds_base + bx_val as u32 + 2, 0x2F00);
            let unk8 = bus.read_u16(ds_base + bx_val as u32 + 8);
            if unk8 == 0 {
                bus.write_u16(ds_base + bx_val as u32 + 8, 1);
            }
        }
    }

    // Pop return IP from stack
    let ss_linear = (cpu.ss as u32) << 4;
    let sp = cpu.sp();
    let ret_ip = bus.read_u16(ss_linear + sp as u32);
    cpu.set_sp(sp.wrapping_add(2));
    cpu.ip = ret_ip;
    true
}

fn exec_grid_hit_quad(cpu: &mut Cpu, bus: &mut impl Bus, di_val: u16, hit_counter: Option<&mut u64>) {
    let ds_base = (cpu.ds as u32) << 4;
    bus.write_u16(ds_base + 0x8168, di_val);
    exec_test_brick_grid_hit_inner(cpu, bus);

    let cur_x = bus.read_u16(ds_base + 0x868A);
    bus.write_u16(ds_base + 0x868A, cur_x.wrapping_add(0x200));
    exec_test_brick_grid_hit_inner(cpu, bus);

    let cur_y = bus.read_u16(ds_base + 0x868C);
    bus.write_u16(ds_base + 0x868C, cur_y.wrapping_add(0x200));
    exec_test_brick_grid_hit_inner(cpu, bus);

    let cur_x2 = bus.read_u16(ds_base + 0x868A);
    bus.write_u16(ds_base + 0x868A, cur_x2.wrapping_sub(0x200));
    exec_test_brick_grid_hit_inner(cpu, bus);

    if let Some(c) = hit_counter {
        *c += 4;
    }
}

// ============================================================================
// Routine 4: Ball-Coordinate to Brick-Cell Mapping & Hit Test (`0x35BA`)
// ============================================================================

/// Maps 1/64th fixed-point ball coordinates to 16x20 brick cell index.
///
/// # Arguments
/// * `x`: 1/64th fixed-point X coordinate
/// * `y`: 1/64th fixed-point Y coordinate
/// * `arena_shifted`: Whether arena is shifted right by 10 pixels (`[DS:0x70D6]`)
///
/// # Returns
/// * `(row, col, cell_index)`: 0-based row (0..19), col (0..15), and 1D index
#[inline]
pub fn coord_to_brick_cell(x: u16, y: u16, arena_shifted: bool) -> (u16, u16, u16) {
    let row = ((y >> 6) / 10) & 0x1F;
    let adj_x = if arena_shifted { x.wrapping_add(0x280) } else { x };
    let col = ((adj_x >> 6) / 20) & 0x0F;
    let cell_idx = (row << 4) + col;
    (row, col, cell_idx)
}

/// Internal execution of `test_brick_grid_hit` without stack pop.
pub fn exec_test_brick_grid_hit_inner(cpu: &mut Cpu, bus: &mut impl Bus) {
    let ds_base = (cpu.ds as u32) << 4;
    let y = bus.read_u16(ds_base + 0x868C);
    let x = bus.read_u16(ds_base + 0x868A);
    let arena_shifted = bus.read_u8(ds_base + 0x70D6) != 0;

    let (row, col, cell_idx) = coord_to_brick_cell(x, y, arena_shifted);
    bus.write_u16(ds_base + 0x816C, row);
    bus.write_u16(ds_base + 0x816A, col);

    let mut si = 0x70D8 + cell_idx;
    let brick_type = bus.read_u8(ds_base + si as u32);
    let mut di = 0x5CA4 + ((brick_type as u16) << 2);
    let mut prop = bus.read_u32(ds_base + di as u32);

    cpu.set_dl(0x14);
    cpu.esi = si as u32;
    cpu.edi = di as u32;
    cpu.eax = prop;
    cpu.ecx = prop;

    let test_20m = prop & 0x2000_0000;
    cpu.ecx = test_20m;
    cpu.update_flags_logic32(test_20m);

    if test_20m != 0 {
        // Slant / prism brick
        let test_40m = prop & 0x4000_0000;
        cpu.ecx = test_40m;
        cpu.update_flags_logic32(test_40m);
        if test_40m != 0 {
            let shr_ecx = prop >> 0x1A;
            cpu.ecx = shr_ecx;
            let cx = (shr_ecx as u16 & 1) + 1;
            bus.write_u16(ds_base + 0x871E, cx);
            cpu.set_cx(cx);
            cpu.update_flags_add8((shr_ecx & 1) as u8, 1, 0);
            return;
        }

        let shr_ecx = prop >> 0x1A;
        cpu.ecx = shr_ecx;

        let col_w = bus.read_u16(ds_base + 0x816A);
        let mut ax = col_w.wrapping_mul(0x14);
        if arena_shifted {
            ax = ax.wrapping_sub(0x0A);
        }
        let orig_x = bus.read_u16(ds_base + 0x868A);
        let dx = (orig_x >> 6).wrapping_sub(ax);
        bus.write_u16(ds_base + 0x816A, dx);

        let row_w = bus.read_u16(ds_base + 0x816C);
        let ax_row = row_w.wrapping_mul(0x0A);
        let orig_y = bus.read_u16(ds_base + 0x868C);
        let dx_row = (orig_y >> 6).wrapping_sub(ax_row);
        bus.write_u16(ds_base + 0x816C, dx_row);

        cpu.set_dx(dx_row);
        let ch_flag = (shr_ecx as u8) & 4;
        let mut cur_col_diff = dx;
        if ch_flag != 0 {
            cur_col_diff = cur_col_diff.wrapping_sub(0x0A);
            bus.write_u16(ds_base + 0x816A, cur_col_diff);
        }

        let sum_xy = cur_col_diff.wrapping_add(dx_row);
        cpu.set_ax(sum_xy);
        let cl_mode = (shr_ecx as u8) & 3;

        let deflect = match cl_mode {
            0 => {
                cpu.update_flags_sub16(sum_xy, 9, 0);
                (sum_xy as i16) < 9
            }
            2 => {
                cpu.update_flags_sub16(sum_xy, 9, 0);
                (sum_xy as i16) > 9
            }
            1 => {
                cpu.set_ax(cur_col_diff);
                cpu.update_flags_sub16(cur_col_diff, dx_row, 0);
                (cur_col_diff as i16) > (dx_row as i16)
            }
            _ => {
                cpu.set_ax(cur_col_diff);
                cpu.update_flags_sub16(cur_col_diff, dx_row, 0);
                (cur_col_diff as i16) < (dx_row as i16)
            }
        };

        if deflect {
            let cx = (shr_ecx as u16 & 1) + 1;
            bus.write_u16(ds_base + 0x871E, cx);
            cpu.set_cx(cx);
            cpu.update_flags_add8((shr_ecx & 1) as u8, 1, 0);
        }
        return;
    }

    // Standard rectangular brick
    let test_point = bus.read_u16(ds_base + 0x8168);
    cpu.update_flags_sub16(test_point, 3, 0);
    if test_point == 3 {
        return;
    }

    let test_80m = prop & 0x8000_0000;
    cpu.ecx = test_80m;
    cpu.update_flags_logic32(test_80m);
    if test_80m == 0 {
        return;
    }

    bus.write_u16(ds_base + 0x871A, 1);
    let test_1m = prop & 0x0100_0000;
    cpu.ecx = test_1m;
    cpu.update_flags_logic32(test_1m);
    if test_1m == 0 {
        return;
    }
    bus.write_u16(ds_base + 0x871C, 1);

    // Queue hit brick into 0x869A
    loop {
        let hit_count = bus.read_u32(ds_base + 0x8696);
        let mut already_queued = false;
        let mut q_di = 0x869A;
        if (hit_count as u16) != 0 {
            for _ in 0..hit_count {
                if bus.read_u16(ds_base + q_di as u32) == si {
                    already_queued = true;
                    cpu.update_flags_sub16(si, bus.read_u16(ds_base + q_di as u32), 0);
                    break;
                }
                q_di += 8;
            }
        }

        if already_queued {
            return;
        }

        bus.write_u32(ds_base + 0x8696, hit_count + 1);
        bus.write_u32(ds_base + q_di as u32, si as u32);
        bus.write_u32(ds_base + q_di as u32 + 4, prop);

        let test_2m = prop & 0x0200_0000;
        cpu.ecx = test_2m;
        cpu.update_flags_logic32(test_2m);
        if test_2m == 0 {
            break;
        }

        // Multi-tile connected brick
        let dir = (prop >> 0x1A) & 3;
        match dir {
            0 => si = si.wrapping_sub(0x10),
            1 => si = si.wrapping_add(1),
            2 => si = si.wrapping_add(0x10),
            _ => si = si.wrapping_sub(1),
        }
        let btype = bus.read_u8(ds_base + si as u32);
        di = 0x5CA4 + ((btype as u16) << 2);
        prop = bus.read_u32(ds_base + di as u32);
        cpu.esi = si as u32;
        cpu.edi = di as u32;
        cpu.eax = prop;
    }
}

/// Native hook adapter for ball-coordinate to brick-cell mapping at `CS:0x35BA`.
pub fn hook_test_brick_grid_hit(cpu: &mut Cpu, bus: &mut impl Bus) -> bool {
    exec_test_brick_grid_hit_inner(cpu, bus);

    // Pop return IP from stack
    let ss_linear = (cpu.ss as u32) << 4;
    let sp = cpu.sp();
    let ret_ip = bus.read_u16(ss_linear + sp as u32);
    cpu.set_sp(sp.wrapping_add(2));
    cpu.ip = ret_ip;
    true
}

// ============================================================================
// Routine 5: Multiball Spawner (`0x21FC`)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnMultiballResult {
    Inhibited,
    SlotAllocated { slot_index: u16, ball_x: u16 },
    NoSlotAvailable,
}

/// Searches the 16 ball slots for an inactive slot and initializes it.
///
/// # Arguments
/// * `inhibit`: Multiball inhibit flag (`[DS:0x8726]`)
/// * `paddle_x`: Paddle horizontal coordinate (`[DS:0x8778]`)
/// * `slots_active`: Active flags of the 16 ball slots
///
/// # Returns
/// * `SpawnMultiballResult`
pub fn spawn_multiball(
    inhibit: bool,
    paddle_x: u16,
    slots_active: &[u16; 16],
) -> SpawnMultiballResult {
    if inhibit {
        return SpawnMultiballResult::Inhibited;
    }
    for (i, &active) in slots_active.iter().enumerate() {
        if active == 0 {
            let slot_index = (i + 1) as u16;
            let ball_x = paddle_x.wrapping_add(0x500);
            return SpawnMultiballResult::SlotAllocated { slot_index, ball_x };
        }
    }
    SpawnMultiballResult::NoSlotAvailable
}

/// Native hook adapter for multiball spawning at `CS:0x21FC`.
pub fn hook_spawn_multiball(cpu: &mut Cpu, bus: &mut impl Bus) -> bool {
    let ds_base = (cpu.ds as u32) << 4;
    let inhibit = bus.read_u16(ds_base + 0x8726) != 0;
    let paddle_x = bus.read_u16(ds_base + 0x8778);

    let mut slots_active = [0u16; 16];
    for i in 0..16 {
        slots_active[i] = bus.read_u16(ds_base + 0x85CA + (i as u32 * 12) + 6);
    }

    let res = spawn_multiball(inhibit, paddle_x, &slots_active);
    match res {
        SpawnMultiballResult::Inhibited => {
            cpu.update_flags_sub16(bus.read_u16(ds_base + 0x8726), 0, 0);
            cpu.set_ax(0);
        }
        SpawnMultiballResult::SlotAllocated { slot_index, ball_x } => {
            let di = 0x85CA + (slot_index - 1) * 12;
            let di_linear = ds_base + di as u32;
            bus.write_u16(di_linear + 0, ball_x);
            bus.write_u16(di_linear + 2, 0x2BC0);
            bus.write_u16(di_linear + 4, 0x00E8);
            let b_active = bus.read_u16(ds_base + 0x87B2);
            bus.write_u16(di_linear + 6, b_active);
            bus.write_u16(di_linear + 8, 0);

            bus.write_u16(ds_base + 0x8780, slot_index);
            bus.write_u16(ds_base + 0x8782, 0x500);
            bus.write_u16(ds_base + 0x8784, 0x20);
            let timer_init = bus.read_u16(ds_base + 0x87BC);
            bus.write_u16(ds_base + 0x8786, timer_init);

            let shadow = bus.read_u16(ds_base + 0x87F8);
            if shadow != 0 {
                bus.write_u16(ds_base + 0x87DE, 0x3800);
            }
            cpu.update_flags_sub16(shadow, 0, 0);

            cpu.set_ax(0);
            cpu.set_cx(slot_index);
            cpu.set_di(di);
        }
        SpawnMultiballResult::NoSlotAvailable => {
            cpu.update_flags_sub16(17, 0x10, 0);
            cpu.set_ax(1);
            cpu.set_cx(17);
            cpu.set_di(0x868A);
        }
    }

    // Pop return IP from stack
    let ss_linear = (cpu.ss as u32) << 4;
    let sp = cpu.sp();
    let ret_ip = bus.read_u16(ss_linear + sp as u32);
    cpu.set_sp(sp.wrapping_add(2));
    cpu.ip = ret_ip;
    true
}

// ============================================================================
// Routine Hook Registry & Dispatcher
// ============================================================================

#[derive(Default, Debug, Clone, Copy)]
pub struct HookMask {
    pub prng: bool,
    pub paddle_bounce: bool,
    pub multiball: bool,
    pub trig_step: bool,
    pub brick_hit: bool,
}

impl HookMask {
    pub fn all() -> Self {
        Self {
            prng: true,
            paddle_bounce: true,
            multiball: true,
            trig_step: true,
            brick_hit: true,
        }
    }

    pub fn parse(s: &str) -> Self {
        let mut mask = Self::default();
        for item in s.split(',') {
            match item.trim().to_lowercase().as_str() {
                "all" => return Self::all(),
                "prng" | "0x4506" => mask.prng = true,
                "paddle" | "bounce" | "0x3477" => mask.paddle_bounce = true,
                "multiball" | "0x21fc" => mask.multiball = true,
                "trig" | "step" | "0x34b7" => mask.trig_step = true,
                "brick" | "grid" | "0x35ba" => mask.brick_hit = true,
                _ => {}
            }
        }
        mask
    }
}

/// Dispatches native hooks if the CPU instruction pointer matches a registered routine.
/// Returns true if a native hook was executed (instruction execution should be skipped).
pub fn try_dispatch_hook(
    cpu: &mut Cpu,
    bus: &mut impl Bus,
    load_seg: u16,
    mask: &HookMask,
    call_counts: &mut [u64; 5],
) -> bool {
    if cpu.cs != load_seg {
        return false;
    }
    match cpu.ip {
        0x4506 if mask.prng => {
            call_counts[0] += 1;
            hook_prng(cpu, bus)
        }
        0x3477 if mask.paddle_bounce => {
            call_counts[1] += 1;
            hook_paddle_bounce_angle(cpu, bus)
        }
        0x21FC if mask.multiball => {
            call_counts[2] += 1;
            hook_spawn_multiball(cpu, bus)
        }
        0x34B7 if mask.trig_step => {
            call_counts[3] += 1;
            let brick_active = mask.brick_hit;
            hook_test_ball_step_collision_ext(
                cpu,
                bus,
                if brick_active { Some(&mut call_counts[4]) } else { None },
            )
        }
        0x35BA if mask.brick_hit => {
            call_counts[4] += 1;
            hook_test_brick_grid_hit(cpu, bus)
        }
        _ => false,
    }
}
