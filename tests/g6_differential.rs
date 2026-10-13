//! Differential test suite for Gate G6:
//! Comparing interpreter single-step vs native Rust routines from routine entry to `ret`
//! across 10,000 random states each.

use cyber_rs::bus::{Bus, FlatMemory};
use cyber_rs::cpu::{Cpu, StepResult};
use cyber_rs::routines::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const LOAD_SEG: u16 = 0x1000;
const DS_SEG: u16 = 0x1575;
const SS_SEG: u16 = 0x1EE4;

fn load_base_memory() -> FlatMemory {
    let mut mem = FlatMemory::new(1024 * 1024);
    let candidates = [
        std::path::PathBuf::from("../../cybersphere/run_target/CYBER.EXE"),
        std::path::PathBuf::from("studio/re/work/cybersphere/run_target/CYBER.EXE"),
        std::path::PathBuf::from("../cybersphere/run_target/CYBER.EXE"),
        std::path::PathBuf::from("run_target/CYBER.EXE"),
    ];
    let mut found = None;
    for c in &candidates {
        if c.exists() {
            found = Some(c.clone());
            break;
        }
    }
    let path = found.expect("failed to locate CYBER.EXE");
    let mut f = File::open(&path).expect("failed to open CYBER.EXE");
    let mut data = Vec::new();
    f.read_to_end(&mut data).expect("failed to read CYBER.EXE");

    let n_relocs = u16::from_le_bytes([data[6], data[7]]) as usize;
    let hdr_paragraphs = u16::from_le_bytes([data[8], data[9]]) as usize;
    let reloc_table_offset = u16::from_le_bytes([data[24], data[25]]) as usize;
    let hdr_bytes = hdr_paragraphs * 16;
    let image_bytes = &data[hdr_bytes..];

    let load_base = (LOAD_SEG as u32) << 4;
    for (i, &b) in image_bytes.iter().enumerate() {
        mem.write_u8(load_base + i as u32, b);
    }

    for i in 0..n_relocs {
        let entry_off = reloc_table_offset + i * 4;
        let rel_off = u16::from_le_bytes([data[entry_off], data[entry_off + 1]]);
        let rel_seg = u16::from_le_bytes([data[entry_off + 2], data[entry_off + 3]]);
        let target_linear = ((rel_seg as u32 + LOAD_SEG as u32) << 4) + rel_off as u32;
        let orig_word = mem.read_u16(target_linear);
        mem.write_u16(target_linear, orig_word.wrapping_add(LOAD_SEG));
    }

    mem
}

struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn next_u16(&mut self) -> u16 {
        self.next_u64() as u16
    }
}

const RET_SENTINEL: u16 = 0x9876;

fn step_interpreter_to_ret(cpu: &mut Cpu, mem: &mut FlatMemory) {
    let mut steps = 0;
    while cpu.ip != RET_SENTINEL && steps < 50_000 {
        match cpu.step(mem) {
            StepResult::Ok => {}
            other => panic!("Interpreter error at CS:IP={:04X}:{:04X}: {:?}", cpu.cs, cpu.ip, other),
        }
        steps += 1;
    }
    assert_eq!(cpu.ip, RET_SENTINEL, "interpreter did not return to sentinel within {} steps", steps);
}

fn compare_cpu_and_mem(
    routine_name: &str,
    iter: usize,
    cpu_interp: &Cpu,
    cpu_hook: &Cpu,
    mem_interp: &FlatMemory,
    mem_hook: &FlatMemory,
) {
    assert_eq!(cpu_interp.ax(), cpu_hook.ax(), "[{}] Iteration {}: AX mismatch", routine_name, iter);
    assert_eq!(cpu_interp.bx(), cpu_hook.bx(), "[{}] Iteration {}: BX mismatch", routine_name, iter);
    assert_eq!(cpu_interp.cx(), cpu_hook.cx(), "[{}] Iteration {}: CX mismatch", routine_name, iter);
    assert_eq!(cpu_interp.dx(), cpu_hook.dx(), "[{}] Iteration {}: DX mismatch", routine_name, iter);
    assert_eq!(cpu_interp.sp(), cpu_hook.sp(), "[{}] Iteration {}: SP mismatch", routine_name, iter);
    assert_eq!(cpu_interp.bp(), cpu_hook.bp(), "[{}] Iteration {}: BP mismatch", routine_name, iter);
    assert_eq!(cpu_interp.si(), cpu_hook.si(), "[{}] Iteration {}: SI mismatch", routine_name, iter);
    assert_eq!(cpu_interp.di(), cpu_hook.di(), "[{}] Iteration {}: DI mismatch", routine_name, iter);
    assert_eq!(cpu_interp.ip, cpu_hook.ip, "[{}] Iteration {}: IP mismatch", routine_name, iter);

    // Flags check: CF, PF, AF, ZF, SF, OF
    assert_eq!(cpu_interp.cf(), cpu_hook.cf(), "[{}] Iteration {}: CF mismatch", routine_name, iter);
    assert_eq!(cpu_interp.pf(), cpu_hook.pf(), "[{}] Iteration {}: PF mismatch", routine_name, iter);
    assert_eq!(cpu_interp.af(), cpu_hook.af(), "[{}] Iteration {}: AF mismatch", routine_name, iter);
    assert_eq!(cpu_interp.zf(), cpu_hook.zf(), "[{}] Iteration {}: ZF mismatch", routine_name, iter);
    assert_eq!(cpu_interp.sf(), cpu_hook.sf(), "[{}] Iteration {}: SF mismatch", routine_name, iter);
    assert_eq!(cpu_interp.of(), cpu_hook.of(), "[{}] Iteration {}: OF mismatch", routine_name, iter);

    // Memory writes check (ignoring transient stack below SP)
    let ss_base = (cpu_interp.ss as usize) << 4;
    let sp = cpu_interp.sp() as usize;
    for (addr, (&b_int, &b_hk)) in mem_interp.data.iter().zip(mem_hook.data.iter()).enumerate() {
        if addr >= ss_base && addr < ss_base + sp {
            continue;
        }
        if b_int != b_hk {
            panic!(
                "[{}] Iteration {}: Memory mismatch at physical 0x{:05X} (interp: 0x{:02X}, hook: 0x{:02X})",
                routine_name, iter, addr, b_int, b_hk
            );
        }
    }
}

#[test]
fn test_gate_g6_differential_prng() {
    let base_mem = load_base_memory();
    let mut rng = Rng(0x1234_5678_9ABC_DEF0);
    let ds_base = (DS_SEG as u32) << 4;
    let ss_base = (SS_SEG as u32) << 4;

    println!("[G6] Testing Routine 1: PRNG (0x4506) across 10,000 random states...");
    for iter in 0..10_000 {
        let mut mem_interp = base_mem.clone();
        let mut cpu_interp = Cpu::new();
        cpu_interp.cs = LOAD_SEG;
        cpu_interp.ds = DS_SEG;
        cpu_interp.ss = SS_SEG;
        cpu_interp.ip = 0x4506;
        let sp = 0xFE00u16;
        cpu_interp.set_sp(sp);
        mem_interp.write_u16(ss_base + sp as u32, RET_SENTINEL);

        let seed = rng.next_u16();
        let mut bx = rng.next_u16();
        if bx == 0 { bx = 1; }
        mem_interp.write_u16(ds_base + 0x70C2, seed);
        cpu_interp.set_bx(bx);
        cpu_interp.set_ax(rng.next_u16());
        cpu_interp.set_cx(rng.next_u16());
        cpu_interp.set_dx(rng.next_u16());

        let mut mem_hook = mem_interp.clone();
        let mut cpu_hook = cpu_interp.clone();

        step_interpreter_to_ret(&mut cpu_interp, &mut mem_interp);
        let hooked = hook_prng(&mut cpu_hook, &mut mem_hook);
        assert!(hooked);

        compare_cpu_and_mem("PRNG", iter, &cpu_interp, &cpu_hook, &mem_interp, &mem_hook);
    }
    println!("[G6] PRNG (0x4506): 10,000 / 10,000 PASSED (0 mismatches)");
}

#[test]
fn test_gate_g6_differential_paddle_bounce() {
    let base_mem = load_base_memory();
    let mut rng = Rng(0xFEDC_BA98_7654_3210);
    let ds_base = (DS_SEG as u32) << 4;
    let ss_base = (SS_SEG as u32) << 4;

    println!("[G6] Testing Routine 2: Paddle Bounce Angle (0x3477) across 10,000 random states...");
    for iter in 0..10_000 {
        let mut mem_interp = base_mem.clone();
        let mut cpu_interp = Cpu::new();
        cpu_interp.cs = LOAD_SEG;
        cpu_interp.ds = DS_SEG;
        cpu_interp.ss = SS_SEG;
        cpu_interp.ip = 0x3477;
        let sp = 0xFE00u16;
        cpu_interp.set_sp(sp);
        mem_interp.write_u16(ss_base + sp as u32, RET_SENTINEL);

        let ball_ptr = 0x85CAu16;
        cpu_interp.set_bx(ball_ptr);
        let ball_x = rng.next_u16();
        let paddle_x = rng.next_u16();
        let is_wide = if (rng.next_u16() % 2) == 1 { 1u16 } else { 0u16 };

        mem_interp.write_u16(ds_base + ball_ptr as u32, ball_x);
        mem_interp.write_u16(ds_base + 0x8778, paddle_x);
        mem_interp.write_u16(ds_base + 0x877A, is_wide);
        cpu_interp.set_ax(rng.next_u16());
        cpu_interp.set_dx(rng.next_u16());

        let mut mem_hook = mem_interp.clone();
        let mut cpu_hook = cpu_interp.clone();

        step_interpreter_to_ret(&mut cpu_interp, &mut mem_interp);
        let hooked = hook_paddle_bounce_angle(&mut cpu_hook, &mut mem_hook);
        assert!(hooked);

        compare_cpu_and_mem("PaddleBounce", iter, &cpu_interp, &cpu_hook, &mem_interp, &mem_hook);
    }
    println!("[G6] Paddle Bounce Angle (0x3477): 10,000 / 10,000 PASSED (0 mismatches)");
}

#[test]
fn test_gate_g6_differential_spawn_multiball() {
    let base_mem = load_base_memory();
    let mut rng = Rng(0xCAFE_BABE_0123_4567);
    let ds_base = (DS_SEG as u32) << 4;
    let ss_base = (SS_SEG as u32) << 4;

    println!("[G6] Testing Routine 5: Multiball Spawner (0x21FC) across 10,000 random states...");
    for iter in 0..10_000 {
        let mut mem_interp = base_mem.clone();
        let mut cpu_interp = Cpu::new();
        cpu_interp.cs = LOAD_SEG;
        cpu_interp.ds = DS_SEG;
        cpu_interp.ss = SS_SEG;
        cpu_interp.ip = 0x21FC;
        let sp = 0xFE00u16;
        cpu_interp.set_sp(sp);
        mem_interp.write_u16(ss_base + sp as u32, RET_SENTINEL);

        let inhibit = if (rng.next_u16() % 10) == 0 { rng.next_u16() } else { 0 };
        mem_interp.write_u16(ds_base + 0x8726, inhibit);
        mem_interp.write_u16(ds_base + 0x8778, rng.next_u16());
        mem_interp.write_u16(ds_base + 0x87B2, rng.next_u16());
        mem_interp.write_u16(ds_base + 0x87BC, rng.next_u16());
        let shadow = if (rng.next_u16() % 2) == 1 { rng.next_u16() } else { 0 };
        mem_interp.write_u16(ds_base + 0x87F8, shadow);

        // Fill slots with random active flags (mix of 0 and non-zero)
        for s in 0..16 {
            let active = if (rng.next_u16() % 3) == 0 { 0 } else { rng.next_u16() };
            mem_interp.write_u16(ds_base + 0x85CA + (s as u32 * 12) + 6, active);
        }

        let mut mem_hook = mem_interp.clone();
        let mut cpu_hook = cpu_interp.clone();

        step_interpreter_to_ret(&mut cpu_interp, &mut mem_interp);
        let hooked = hook_spawn_multiball(&mut cpu_hook, &mut mem_hook);
        assert!(hooked);

        compare_cpu_and_mem("SpawnMultiball", iter, &cpu_interp, &cpu_hook, &mem_interp, &mem_hook);
    }
    println!("[G6] Multiball Spawner (0x21FC): 10,000 / 10,000 PASSED (0 mismatches)");
}

#[test]
fn test_gate_g6_differential_brick_grid_hit() {
    let base_mem = load_base_memory();
    let mut rng = Rng(0x55AA_1234_9876_FEDC);
    let ds_base = (DS_SEG as u32) << 4;
    let ss_base = (SS_SEG as u32) << 4;

    println!("[G6] Testing Routine 4: Ball-Coord to Brick-Cell Hit (0x35BA) across 10,000 random states...");
    for iter in 0..10_000 {
        let mut mem_interp = base_mem.clone();
        let mut cpu_interp = Cpu::new();
        cpu_interp.cs = LOAD_SEG;
        cpu_interp.ds = DS_SEG;
        cpu_interp.ss = SS_SEG;
        cpu_interp.ip = 0x35BA;
        let sp = 0xFE00u16;
        cpu_interp.set_sp(sp);
        mem_interp.write_u16(ss_base + sp as u32, RET_SENTINEL);

        // Valid on-screen coordinates: X in 0..320*64, Y in 0..200*64
        let ball_x = (rng.next_u16() % (320 * 64)).max(64);
        let ball_y = (rng.next_u16() % (200 * 64)).max(64);
        let arena_shifted = if (rng.next_u16() % 2) == 1 { 1u8 } else { 0u8 };
        let test_pt = rng.next_u16() % 4;

        mem_interp.write_u16(ds_base + 0x868A, ball_x);
        mem_interp.write_u16(ds_base + 0x868C, ball_y);
        mem_interp.write_u8(ds_base + 0x70D6, arena_shifted);
        mem_interp.write_u16(ds_base + 0x8168, test_pt);

        // Reset outputs
        mem_interp.write_u16(ds_base + 0x871A, 0);
        mem_interp.write_u16(ds_base + 0x871C, 0);
        mem_interp.write_u16(ds_base + 0x871E, 0);
        mem_interp.write_u32(ds_base + 0x8696, 0);

        // Randomize brick grid cell at this coordinate to a valid brick type 0..20
        let (r, c, idx) = coord_to_brick_cell(ball_x, ball_y, arena_shifted != 0);
        let btype = (rng.next_u16() % 16) as u8;
        mem_interp.write_u8(ds_base + 0x70D8 + idx as u32, btype);

        let mut mem_hook = mem_interp.clone();
        let mut cpu_hook = cpu_interp.clone();

        step_interpreter_to_ret(&mut cpu_interp, &mut mem_interp);
        let hooked = hook_test_brick_grid_hit(&mut cpu_hook, &mut mem_hook);
        assert!(hooked);

        if iter == 0 {
            println!("Iter 0 Interp: AX={:X} CX={:X} DX={:X} SI={:X} DI={:X} EFLAGS={:08X}",
                cpu_interp.ax(), cpu_interp.cx(), cpu_interp.dx(), cpu_interp.si(), cpu_interp.di(), cpu_interp.eflags);
            println!("Iter 0 Hook:   AX={:X} CX={:X} DX={:X} SI={:X} DI={:X} EFLAGS={:08X}",
                cpu_hook.ax(), cpu_hook.cx(), cpu_hook.dx(), cpu_hook.si(), cpu_hook.di(), cpu_hook.eflags);
        }

        compare_cpu_and_mem("BrickGridHit", iter, &cpu_interp, &cpu_hook, &mem_interp, &mem_hook);
    }
    println!("[G6] Ball-Coord to Brick-Cell Hit (0x35BA): 10,000 / 10,000 PASSED (0 mismatches)");
}

#[test]
fn test_gate_g6_differential_trig_collision() {
    let base_mem = load_base_memory();
    let mut rng = Rng(0x9876_5432_10FE_DCBA);
    let ds_base = (DS_SEG as u32) << 4;
    let ss_base = (SS_SEG as u32) << 4;

    println!("[G6] Testing Routine 3: Trig Step Displacement & Collision (0x34B7) across 10,000 random states...");
    for iter in 0..10_000 {
        let mut mem_interp = base_mem.clone();
        let mut cpu_interp = Cpu::new();
        cpu_interp.cs = LOAD_SEG;
        cpu_interp.ds = DS_SEG;
        cpu_interp.ss = SS_SEG;
        cpu_interp.ip = 0x34B7;
        let sp = 0xFE00u16;
        cpu_interp.set_sp(sp);
        mem_interp.write_u16(ss_base + sp as u32, RET_SENTINEL);

        let ball_ptr = 0x85CAu16;
        cpu_interp.set_bx(ball_ptr);

        // di in 0..=3 (0=move step, 1=test X, 2=test Y, 3=test diagonal)
        let di = (rng.next_u16() % 4) as u16;
        cpu_interp.set_di(di);

        // Coordinates within active game field: X in 64..310*64, Y in 64..180*64
        let ball_x = 64 + (rng.next_u16() % (300 * 64));
        let ball_y = 64 + (rng.next_u16() % (170 * 64));
        let angle = rng.next_u16() & 0xFF;
        let speed = 0x0080 + (rng.next_u16() % 0x0280);

        mem_interp.write_u16(ds_base + ball_ptr as u32, ball_x);
        mem_interp.write_u16(ds_base + ball_ptr as u32 + 2, ball_y);
        mem_interp.write_u16(ds_base + ball_ptr as u32 + 4, angle);
        mem_interp.write_u16(ds_base + ball_ptr as u32 + 6, speed);
        mem_interp.write_u16(ds_base + ball_ptr as u32 + 8, 0);

        let arena_shifted = if (rng.next_u16() % 2) == 1 { 1u8 } else { 0u8 };
        mem_interp.write_u8(ds_base + 0x70D6, arena_shifted);

        // Reset hit flags
        mem_interp.write_u16(ds_base + 0x871A, 0);
        mem_interp.write_u16(ds_base + 0x871C, 0);
        mem_interp.write_u16(ds_base + 0x871E, 0);
        mem_interp.write_u16(ds_base + 0x8724, 0);
        mem_interp.write_u32(ds_base + 0x8696, 0);

        // Randomize scratch registers
        cpu_interp.set_ax(rng.next_u16());
        cpu_interp.set_cx(rng.next_u16());
        cpu_interp.set_dx(rng.next_u16());
        cpu_interp.set_si(rng.next_u16());

        let mut mem_hook = mem_interp.clone();
        let mut cpu_hook = cpu_interp.clone();

        step_interpreter_to_ret(&mut cpu_interp, &mut mem_interp);
        let hooked = hook_test_ball_step_collision(&mut cpu_hook, &mut mem_hook);
        assert!(hooked);

        if iter == 0 {
            println!("Iter 0 Interp: AX={:X} CX={:X} DX={:X} SI={:X} DI={:X} EFLAGS={:08X}",
                cpu_interp.ax(), cpu_interp.cx(), cpu_interp.dx(), cpu_interp.si(), cpu_interp.di(), cpu_interp.eflags);
            println!("Iter 0 Hook:   AX={:X} CX={:X} DX={:X} SI={:X} DI={:X} EFLAGS={:08X}",
                cpu_hook.ax(), cpu_hook.cx(), cpu_hook.dx(), cpu_hook.si(), cpu_hook.di(), cpu_hook.eflags);
        }

        compare_cpu_and_mem("TrigCollision", iter, &cpu_interp, &cpu_hook, &mem_interp, &mem_hook);
    }
    println!("[G6] Trig Step Displacement & Collision (0x34B7): 10,000 / 10,000 PASSED (0 mismatches)");
}

