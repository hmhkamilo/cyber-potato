use cyber_rs::{Bus, Cpu, FlatMemory, StepResult};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

const SPLITMIX64_GAMMA: u64 = 0x9E3779B97F4A7C15;
const SPLITMIX64_MUL1: u64 = 0xBF58476D1CE4E5B9;
const SPLITMIX64_MUL2: u64 = 0x94D049BB133111EB;

fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(SPLITMIX64_GAMMA);
    z = (z ^ (z >> 30)).wrapping_mul(SPLITMIX64_MUL1);
    z = (z ^ (z >> 27)).wrapping_mul(SPLITMIX64_MUL2);
    z ^ (z >> 31)
}

#[derive(Default)]
struct TestStats {
    passed: usize,
    failed: usize,
    skipped: usize,
}

fn main() {
    println!("============================================================");
    println!(" cyber-rs 16-bit x86 Real-Mode CPU Interpreter Test Runner");
    println!("============================================================");

    let mut mnemonic_results: BTreeMap<String, TestStats> = BTreeMap::new();

    // 1. Run Comprehensive Built-in Mnemonic Test Suite
    println!("\n[Phase 1] Executing Built-in Mnemonic Verification Suite...");
    run_all_builtin_tests(&mut mnemonic_results);

    // 2. Execute Reference Vectors from Referee
    println!("\n[Phase 2] Executing Unicorn Reference Vectors (vectors.bin)...");
    let vector_candidates = [
        PathBuf::from("../vectors"),
        PathBuf::from("studio/re/work/rust/vectors"),
        PathBuf::from("../../vectors"),
        PathBuf::from("vectors"),
    ];

    let mut executed_external = false;
    for dir in &vector_candidates {
        let bin_path = dir.join("vectors.bin");
        if bin_path.exists() {
            println!("  Found reference vectors: {}", bin_path.display());
            run_external_vectors_bin(dir, &bin_path, &mut mnemonic_results);
            executed_external = true;
            break;
        }
    }

    if !executed_external {
        println!("  [INFO] vectors.bin not found in search paths.");
    }

    // 3. Print Comprehensive Scoreboard
    println!("\n============================================================");
    println!(" MNEMONIC VERIFICATION SCOREBOARD");
    println!("============================================================");
    println!("{:<16} | {:<8} | {:<8} | {:<8} | {:<8}", "Mnemonic", "Passed", "Failed", "Skipped", "Status");
    println!("------------------------------------------------------------");

    let mut total_pass = 0;
    let mut total_fail = 0;
    let mut total_skip = 0;

    for (mnemonic, stats) in &mnemonic_results {
        total_pass += stats.passed;
        total_fail += stats.failed;
        total_skip += stats.skipped;
        let status = if stats.failed == 0 && stats.passed > 0 {
            "PASS"
        } else if stats.failed > 0 {
            "FAIL"
        } else {
            "SKIP"
        };
        println!("{:<16} | {:<8} | {:<8} | {:<8} | {:<8}", mnemonic, stats.passed, stats.failed, stats.skipped, status);
    }

    println!("------------------------------------------------------------");
    println!("TOTAL: {} mnemonics verified | {} passed | {} failed | {} skipped",
        mnemonic_results.len(), total_pass, total_fail, total_skip);
    println!("============================================================\n");

    if total_fail > 0 {
        println!("[!] Test run completed with failures.");
        std::process::exit(1);
    } else {
        println!("[+] All vectors and mnemonic tests PASSED cleanly!");
    }
}

fn record(results: &mut BTreeMap<String, TestStats>, mnemonic: &str, passed: bool) {
    let entry = results.entry(mnemonic.to_string()).or_default();
    if passed {
        entry.passed += 1;
    } else {
        entry.failed += 1;
    }
}

// ---------------------------------------------------------------------------
// Memory write tracking bus wrapper to ensure zero memory leakage between test cases
// ---------------------------------------------------------------------------
struct DirtyTracker<'a> {
    mem: &'a mut FlatMemory,
    dirty: Vec<usize>,
}

impl<'a> Bus for DirtyTracker<'a> {
    #[inline(always)]
    fn read_u8(&mut self, addr: u32) -> u8 {
        self.mem.read_u8(addr)
    }

    #[inline(always)]
    fn write_u8(&mut self, addr: u32, val: u8) {
        let idx = (addr as usize) & 0x001F_FFFF;
        self.dirty.push(idx);
        self.mem.write_u8(addr, val);
    }
}

// ---------------------------------------------------------------------------
// External Vector Runner (Format parser for vectors.bin)
// ---------------------------------------------------------------------------
fn run_external_vectors_bin(dir: &Path, bin_path: &Path, results: &mut BTreeMap<String, TestStats>) {
    // Load offset -> mnemonic mapping if available
    let map_path = dir.join("offset_mnemonic.json");
    let offset_map: BTreeMap<u32, String> = if map_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&map_path) {
            let parsed: Result<BTreeMap<String, String>, _> = serde_json_lite(&content);
            match parsed {
                Ok(m) => m.into_iter().filter_map(|(k, v)| k.parse::<u32>().ok().map(|off| (off, v))).collect(),
                Err(_) => BTreeMap::new(),
            }
        } else {
            BTreeMap::new()
        }
    } else {
        BTreeMap::new()
    };

    let f = match File::open(bin_path) {
        Ok(f) => f,
        Err(e) => {
            println!("  [ERROR] Failed to open {}: {}", bin_path.display(), e);
            return;
        }
    };
    let mut reader = BufReader::new(f);

    // Read Header: 20 bytes (<4sHHIQ)
    let mut hdr_bytes = [0u8; 20];
    if reader.read_exact(&mut hdr_bytes).is_err() {
        println!("  [ERROR] Failed to read header.");
        return;
    }
    let magic = &hdr_bytes[0..4];
    if magic != b"VEC1" {
        println!("  [ERROR] Invalid magic: {:?}", magic);
        return;
    }
    let version = u16::from_le_bytes([hdr_bytes[4], hdr_bytes[5]]);
    let k_cases = u16::from_le_bytes([hdr_bytes[6], hdr_bytes[7]]);
    let total_vectors = u32::from_le_bytes([hdr_bytes[8], hdr_bytes[9], hdr_bytes[10], hdr_bytes[11]]);
    let seed = u64::from_le_bytes([
        hdr_bytes[12], hdr_bytes[13], hdr_bytes[14], hdr_bytes[15],
        hdr_bytes[16], hdr_bytes[17], hdr_bytes[18], hdr_bytes[19],
    ]);

    println!("  Header: version={}, k_cases={}, total_vectors={}, seed=0x{:016X}",
        version, k_cases, total_vectors, seed);

    // Initialize 2 MB RAM with SplitMix64
    println!("  Initializing 2 MB deterministic RAM buffer...");
    let ram_size = 2 * 1024 * 1024;
    let mut ram = FlatMemory::new(ram_size);
    let words = ram_size / 8;
    for w in 0..words {
        let val = splitmix64(seed ^ (w as u64));
        ram.data[w*8..(w+1)*8].copy_from_slice(&val.to_le_bytes());
    }

    // Keep an immutable reference copy to restore quickly
    let original_ram = ram.data.clone();

    // Mask table for undefined flags (Intel SDM Vol 2)
    let get_undef_mask = |mn: &str| -> u32 {
        match mn {
            "and" | "or" | "xor" | "test" => 0x0010,
            "shl" | "shr" | "sar" => 0x0810,
            "mul" | "imul" => 0x00D4,
            "div" | "idiv" => 0x08D5,
            "bt" | "bts" | "btr" => 0x08D4,
            _ => 0x0000,
        }
    };

    let mut rec_buf = [0u8; 208];
    let mut vec_idx = 0;
    let mut batch_pass = 0;
    let mut batch_fail = 0;
    let mut fail_counts_by_mn: BTreeMap<String, usize> = BTreeMap::new();

    let start_time = std::time::Instant::now();

    while reader.read_exact(&mut rec_buf).is_ok() {
        vec_idx += 1;

        let image_offset = u32::from_le_bytes([rec_buf[0], rec_buf[1], rec_buf[2], rec_buf[3]]);
        let insn_len = rec_buf[4] as usize;
        let is_fault = rec_buf[5] != 0;
        let num_mem_diffs = rec_buf[6] as usize;
        let insn_bytes = &rec_buf[8..24];

        let mut init_gprs = [0u32; 8];
        for i in 0..8 {
            let o = 24 + i * 4;
            init_gprs[i] = u32::from_le_bytes([rec_buf[o], rec_buf[o+1], rec_buf[o+2], rec_buf[o+3]]);
        }

        let mut init_segs = [0u16; 6];
        for i in 0..6 {
            let o = 56 + i * 2;
            init_segs[i] = u16::from_le_bytes([rec_buf[o], rec_buf[o+1]]);
        }

        let init_ip = u32::from_le_bytes([rec_buf[68], rec_buf[69], rec_buf[70], rec_buf[71]]);
        let init_flags = u32::from_le_bytes([rec_buf[72], rec_buf[73], rec_buf[74], rec_buf[75]]);

        let mut final_gprs = [0u32; 8];
        for i in 0..8 {
            let o = 76 + i * 4;
            final_gprs[i] = u32::from_le_bytes([rec_buf[o], rec_buf[o+1], rec_buf[o+2], rec_buf[o+3]]);
        }

        let mut final_segs = [0u16; 6];
        for i in 0..6 {
            let o = 108 + i * 2;
            final_segs[i] = u16::from_le_bytes([rec_buf[o], rec_buf[o+1]]);
        }

        let final_ip = u32::from_le_bytes([rec_buf[120], rec_buf[121], rec_buf[122], rec_buf[123]]);
        let final_flags = u32::from_le_bytes([rec_buf[124], rec_buf[125], rec_buf[126], rec_buf[127]]);

        let mut mem_diff_addr = [0u32; 16];
        for i in 0..16 {
            let o = 128 + i * 4;
            mem_diff_addr[i] = u32::from_le_bytes([rec_buf[o], rec_buf[o+1], rec_buf[o+2], rec_buf[o+3]]);
        }
        let mem_diff_bytes = &rec_buf[192..208];

        // Resolve mnemonic
        let mnemonic = offset_map.get(&image_offset).cloned().unwrap_or_else(|| "unknown".to_string());

        // Setup CPU
        let mut cpu = Cpu::new();
        cpu.eax = init_gprs[0];
        cpu.ecx = init_gprs[1];
        cpu.edx = init_gprs[2];
        cpu.ebx = init_gprs[3];
        cpu.esp = init_gprs[4];
        cpu.ebp = init_gprs[5];
        cpu.esi = init_gprs[6];
        cpu.edi = init_gprs[7];

        cpu.cs = init_segs[0];
        cpu.ds = init_segs[1];
        cpu.es = init_segs[2];
        cpu.ss = init_segs[3];
        cpu.fs = init_segs[4];
        cpu.gs = init_segs[5];

        cpu.ip = init_ip as u16;
        cpu.eflags = init_flags;

        // Place instruction bytes in RAM
        let phys_addr = ((cpu.cs as u32) * 16 + (cpu.ip as u32)) as usize;
        ram.data[phys_addr..phys_addr + insn_len].copy_from_slice(&insn_bytes[..insn_len]);

        // Execute 1 step with dirty memory tracking
        let (step_res, dirty) = {
            let mut tracker = DirtyTracker {
                mem: &mut ram,
                dirty: Vec::with_capacity(32),
            };
            let res = cpu.step(&mut tracker);
            (res, tracker.dirty)
        };

        // Verify
        let mut passed = true;
        let mut reason = "";

        let expect_fault = is_fault || ((mnemonic == "div" || mnemonic == "idiv") && final_ip == init_ip);

        if expect_fault {
            match step_res {
                StepResult::Fault(_) => {}
                _ => { passed = false; reason = "expected fault, got normal completion"; }
            }
        } else {
            match step_res {
                StepResult::Ok => {
                    // Check GPRs
                    if cpu.eax != final_gprs[0] { passed = false; reason = "EAX mismatch"; }
                    else if cpu.ecx != final_gprs[1] { passed = false; reason = "ECX mismatch"; }
                    else if cpu.edx != final_gprs[2] { passed = false; reason = "EDX mismatch"; }
                    else if cpu.ebx != final_gprs[3] { passed = false; reason = "EBX mismatch"; }
                    else if cpu.esp != final_gprs[4] { passed = false; reason = "ESP mismatch"; }
                    else if cpu.ebp != final_gprs[5] { passed = false; reason = "EBP mismatch"; }
                    else if cpu.esi != final_gprs[6] { passed = false; reason = "ESI mismatch"; }
                    else if cpu.edi != final_gprs[7] { passed = false; reason = "EDI mismatch"; }
                    // Check Segments
                    else if cpu.cs != final_segs[0] { passed = false; reason = "CS mismatch"; }
                    else if cpu.ds != final_segs[1] { passed = false; reason = "DS mismatch"; }
                    else if cpu.es != final_segs[2] { passed = false; reason = "ES mismatch"; }
                    else if cpu.ss != final_segs[3] { passed = false; reason = "SS mismatch"; }
                    else if cpu.fs != final_segs[4] { passed = false; reason = "FS mismatch"; }
                    else if cpu.gs != final_segs[5] { passed = false; reason = "GS mismatch"; }
                    // Check IP
                    else if (cpu.ip as u32) != final_ip { passed = false; reason = "IP mismatch"; }
                    else {
                        // Check FLAGS with undefined mask
                        let undef_mask = get_undef_mask(&mnemonic);
                        const STATUS_FLAGS_MASK: u32 = 0x0CD5; // CF, PF, AF, ZF, SF, OF, DF
                        let cmp_mask = STATUS_FLAGS_MASK & !undef_mask;
                        if (cpu.eflags & cmp_mask) != (final_flags & cmp_mask) {
                            passed = false;
                            reason = "EFLAGS mismatch";
                        } else {
                            // Check Memory diffs
                            for i in 0..num_mem_diffs {
                                let m_addr = mem_diff_addr[i] as usize;
                                let exp_b = mem_diff_bytes[i];
                                if ram.data[m_addr] != exp_b {
                                    passed = false;
                                    reason = "Memory write mismatch";
                                    break;
                                }
                            }
                        }
                    }
                }
                StepResult::Fault(_) => {
                    passed = false;
                    reason = "unexpected fault";
                }
                _ => {
                    passed = false;
                    reason = "unexpected delegation";
                }
            }
        }

        if passed && !expect_fault {
            for &idx in dirty.iter() {
                if ram.data[idx] != original_ram[idx] {
                    let expected = (0..num_mem_diffs).any(|i| mem_diff_addr[i] as usize == idx);
                    if !expected {
                        passed = false;
                        reason = "EXTRA unexpected memory write";
                        break;
                    }
                }
            }
        }

        // Restore all modified memory
        for idx in dirty {
            ram.data[idx] = original_ram[idx];
        }
        for i in 0..num_mem_diffs {
            let m_addr = mem_diff_addr[i] as usize;
            ram.data[m_addr] = original_ram[m_addr];
        }
        ram.data[phys_addr..phys_addr + insn_len].copy_from_slice(&original_ram[phys_addr..phys_addr + insn_len]);

        if passed {
            batch_pass += 1;
            record(results, &mnemonic, true);
        } else {
            batch_fail += 1;
            record(results, &mnemonic, false);
            let fail_count = fail_counts_by_mn.entry(mnemonic.clone()).or_insert(0);
            if *fail_count < 2 {
                *fail_count += 1;
                println!("  [FAIL] {} (offset 0x{:04X}): {}", mnemonic, image_offset, reason);
                println!("    bytes: {:02X?}, is_fault: {}", &insn_bytes[..insn_len], is_fault);
                println!("    cpu: IP=0x{:04X}, EAX=0x{:08X}, FLAGS=0x{:04X}", cpu.ip, cpu.eax, cpu.eflags & 0x0CD5);
                println!("    exp: IP=0x{:04X}, EAX=0x{:08X}, FLAGS=0x{:04X}", final_ip, final_gprs[0], final_flags & 0x0CD5);
            }
        }

        if vec_idx % 10000 == 0 || vec_idx == total_vectors {
            let elapsed = start_time.elapsed().as_secs_f64();
            println!("  Tested {} / {} vectors ({:.1}%) - {} passed, {} failed ({:.1} v/s)",
                vec_idx, total_vectors, (vec_idx as f64 / total_vectors as f64) * 100.0,
                batch_pass, batch_fail, (vec_idx as f64) / elapsed.max(0.001));
        }
    }
}

// Minimal json parser helper for flat string->string map
fn serde_json_lite(json: &str) -> Result<BTreeMap<String, String>, ()> {
    let mut map = BTreeMap::new();
    let trimmed = json.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return Err(());
    }
    let inner = &trimmed[1..trimmed.len()-1];
    for part in inner.split(',') {
        let kv: Vec<&str> = part.split(':').collect();
        if kv.len() == 2 {
            let k = kv[0].trim().trim_matches('"');
            let v = kv[1].trim().trim_matches('"');
            map.insert(k.to_string(), v.to_string());
        }
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Built-in Verification Suite covering all 46 game mnemonics
// ---------------------------------------------------------------------------
fn run_all_builtin_tests(res: &mut BTreeMap<String, TestStats>) {
    // 1. mov
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        mem.write_u8(0x10000, 0xB8); mem.write_u8(0x10001, 0x34); mem.write_u8(0x10002, 0x12);
        mem.write_u8(0x10003, 0x66); mem.write_u8(0x10004, 0xB8);
        mem.write_u8(0x10005, 0x78); mem.write_u8(0x10006, 0x56); mem.write_u8(0x10007, 0x34); mem.write_u8(0x10008, 0x12);
        let s1 = cpu.step(&mut mem);
        let ok1 = s1 == StepResult::Ok && cpu.ax() == 0x1234;
        let s2 = cpu.step(&mut mem);
        let ok2 = s2 == StepResult::Ok && cpu.eax == 0x12345678;
        record(res, "mov", ok1 && ok2);
    }

    // 2. add & 3. adc
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        mem.write_u8(0x10000, 0x05); mem.write_u8(0x10001, 0xFF); mem.write_u8(0x10002, 0xFF);
        mem.write_u8(0x10003, 0x15); mem.write_u8(0x10004, 0x01); mem.write_u8(0x10005, 0x00);
        cpu.step(&mut mem);
        let ok_add = cpu.ax() == 0xFFFF && !cpu.cf();
        record(res, "add", ok_add);
        cpu.step(&mut mem);
        let ok_adc = cpu.ax() == 0x0000 && cpu.cf() && cpu.zf();
        record(res, "adc", ok_adc);
    }

    // 4. sub & 5. sbb & 6. cmp
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.set_ax(5);
        mem.write_u8(0x10000, 0x2D); mem.write_u8(0x10001, 0x05); mem.write_u8(0x10002, 0x00);
        mem.write_u8(0x10003, 0x1D); mem.write_u8(0x10004, 0x00); mem.write_u8(0x10005, 0x00);
        mem.write_u8(0x10006, 0x3D); mem.write_u8(0x10007, 0x00); mem.write_u8(0x10008, 0x00);
        cpu.step(&mut mem);
        record(res, "sub", cpu.ax() == 0 && cpu.zf());
        cpu.step(&mut mem);
        record(res, "sbb", cpu.ax() == 0 && !cpu.cf());
        cpu.step(&mut mem);
        record(res, "cmp", cpu.ax() == 0 && cpu.zf());
    }

    // 7. and & 8. or & 9. xor & 10. test
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.set_al(0b1010_1010);
        mem.write_u8(0x10000, 0x24); mem.write_u8(0x10001, 0x55);
        mem.write_u8(0x10002, 0x0C); mem.write_u8(0x10003, 0xAA);
        mem.write_u8(0x10004, 0x34); mem.write_u8(0x10005, 0xAA);
        mem.write_u8(0x10006, 0xA8); mem.write_u8(0x10007, 0x00);
        cpu.step(&mut mem);
        record(res, "and", cpu.al() == 0 && cpu.zf() && !cpu.cf());
        cpu.step(&mut mem);
        record(res, "or", cpu.al() == 0xAA && !cpu.zf());
        cpu.step(&mut mem);
        record(res, "xor", cpu.al() == 0 && cpu.zf());
        cpu.step(&mut mem);
        record(res, "test", cpu.al() == 0 && cpu.zf());
    }

    // 11. inc & 12. dec
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.set_ax(0xFFFF);
        cpu.set_cf(true);
        mem.write_u8(0x10000, 0x40);
        mem.write_u8(0x10001, 0x48);
        cpu.step(&mut mem);
        record(res, "inc", cpu.ax() == 0 && cpu.zf() && cpu.cf());
        cpu.step(&mut mem);
        record(res, "dec", cpu.ax() == 0xFFFF && !cpu.zf() && cpu.cf());
    }

    // 13. neg & 14. not
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.set_al(1);
        mem.write_u8(0x10000, 0xF6); mem.write_u8(0x10001, 0xD8);
        mem.write_u8(0x10002, 0xF6); mem.write_u8(0x10003, 0xD0);
        cpu.step(&mut mem);
        record(res, "neg", cpu.al() == 0xFF && cpu.cf());
        cpu.step(&mut mem);
        record(res, "not", cpu.al() == 0x00 && cpu.cf());
    }

    // 15. mul & 16. imul
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.set_al(10);
        cpu.set_bl(20);
        mem.write_u8(0x10000, 0xF6); mem.write_u8(0x10001, 0xE3);
        mem.write_u8(0x10002, 0x6B); mem.write_u8(0x10003, 0xC0); mem.write_u8(0x10004, 0x0A);
        cpu.step(&mut mem);
        record(res, "mul", cpu.ax() == 200 && !cpu.cf());
        cpu.step(&mut mem);
        record(res, "imul", cpu.ax() == 2000);
    }

    // 17. div & 18. idiv
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.set_ax(205);
        cpu.set_bl(10);
        mem.write_u8(0x10000, 0xF6); mem.write_u8(0x10001, 0xF3);
        cpu.step(&mut mem);
        record(res, "div", cpu.al() == 20 && cpu.ah() == 5);

        cpu.set_ax(0xFFEC);
        cpu.set_bl(3);
        mem.write_u8(0x10002, 0xF6); mem.write_u8(0x10003, 0xFB);
        cpu.step(&mut mem);
        record(res, "idiv", cpu.al() == 0xFA && cpu.ah() == 0xFE);
    }

    // 19. shl & 20. shr & 21. sar
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.set_al(0b1000_0001);
        mem.write_u8(0x10000, 0xD0); mem.write_u8(0x10001, 0xE0);
        mem.write_u8(0x10002, 0xD0); mem.write_u8(0x10003, 0xE8);
        mem.write_u8(0x10004, 0xD0); mem.write_u8(0x10005, 0xF8);
        cpu.step(&mut mem);
        record(res, "shl", cpu.al() == 0x02 && cpu.cf());
        cpu.step(&mut mem);
        record(res, "shr", cpu.al() == 0x01 && !cpu.cf());
        cpu.step(&mut mem);
        record(res, "sar", cpu.al() == 0x00 && cpu.cf());
    }

    // 22. push & 23. pop & 24. pusha & 25. popa & 26. pushf & 27. popf
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.ss = 0x2000; cpu.esp = 0x0200;
        cpu.set_ax(0x1234);
        mem.write_u8(0x10000, 0x50);
        mem.write_u8(0x10001, 0x5B);
        mem.write_u8(0x10002, 0x60);
        mem.write_u8(0x10003, 0x61);
        mem.write_u8(0x10004, 0x9C);
        mem.write_u8(0x10005, 0x9D);
        cpu.step(&mut mem);
        record(res, "push", cpu.sp() == 0x01FE);
        cpu.step(&mut mem);
        record(res, "pop", cpu.bx() == 0x1234 && cpu.sp() == 0x0200);
        cpu.step(&mut mem);
        record(res, "pusha", cpu.sp() == 0x01F0);
        cpu.step(&mut mem);
        record(res, "popa", cpu.sp() == 0x0200 && cpu.bx() == 0x1234);
        cpu.set_cf(true);
        cpu.step(&mut mem);
        record(res, "pushf", cpu.sp() == 0x01FE);
        cpu.set_cf(false);
        cpu.step(&mut mem);
        record(res, "popf", cpu.cf() == true && cpu.sp() == 0x0200);
    }

    // 28. jmp & 29. jcc & 30. jcxz & 31. loop
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        mem.write_u8(0x10000, 0xEB); mem.write_u8(0x10001, 0x02);
        cpu.step(&mut mem);
        record(res, "jmp", cpu.ip == 0x0004);

        cpu.set_zf(true);
        mem.write_u8(0x10004, 0x74); mem.write_u8(0x10005, 0x02);
        cpu.step(&mut mem);
        record(res, "jcc", cpu.ip == 0x0008);

        cpu.set_cx(0);
        mem.write_u8(0x10008, 0xE3); mem.write_u8(0x10009, 0x02);
        cpu.step(&mut mem);
        record(res, "jcxz", cpu.ip == 0x000C);

        cpu.set_cx(2);
        mem.write_u8(0x1000C, 0xE2); mem.write_u8(0x1000D, 0x02);
        cpu.step(&mut mem);
        record(res, "loop", cpu.cx() == 1 && cpu.ip == 0x0010);
    }

    // 32. call & 33. ret
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.ss = 0x2000; cpu.esp = 0x0100;
        mem.write_u8(0x10000, 0xE8); mem.write_u8(0x10001, 0x05); mem.write_u8(0x10002, 0x00);
        mem.write_u8(0x10008, 0xC3);
        cpu.step(&mut mem);
        record(res, "call", cpu.ip == 0x0008 && cpu.sp() == 0x00FE);
        cpu.step(&mut mem);
        record(res, "ret", cpu.ip == 0x0003 && cpu.sp() == 0x0100);
    }

    // 34. movs & 35. stos & 36. lods & 37. scas
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.ds = 0x1000; cpu.es = 0x2000;
        cpu.set_si(0x0100); cpu.set_di(0x0200);
        cpu.set_cx(4);
        mem.write_u8(0x10100, 0xAA); mem.write_u8(0x10101, 0xBB); mem.write_u8(0x10102, 0xCC); mem.write_u8(0x10103, 0xDD);
        mem.write_u8(0x10000, 0xF3); mem.write_u8(0x10001, 0xA4);
        while cpu.cx() > 0 { cpu.step(&mut mem); }
        let ok_movs = mem.read_u8(0x20200) == 0xAA && mem.read_u8(0x20203) == 0xDD && cpu.cx() == 0;
        record(res, "movs", ok_movs);

        cpu.set_al(0x55);
        cpu.set_di(0x0200);
        cpu.set_cx(4);
        mem.write_u8(0x10002, 0xF3); mem.write_u8(0x10003, 0xAA);
        while cpu.cx() > 0 { cpu.step(&mut mem); }
        let ok_stos = mem.read_u8(0x20200) == 0x55 && mem.read_u8(0x20203) == 0x55 && cpu.cx() == 0;
        record(res, "stos", ok_stos);

        cpu.set_si(0x0100);
        mem.write_u8(0x10004, 0xAC);
        cpu.step(&mut mem);
        record(res, "lods", cpu.al() == 0xAA && cpu.si() == 0x0101);

        cpu.set_di(0x0200);
        mem.write_u8(0x10005, 0xAE);
        cpu.step(&mut mem);
        record(res, "scas", !cpu.zf() && cpu.di() == 0x0201);
    }

    // 38. cbw/cwde & 39. cwd/cdq & 40. sahf & 41. lahf
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.set_al(0xFE);
        mem.write_u8(0x10000, 0x98);
        mem.write_u8(0x10001, 0x99);
        mem.write_u8(0x10002, 0x9E);
        mem.write_u8(0x10003, 0x9F);
        cpu.step(&mut mem);
        record(res, "cbw", cpu.ax() == 0xFFFE);
        cpu.step(&mut mem);
        record(res, "cwd", cpu.dx() == 0xFFFF);
        cpu.set_ah(0b1101_0101);
        cpu.step(&mut mem);
        record(res, "sahf", cpu.cf() == true && cpu.zf() == true);
        cpu.step(&mut mem);
        record(res, "lahf", (cpu.ah() & 0xD5) == 0xD5);
    }

    // 42. in & 43. out
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.set_dx(0x3DA);
        cpu.set_al(0x42);
        mem.write_u8(0x10000, 0xEC);
        mem.write_u8(0x10001, 0xEE);
        let s1 = cpu.step(&mut mem);
        let ok_in = matches!(s1, StepResult::PortIn { port: 0x3DA, size: 1 });
        record(res, "in", ok_in);
        let s2 = cpu.step(&mut mem);
        let ok_out = matches!(s2, StepResult::PortOut { port: 0x3DA, val: 0x42, size: 1 });
        record(res, "out", ok_out);
    }

    // 44. int & 45. iret
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.ss = 0x2000; cpu.esp = 0x0100;
        mem.write_u8(0x10000, 0xCD); mem.write_u8(0x10001, 0x21);
        mem.write_u8(0x10002, 0xCF);
        let s1 = cpu.step(&mut mem);
        record(res, "int", s1 == StepResult::Int(0x21));

        cpu.push16(&mut mem, 0x0202);
        cpu.push16(&mut mem, 0x1234);
        cpu.push16(&mut mem, 0x5678);
        let s2 = cpu.step(&mut mem);
        record(res, "iret", s2 == StepResult::Ok && cpu.cs == 0x1234 && cpu.ip == 0x5678);
    }

    // 46. bt / bts / btr
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000;
        cpu.set_ax(0b0000_1000);
        mem.write_u8(0x10000, 0x0F); mem.write_u8(0x10001, 0xBA); mem.write_u8(0x10002, 0xE0); mem.write_u8(0x10003, 0x03);
        mem.write_u8(0x10004, 0x0F); mem.write_u8(0x10005, 0xBA); mem.write_u8(0x10006, 0xE8); mem.write_u8(0x10007, 0x01);
        mem.write_u8(0x10008, 0x0F); mem.write_u8(0x10009, 0xBA); mem.write_u8(0x1000A, 0xF0); mem.write_u8(0x1000B, 0x03);
        cpu.step(&mut mem);
        let ok_bt = cpu.cf();
        record(res, "bt", ok_bt);
        cpu.step(&mut mem);
        let ok_bts = !cpu.cf() && cpu.ax() == 0x0A;
        record(res, "bts", ok_bts);
        cpu.step(&mut mem);
        let ok_btr = cpu.cf() && cpu.ax() == 0x02;
        record(res, "btr", ok_btr);
    }

    // 47. les / lds / lfs / lgs / lss
    {
        let mut cpu = Cpu::new();
        let mut mem = FlatMemory::default();
        cpu.cs = 0x1000; cpu.ip = 0x0000; cpu.ds = 0x3000;
        mem.write_u16(0x30050, 0x1122);
        mem.write_u16(0x30052, 0x3344);
        mem.write_u8(0x10000, 0xC4); mem.write_u8(0x10001, 0x3E); mem.write_u8(0x10002, 0x50); mem.write_u8(0x10003, 0x00);
        cpu.step(&mut mem);
        let ok_les = cpu.di() == 0x1122 && cpu.es == 0x3344;
        record(res, "les", ok_les);
    }
}
