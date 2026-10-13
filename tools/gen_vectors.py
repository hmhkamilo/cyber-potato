#!/usr/bin/env python3
"""
Cybersphere 16-bit x86 Reference Test Vector Generator
Executes every oracle instruction in Unicorn (UC_MODE_16) across K=8 seeded random states.
Outputs compact binary test vectors, manifest, and validation self-check.
"""

import os
import sys
import json
import time
import struct
import collections

# Add pylib to path for capstone and unicorn
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

import capstone
from unicorn import *
from unicorn.x86_const import *

# ---------------------------------------------------------------------------
# Constants & SplitMix64 Deterministic Memory PRNG
# ---------------------------------------------------------------------------
SEED = 0x1996041220261012
K_CASES = 8
RAM_SIZE = 2 * 1024 * 1024  # 2 MB flat physical RAM
CODE_SEG = 0x1000           # CS base: physical 0x10000 + image_offset

SPLITMIX64_GAMMA = 0x9E3779B97F4A7C15
SPLITMIX64_MUL1  = 0xBF58476D1CE4E5B9
SPLITMIX64_MUL2  = 0x94D049BB133111EB

def splitmix64(x: int) -> int:
    z = (x + SPLITMIX64_GAMMA) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 30)) * SPLITMIX64_MUL1) & 0xFFFFFFFFFFFFFFFF
    z = ((z ^ (z >> 27)) * SPLITMIX64_MUL2) & 0xFFFFFFFFFFFFFFFF
    return (z ^ (z >> 31)) & 0xFFFFFFFFFFFFFFFF

def next_u64(state: int):
    new_state = (state + SPLITMIX64_GAMMA) & 0xFFFFFFFFFFFFFFFF
    z = (new_state ^ (new_state >> 30)) * SPLITMIX64_MUL1 & 0xFFFFFFFFFFFFFFFF
    z = (z ^ (z >> 27)) * SPLITMIX64_MUL2 & 0xFFFFFFFFFFFFFFFF
    val = (z ^ (z >> 31)) & 0xFFFFFFFFFFFFFFFF
    return new_state, val

# Binary Struct Formats
# Header: 20 bytes: magic (4s), version (H), k_cases (H), total_vectors (I), seed (Q)
HDR_FMT = '<4sHHIQ'
# Record: 208 bytes:
# image_offset (I), insn_len (B), is_fault (B), num_mem_diffs (B), pad0 (B), insn_bytes (16s),
# init_gprs (8I), init_segs (6H), init_ip (I), init_flags (I),
# final_gprs (8I), final_segs (6H), final_ip (I), final_flags (I),
# mem_diff_addr (16I), mem_diff_byte (16s)
VEC_FMT = '<IBBBB16s8I6H2I8I6H2I16I16s'

assert struct.calcsize(HDR_FMT) == 20
assert struct.calcsize(VEC_FMT) == 208

# Per-Mnemonic Undefined Flag Masks (Intel SDM Vol 2)
# Flags bit positions: CF=0x0001, PF=0x0004, AF=0x0010, ZF=0x0040, SF=0x0080, OF=0x0800
UNDEFINED_FLAG_MASKS = {
    "and":  0x0010,  # AF undefined (Intel SDM Vol 2A)
    "or":   0x0010,  # AF undefined (Intel SDM Vol 2A)
    "xor":  0x0010,  # AF undefined (Intel SDM Vol 2A)
    "test": 0x0010,  # AF undefined (Intel SDM Vol 2A)
    "shl":  0x0810,  # AF always undefined; OF undefined for shift > 1 (Intel SDM Vol 2B)
    "shr":  0x0810,  # AF always undefined; OF undefined for shift > 1 (Intel SDM Vol 2B)
    "sar":  0x0810,  # AF always undefined; OF undefined for shift > 1 (Intel SDM Vol 2B)
    "mul":  0x00D4,  # SF, ZF, AF, PF undefined (Intel SDM Vol 2A)
    "imul": 0x00D4,  # SF, ZF, AF, PF undefined (Intel SDM Vol 2A)
    "div":  0x08D5,  # All arithmetic flags undefined (Intel SDM Vol 2A)
    "bt":   0x08D4,  # OF, SF, ZF, AF, PF undefined (Intel SDM Vol 2A)
    "bts":  0x08D4,  # OF, SF, ZF, AF, PF undefined (Intel SDM Vol 2A)
    "btr":  0x08D4,  # OF, SF, ZF, AF, PF undefined (Intel SDM Vol 2A)
}

SKIPPED_MNEMONICS = {"int", "in", "out", "hlt", "cli", "sti"}


def init_ram_buffer(seed: int) -> bytearray:
    buf = bytearray(RAM_SIZE)
    words = RAM_SIZE // 8
    for w in range(words):
        val = splitmix64(seed ^ w)
        buf[w*8:(w+1)*8] = val.to_bytes(8, 'little')
    return buf


def main():
    print("=" * 70)
    print("      CYBERSPHERE 16-BIT REAL MODE REFERENCE VECTOR GENERATOR")
    print("=" * 70)
    start_time = time.time()

    if len(sys.argv) != 2:
        sys.exit("usage: python gen_vectors.py <path to your own CYBER.EXE>")
    exe_path = sys.argv[1]
    oracle_path = os.path.join(SCRIPT_DIR, "oracle_ranges.json")
    out_dir = os.path.join(SCRIPT_DIR, "..", "vectors")
    os.makedirs(out_dir, exist_ok=True)

    with open(exe_path, "rb") as f:
        f.seek(512)
        image = f.read()

    with open(oracle_path, "r", encoding="utf-8") as f:
        oracle_data = json.load(f)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    md.detail = True

    # 1. Decode all instructions from oracle
    all_insns = []
    skipped_counts = collections.Counter()
    all_mnemonic_counts = collections.Counter()

    for r_start, r_end in oracle_data["ranges"]:
        curr = r_start
        while curr < r_end:
            chunk = image[curr:r_end]
            dis = list(md.disasm(chunk, curr, count=1))
            if not dis:
                break
            insn = dis[0]
            mn = insn.mnemonic
            all_mnemonic_counts[mn] += 1
            if mn in SKIPPED_MNEMONICS:
                skipped_counts[mn] += 1
            else:
                raw_bytes = chunk[:insn.size]
                all_insns.append((curr, insn, raw_bytes))
            curr += insn.size

    print(f"Total instructions in oracle: {sum(all_mnemonic_counts.values()):,}")
    print(f"Skipped instructions (I/O & Interrupts): {sum(skipped_counts.values()):,}")
    print(f"Active instructions to vectorize: {len(all_insns):,}")
    print(f"Test vectors to generate (K={K_CASES}): {len(all_insns) * K_CASES:,}")

    # 2. Setup Unicorn engine
    print("\nInitializing 2 MB deterministic RAM with SplitMix64...")
    t_ram = time.time()
    initial_ram = init_ram_buffer(SEED)
    print(f"Deterministic RAM initialized in {time.time() - t_ram:.2f}s")

    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, RAM_SIZE)
    uc.mem_write(0, bytes(initial_ram))

    # Hook memory writes
    mem_writes = []
    def hook_mem_write(uc_inst, access, address, size, value, user_data):
        val_unsigned = value & ((1 << (size * 8)) - 1)
        val_bytes = val_unsigned.to_bytes(size, 'little')
        for idx, b in enumerate(val_bytes):
            mem_writes.append((address + idx, b))

    uc.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)

    # 3. Vector generation loop
    print("Generating reference execution vectors in Unicorn...")
    vectors = []
    fault_count = 0
    t_gen = time.time()

    for idx, (offset, insn, raw_bytes) in enumerate(all_insns):
        mn = insn.mnemonic
        insn_len = len(raw_bytes)
        insn_padded = raw_bytes.ljust(16, b'\x00')
        phys_insn_addr = (CODE_SEG * 16) + offset

        # Ensure instruction bytes are at CS:IP
        uc.mem_write(phys_insn_addr, raw_bytes)
        uc.ctl_flush_tb()

        for k in range(K_CASES):
            prng_state = splitmix64(SEED ^ (offset << 8) ^ k)

            def get_rand():
                nonlocal prng_state
                prng_state, val = next_u64(prng_state)
                return val

            # Generate initial registers
            # Safe address ranges: EBX, ESI, EDI, EBP, ESP in [0x1000, 0x7FFF]
            r_eax = get_rand() & 0xFFFFFFFF
            r_ecx = get_rand() & 0xFFFFFFFF
            r_edx = get_rand() & 0xFFFFFFFF
            r_ebx = 0x1000 + (get_rand() & 0x2FFF)
            r_esi = 0x1000 + (get_rand() & 0x2FFF)
            r_edi = 0x1000 + (get_rand() & 0x2FFF)
            r_ebp = 0x2000 + (get_rand() & 0x1FFF)
            r_esp = 0x4000 + (get_rand() & 0x3FFF)

            # Heuristics for special mnemonics to ensure balanced coverage:
            if mn == "loop":
                # Cover both jump taken (CX > 1) and fallthrough (CX = 1)
                r_ecx = 1 if (k % 2 == 0) else (2 + (get_rand() & 0x7))
            elif mn in ("div", "idiv"):
                # Vary dividend and divisor to cover both normal execution and #DE
                if k % 2 == 0:
                    r_eax = get_rand() & 0x00FF  # Small dividend
                    r_edx = 0
                    r_ebx = 0x0010 + (get_rand() & 0x007F)  # Non-zero divisor
                else:
                    if k == 1:
                        r_ebx = 0  # Trigger divide-by-zero #DE fault
                    else:
                        r_eax = 0xFFFF0000  # Trigger quotient overflow #DE fault

            # Segment registers (disjoint in 0x2000..0x6FFF)
            r_cs = CODE_SEG
            r_ds = 0x2000 + (get_rand() & 0x07FF)
            r_es = 0x3000 + (get_rand() & 0x07FF)
            r_ss = 0x4000 + (get_rand() & 0x07FF)
            r_fs = 0x5000 + (get_rand() & 0x07FF)
            r_gs = 0x6000 + (get_rand() & 0x07FF)

            # EFLAGS: status flags (CF=0x1, PF=0x4, AF=0x10, ZF=0x40, SF=0x80, DF=0x400, OF=0x800)
            status_flags = (get_rand() & 0x0CD5) | 0x0002
            # For conditional jumps, alternate tested flag so both branches are hit
            if mn in ("je", "jne"):
                status_flags = (status_flags | 0x0040) if (k % 2 == 0) else (status_flags & ~0x0040)
            elif mn in ("jb", "jae"):
                status_flags = (status_flags | 0x0001) if (k % 2 == 0) else (status_flags & ~0x0001)
            elif mn in ("jbe", "ja"):
                status_flags = (status_flags | 0x0041) if (k % 2 == 0) else (status_flags & ~0x0041)
            elif mn in ("jl", "jge"):
                status_flags = (status_flags | 0x0080) if (k % 2 == 0) else (status_flags & ~0x0080)

            init_gprs = (r_eax, r_ecx, r_edx, r_ebx, r_esp, r_ebp, r_esi, r_edi)
            init_segs = (r_cs, r_ds, r_es, r_ss, r_fs, r_gs)
            init_ip = offset
            init_flags = status_flags

            # Set registers in Unicorn
            uc.reg_write(UC_X86_REG_EAX, r_eax)
            uc.reg_write(UC_X86_REG_ECX, r_ecx)
            uc.reg_write(UC_X86_REG_EDX, r_edx)
            uc.reg_write(UC_X86_REG_EBX, r_ebx)
            uc.reg_write(UC_X86_REG_ESP, r_esp)
            uc.reg_write(UC_X86_REG_EBP, r_ebp)
            uc.reg_write(UC_X86_REG_ESI, r_esi)
            uc.reg_write(UC_X86_REG_EDI, r_edi)

            uc.reg_write(UC_X86_REG_CS, r_cs)
            uc.reg_write(UC_X86_REG_DS, r_ds)
            uc.reg_write(UC_X86_REG_ES, r_es)
            uc.reg_write(UC_X86_REG_SS, r_ss)
            uc.reg_write(UC_X86_REG_FS, r_fs)
            uc.reg_write(UC_X86_REG_GS, r_gs)

            uc.reg_write(UC_X86_REG_IP, init_ip)
            uc.reg_write(UC_X86_REG_EFLAGS, init_flags)

            mem_writes.clear()
            is_fault = 0

            try:
                uc.emu_start(phys_insn_addr, phys_insn_addr + 15, count=1)
                final_gprs = (
                    uc.reg_read(UC_X86_REG_EAX),
                    uc.reg_read(UC_X86_REG_ECX),
                    uc.reg_read(UC_X86_REG_EDX),
                    uc.reg_read(UC_X86_REG_EBX),
                    uc.reg_read(UC_X86_REG_ESP),
                    uc.reg_read(UC_X86_REG_EBP),
                    uc.reg_read(UC_X86_REG_ESI),
                    uc.reg_read(UC_X86_REG_EDI),
                )
                final_segs = (
                    uc.reg_read(UC_X86_REG_CS),
                    uc.reg_read(UC_X86_REG_DS),
                    uc.reg_read(UC_X86_REG_ES),
                    uc.reg_read(UC_X86_REG_SS),
                    uc.reg_read(UC_X86_REG_FS),
                    uc.reg_read(UC_X86_REG_GS),
                )
                final_ip = uc.reg_read(UC_X86_REG_IP)
                final_flags = uc.reg_read(UC_X86_REG_EFLAGS)

                # Process memory diffs (latest write wins)
                diff_dict = {}
                for w_addr, w_byte in mem_writes:
                    diff_dict[w_addr] = w_byte
                diff_items = sorted(diff_dict.items())[:16]
                num_mem_diffs = len(diff_items)

                diff_addrs = [item[0] for item in diff_items] + [0] * (16 - num_mem_diffs)
                diff_bytes = bytes([item[1] for item in diff_items]) + b'\x00' * (16 - num_mem_diffs)

            except UcError:
                is_fault = 1
                fault_count += 1
                final_gprs = init_gprs
                final_segs = init_segs
                final_ip = init_ip
                final_flags = init_flags
                num_mem_diffs = 0
                diff_addrs = [0] * 16
                diff_bytes = b'\x00' * 16

            finally:
                # Restore modified memory in Unicorn
                for w_addr, _ in mem_writes:
                    uc.mem_write(w_addr, bytes([initial_ram[w_addr]]))

            # Pack vector
            rec = struct.pack(
                VEC_FMT,
                offset,
                insn_len,
                is_fault,
                num_mem_diffs,
                0,  # pad0
                insn_padded,
                *init_gprs,
                *init_segs,
                init_ip,
                init_flags,
                *final_gprs,
                *final_segs,
                final_ip,
                final_flags,
                *diff_addrs,
                diff_bytes
            )
            vectors.append(rec)

        # Restore instruction bytes in RAM back to initial_ram
        uc.mem_write(phys_insn_addr, bytes(initial_ram[phys_insn_addr:phys_insn_addr + insn_len]))
        uc.ctl_flush_tb()

        if (idx + 1) % 1000 == 0 or (idx + 1) == len(all_insns):
            print(f"  Processed {idx + 1:,} / {len(all_insns):,} instructions ({(idx+1)/len(all_insns)*100:.1f}%)")

    print(f"Vector generation completed in {time.time() - t_gen:.2f}s")
    print(f"Total vectors generated: {len(vectors):,} (Faults: {fault_count:,})")

    # 4. Write binary vector file
    bin_path = os.path.join(out_dir, "vectors.bin")
    print(f"Writing {len(vectors):,} vectors to {bin_path}...")
    hdr = struct.pack(HDR_FMT, b"VEC1", 1, K_CASES, len(vectors), SEED)
    with open(bin_path, "wb") as f:
        f.write(hdr)
        for v in vectors:
            f.write(v)
    bin_size = os.path.getsize(bin_path)
    print(f"Binary file written: {bin_size:,} bytes ({bin_size / (1024*1024):.2f} MB)")

    # 5. Self-check: Re-run every vector in Unicorn to verify determinism
    print("\nRunning Self-Check: Re-executing all 67,416 vectors in Unicorn...")
    t_chk = time.time()
    mismatches = 0

    uc_chk = Uc(UC_ARCH_X86, UC_MODE_16)
    uc_chk.mem_map(0, RAM_SIZE)
    uc_chk.mem_write(0, bytes(initial_ram))

    chk_mem_writes = []
    def chk_hook_mem_write(uc_inst, access, address, size, value, user_data):
        for idx in range(size):
            chk_mem_writes.append(address + idx)
    uc_chk.hook_add(UC_HOOK_MEM_WRITE, chk_hook_mem_write)

    for v_idx in range(len(vectors)):
        v_data = vectors[v_idx]
        (
            v_off, v_len, v_fault, v_ndiff, _, v_bytes,
            i_eax, i_ecx, i_edx, i_ebx, i_esp, i_ebp, i_esi, i_edi,
            i_cs, i_ds, i_es, i_ss, i_fs, i_gs,
            i_ip, i_flags,
            f_eax, f_ecx, f_edx, f_ebx, f_esp, f_ebp, f_esi, f_edi,
            f_cs, f_ds, f_es, f_ss, f_fs, f_gs,
            f_ip, f_flags,
            *diff_tail
        ) = struct.unpack(VEC_FMT, v_data)

        # Setup and run once more
        phys_addr = (i_cs * 16) + i_ip
        uc_chk.mem_write(phys_addr, v_bytes[:v_len])
        uc_chk.ctl_flush_tb()
        uc_chk.reg_write(UC_X86_REG_EAX, i_eax)
        uc_chk.reg_write(UC_X86_REG_ECX, i_ecx)
        uc_chk.reg_write(UC_X86_REG_EDX, i_edx)
        uc_chk.reg_write(UC_X86_REG_EBX, i_ebx)
        uc_chk.reg_write(UC_X86_REG_ESP, i_esp)
        uc_chk.reg_write(UC_X86_REG_EBP, i_ebp)
        uc_chk.reg_write(UC_X86_REG_ESI, i_esi)
        uc_chk.reg_write(UC_X86_REG_EDI, i_edi)
        uc_chk.reg_write(UC_X86_REG_CS, i_cs)
        uc_chk.reg_write(UC_X86_REG_DS, i_ds)
        uc_chk.reg_write(UC_X86_REG_ES, i_es)
        uc_chk.reg_write(UC_X86_REG_SS, i_ss)
        uc_chk.reg_write(UC_X86_REG_FS, i_fs)
        uc_chk.reg_write(UC_X86_REG_GS, i_gs)
        uc_chk.reg_write(UC_X86_REG_IP, i_ip)
        uc_chk.reg_write(UC_X86_REG_EFLAGS, i_flags)

        chk_mem_writes.clear()
        try:
            uc_chk.emu_start(phys_addr, phys_addr + 15, count=1)
            chk_ip = uc_chk.reg_read(UC_X86_REG_IP)
            chk_eax = uc_chk.reg_read(UC_X86_REG_EAX)
            if v_fault != 0 or chk_ip != f_ip or chk_eax != f_eax:
                mismatches += 1
                if mismatches <= 5:
                    print(f"Mismatch at vector {v_idx}: v_fault={v_fault}, chk_ip=0x{chk_ip:x} vs 0x{f_ip:x}, chk_eax=0x{chk_eax:x} vs 0x{f_eax:x}")
        except UcError as ue:
            if v_fault != 1:
                mismatches += 1
                if mismatches <= 5:
                    print(f"Mismatch exception at vector {v_idx}: expected no fault, got {ue}")
        finally:
            for w_addr in chk_mem_writes:
                uc_chk.mem_write(w_addr, bytes([initial_ram[w_addr]]))
            uc_chk.mem_write(phys_addr, bytes(initial_ram[phys_addr:phys_addr + v_len]))
            uc_chk.ctl_flush_tb()

    print(f"Self-check completed in {time.time() - t_chk:.2f}s with {mismatches} mismatches!")
    assert mismatches == 0, "Self-check detected non-deterministic behavior!"

    # 6. Write MANIFEST.json
    manifest_path = os.path.join(out_dir, "MANIFEST.json")
    manifest = {
        "metadata": {
            "format_version": 1,
            "seed": f"0x{SEED:016X}",
            "k_cases": K_CASES,
            "total_oracle_instructions": sum(all_mnemonic_counts.values()),
            "active_instructions": len(all_insns),
            "total_vectors": len(vectors),
            "fault_vectors": fault_count,
            "binary_file": "vectors.bin",
            "binary_size_bytes": bin_size,
            "vector_record_size": 208,
            "ram_size_bytes": RAM_SIZE,
            "splitmix64_constants": {
                "gamma": f"0x{SPLITMIX64_GAMMA:016X}",
                "mul1": f"0x{SPLITMIX64_MUL1:016X}",
                "mul2": f"0x{SPLITMIX64_MUL2:016X}"
            }
        },
        "counts_per_mnemonic": dict(all_mnemonic_counts.most_common()),
        "skipped_instructions": dict(skipped_counts),
        "undefined_flag_masks": {mn: f"0x{mask:04X}" for mn, mask in sorted(UNDEFINED_FLAG_MASKS.items())}
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Manifest written to {manifest_path}")

    elapsed = time.time() - start_time
    print(f"\nAll tasks completed successfully in {elapsed:.2f}s!")


if __name__ == "__main__":
    main()
