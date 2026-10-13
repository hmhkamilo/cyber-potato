# Architecture & Design Specification — cyber-rs CPU Interpreter

## 1. Overview
`cyber-rs` is a high-performance, standalone 16-bit real-mode (8086/80286/80386 real-mode) x86 CPU interpreter implemented in pure safe Rust (`std` only). It is specifically tailored to execute the 1996 DOS game *Cybersphere* natively on Windows, with a pluggable hardware abstraction layer (Bus) and external shim delegates.

---

## 2. Instruction Decoding Strategy (Match vs. Table)
- **Primary Mechanism:** Pattern-matched single-byte and two-byte (`0x0F` escape) dispatch via Rust's exhaustive `match` constructs.
- **Rationale:**
  - Modern LLVM/rustc compiles dense `match opcode { ... }` blocks into optimized jump tables (direct jump via jump table array) with zero runtime heap overhead or function pointer indirection penalties.
  - Prefix processing (`0x66` operand size, segment overrides `0x26`, `0x2E`, `0x36`, `0x3E`, `0x64`, `0x65`, and string repeat prefixes `0xF2`, `0xF3`) is handled in a compact, deterministic loop before entering the primary opcode match.
  - Variable-length real-mode instructions and ModR/M addressing decoding benefit from inline state tracking (instruction pointer advancement) without separate multi-stage pipeline overhead.

---

## 3. Cycle & Timing Model
- **Decision:** Non-cycle-stepped, instruction-level sequential execution.
- **Rationale:**
  - *Cybersphere* does not rely on cycle-exact CPU cycle counting or raster-line beam racing; all video synchronizations poll port `0x3DA` bit 3 (`wait_vblank`), and timer delays use standard DOS timer ticks or BIOS wait services.
  - Instruction-level interpretation minimizes execution latency, easily exceeding real-time 60 FPS gameplay on modern host CPUs.

---

## 4. Hardware & System Call Delegation
- **Decision:** The CPU execution loop delegates I/O ports and software interrupts via `StepResult` event yields:
  - `StepResult::Ok`: Instruction executed normally; CPU continues.
  - `StepResult::Int(vector)`: A software interrupt was executed (e.g. `int 21h` for DOS, `int 10h` for BIOS VGA, `int 33h` for mouse, `int 16h` for keyboard buffer). The CPU preserves register state, and the host system shim executes the high-level handler before resuming CPU execution.
  - `StepResult::PortIn { port, size }`: An `in` instruction was decoded. Host platform shims (e.g. VGA status `0x3DA`, timer `0x40`) respond with the appropriate port value.
  - `StepResult::PortOut { port, val, size }`: An `out` instruction was decoded (e.g. OPL3 FM sound ports `0x388`/`0x38A`, VGA DAC palette ports `0x3C8`/`0x3C9`).
  - `StepResult::Halt`: The CPU executed `hlt`.
  - `StepResult::Fault(fault)`: CPU generated a fault (e.g. `Fault::DivideError`).
- **Benefit:** Decouples CPU arithmetic and register mechanics entirely from OS-level emulation and Win32/SDL2 presentation layers.

---

## 5. String Instructions & Repeat Prefixes (`REP` / `REPE` / `REPNE`)
- **Interaction with Interrupts & Step Semantics:**
  - For repeated string instructions (`rep movsd`, `rep stosd`, etc.), the interpreter decrements `CX`/`ECX` per unit iteration.
  - In real hardware, interrupts can trigger between iterations of a `REP` string operation (with IP pointing back to the prefix).
  - In `cyber-rs`, small `REP` operations execute to completion per step if no asynchronous external interrupts are pending, or can be stepped iteratively by retaining the instruction start address if cooperative multitasking is requested.
  - For *Cybersphere*, the primary repeated operations are bulk framebuffer copies (`rep movsd` 16,000 dwords to VGA `0xA000:0`) and backbuffer clearing (`rep stosd` 16,000 dwords), which execute cleanly.

---

## 6. Real-Mode Memory & A20 Gate Wrapping
- **Address Calculation:** `linear_address = ((segment as u32) << 4) + (offset as u32)`.
- **A20 Address Mask:**
  - Standard real mode without A20 gate: addresses wrap at 1 MB boundary (`linear_address & 0x000F_FFFF`).
  - Real mode with A20 enabled (DOS high memory area / HMA): addresses up to `0x10FFEF` (`linear_address & 0x001F_FFFF`).
  - Configurable via `Bus::a20_mask` (default enabled for flat 386 DOS extenders and modern loaders).
