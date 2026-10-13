# cyber-potato

A native 16-bit real-mode x86 CPU interpreter in Rust that runs the 1996 DOS game **Cybersphere** (a breakout game) from your own copy of `CYBER.EXE`, plus a patch that turns the ball into a potato.

Built for the video **CYBER POTATO**: three AI agents in [HarnessTron](https://github.com/hmhkamilo/harnesstron) rebuilt the game's file byte for byte, and then we proved we understood it by changing 81 bytes of the ball sprite.

## What is NOT in this repository

No game binary, graphics, audio, levels or disassembly. You must supply your own legitimate copy of `CYBER.EXE`. The potato patch contains only our new sprite bytes; the original bytes are left out.

*Cybersphere is © 1996 Psycon Software / Clay Hellman. This is an independent research and learning project, not affiliated with or endorsed by them. Not legal advice.*

## Requirements

- Rust (stable) and a Windows/Linux desktop with a window system (the window uses `minifb`).
- Your own `CYBER.EXE`.
- Only for regenerating the test vectors: Python 3 with `unicorn` and `capstone` (`pip install unicorn capstone`).

## Run it

```
cargo run --release --bin cyber -- --exe path/to/CYBER.EXE
cargo run --release --bin cyber -- --exe path/to/CYBER.EXE --potato potato.patch.json
```

Flags: `--exe <file>`, `--potato <patch.json>`, `--frames N`, `--dump <out.png|ppm>`, `--script <f:k,...>`, `--headless`, `--autoplay`, `--record <out.mp4>`, `--record-start N`, `--rust-routines <all|list>`, `--frame-hashes <out.hashes>`.
Input: mouse position and left/right buttons, and the keys Enter, Esc, Space, Up, Down, P, Y, N and Backspace are passed to the game.

`--rust-routines` swaps in five routines that were rewritten by hand as plain Rust: the random-number generator, the paddle bounce angle, the ball collision trigonometry, brick hits, and the extra-ball spawn.

## What is verified, and what is not

| Claim | Evidence |
|---|---|
| The CPU matches a reference CPU | 67,416 / 67,416 test vectors pass (8,427 game instructions x 8 random states, 46 instruction types; the reference is the Unicorn emulator), plus 49 built-in tests |
| Each hand-rewritten routine matches the original code | `cargo test --release --test g6_differential`: 5 tests, 10,000 random states each (needs `run_target/CYBER.EXE`) |
| The whole game is unchanged with the Rust routines | a 3,000-frame autoplay run gives the same SHA-256 for every frame as the run with the original code (`--frame-hashes`) |
| Not covered | 32 `int`/`in`/`out` instructions and 129 further instructions are not in the vector suite. Sound is not ported. Only level 1-1 was played live |

Regenerate and run the vectors:

```
python tools/gen_vectors.py path/to/CYBER.EXE     # writes vectors/vectors.bin (not committed)
cargo run --release --bin vector_runner
```

Design notes are in [DESIGN.md](DESIGN.md).
