# JIT-Guard: Formal Hoare-Logic Linear Memory Safety Sentry for LLM-Generated WebAssembly (WASM)

[![Tests](https://img.shields.io/badge/Tests-10%2F10%20Passing-brightgreen.svg)](test_jit_guard.py)
[![Latency](https://img.shields.io/badge/Latency-0.0317ms%2Faudit-blue.svg)](test_jit_guard.py)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Standards](https://img.shields.io/badge/WASM%20Safety-Hoare%20Logic%20Intervals-orange.svg)]()

> **JIT-Guard** is a formal verification sentry that prevents LLM-generated WebAssembly (WASM) bytecode from corrupting linear memory, escaping sandboxes, or hijacking indirect call tables. By applying Hoare-logic interval abstract interpretation ahead of runtime, JIT-Guard delivers mathematical proof of safety in **0.031 milliseconds** before generative bytecode touches the CPU.

---

## ⚡ Key Features

- **Hoare-Logic Pointer Bounds:** Proves `{P: ptr + offset + 4 <= max_pages * 64KB} i32.store {Q: heap_sound}` via interval abstract interpretation.
- **Indirect Call Table Protection:** Enforces strict boundary verification for `call_indirect` to prevent function table hijacking.
- **Stack & Heap Invariant Guards:** Intercepts stack underflow/overflow and caps dynamic `memory.grow` heap allocations.
- **Loop Termination Checks:** Detects hazardous infinite loop constructs before JIT execution.
- **Cryptographic Attestation:** Generates a SHA-256 certificate for verified safe bytecode blocks.
- **Aerospace Titanium Cockpit:** Live standalone interactive web dashboard (`index.html`) for real-time bytecode testing and memory visualization.

---

## 🚀 Quick Start

### 1. Run Verification & Test Suite
```bash
python test_jit_guard.py
```

Expected Output:
```
..........
----------------------------------------------------------------------
Ran 10 tests in 0.001s

OK

[BENCHMARK] 200 JIT-Guard Verifications: 0.0063s | Avg Latency: 0.0317 ms/audit
```

### 2. Launch the Interactive Operations Cockpit
Open `index.html` in any modern web browser to test safe bytecode, trigger simulated buffer overflow breaches, and inspect memory allocation maps.

---

## 📂 Repository Structure

- `jit_guard_engine.py` — Core abstract interpreter, Hoare-logic bounds checker, and SHA-256 attestation generator.
- `test_jit_guard.py` — Formal test suite (10 unit & benchmark tests).
- `index.html` — Obsidian titanium interactive operations cockpit.
- `SUBMISSION_DOSSIER.md` — Complete hackathon submission documentation and pitch materials.

---

## 🛡️ License
MIT License. Built by Usman Bamidele for the GenHacks 2026 Hackathon.
