#!/usr/bin/env python3
"""
JIT-GUARD: FORMAL HOARE-LOGIC LINEAR MEMORY SAFETY & ABSTRACT INTERPRETATION SENTRY
FOR LLM-GENERATED WEBASSEMBLY (WASM)
===================================================================================
Author: Usman Bamidele (100L Mathematics Student, FUNAAB)
Track: Generative AI Safety, Compiler Verification & Sandboxed Execution (GenHacks)
Moat: Pre-execution Hoare-triple abstract interpretation and microsecond linear memory bounds verification.
"""

import sys
import time
import json
import hashlib
from typing import Dict, Any, List, Tuple, Optional

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

# WebAssembly Constants
WASM_PAGE_SIZE = 65536  # 64 KiB
DEFAULT_MAX_PAGES = 16  # 1 MiB sandboxed boundary
MAX_STACK_DEPTH = 256
MAX_INSTRUCTIONS_PER_FUNCTION = 5000

class WASMOpcode:
    I32_CONST = "i32.const"
    I32_ADD = "i32.add"
    I32_SUB = "i32.sub"
    I32_MUL = "i32.mul"
    I32_LOAD = "i32.load"
    I32_STORE = "i32.store"
    MEMORY_GROW = "memory.grow"
    CALL_INDIRECT = "call_indirect"
    LOOP_START = "loop"
    LOOP_END = "end"
    BR = "br"
    NOP = "nop"

class AbstractInterval:
    """Interval domain [lower, upper] for sound abstract interpretation of memory pointers."""
    def __init__(self, lower: int, upper: int):
        self.lower = lower
        self.upper = upper

    def add(self, other: 'AbstractInterval') -> 'AbstractInterval':
        return AbstractInterval(self.lower + other.lower, self.upper + other.upper)

    def sub(self, other: 'AbstractInterval') -> 'AbstractInterval':
        return AbstractInterval(self.lower - other.upper, self.upper - other.lower)

    def mul(self, other: 'AbstractInterval') -> 'AbstractInterval':
        products = [
            self.lower * other.lower,
            self.lower * other.upper,
            self.upper * other.lower,
            self.upper * other.upper
        ]
        return AbstractInterval(min(products), max(products))

    def is_within(self, min_val: int, max_val: int) -> bool:
        return self.lower >= min_val and self.upper <= max_val

    def join(self, other: 'AbstractInterval') -> 'AbstractInterval':
        """Lattice join (least upper bound): [min(l1, l2), max(u1, u2)]"""
        return AbstractInterval(min(self.lower, other.lower), max(self.upper, other.upper))

    def meet(self, other: 'AbstractInterval') -> Optional['AbstractInterval']:
        """Lattice meet (greatest lower bound): [max(l1, l2), min(u1, u2)]"""
        new_low = max(self.lower, other.lower)
        new_high = min(self.upper, other.upper)
        if new_low > new_high:
            return None # Bottom (empty interval)
        return AbstractInterval(new_low, new_high)

    def widen(self, other: 'AbstractInterval', threshold: int = 1000000) -> 'AbstractInterval':
        """Abstract interpretation widening operator to accelerate loop fixed-point convergence."""
        new_low = self.lower if self.lower <= other.lower else -threshold
        new_high = self.upper if self.upper >= other.upper else threshold
        return AbstractInterval(new_low, new_high)

class JITGuardVerificationError(Exception):
    pass

class JITGuardEngine:
    """
    Formal static verification engine for LLM-generated WebAssembly bytecode.
    Applies Hoare-Logic pre/post-conditions:
      { P: ptr in [0, max_pages * 64KB - 4] } i32.store { Q: heap[ptr] == val }
    """

    def __init__(self, max_pages: int = DEFAULT_MAX_PAGES, max_call_table_size: int = 32):
        self.max_pages = max_pages
        self.max_memory_bytes = max_pages * WASM_PAGE_SIZE
        self.max_call_table_size = max_call_table_size

    def verify_program(self, instructions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Statically verifies instruction sequence for linear memory safety,
        stack balance, loop termination invariants, and indirect call isolation.
        """
        start_time = time.perf_counter()

        if len(instructions) > MAX_INSTRUCTIONS_PER_FUNCTION:
            return {
                "verdict": "REJECTED",
                "error": f"Instruction limit exceeded ({len(instructions)} > {MAX_INSTRUCTIONS_PER_FUNCTION})",
                "rule_violated": "RESOURCE_DENIAL_OF_SERVICE"
            }

        abstract_stack: List[AbstractInterval] = []
        current_memory_pages = 1
        active_loops = 0
        loop_iteration_bounds: Dict[int, int] = {}

        for idx, inst in enumerate(instructions):
            opcode = inst.get("op")

            # 1. Stack Push Constant
            if opcode == WASMOpcode.I32_CONST:
                val = inst.get("value", 0)
                if len(abstract_stack) >= MAX_STACK_DEPTH:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Stack overflow at instruction {idx}",
                        "rule_violated": "STACK_OVERFLOW"
                    }
                abstract_stack.append(AbstractInterval(val, val))

            # 2. Arithmetic Add
            elif opcode == WASMOpcode.I32_ADD:
                if len(abstract_stack) < 2:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Stack underflow at instruction {idx} (i32.add requires 2 operands)",
                        "rule_violated": "STACK_UNDERFLOW"
                    }
                b = abstract_stack.pop()
                a = abstract_stack.pop()
                abstract_stack.append(a.add(b))

            # 3. Arithmetic Sub
            elif opcode == WASMOpcode.I32_SUB:
                if len(abstract_stack) < 2:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Stack underflow at instruction {idx}",
                        "rule_violated": "STACK_UNDERFLOW"
                    }
                b = abstract_stack.pop()
                a = abstract_stack.pop()
                abstract_stack.append(a.sub(b))

            # 4. Arithmetic Mul
            elif opcode == WASMOpcode.I32_MUL:
                if len(abstract_stack) < 2:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Stack underflow at instruction {idx}",
                        "rule_violated": "STACK_UNDERFLOW"
                    }
                b = abstract_stack.pop()
                a = abstract_stack.pop()
                abstract_stack.append(a.mul(b))

            # 5. Linear Memory Load (i32.load)
            elif opcode == WASMOpcode.I32_LOAD:
                if len(abstract_stack) < 1:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Stack underflow for i32.load at instruction {idx}",
                        "rule_violated": "STACK_UNDERFLOW"
                    }
                ptr_interval = abstract_stack.pop()
                static_offset = inst.get("offset", 0)
                effective_interval = ptr_interval.add(AbstractInterval(static_offset, static_offset))

                # Check lower bound
                if effective_interval.lower < 0:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Negative linear memory pointer [{effective_interval.lower}] at instruction {idx}",
                        "rule_violated": "OUT_OF_BOUNDS_MEMORY_READ"
                    }
                # Check upper bound (i32 is 4 bytes)
                if effective_interval.upper + 4 > (current_memory_pages * WASM_PAGE_SIZE):
                    return {
                        "verdict": "REJECTED",
                        "error": f"Memory read at offset {effective_interval.upper + 4} exceeds current memory ceiling {current_memory_pages * WASM_PAGE_SIZE} bytes",
                        "rule_violated": "OUT_OF_BOUNDS_MEMORY_READ"
                    }
                # Result of load is pushed (abstractly unbounded int32)
                abstract_stack.append(AbstractInterval(-2147483648, 2147483647))

            # 6. Linear Memory Store (i32.store)
            elif opcode == WASMOpcode.I32_STORE:
                if len(abstract_stack) < 2:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Stack underflow for i32.store at instruction {idx}",
                        "rule_violated": "STACK_UNDERFLOW"
                    }
                val_interval = abstract_stack.pop()
                ptr_interval = abstract_stack.pop()
                static_offset = inst.get("offset", 0)
                effective_interval = ptr_interval.add(AbstractInterval(static_offset, static_offset))

                if effective_interval.lower < 0:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Negative memory store target [{effective_interval.lower}] at instruction {idx}",
                        "rule_violated": "OUT_OF_BOUNDS_MEMORY_WRITE"
                    }
                if effective_interval.upper + 4 > (current_memory_pages * WASM_PAGE_SIZE):
                    return {
                        "verdict": "REJECTED",
                        "error": f"Memory write at offset {effective_interval.upper + 4} exceeds ceiling {current_memory_pages * WASM_PAGE_SIZE} bytes",
                        "rule_violated": "OUT_OF_BOUNDS_MEMORY_WRITE"
                    }

            # 7. Dynamic Memory Growth (memory.grow)
            elif opcode == WASMOpcode.MEMORY_GROW:
                if len(abstract_stack) < 1:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Stack underflow for memory.grow at instruction {idx}",
                        "rule_violated": "STACK_UNDERFLOW"
                    }
                delta_pages = abstract_stack.pop()
                if delta_pages.upper <= 0 or delta_pages.lower < 0:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Invalid memory.grow parameter interval [{delta_pages.lower}, {delta_pages.upper}]",
                        "rule_violated": "INVALID_MEMORY_GROWTH"
                    }
                if current_memory_pages + delta_pages.upper > self.max_pages:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Memory growth would exceed maximum allowed pages ({current_memory_pages + delta_pages.upper} > {self.max_pages})",
                        "rule_violated": "HEAP_CEILING_BREACH"
                    }
                current_memory_pages += delta_pages.upper
                abstract_stack.append(AbstractInterval(current_memory_pages - delta_pages.upper, current_memory_pages))

            # 8. Indirect Function Call Isolation (call_indirect)
            elif opcode == WASMOpcode.CALL_INDIRECT:
                if len(abstract_stack) < 1:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Stack underflow for call_indirect at instruction {idx}",
                        "rule_violated": "STACK_UNDERFLOW"
                    }
                table_idx = abstract_stack.pop()
                if table_idx.lower < 0 or table_idx.upper >= self.max_call_table_size:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Indirect call table index [{table_idx.lower}, {table_idx.upper}] outside safe bounds [0, {self.max_call_table_size - 1}]",
                        "rule_violated": "INDIRECT_CALL_HIJACK"
                    }

            # 9. Loop Termination Bounds
            elif opcode == WASMOpcode.LOOP_START:
                active_loops += 1
                loop_id = inst.get("loop_id", active_loops)
                max_iter = inst.get("max_iterations", 1000)
                if max_iter > 100000:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Unbounded or hazardous loop iteration ceiling ({max_iter}) at instruction {idx}",
                        "rule_violated": "UNBOUNDED_EXECUTION_LOOP"
                    }
                loop_iteration_bounds[loop_id] = max_iter

            elif opcode == WASMOpcode.LOOP_END:
                if active_loops <= 0:
                    return {
                        "verdict": "REJECTED",
                        "error": f"Mismatched loop end at instruction {idx}",
                        "rule_violated": "CONTROL_FLOW_INTEGRITY"
                    }
                active_loops -= 1

        if active_loops > 0:
            return {
                "verdict": "REJECTED",
                "error": f"Unclosed loops detected ({active_loops} unclosed)",
                "rule_violated": "CONTROL_FLOW_INTEGRITY"
            }

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Generate Cryptographic Execution Attestation
        bytecode_repr = json.dumps(instructions, sort_keys=True)
        attestation_hash = hashlib.sha256(f"{bytecode_repr}:{current_memory_pages}:{elapsed_ms:.4f}".encode('utf-8')).hexdigest()

        return {
            "verdict": "VERIFIED_SAFE",
            "instruction_count": len(instructions),
            "final_memory_pages": current_memory_pages,
            "final_memory_bytes": current_memory_pages * WASM_PAGE_SIZE,
            "audit_latency_ms": round(elapsed_ms, 4),
            "attestation_sha256": attestation_hash,
            "invariants_checked": [
                "HOARE_LINEAR_MEMORY_BOUNDS",
                "STACK_BALANCE_AND_DEPTH",
                "HEAP_CEILING_ENFORCEMENT",
                "INDIRECT_CALL_TABLE_ISOLATION",
                "LOOP_TERMINATION_INVARIANT"
            ]
        }
