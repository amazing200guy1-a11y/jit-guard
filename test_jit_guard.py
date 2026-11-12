#!/usr/bin/env python3
"""
TEST SUITE FOR JIT-GUARD
========================
Tests formal Hoare-logic linear memory safety, stack bounds, call table isolation,
loop termination guarantees, and sub-millisecond execution benchmark.
"""

import unittest
import time
from jit_guard_engine import JITGuardEngine, WASMOpcode

class TestJITGuard(unittest.TestCase):

    def setUp(self):
        self.engine = JITGuardEngine(max_pages=8, max_call_table_size=16)

    def test_01_valid_memory_write_and_read(self):
        """Verifies sound abstract interpretation for safe memory store and load within 1 page (64KB)."""
        instructions = [
            {"op": WASMOpcode.I32_CONST, "value": 1024},     # pointer
            {"op": WASMOpcode.I32_CONST, "value": 42},       # value
            {"op": WASMOpcode.I32_STORE, "offset": 0},       # store 42 at 1024
            {"op": WASMOpcode.I32_CONST, "value": 1024},     # pointer
            {"op": WASMOpcode.I32_LOAD, "offset": 0}         # load from 1024
        ]
        result = self.engine.verify_program(instructions)
        self.assertEqual(result["verdict"], "VERIFIED_SAFE")
        self.assertIn("attestation_sha256", result)
        self.assertEqual(result["instruction_count"], 5)

    def test_02_out_of_bounds_store_rejected(self):
        """Intercepts pointer write that exceeds linear memory ceiling."""
        instructions = [
            {"op": WASMOpcode.I32_CONST, "value": 65534},    # 65534 + 4 = 65538 > 65536 (1 page limit)
            {"op": WASMOpcode.I32_CONST, "value": 100},
            {"op": WASMOpcode.I32_STORE, "offset": 0}
        ]
        result = self.engine.verify_program(instructions)
        self.assertEqual(result["verdict"], "REJECTED")
        self.assertEqual(result["rule_violated"], "OUT_OF_BOUNDS_MEMORY_WRITE")

    def test_03_out_of_bounds_load_rejected(self):
        """Intercepts memory read past linear memory ceiling."""
        instructions = [
            {"op": WASMOpcode.I32_CONST, "value": 70000},
            {"op": WASMOpcode.I32_LOAD, "offset": 0}
        ]
        result = self.engine.verify_program(instructions)
        self.assertEqual(result["verdict"], "REJECTED")
        self.assertEqual(result["rule_violated"], "OUT_OF_BOUNDS_MEMORY_READ")

    def test_04_stack_underflow_intercepted(self):
        """Intercepts stack underflow on arithmetic operations."""
        instructions = [
            {"op": WASMOpcode.I32_CONST, "value": 10},
            {"op": WASMOpcode.I32_ADD}                       # Needs 2 operands, only 1 on stack
        ]
        result = self.engine.verify_program(instructions)
        self.assertEqual(result["verdict"], "REJECTED")
        self.assertEqual(result["rule_violated"], "STACK_UNDERFLOW")

    def test_05_dynamic_memory_growth_verified(self):
        """Validates dynamic memory.grow within maximum allowed pages."""
        instructions = [
            {"op": WASMOpcode.I32_CONST, "value": 2},        # Grow by 2 pages
            {"op": WASMOpcode.MEMORY_GROW},
            {"op": WASMOpcode.I32_CONST, "value": 130000},   # 130000 < 3 * 65536 (196608)
            {"op": WASMOpcode.I32_CONST, "value": 99},
            {"op": WASMOpcode.I32_STORE, "offset": 0}
        ]
        result = self.engine.verify_program(instructions)
        self.assertEqual(result["verdict"], "VERIFIED_SAFE")
        self.assertEqual(result["final_memory_pages"], 3)

    def test_06_excessive_memory_growth_rejected(self):
        """Enforces hard ceiling on total page allocations."""
        instructions = [
            {"op": WASMOpcode.I32_CONST, "value": 10},       # Current 1 + 10 = 11 > max 8
            {"op": WASMOpcode.MEMORY_GROW}
        ]
        result = self.engine.verify_program(instructions)
        self.assertEqual(result["verdict"], "REJECTED")
        self.assertEqual(result["rule_violated"], "HEAP_CEILING_BREACH")

    def test_07_indirect_call_table_bounds_safety(self):
        """Proves indirect calls within table boundary are approved."""
        instructions = [
            {"op": WASMOpcode.I32_CONST, "value": 5},        # table index 5 < max 16
            {"op": WASMOpcode.CALL_INDIRECT}
        ]
        result = self.engine.verify_program(instructions)
        self.assertEqual(result["verdict"], "VERIFIED_SAFE")

    def test_08_indirect_call_table_breach_rejected(self):
        """Intercepts indirect call table index overflow (prevents function pointer hijacking)."""
        instructions = [
            {"op": WASMOpcode.I32_CONST, "value": 20},       # table index 20 >= max 16
            {"op": WASMOpcode.CALL_INDIRECT}
        ]
        result = self.engine.verify_program(instructions)
        self.assertEqual(result["verdict"], "REJECTED")
        self.assertEqual(result["rule_violated"], "INDIRECT_CALL_HIJACK")

    def test_09_unbounded_loop_intercepted(self):
        """Detects hazardous loops with unbounded iterations."""
        instructions = [
            {"op": WASMOpcode.LOOP_START, "max_iterations": 500000},
            {"op": WASMOpcode.LOOP_END}
        ]
        result = self.engine.verify_program(instructions)
        self.assertEqual(result["verdict"], "REJECTED")
        self.assertEqual(result["rule_violated"], "UNBOUNDED_EXECUTION_LOOP")

    def test_10_unclosed_loop_control_flow_failure(self):
        """Intercepts broken control flow integrity (unclosed loop)."""
        instructions = [
            {"op": WASMOpcode.LOOP_START, "max_iterations": 50}
            # Missing loop end
        ]
        result = self.engine.verify_program(instructions)
        self.assertEqual(result["verdict"], "REJECTED")
        self.assertEqual(result["rule_violated"], "CONTROL_FLOW_INTEGRITY")

if __name__ == '__main__':
    # Run Benchmark
    engine = JITGuardEngine()
    sample_program = [
        {"op": WASMOpcode.I32_CONST, "value": 256},
        {"op": WASMOpcode.I32_CONST, "value": 512},
        {"op": WASMOpcode.I32_ADD},
        {"op": WASMOpcode.I32_CONST, "value": 12345},
        {"op": WASMOpcode.I32_STORE, "offset": 0},
        {"op": WASMOpcode.I32_CONST, "value": 768},
        {"op": WASMOpcode.I32_LOAD, "offset": 0}
    ]

    t0 = time.perf_counter()
    iterations = 200
    for _ in range(iterations):
        engine.verify_program(sample_program)
    t1 = time.perf_counter()

    avg_latency_ms = ((t1 - t0) / iterations) * 1000.0
    print(f"\n[BENCHMARK] {iterations} JIT-Guard Verifications: {(t1 - t0):.4f}s | Avg Latency: {avg_latency_ms:.4f} ms/audit\n")

    unittest.main()
