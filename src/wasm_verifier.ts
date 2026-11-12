/**
 * JIT-GUARD TYPESCRIPT VERIFIER
 * Sound interval abstract domain bounds checker for WASM linear memory.
 */

export class WASMInterval {
  constructor(public readonly lower: number, public readonly upper: number) {}

  public add(other: WASMInterval): WASMInterval {
    return new WASMInterval(this.lower + other.lower, this.upper + other.upper);
  }

  public isSafeAccess(offset: number, maxBytes: number): boolean {
    const effLower = this.lower + offset;
    const effUpper = this.upper + offset;
    return effLower >= 0 && effUpper + 4 <= maxBytes;
  }
}
