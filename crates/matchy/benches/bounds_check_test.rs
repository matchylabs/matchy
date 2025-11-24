// Quick test to verify LLVM eliminates bounds checks
// Run with: cargo rustc --release --bench bounds_check_test -- --emit=asm
// Then inspect assembly for panic/bounds check code

static TABLE: [bool; 256] = [false; 256];

#[inline(never)] // Prevent inlining so we can see the assembly
pub fn safe_lookup(b: u8) -> bool {
    TABLE[b as usize]
}

#[inline(never)]
pub fn unsafe_lookup(b: u8) -> bool {
    unsafe { *TABLE.get_unchecked(b as usize) }
}

fn main() {
    // Both should compile to identical assembly (just a load)
    let x = safe_lookup(42);
    let y = unsafe_lookup(42);
    assert_eq!(x, y);
}
