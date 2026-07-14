#[cfg(all(feature = "mimalloc-allocator", not(feature = "system-allocator")))]
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> anyhow::Result<()> {
    qpxd::main_entry()
}
