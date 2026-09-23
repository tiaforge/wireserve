//! Measuring what a piece of code asks the allocator for, so the readers
//! that must not materialise what they skip can be pinned against a
//! number rather than against a shape.
//!
//! Per thread, because the test harness runs tests in parallel and a
//! global counter would see all of them at once.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Counting;

thread_local! {
    /// No destructor, so it stays readable during thread teardown.
    static USED: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // `try_with`: this runs on threads that are tearing down too.
        let _ = USED.try_with(|u| u.set(u.get() + layout.size()));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Total bytes `f` asked the allocator for on this thread. Counts every
/// allocation, freed or not — the point is what was built, not what was
/// kept, since glibc gives small allocations back to the process rather
/// than to the kernel (see `host_interop::ruleset`).
pub fn allocated(f: impl FnOnce()) -> usize {
    let before = USED.with(Cell::get);
    f();
    USED.with(Cell::get) - before
}
