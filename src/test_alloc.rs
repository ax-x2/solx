//! Per-thread allocation counting for the prepared signing path.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

#[derive(Clone, Copy, Default)]
struct Watch {
    count: bool,
    allocations: usize,
}
thread_local! { static WATCH: Cell<Watch> = const { Cell::new(Watch {
    count: false, allocations: 0,
}) }; }

struct Allocator;
#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

fn count() {
    let _ = WATCH.try_with(|watch| {
        let mut state = watch.get();
        if state.count {
            state.allocations = state.allocations.saturating_add(1);
        }
        watch.set(state);
    });
}

// SAFETY: all operations forward the original pointer/layout to System. The
// instrumentation has no allocation, locks, unwinding, or access after deallocation.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count();
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

pub fn allocations_during<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            WATCH.with(|w| w.set(Watch::default()));
        }
    }
    WATCH.with(|w| {
        w.set(Watch {
            count: true,
            ..Watch::default()
        })
    });
    let guard = Reset;
    let result = operation();
    let count = WATCH.with(|w| w.get().allocations);
    drop(guard);
    (result, count)
}
