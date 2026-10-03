//! `NativeCrash.crashIn(ByteBuffer)`: loads the direct buffer's address (and addresses inside it)
//! into eight general-purpose registers, then writes to address 8, which faults (SIGSEGV,
//! SEGV_MAPERR). debuggerd's tombstone dumps memory near every register that points into a
//! readable mapping, so this shows whether a `:mdec` tombstone carries the bytes a decoder was
//! working on. x86_64 only (the emulator images).
#![allow(clippy::missing_safety_doc)]
use core::ffi::c_void;

type GetDirectBufferAddress = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *mut u8;

/// JNI entry point. `env` is a `JNIEnv*`: a pointer to the pointer to the function table, in
/// which `GetDirectBufferAddress` is entry 230 (JNI specification, "Interface Function Table").
#[no_mangle]
pub unsafe extern "C" fn Java_org_ghost_spike_media_NativeCrash_crashIn(env: *mut c_void, _class: *mut c_void, buffer: *mut c_void) {
    let table = *(env as *const *const *const c_void);
    let get: GetDirectBufferAddress = core::mem::transmute(*table.add(230));
    let p = get(env, buffer);
    #[cfg(target_arch = "x86_64")]
    core::arch::asm!(
        "mov rsi, {p}",
        "lea rdi, [{p} + 256]",
        "lea r8, [{p} + 1024]",
        "lea r9, [{p} + 4096]",
        "lea r10, [{p} + 16384]",
        "lea r11, [{p} + 65536]",
        "lea rdx, [{p} + 131072]",
        "lea rcx, [{p} + 262144]",
        "mov qword ptr [8], rax",
        p = in(reg) p,
        out("rsi") _, out("rdi") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _, out("rdx") _, out("rcx") _,
    );
    #[cfg(not(target_arch = "x86_64"))]
    core::ptr::write_volatile(8 as *mut u64, p as u64);
}
