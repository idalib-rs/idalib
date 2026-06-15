#[cfg(target_os = "linux")]
pub fn is_main_thread() -> bool {
    use libc::{c_long, getpid, syscall, SYS_gettid};

    unsafe { syscall(SYS_gettid) == getpid() as c_long }
}

#[cfg(target_os = "macos")]
pub fn is_main_thread() -> bool {
    use objc2::*;

    #[allow(unexpected_cfgs)]
    unsafe { msg_send![class!(NSThread), isMainThread] }
}

#[cfg(target_os = "windows")]
fn main_thread_id() -> u32 {
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;

    static mut MAIN_THREAD_ID: u32 = 0;

    // Function pointer used in CRT initialization section to set the above static field's value.

    // Mark as used so this is not removable.
    #[used]
    #[allow(non_upper_case_globals)]
    // Place the function pointer inside of CRT initialization section so it is loaded before
    // main entrypoint.
    //
    // See: https://doc.rust-lang.org/stable/reference/abi.html#the-link_section-attribute
    #[unsafe(link_section = ".CRT$XCU")]
    static INIT_MAIN_THREAD_ID: unsafe fn() = {
        unsafe fn initer() {
            unsafe { MAIN_THREAD_ID = GetCurrentThreadId() };
        }
        initer
    };

    unsafe { MAIN_THREAD_ID }
}

#[cfg(target_os = "windows")]
pub fn is_main_thread() -> bool {
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;

    let thread_id = unsafe { GetCurrentThreadId() };

    thread_id == main_thread_id()
}
