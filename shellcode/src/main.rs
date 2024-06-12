#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]

 mod resolver;

use core::{arch::asm, ffi::c_void, mem::transmute, panic::PanicInfo, ptr::null};

#[link(name = "vcruntime")]
extern {}

#[link(name = "ucrt")]
extern {}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// FFI binding for MessageBoxA
type MessageBoxA = extern "system" fn(
    handle: *const u8,
    lp_text: *const u8,
    lp_caption: *const u8,
    t: usize,
) -> *const c_void;

/// FFI for LoadLibraryA
type LoadLibraryA = extern "system" fn(
    lib_name: *const u8,
) -> isize;

/// FFI for
type GetProcAddress = extern "system" fn(
    handle: *const usize,
    proc_name: *const u8,
  ) -> *mut c_void;

#[no_mangle]
pub extern "C" fn main() {
    // stack strings
    let kernel_32 = b"KERNEL32.DLL\0";
    let load_library_a = b"LoadLibraryA\0";
    let get_proc_addr = b"GetProcAddress\0";
    let message_box_a = b"MessageBoxA\0";
    let user_32 = b"User32.dll\0";

    // get virtual addresses
    let load_library_a = resolver::get_function_from_exports(kernel_32, load_library_a).unwrap();
    let get_proc_addr = resolver::get_function_from_exports(kernel_32, get_proc_addr).unwrap();

    // obtaining User32.dll
    let load_library_a: LoadLibraryA = unsafe { transmute(load_library_a.address) };
    let user_32_dll = load_library_a(user_32 as *const u8);
    let get_proc_address: GetProcAddress = unsafe { transmute(get_proc_addr.address) };

    // get msg box fn
    let message_box_address = get_proc_address(user_32_dll as *const usize, message_box_a as *const u8);
    let message_box_a:MessageBoxA = unsafe { transmute(message_box_address) };

    // align the stack to divisible by 16
    unsafe { asm!("and rsp, ~0xf") };

    let msg = b"Injected!\0";

    // unsafe { asm!("int3") };
    message_box_a(
        null(),
        msg as *const u8,
        msg as *const u8,
        0x0,
    );
}



