#![no_main]
#![no_std]

use core::{arch::asm, mem::transmute, panic::PanicInfo};

use resolver::{get_function_from_exports, LPCSTR};

mod resolver;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub type WinExec = extern "system" fn(lpCmdLine: LPCSTR, uCmdShow: u32) -> u32;

#[no_mangle]
pub extern "system" fn main() -> ! {
    
    unsafe {
        // clean argc and argv
        asm!("mov rcx, 0", "mov rdx, 0");
        // asm!("and rsp, ~0xf");
    }

    let k32: &[u16] = &[
        'K' as u16,
        'E' as u16,
        'R' as u16,
        'N' as u16,
        'E' as u16,
        'L' as u16,
        '3' as u16,
        '2' as u16,
        '.' as u16,
        'D' as u16,
        'L' as u16,
        'L' as u16,
        0u16,
    ];

    let win_exec_str: &[u8] = &[
        'W' as u8,
        'i' as u8,
        'n' as u8,
        'E' as u8,
        'x' as u8,
        'e' as u8,
        'c' as u8,
        0u8,
    ];

    let k32_base_addr = resolver::get_dll_base(k32.as_ptr());

    let win_exec_fn_addr = get_function_from_exports(k32_base_addr, win_exec_str.as_ptr());

    let WinExec: WinExec = unsafe { transmute(win_exec_fn_addr) };
    WinExec("calc.exe\0" as *const _ as *const i8, 1);

    // black_box(b, load_library_a_addr);

    loop{}
}

#[inline(never)]
extern "system" fn black_box<T, C>(dummy: T, dummy_b: C) -> C {
    unsafe { core::ptr::read_volatile(&dummy) };
    unsafe { core::ptr::read_volatile(&dummy_b) }
}