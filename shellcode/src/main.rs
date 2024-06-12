#![no_std]
#![no_main]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(overflowing_literals)]

use core::{arch::asm, ffi::c_void, mem::transmute, panic::PanicInfo, ptr::null_mut};

#[link(name = "vcruntime")]
extern {}

#[link(name = "ucrt")]
extern {}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

pub type BOOLEAN = u8;
pub type HANDLE = *mut c_void;
pub type PVOID = *mut c_void;
pub type ULONG = u32;
pub type LPSTR = *mut i8;
pub type LPCSTR = *const i8;

/// FFI binding for MessageBoxA
pub type LoadLibraryAFn = extern "system" fn(lpFileName: LPCSTR) -> PVOID;
pub type GetProcAddressFn = extern "system" fn(hmodule: PVOID, name: LPCSTR) -> PVOID;
pub type MessageBoxAFn = extern "system" fn(h: PVOID, text: LPCSTR, caption: LPCSTR, t: u32) -> u32;

#[no_mangle]
pub extern "C" fn main() {
    unsafe {
        // clean argc and argv
        asm!("mov rcx, 0", "mov rdx, 0");
        // asm!("and rsp, ~0xf");
        // asm!("int3");
    }

    // stack strings
    let kernel32_dll = "Kernel32.DLL\0";
    let load_library_a = "LoadLibraryA\0";

    // get virtual addresses   
    let load_library_a_result = get_function_from_exports(kernel32_dll, load_library_a);
    if load_library_a_result.is_none() {
        // Handle error: Function not found
        return;
    }
    let load_library_a = load_library_a_result.unwrap();

    let user32_dll = "user32.dll\0";
    let get_proc_address = "GetProcAddress\0";
    let message_box_a = "MessageBoxA\0";

    let get_proc_addr = get_function_from_exports(kernel32_dll, get_proc_address).unwrap();

    // align the stack to divisible by 16
    unsafe { asm!("and rsp, ~0xf") };

    // obtaining User32.dll
    let load_library_a: LoadLibraryAFn = unsafe { transmute(load_library_a) };
    let user_32_dll = load_library_a(user32_dll.as_ptr() as *const i8);
    let get_proc_address: GetProcAddressFn = unsafe { transmute(get_proc_addr) };

    // get msg box fn
    let message_box_address = get_proc_address(user_32_dll, message_box_a.as_ptr() as *const i8);
    let message_box_a: MessageBoxAFn = unsafe { transmute(message_box_address) };

    message_box_a(
        null_mut(),
        b"Injected!\0".as_ptr() as *const i8,
        b"Injected!\0".as_ptr() as *const i8,
        0x0,
    );

    loop {}
}


use core::{ops::Add, str::{from_utf8, from_utf8_mut}};

/// Get the base address of a specified module. Obtains the base address by reading from the TEB -> PEB -> 
/// PEB_LDR_DATA -> InMemoryOrderModuleList -> InMemoryOrderLinks -> DllBase 
/// 
/// Returns the DLL base address as a Option<usize> 
#[allow(unused_variables)]
#[allow(unused_assignments)]
pub extern "system" fn get_module_base(module_name: &str) -> Option<usize> {

    // let module_name: &str = from_utf8(module_name).unwrap();

    let mut peb: usize;
    let mut ldr: usize;
    let mut in_memory_order_module_list: usize;
    let mut current_entry: usize;

    unsafe {
        // get the peb and module list
        asm!(
            "mov {peb}, gs:[0x60]",
            "mov {ldr}, [{peb} + 0x18]",
            "mov {in_memory_order_module_list}, [{ldr} + 0x10]", // points to the Flink
            peb = out(reg) peb,
            ldr = out(reg) ldr,
            in_memory_order_module_list = out(reg) in_memory_order_module_list,
        );

        // set the current entry to the head of the list
        current_entry = in_memory_order_module_list;
        
        // iterate the modules searching for 
        loop {
            // get the attributes we are after of the current entry
            let dll_base = *(current_entry.add(0x30) as *const usize);
            let module_name_address = *(current_entry.add(0x60) as *const usize);
            let module_length = *(current_entry.add(0x58) as *const u16);

            // check if the module name address is valid and not zero
            if module_name_address != 0 && module_length > 0 {
                // read the module name from memory
                let mut buffer = [0u8; 512];
                let dll_name = unsafe {
                    let mut len = 0;
                    while len < (module_length / 2) as usize && (module_name_address as *const u16).add(len).read() != 0 {
                        buffer[len] = (module_name_address as *const u16).add(len).read() as u8;
                        len += 1;
                    }
                    from_utf8(&buffer[..len]).unwrap_or("")
                };

                // do we have a match on the module name?
                if dll_name.eq_ignore_ascii_case(module_name) {
                    return Some(dll_base);
                }
            } else {
                return None;
            }

            // dereference current_entry which contains the value of the next LDR_DATA_TABLE_ENTRY (specifically a pointer to LIST_ENTRY 
            // within the next LDR_DATA_TABLE_ENTRY)
            current_entry = *(current_entry as *const usize);

            // If we have looped back to the start, break
            if current_entry == in_memory_order_module_list {
                return None;
            }
        }
    }
}

/// Get the function address of a function in a specified DLL from the DLL Base.
/// 
/// # Parameters 
/// * dll_name -> the name of the DLL / module you are wanting to query
/// * needle -> the function name (case sensitive) of the function you are looking for
/// 
/// # Returns
/// Option<*const c_void> -> the function address as a pointer
pub extern "system" fn get_function_from_exports(dll_name: &str, needle: &str) -> Option<usize> {

    let dll_name = dll_name.trim_end_matches('\u{0}');
    let needle = needle.trim_end_matches('\u{0}');

    // let dll_name = strip_null_terminator(dll_name);
    // let needle = strip_null_terminator(&needle);

    // let needle = from_utf8(&needle).unwrap();

    // if the dll_base was already found from a previous search then use that
    // otherwise, if it was None, make a call to get_module_base
    let dll_base: *mut c_void = match get_module_base(dll_name) {
            Some(a) => a as *mut c_void,
            None => {
                return None;
            },
        };

    // let dll_name = from_utf8(dll_name).unwrap();

    // check we match the DOS header, cast as pointer to tell the compiler to treat the memory
    // address as if it were a IMAGE_DOS_HEADER structure
    let dos_header: IMAGE_DOS_HEADER = unsafe { read_memory(dll_base as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        return None;
    }

    // check the NT headers
    let nt_headers = unsafe { read_memory(dll_base.offset(dos_header.e_lfanew as isize) as *const IMAGE_NT_HEADERS64) };
    if nt_headers.Signature != IMAGE_NT_SIGNATURE {
        return None;
    }

    // get the export directory
    // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
    // found from first item in the DataDirectory; then we take the structure in memory at dll_base + RVA
    let export_dir_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress;
    let export_offset = unsafe {dll_base.add(export_dir_rva as usize) };
    let export_dir: IMAGE_EXPORT_DIRECTORY = unsafe { read_memory(export_offset as *const IMAGE_EXPORT_DIRECTORY) };
    
    // get the addresses we need
    let address_of_functions_rva = export_dir.AddressOfFunctions as usize;
    let address_of_names_rva = export_dir.AddressOfNames as usize;
    let ordinals_rva = export_dir.AddressOfNameOrdinals as usize;

    let functions = unsafe { dll_base.add(address_of_functions_rva as usize) } as *const u32;
    let names = unsafe { dll_base.add(address_of_names_rva as usize) } as *const u32;
    let ordinals = unsafe { dll_base.add(ordinals_rva as usize) } as *const u16;

    // get the amount of names to iterate over
    let number_of_names = export_dir.NumberOfNames;

    for i in 0..number_of_names {
        // calculate the RVA of the function name
        let name_rva = unsafe { *names.offset(i.try_into().unwrap()) as usize };
        // actual memory address of the function name
        let name_addr = unsafe { dll_base.add(name_rva) };
        
        // read the function name
        let mut function_name = [0u8; 256];
        let mut len = 0;
        unsafe {
            while len < function_name.len() && (name_addr.add(len) as *const u8).read() != 0 {
                function_name[len] = (name_addr.add(len) as *const u8).read();
                len += 1;
            }
        }

        let function_name = from_utf8(&function_name[..len]).unwrap_or("Invalid UTF-8");
        if function_name.eq("Invalid UTF-8") {
            return None;
        }

        // if we have a match on our function name
        if function_name.eq(needle) {

            // calculate the RVA of the function address
            let ordinal = unsafe { *ordinals.offset(i.try_into().unwrap()) as usize };
            let fn_rva = unsafe { *functions.add(ordinal) as usize };
            // actual memory address of the function address
            let fn_addr = unsafe { dll_base.add(fn_rva) } as *const c_void;

            return Some(fn_addr as usize);
        }
    }

    None
}

/// Read memory of any type
unsafe fn read_memory<T>(address: *const T) -> T {
    core::ptr::read(address)
}

fn wide_to_str<'a>(wide: &[u16], buffer: &'a mut [u8]) -> Option<&'a str> {
    let mut len = 0;

    for &w in wide {
        // convert each u16 character to u8 and store in the byte array
        if w == 0 { break; } // stop at null terminator
        if w > 0xFF {
            return None; // non-ASCII characters are not handled here
        }
        if len >= buffer.len() {
            return None; // buffer overflow protection
        }
        buffer[len] = w as u8;
        len += 1;
    }

    // Convert the byte array to &str
    match from_utf8_mut(&mut buffer[..len]) {
        Ok(s) => Some(s),
        Err(_) => None,
    }
}

fn strip_null_terminator(bytes: &[u8]) -> &[u8] {
    if let Some(pos) = bytes.iter().position(|&x| x == 0) {
        &bytes[..pos]
    } else {
        bytes
    }
}

#[repr(C, packed(2))]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

pub const IMAGE_DOS_SIGNATURE: u16 = 23117u16;

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: IMAGE_FILE_MACHINE,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: IMAGE_FILE_CHARACTERISTICS,
}

#[repr(C, packed(4))]
pub struct IMAGE_OPTIONAL_HEADER64 {

    pub Magic: IMAGE_OPTIONAL_HEADER_MAGIC,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: IMAGE_SUBSYSTEM,
    pub DllCharacteristics: IMAGE_DLL_CHARACTERISTICS,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(transparent)]
pub struct IMAGE_FILE_MACHINE(pub u16);

#[repr(transparent)]
pub struct IMAGE_FILE_CHARACTERISTICS(pub u16);

#[repr(transparent)]
pub struct IMAGE_OPTIONAL_HEADER_MAGIC(pub u16);

#[repr(transparent)]
pub struct IMAGE_SUBSYSTEM(pub u16);

#[repr(transparent)]
pub struct IMAGE_DLL_CHARACTERISTICS(pub u16);

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: u32,
    pub Size: u32,
}

pub const IMAGE_NT_SIGNATURE: u32 = 17744u32;

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}