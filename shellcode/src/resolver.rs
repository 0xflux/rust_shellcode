#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use core::{arch::asm, ffi::c_void, ops::Add, slice::from_raw_parts, str::{from_utf8, from_utf8_mut}};

/// A structure containing the module name, function name, and export address for each function loaded
/// into the portable executable on x64 systems only.
pub struct ExportResolver<'a> {
    pub module: &'a str,
    pub base_address: usize, // to prevent repeat reads of the peb
    pub function: &'a str,
    pub address: usize,
}

/// Get the base address of a specified module. Obtains the base address by reading from the TEB -> PEB -> 
/// PEB_LDR_DATA -> InMemoryOrderModuleList -> InMemoryOrderLinks -> DllBase 
/// 
/// Returns the DLL base address as a Option<usize> 
#[allow(unused_variables)]
#[allow(unused_assignments)]
fn get_module_base(module_name: &[u8]) -> Option<usize> {

    let module_name: &str = from_utf8(module_name).unwrap();

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
                let dll_name_slice = from_raw_parts(module_name_address as *const u16, (module_length / 2) as usize);
                let mut buffer = [0u8; 512];
                if let Some(dll_name) = wide_to_str(dll_name_slice, &mut buffer) {
                    // do we have a match on the module name?
                    if dll_name.eq_ignore_ascii_case(module_name) {
                        return Some(dll_base);
                    }
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
pub fn get_function_from_exports<'a>(dll_name: &'a [u8], needle: &'a [u8]) -> Option<ExportResolver<'a>> {

    let dll_name = strip_null_terminator(dll_name);
    let needle = strip_null_terminator(&needle);

    let needle = from_utf8(&needle).unwrap();

    // if the dll_base was already found from a previous search then use that
    // otherwise, if it was None, make a call to get_module_base
    let dll_base: *mut c_void = match get_module_base(dll_name) {
            Some(a) => a as *mut c_void,
            None => {
                return None;
            },
        };

    let dll_name = from_utf8(dll_name).unwrap();

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
        let function_name = unsafe {
            let char = name_addr as *const u8;
            let mut len = 0;
            // iterate over the memory until a null terminator is found
            while *char.add(len) != 0 {
                len += 1;
            }

            from_raw_parts(char, len)
        };

        let function_name = from_utf8(function_name).unwrap_or("Invalid UTF-8");
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

            let result = ExportResolver {
                module: dll_name,
                base_address: dll_base as usize,
                function: needle,
                address: fn_addr as usize,
            };

            return Some(result);
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