use core::{arch::asm, ops::Add};

#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[link(name = "vcruntime")] extern {}

pub extern "system" fn get_dll_base(module_name: *const u16) -> *const c_void {
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
                let cur_name = core::slice::from_raw_parts(module_name_address as *const u16, (module_length / 2) as usize) as *const _ as *const u16;
                if raw_eq(module_name, cur_name) {
                    return dll_base as PVOID;
                }
            }

            // dereference current_entry which contains the value of the next LDR_DATA_TABLE_ENTRY (specifically a pointer to LIST_ENTRY 
            // within the next LDR_DATA_TABLE_ENTRY)
            current_entry = *(current_entry as *const usize);

            // If we have looped back to the start, break
            if current_entry == in_memory_order_module_list {
                // using 12345678 as a marker for it gone wrong
                return 0x12345678 as *const c_void;
            }
        }
    }
}

/// Get the function address from the givin module DLL base
pub extern "system" fn get_function_from_exports(dll_base: *const c_void, needle: *const u8) -> *const c_void {
    unsafe {
        // cast the dos header
        let dos_header = &*(dll_base as *const IMAGE_DOS_HEADER);
        if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return 0x87654321 as *const c_void;
        }

        // get us to the export directory
        let e_lfanew = (*dos_header).e_lfanew;
        let nt_headers = (dll_base as *const u8).offset(e_lfanew as isize) as *const IMAGE_NT_HEADERS64;
        let optional_headers = &(*nt_headers).OptionalHeader;
        let virtual_addr = (&optional_headers.DataDirectory[0]).VirtualAddress;
        let export_dir: *const IMAGE_EXPORT_DIRECTORY = (dll_base as *const u8).offset(virtual_addr as _) as _;

        // get the location of each list
        let number_of_names = (*export_dir).NumberOfNames;
        let addr_of_funcs = (*export_dir).AddressOfFunctions;
        let addr_of_names = (*export_dir).AddressOfNames;
        let addr_of_ords = (*export_dir).AddressOfNameOrdinals;

        // iterate through each export, looking for our chosen
        for i in 0..number_of_names {
            let p_name_rva: *const DWORD = (dll_base as *const u8).offset((addr_of_names + i * 4) as isize) as *const _;
            let p_name_index: *const WORD = (dll_base as *const u8).offset((addr_of_ords + i * 2) as isize) as *const _;
            let name_index = p_name_index.as_ref().unwrap();
            let mut offset: u32 = (4 * name_index) as u32;
            offset = offset + addr_of_funcs;
            let func_rva: *const DWORD = (dll_base as *const u8).offset(offset as _) as *const _;

            let name_rva = p_name_rva.as_ref().unwrap();
            let curr_name = (dll_base as *const u8).offset(*name_rva as isize);

            if *curr_name == 0 {
                continue;
            }
            if raw_eq(needle, curr_name) {
                let res = (dll_base as *const u8).offset(*func_rva as isize);
                return res as *const c_void;
            }
        }
    }

    0x11223344 as *const c_void
}

pub fn raw_eq<T>(s: *const T, u: *const T) -> bool
where
    T: PartialEq + Default,
{
    unsafe {
        // calculate the length of the first string (s)
        let s_len = (0..).take_while(|&i| *s.offset(i) != T::default()).count();
        let s_slice = core::slice::from_raw_parts(s, s_len);

        // calculate the length of the second string (u)
        let u_len = (0..).take_while(|&i| *u.offset(i) != T::default()).count();
        let u_slice = core::slice::from_raw_parts(u, u_len);

        // compare lengths
        if s_len != u_len {
            return false;
        }       

        // compare content
        for i in 0..s_len {
            // bounds check on u; shouldn't matter actually, but leaving for safety
            if i > u_len {
                return false;
            }

            // compare each char in the string
            if s_slice[i] != u_slice[i] {
                return false;
            }
        }

        // matched
        true
    }
}

// types
pub type USHORT = u16;
pub type PWCH = *mut u16;
pub type BYTE = u8;
pub type BOOL = BYTE;
pub type HANDLE = *mut c_void;
pub type PVOID = *mut c_void;
pub type ULONG = u32;
pub enum c_void {}
pub type LPSTR = *mut i8;
pub type LPCSTR = *const i8;
pub type DWORD = u32;
pub type WORD = u16;
pub type LONG = u32;
pub type ULONGLONG = u64;

#[repr(C)]
pub struct PEB {

    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    pub Reserved3: [*mut c_void; 2],
    pub Ldr: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub Reserved4: [*mut c_void; 3],
}

#[repr(C)]
struct PEB_LDR_DATA {
    Length: ULONG,
    Initialized: BOOL,
    SsHandle: HANDLE,
    InLoadOrderModuleList: LIST_ENTRY,
    // ...
}

#[repr(C)]
struct RTL_USER_PROCESS_PARAMETERS {
    MaximumLength: ULONG,
    Length: ULONG,
    Flags: ULONG,
    DebugFlags: ULONG,
    ConsoleHandle: HANDLE,
    ConsoleFlags: ULONG,
    StandardInput: HANDLE,
    StandardOutput: HANDLE,
    StandardError: HANDLE,
}

#[repr(C)]
struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)] 
struct LDR_DATA_TABLE_ENTRY {
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
    BaseAddress: PVOID,
    EntryPoint: PVOID,
    SizeOfImage: ULONG,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
}

#[repr(C)] 
struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PWCH,
}

#[repr(C)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: WORD,
    pub e_cblp: WORD,
    pub e_cp: WORD,
    pub e_crlc: WORD,
    pub e_cparhdr: WORD,
    pub e_minalloc: WORD,
    pub e_maxalloc: WORD,
    pub e_ss: WORD,
    pub e_sp: WORD,
    pub e_csum: WORD,
    pub e_ip: WORD,
    pub e_cs: WORD,
    pub e_lfarlc: WORD,
    pub e_ovno: WORD,
    pub e_res: [WORD; 4],
    pub e_oemid: WORD,
    pub e_oeminfo: WORD,
    pub e_res2: [WORD; 10],
    pub e_lfanew: LONG,
}

pub const IMAGE_DOS_SIGNATURE: WORD = 0x5A4D;

#[repr(C)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: WORD,
    pub NumberOfSections: WORD,
    pub TimeDateStamp: DWORD,
    pub PointerToSymbolTable: DWORD,
    pub NumberOfSymbols: DWORD,
    pub SizeOfOptionalHeader: WORD,
    pub Characteristics: WORD,
}

#[repr(C)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: WORD,
    pub MajorLinkerVersion: BYTE,
    pub MinorLinkerVersion: BYTE,
    pub SizeOfCode: DWORD,
    pub SizeOfInitializedData: DWORD,
    pub SizeOfUninitializedData: DWORD,
    pub AddressOfEntryPoint: DWORD,
    pub BaseOfCode: DWORD,
    pub ImageBase: ULONGLONG,
    pub SectionAlignment: DWORD,
    pub FileAlignment: DWORD,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: DWORD,
    pub SizeOfImage: DWORD,
    pub SizeOfHeaders: DWORD,
    pub CheckSum: DWORD,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: ULONGLONG,
    pub SizeOfStackCommit: ULONGLONG,
    pub SizeOfHeapReserve: ULONGLONG,
    pub SizeOfHeapCommit: ULONGLONG,
    pub LoaderFlags: DWORD,
    pub NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: DWORD,
    pub Size: DWORD,
}

#[repr(C)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: DWORD,
    pub TimeDateStamp: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub Name: DWORD,
    pub Base: DWORD,
    pub NumberOfFunctions: DWORD,
    pub NumberOfNames: DWORD,
    pub AddressOfFunctions: DWORD,
    pub AddressOfNames: DWORD,
    pub AddressOfNameOrdinals: DWORD,
}