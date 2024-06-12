use std::{env, ffi::c_void, fs::File, io::{BufWriter, Read, Write}, ptr::read, str::from_utf8};
use anyhow::Result;
use windows::Win32::System::{Diagnostics::Debug::{IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER}, SystemServices::IMAGE_DOS_HEADER};

fn main() -> Result<()> {
    // read the assembly dump
    let src_path = collect_args();
    let mut file = File::open(src_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // parse DOS header
    let dos_header: IMAGE_DOS_HEADER = unsafe { read_windows_struct(&buffer, 0) };
    let pe_offset = dos_header.e_lfanew as usize;

    // parse the pe header
    let pe_header: IMAGE_NT_HEADERS64 = unsafe { read_windows_struct(&buffer, pe_offset) };
    let file_header: IMAGE_FILE_HEADER = pe_header.FileHeader;
    let optional_header: IMAGE_OPTIONAL_HEADER64 = pe_header.OptionalHeader;

    let number_of_sections = file_header.NumberOfSections as usize;
    let entry_point = optional_header.AddressOfEntryPoint;
    let base_of_code = optional_header.BaseOfCode;
    let entry_offset = entry_point - base_of_code;

    // parse the headers
    let section_header_start = pe_offset + size_of::<IMAGE_NT_HEADERS64>();
    let section_headers = &buffer[section_header_start..section_header_start + (number_of_sections * size_of::<IMAGE_SECTION_HEADER>())];

    // collect all section information first to avoid overlapping borrows
    let mut text_section_info = None;

    for i in 0..number_of_sections {
        let section = &section_headers[i * size_of::<IMAGE_SECTION_HEADER>()..(i + 1) * size_of::<IMAGE_SECTION_HEADER>()];
        let name = from_utf8(&section[..8])?.trim_end_matches('\u{0}');

        // let virtual_address = u32::from_le_bytes([section[12], section[13], section[14], section[15]]) as usize;
        let raw_data_ptr = u32::from_le_bytes([section[20], section[21], section[22], section[23]]) as usize;
        let raw_data_size = u32::from_le_bytes([section[16], section[17], section[18], section[19]]) as usize;

        if name.starts_with(".text") {
            text_section_info = Some((raw_data_ptr, raw_data_size));
            break;
        }
    }

    if let Some((start, size)) = text_section_info {
        let dst_path = r"output/shellcode.bin";
        let shellcode = File::create(&dst_path)?;
        let mut buf_writer = BufWriter::new(shellcode);

        println!("[+] Section text addr: {:p}, size: {:x}", start as *const c_void, size);
        println!("[+] Section offset: {:p}", entry_offset as *const c_void);

        // Perform buffer modification
        let buffer_start = start;
        let buffer_end = start + 5;
        let (head, _) = buffer.split_at_mut(buffer_end);

        // Calculate the offset for the jmp to our entry point
        if entry_offset >= 0x80 {
            // Near jmp with shorter offset
            head[buffer_start] = 0xe9; // Near jmp
            let offset = (entry_offset - 5) as i32;
            let offset_bytes = offset.to_le_bytes();
            head[buffer_start + 1..buffer_start + 5].copy_from_slice(&offset_bytes);
        } else {
            // Short jmp
            head[buffer_start] = 0xeb; // Short jmp opcode
            head[buffer_start + 1] = (entry_offset - 2) as u8; // Offset for short jmp
        }

        for i in start..start + size {
            buf_writer.write(&[buffer[i]])?;
        }
        buf_writer.flush()?;
        println!("[+] Done. Shellcode saved at {}", dst_path);
    }

    Ok(())
    
}

unsafe fn read_windows_struct<T>(buffer: &[u8], offset: usize) -> T {
    read(buffer[offset..offset + size_of::<T>()].as_ptr() as *const T)
}

fn collect_args() -> String {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("[-] Expected argument path to assembly dump.");
    }

    let path = args[1].clone();
    path
}