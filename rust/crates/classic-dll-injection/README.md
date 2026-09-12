# classic-dll-injection

Rust port of the Classic DLL Injection technique originally implemented in
`Classic_DLL_Injection/Classic_DLL_Injection/Source.cpp`.

## Technique

Classic DLL Injection abuses the Windows process model to load an arbitrary DLL
into a live target process:

1. **OpenProcess** — acquire a handle to the target process with
   `PROCESS_ALL_ACCESS`.
2. **VirtualAllocEx** — allocate a `PAGE_READWRITE` buffer in the target's
   virtual address space large enough to hold the DLL path string (including null
   terminator).
3. **WriteProcessMemory** — copy the null-terminated DLL path into the remote
   buffer.
4. **GetProcAddress(kernel32, "LoadLibraryA")** — resolve the address of
   `LoadLibraryA`.  Because kernel32.dll is mapped at the same base across all
   processes in a session, the local address is valid as a remote thread entry
   point.
5. **CreateRemoteThread** — create a thread in the target process whose start
   address is `LoadLibraryA` and whose single argument is the remote buffer
   address.  The OS loader then maps the DLL into the target and runs its
   `DllMain`.

## Usage

```
classic-dll-injection --pid <target PID> --dll <absolute path to DLL>
```

Example:

```
classic-dll-injection --pid 1234 --dll C:\payloads\inject.dll
```

## Detection vectors

| Signal | Detail |
|--------|--------|
| `OpenProcess(PROCESS_ALL_ACCESS)` | High-privilege cross-process handle — flagged by EDRs on the handle table. |
| `VirtualAllocEx` + `WriteProcessMemory` | Classic sequence in ETW `Microsoft-Windows-Kernel-Process` events. |
| `CreateRemoteThread` into another process | Triggers `IMAGE_LOAD` / thread-creation callbacks registered by AV drivers. |
| DLL path in remote memory | Path string visible in a memory scan of the target at the time of injection. |
| Module list of target process | The injected DLL appears in `EnumProcessModules` / the PEB loader list. |

## Tradeoffs vs. C++ original

| | C++ original | Rust port |
|---|---|---|
| **Safety** | Manual `CloseHandle` / `VirtualFreeEx` in every error path | Rust's `?` operator unwinds through cleanup calls; no double-free possible |
| **Error handling** | `GetLastError()` printed to stderr | `windows::core::Error` propagated as `Box<dyn Error>` |
| **Target resolution** | Resolves PID by iterating the snapshot by process name | Accepts PID directly via `--pid`; process-name lookup is the caller's concern |
| **Dependency surface** | Win32 headers only | `windows` crate with feature-gated bindings; binary links the same SDK DLLs |
| **Compile target** | MSVC x64 | `cargo build --target x86_64-pc-windows-msvc` (cross-compile from Linux also supported with `cargo-xwin`) |

## Build

Requires the MSVC toolchain or `cargo-xwin` for cross-compilation:

```
cargo build --release
```
