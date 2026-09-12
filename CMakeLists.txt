cmake_minimum_required(VERSION 3.20)
project(injectlab LANGUAGES C CXX ASM_MASM)

# ---------------------------------------------------------------------------
# Requirements: Windows SDK, MSVC 2019 or later, CMake 3.20+.
# Usage:
#   cmake -B build -G "Visual Studio 17 2022" -A x64
#   cmake --build build --config Release
#
# Each technique directory that contains a Source.cpp (or Source.c) with a
# main() entry point is compiled into a standalone executable.  The target name
# matches the technique directory name for easy identification.
# ---------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Apply common MSVC flags to all targets.
if(MSVC)
    add_compile_options(/W3 /WX- /MP)
    # Ensure x64 intrinsics and Windows headers are available.
    add_compile_definitions(
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
endif()

# ---------------------------------------------------------------------------
# Helper: add_technique(<dir-name> <source-file-relative-to-dir>)
#
# Creates an executable target named <dir-name> that links against the Windows
# default libraries.  The source path is resolved relative to CMAKE_SOURCE_DIR.
# ---------------------------------------------------------------------------
function(add_technique TARGET_NAME SOURCE_REL_PATH)
    set(SRC "${CMAKE_SOURCE_DIR}/${SOURCE_REL_PATH}")
    if(NOT EXISTS "${SRC}")
        message(STATUS "[injectlab] Skipping ${TARGET_NAME}: ${SRC} not found")
        return()
    endif()
    add_executable(${TARGET_NAME} "${SRC}")
    target_link_libraries(${TARGET_NAME} PRIVATE ntdll)
    # Some techniques reference winternl types; add the SDK include.
    target_include_directories(${TARGET_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/${TARGET_NAME}"
    )
    set_target_properties(${TARGET_NAME} PROPERTIES
        OUTPUT_NAME "${TARGET_NAME}"
    )
endfunction()

# ---------------------------------------------------------------------------
# Helper: add_technique_with_header(<dir-name> <source> <header-dir>)
#
# Same as add_technique but also adds a private include directory for targets
# that ship a local Header.h (e.g. Process_Hollowing).
# ---------------------------------------------------------------------------
function(add_technique_with_header TARGET_NAME SOURCE_REL_PATH HEADER_REL_DIR)
    set(SRC "${CMAKE_SOURCE_DIR}/${SOURCE_REL_PATH}")
    if(NOT EXISTS "${SRC}")
        message(STATUS "[injectlab] Skipping ${TARGET_NAME}: ${SRC} not found")
        return()
    endif()
    add_executable(${TARGET_NAME} "${SRC}")
    target_link_libraries(${TARGET_NAME} PRIVATE ntdll)
    target_include_directories(${TARGET_NAME} PRIVATE
        "${CMAKE_SOURCE_DIR}/${HEADER_REL_DIR}"
    )
    set_target_properties(${TARGET_NAME} PROPERTIES
        OUTPUT_NAME "${TARGET_NAME}"
    )
endfunction()

# ---------------------------------------------------------------------------
# Technique targets
#
# Pattern A — nested VS project layout: <Dir>/<Dir>/Source.cpp
# Pattern B — flat layout: <Dir>/Source.cpp (or .c)
# ---------------------------------------------------------------------------

# APC Queue Injection
add_technique(APC_QUEUE_INJECTION
    "APC_QUEUE_INJECTION/APC_QUEUE_INJECTION/Source.cpp")

# Address-of-Entry-Point Code Injection
add_technique(AddressOfEntryPoint_Code_Injection
    "AddressOfEntryPoint_Code_Injection/AddressOfEntryPoint_Code_Injection/Source.cpp")

# Classic Code Injection (API obfuscation variant)
add_technique(Classic_Code_Injection_API_Obfuscate
    "Classic_Code_Injection_API_Obfuscate/Classic_Code_Injection_API_Obfuscate/Source.cpp")

# Classic Code Injection (local)
add_technique(Classic_Code_Injection_Local
    "Classic_Code_Injection_Local/Classic_Code_Injection_Local/Source.cpp")

# Classic Code Injection (remote)
add_technique(Classic_Code_Injection_Remote
    "Classic_Code_Injection_Remote/Classic_Code_Injection_Remote/Source.cpp")

# Classic Code Injection (remote, VirtualProtect variant)
add_technique(Classic_Code_Injection_Remote_VP
    "Classic_Code_Injection_Remote_VP/Classic_Code_Injection_Remote_VP/Source.cpp")

# Classic DLL Injection
add_technique(Classic_DLL_Injection
    "Classic_DLL_Injection/Classic_DLL_Injection/Source.cpp")

# Direct Syscalls (flat layout, C source)
add_technique(DirectSyscalls
    "DirectSyscalls/arsenal.cpp")

# EarlyBird Code Injection
add_technique(EarlyBird_Code_Injection
    "EarlyBird_Code_Injection/EarlyBird_Code_Injection/Source.cpp")

# Indirect Syscalls
add_technique(IndirectSyscalls
    "IndirectSyscalls/IndirectSyscalls/Source.c")

# Injection Through Fiber
add_technique(Injection_Through_Fiber
    "Injection_Through_Fiber/Injection_Through_Fiber/Source.cpp")

# Module Stomping
add_technique(Module_Stomping
    "Module_Stomping/Module_Stomping/Source.cpp")

# Mockingjay
add_technique(Mokingjay
    "Mokingjay/Mokingjay/Source.cpp")

# NT API Injection
add_technique(NTAPI_Injection
    "NTAPI_Injection/NTAPI_Injection/Source.cpp")

# NtCreateSection + NtMapViewOfSection
add_technique(NtCreateSection_MapViewOfSection
    "NtCreateSection_MapViewOfSection/NtCreateSection_MapViewOfSection/Source.cpp")

# PEB Walk + API Obfuscation
add_technique(PEB_WALK_API_OBFUSCATION
    "PEB_WALK_API_OBFUSCATION/PEB_WALK_API_OBFUSCATION/Source.cpp")

# PEB Walk Injection
add_technique(PEB_WALK_INJECTION
    "PEB_WALK_INJECTION/PEB_WALK_INJECTION/Source.cpp")

# PE Code Injection
add_technique(PE_Code_Injection
    "PE_Code_Injection/PE_Code_Injection/Source.cpp")

# Process Ghosting
add_technique(Process_Ghosting
    "Process_Ghosting/Process_Ghosting/Source.cpp")

# Process Hollowing (original — uses Header.h in same directory)
add_technique_with_header(Process_Hollowing
    "Process_Hollowing/ProcessHollowing/Source.cpp"
    "Process_Hollowing/ProcessHollowing")

# Process Hollowing — Indirect Syscall variant (this repo's addition)
add_executable(ProcessHollowing_IndirectSyscall
    "${CMAKE_SOURCE_DIR}/ProcessHollowing_IndirectSyscall/Source.cpp")
target_link_libraries(ProcessHollowing_IndirectSyscall PRIVATE ntdll)
if(EXISTS "${CMAKE_SOURCE_DIR}/ProcessHollowing_IndirectSyscall/Source.cpp")
    message(STATUS "[injectlab] Adding ProcessHollowing_IndirectSyscall")
endif()

# RWX Hunting Injection
add_technique(RWX_Hunting_Injection
    "RWX_Hunting_Injection/RWX_Hunting_Injection/Source.cpp")

# Reflective DLL Injection
add_technique(Reflective_DLL_Injection
    "Reflective_DLL_Injection/Reflective_DLL_Injection/Source.cpp")

# Reflective DLL Loading — Lagos Island variant
add_technique(Reflective_DLL_Loading_Lagos_Island
    "Reflective_DLL_Loading_Lagos_Island/Reflective_DLL_Loading_Lagos_Island/Source.cpp")

# Remote Thread Hijacking
add_technique(Remote_Thread_Hijacking
    "Remote_Thread_Hijacking/Remote_Thread_Hijacking/Source.cpp")

# DV_NEW technique
add_technique(DV_NEW
    "DV_NEW/DV_NEW/Source.cpp")
