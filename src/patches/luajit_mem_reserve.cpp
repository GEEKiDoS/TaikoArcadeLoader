#include "helpers.h"
#include "patches.h"

namespace patches::LuaJITMem {
namespace {
HMODULE ntdll;
long (*avm) (HANDLE handle, void **addr, ULONG zbits, size_t *size, ULONG alloctype, ULONG prot);
long (*fvm) (HANDLE handle, void **addr, size_t *size, ULONG freetype);
void *reserved_mem;
size_t reserved_size = 0;

long
avm_hook (HANDLE handle, void **addr, ULONG zbits, size_t *size, ULONG alloctype, ULONG prot) {
    // LuaJIT call this api with zero bits set to 1
    if (zbits == 1 && reserved_mem) {
        LogMessage (LogLevel::INFO, "Freeing reserved memory for LuaJIT...");
        auto free_size = size_t{0};
        auto err       = fvm (INVALID_HANDLE_VALUE, &reserved_mem, &free_size, MEM_RELEASE);
        if (err == 0) {
            reserved_mem  = nullptr;
            reserved_size = 0;
        } else {
            LogMessage (LogLevel::ERROR, "Failed to free reserved memory for LuaJIT: {:x}", err);
        }
    }

    return avm (handle, addr, zbits, size, alloctype, prot);
}

HOOK (void *, _get_proc_address, PROC_ADDRESS ("kernel32.dll", "GetProcAddress"), HANDLE dll, const char *proc) {
    if (dll == ntdll && !IS_INTRESOURCE (proc) && !strcmp (proc, "NtAllocateVirtualMemory")) return avm_hook;
    return original_get_proc_address (dll, proc);
}

}

void
Init (size_t reserveSizeMB) {
    if (!reserveSizeMB) return;

    ntdll = GetModuleHandleA ("ntdll.dll");

    if (!ntdll) {
        LogMessage (LogLevel::ERROR, "Failed to get ntdll");
        return;
    }

    avm = reinterpret_cast<decltype (avm)> (GetProcAddress (ntdll, "NtAllocateVirtualMemory"));
    fvm = reinterpret_cast<decltype (fvm)> (GetProcAddress (ntdll, "NtFreeVirtualMemory"));
    if (!avm || !fvm) {
        LogMessage (LogLevel::ERROR, "Failed to get NtAllocateVirtualMemory or NtFreeVirtualMemory");
        return;
    }

    reserved_mem  = nullptr;
    reserved_size = reserveSizeMB * 1024 * 1024;
    auto err      = avm (INVALID_HANDLE_VALUE, &reserved_mem, 1, &reserved_size, MEM_RESERVE, PAGE_NOACCESS);

    if (err != 0) {
        LogMessage (LogLevel::ERROR, "Failed to reserve low address memory for LuaJIT: {:x}", err);
        return;
    }

    LogMessage (LogLevel::INFO, "Reserved {}MB for LuaJIT at {}", reserved_size / 1024.f / 1024.f, reserved_mem);

    INSTALL_HOOK (_get_proc_address);
}
}
