#include "helpers.h"
#include "patches.h"
#include <atomic>
#include <cstddef>
#include <cstring>
#include <cassert>

namespace patches::LuaJITMem {
namespace {
HMODULE ntdll;
long (*avm) (HANDLE handle, void **addr, ULONG zbits, size_t *size, ULONG alloctype, ULONG prot);
void *reserved_mem;
size_t reserved_size               = 0;
std::atomic_size_t reserved_offset = 0;

struct alignas (MEMORY_ALLOCATION_ALIGNMENT) AllocationHeader {
    SLIST_ENTRY entry;
    size_t size;
    size_t block_size;
    u32 class_index;
};

constexpr size_t ALIGNMENT      = alignof (std::max_align_t);
constexpr size_t MIN_BLOCK_SIZE = 64;
constexpr size_t NUM_CLASSES    = 24;
constexpr size_t HEADER_SIZE    = (sizeof (AllocationHeader) + ALIGNMENT - 1) & ~(ALIGNMENT - 1);

alignas (MEMORY_ALLOCATION_ALIGNMENT) SLIST_HEADER free_lists[NUM_CLASSES];

size_t
align_size (size_t size) {
    return (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);
}

size_t
class_index_for (size_t size) {
    size_t block_size = MIN_BLOCK_SIZE;
    for (size_t i = 0; i < NUM_CLASSES; i++) {
        if (size <= block_size) return i;
        block_size <<= 1;
    }
    return NUM_CLASSES;
}

void *
alloc_from_reserved (size_t size) {
    const auto total_size  = HEADER_SIZE + size;
    const auto class_index = class_index_for (total_size);
    if (class_index >= NUM_CLASSES) {
        LogMessage (LogLevel::ERROR, "0x{:x} is too big for allocating on reserved space!", size);
        throw std::runtime_error{"Requesting too big memory."};
    }

    const auto block_size = MIN_BLOCK_SIZE << class_index;
    if (auto entry = InterlockedPopEntrySList (&free_lists[class_index])) {
        auto block  = reinterpret_cast<AllocationHeader *> (entry);
        block->size = size;
        return reinterpret_cast<char *> (block) + HEADER_SIZE;
    }

    const auto offset = reserved_offset.fetch_add (block_size, std::memory_order_relaxed);
    if (offset > reserved_size || block_size > reserved_size - offset) {
        reserved_offset.fetch_sub (block_size, std::memory_order_relaxed);

        LogMessage (LogLevel::ERROR, "Failed to allocate 0x{:x} on reserved space, consider increasing luajit_reserve_mem!", size);
        throw std::runtime_error{"Failed to allocate memory for LuaJIT."};
    }

    auto block         = reinterpret_cast<AllocationHeader *> (reinterpret_cast<char *> (reserved_mem) + offset);
    block->size        = size;
    block->block_size  = block_size;
    block->class_index = static_cast<u32> (class_index);
    return reinterpret_cast<char *> (block) + HEADER_SIZE;
}

void
free_reserved (void *ptr) {
    auto block       = reinterpret_cast<AllocationHeader *> (reinterpret_cast<char *> (ptr) - HEADER_SIZE);
    const auto index = block->class_index;
    InterlockedPushEntrySList (&free_lists[index], &block->entry);
}

void *
lj_alloc_f (void *msp, void *ptr, size_t osize, size_t nsize) {
    (void)msp;
    (void)osize;

    if (!reserved_mem || !reserved_size) return nullptr;

    if (nsize == 0) {
        if (!ptr) return nullptr;
        free_reserved (ptr);
        return nullptr;
    }

    const auto size = align_size (nsize);

    if (!ptr) return alloc_from_reserved (size);

    auto block = reinterpret_cast<AllocationHeader *> (reinterpret_cast<char *> (ptr) - HEADER_SIZE);
    if (block->size >= size) {
        block->size = size;
        return ptr;
    }

    if (block->block_size >= HEADER_SIZE + size) {
        block->size = size;
        return ptr;
    }

    auto new_ptr = alloc_from_reserved (size);

    std::memcpy (new_ptr, ptr, std::min (block->size, size));
    free_reserved (ptr);

    return new_ptr;
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
    if (!avm) {
        LogMessage (LogLevel::ERROR, "Failed to get NtAllocateVirtualMemory");
        return;
    }

    reserved_mem  = nullptr;
    reserved_size = reserveSizeMB * 1024 * 1024;
    auto err      = avm (INVALID_HANDLE_VALUE, &reserved_mem, 1, &reserved_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (err != 0) {
        LogMessage (LogLevel::ERROR, "Failed to reserve low address memory for LuaJIT: {:x}", err);
        return;
    }

    LogMessage (LogLevel::INFO, "Reserved {}MB for LuaJIT at {}", reserved_size / 1024.f / 1024.f, reserved_mem);

    if (reserved_size <= HEADER_SIZE) {
        LogMessage (LogLevel::ERROR, "Reserved LuaJIT memory is too small");
        reserved_mem  = nullptr;
        reserved_size = 0;
        return;
    }

    reserved_offset.store (0, std::memory_order_relaxed);
    for (auto &free_list : free_lists)
        InitializeSListHead (&free_list);

    auto luajit = LoadLibraryA ("lua51.dll");
    assert (luajit);

    auto luaL_newstate_ptr = reinterpret_cast<uintptr_t> (GetProcAddress (luajit, "luaL_newstate"));
    assert (luaL_newstate_ptr);

    // don't call lj_alloc_create
    WRITE_NOP (luaL_newstate_ptr + 4, 5);
    WRITE_MEMORY (luaL_newstate_ptr + 0xC, u8, 0xEB);
    // use our own allocator
    WRITE_MEMORY (luaL_newstate_ptr + 0x13, u8, 0x48, 0xB9);
    WRITE_MEMORY (luaL_newstate_ptr + 0x15, void *, lj_alloc_f);
}

void
Exit () {
    if (reserved_mem) VirtualFree (reserved_mem, 0, MEM_RELEASE);
}
}
