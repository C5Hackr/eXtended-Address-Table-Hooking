//XAT - eXtended Address Table hooking library

#include <Windows.h>
#include <psapi.h>

typedef struct {
    PVOID ImageBase;
    PIMAGE_DOS_HEADER Dos;
    PIMAGE_NT_HEADERS NtHeaders;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
    IMAGE_FILE_HEADER FileHeader;
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
} ParsedPEImage;

typedef struct {
    ULONG_PTR* IatSlot;
    ULONG_PTR Original;
} IatPatch;

typedef struct {
    BOOL isIatHooked;
    BOOL isEatHooked;
} HookState;

typedef struct {
    IatPatch* IatPatches;
    DWORD IatPatchCount;
    DWORD IatPatchCap;

    LPCSTR ModuleName;
    LPCSTR ProcedureName;
    PVOID HookFunction;

    DWORD OriginalRva;
    ParsedPEImage peImage;
    ParsedPEImage modImage;
    HookState state;

    PVOID Trampoline;
} XATHook;

__declspec(noinline) PVOID AllocateJmpNearModule(PVOID modAddress, SIZE_T payloadSize) {
    HANDLE hProc = GetCurrentProcess();

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    SIZE_T gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    if ((gran & (gran - 1)) != 0) {
        gran = 0x10000;
    }

    MODULEINFO modInfo;
    if (!GetModuleInformation(hProc, (HMODULE)modAddress, &modInfo, sizeof(modInfo))) {
        return NULL;
    }

    DWORD_PTR base = (DWORD_PTR)modInfo.lpBaseOfDll;
    DWORD_PTR end = base + (DWORD_PTR)modInfo.SizeOfImage;

    DWORD_PTR start = (end + (gran - 1)) & ~(DWORD_PTR)(gran - 1);

#if defined(_WIN64)
    DWORD_PTR window = (DWORD_PTR)0x80000000ULL;
#else
    DWORD_PTR window = (DWORD_PTR)0x40000000UL;
#endif

    DWORD_PTR minAddr = (start > window) ? (start - window) : 0;
    DWORD_PTR maxAddr = start + window;
    if (maxAddr < start) {
        maxAddr = (DWORD_PTR)~(DWORD_PTR)0;
    }

    DWORD_PTR userMin = (DWORD_PTR)si.lpMinimumApplicationAddress;
    DWORD_PTR userMax = (DWORD_PTR)si.lpMaximumApplicationAddress;

    if (minAddr < userMin) minAddr = userMin;
    if (maxAddr > userMax) maxAddr = userMax;

    if (maxAddr < minAddr) {
        return NULL;
    }

    DWORD_PTR span = maxAddr - minAddr;

    DWORD maxSteps = (DWORD)(span / gran);
    if (maxSteps > 0x20000) {
        maxSteps = 0x20000;
    }

    for (DWORD i = 0; i <= maxSteps; i++) {
        DWORD_PTR off = (DWORD_PTR)i * (DWORD_PTR)gran;
        if (i != 0 && off / (DWORD_PTR)gran != (DWORD_PTR)i) {
            break;
        }

        if (start <= maxAddr && off <= (maxAddr - start)) {
            DWORD_PTR up = start + off;
            if (up >= minAddr && up <= maxAddr) {
                PVOID p = VirtualAlloc((PVOID)up, payloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (p) {
                    return p;
                }
            }
        }

        if (start >= minAddr && off <= (start - minAddr)) {
            DWORD_PTR down = start - off;
            if (down >= minAddr && down <= maxAddr) {
                PVOID p = VirtualAlloc((PVOID)down, payloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (p) {
                    return p;
                }
            }
        }
    }

    return NULL;
}

__declspec(noinline) ParsedPEImage ParsePeImage(LPCSTR imageName) {
    ParsedPEImage pe = { 0 };

    PVOID imageBase = GetModuleHandleA(imageName);
    if (!imageBase) {
        return pe;
    }

    DWORD_PTR peBase = (DWORD_PTR)imageBase;

    PIMAGE_DOS_HEADER Dos = (PIMAGE_DOS_HEADER)imageBase;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return pe;
    }

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)(peBase + Dos->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return pe;
    }

    IMAGE_OPTIONAL_HEADER OptionalHeader = NtHeaders->OptionalHeader;
    IMAGE_FILE_HEADER FileHeader = NtHeaders->FileHeader;

    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = NULL;
    if (OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(peBase + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    }

    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    if (OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(peBase + OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }

    pe.ImageBase = imageBase;
    pe.Dos = Dos;
    pe.NtHeaders = NtHeaders;
    pe.OptionalHeader = OptionalHeader;
    pe.FileHeader = FileHeader;
    pe.ImportDescriptor = ImportDescriptor;
    pe.ExportDirectory = ExportDirectory;

    return pe;
}

__declspec(noinline) BOOL XATHook_ReservePatches(XATHook* hook, DWORD want) {
    if (hook->IatPatchCap >= want) {
        return TRUE;
    }

    DWORD newCap = hook->IatPatchCap ? hook->IatPatchCap : 256;
    while (newCap < want) {
        if (newCap > 0x7FFFFFFF / 2) {
            newCap = want;
            break;
        }
        newCap *= 2;
    }

    SIZE_T bytes = (SIZE_T)newCap * sizeof(IatPatch);

    if (!hook->IatPatches) {
        hook->IatPatches = (IatPatch*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes);
        if (!hook->IatPatches) {
            return FALSE;
        }
    }
    else {
        IatPatch* p = (IatPatch*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, hook->IatPatches, bytes);
        if (!p) {
            return FALSE;
        }
        hook->IatPatches = p;
    }

    hook->IatPatchCap = newCap;
    return TRUE;
}

__declspec(noinline) void XATHook_FreePatches(XATHook* hook) {
    if (hook->IatPatches) {
        HeapFree(GetProcessHeap(), 0, hook->IatPatches);
        hook->IatPatches = NULL;
    }
    hook->IatPatchCount = 0;
    hook->IatPatchCap = 0;
}

__declspec(noinline) BOOL XATHook_Init(XATHook* hook, LPCSTR ModuleName, LPCSTR ProcedureName, PVOID HookFunction, PVOID* OriginalExportFunction) {
    ZeroMemory(hook, sizeof(*hook));

    HMODULE hMod = GetModuleHandleA(ModuleName);
    if (!hMod) {
        hMod = LoadLibraryA(ModuleName);

        if (!hMod) {
            return FALSE;
        }
    }

    hook->ModuleName = ModuleName;
    hook->ProcedureName = ProcedureName;
    hook->HookFunction = HookFunction;

    hook->IatPatches = NULL;
    hook->IatPatchCount = 0;
    hook->IatPatchCap = 0;
    hook->state.isIatHooked = FALSE;
    hook->state.isEatHooked = FALSE;
    hook->Trampoline = NULL;
    hook->OriginalRva = 0;

    hook->peImage = ParsePeImage(NULL);
    hook->modImage = ParsePeImage(ModuleName);

    if (OriginalExportFunction) {
        *OriginalExportFunction = NULL;
        if (hMod) {
            *OriginalExportFunction = (PVOID)GetProcAddress(hMod, ProcedureName);
        }
    }

    if (!hook->modImage.ImageBase || !hook->modImage.ExportDirectory) {
        return FALSE;
    }

    DWORD_PTR modBase = (DWORD_PTR)hook->modImage.ImageBase;
    PIMAGE_EXPORT_DIRECTORY exp = hook->modImage.ExportDirectory;

    if (!exp->AddressOfNames || !exp->AddressOfFunctions || !exp->AddressOfNameOrdinals) {
        return FALSE;
    }

    PDWORD names = (PDWORD)(modBase + exp->AddressOfNames);
    PDWORD funcs = (PDWORD)(modBase + exp->AddressOfFunctions);
    PWORD ords = (PWORD)(modBase + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        LPCSTR name = (LPCSTR)(modBase + names[i]);
        if (_stricmp(name, ProcedureName) == 0) {
            hook->OriginalRva = funcs[ords[i]];
            break;
        }
    }

    return TRUE;
}

__declspec(noinline) void XATHook_EnableDelayIAT(XATHook* hook) {
    HANDLE hProc = GetCurrentProcess();

    FARPROC realProc = GetProcAddress((HMODULE)hook->modImage.ImageBase, hook->ProcedureName);
    ULONG_PTR exportAddr = 0;
    if (hook->modImage.ImageBase && hook->OriginalRva) {
        exportAddr = (ULONG_PTR)hook->modImage.ImageBase + (ULONG_PTR)hook->OriginalRva;
    }

    HMODULE hMods[2048];
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        return;
    }

    for (DWORD mi = 0; mi < cbNeeded / sizeof(HMODULE); mi++) {
        MODULEINFO info;
        if (!GetModuleInformation(hProc, hMods[mi], &info, sizeof(info))) {
            continue;
        }

        DWORD_PTR base = (DWORD_PTR)info.lpBaseOfDll;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            continue;
        }

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            continue;
        }

        DWORD dlyVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
        if (!dlyVA) {
            continue;
        }

        PIMAGE_DELAYLOAD_DESCRIPTOR dly = (PIMAGE_DELAYLOAD_DESCRIPTOR)(base + dlyVA);

        while (dly->DllNameRVA) {
#if defined(_WIN64)
            PIMAGE_THUNK_DATA64 iat = (PIMAGE_THUNK_DATA64)(base + dly->ImportAddressTableRVA);
            PIMAGE_THUNK_DATA64 intb = dly->ImportNameTableRVA ? (PIMAGE_THUNK_DATA64)(base + dly->ImportNameTableRVA) : NULL;
#else
            PIMAGE_THUNK_DATA32 iat = (PIMAGE_THUNK_DATA32)(base + dly->ImportAddressTableRVA);
            PIMAGE_THUNK_DATA32 intb = dly->ImportNameTableRVA ? (PIMAGE_THUNK_DATA32)(base + dly->ImportNameTableRVA) : NULL;
#endif

            while (iat && iat->u1.Function) {
                ULONG_PTR cur = (ULONG_PTR)iat->u1.Function;
                BOOL match = FALSE;

                if (intb && intb->u1.AddressOfData && !IMAGE_SNAP_BY_ORDINAL(intb->u1.Ordinal)) {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(base + intb->u1.AddressOfData);
                    if (_stricmp((char*)ibn->Name, hook->ProcedureName) == 0) {
                        if ((realProc && cur == (ULONG_PTR)realProc) || (exportAddr && cur == exportAddr)) {
                            match = TRUE;
                        }
                    }
                }
                else {
                    if ((realProc && cur == (ULONG_PTR)realProc) || (exportAddr && cur == exportAddr)) {
                        match = TRUE;
                    }
                }

                if (match) {
                    if (!XATHook_ReservePatches(hook, hook->IatPatchCount + 1)) {
                        return;
                    }

                    ULONG_PTR* slot = (ULONG_PTR*)&iat->u1.Function;

                    DWORD old;
                    VirtualProtect(slot, sizeof(ULONG_PTR), PAGE_READWRITE, &old);
                    hook->IatPatches[hook->IatPatchCount].IatSlot = slot;
                    hook->IatPatches[hook->IatPatchCount].Original = *slot;
                    hook->IatPatchCount++;
#if defined(_WIN64)
                    *slot = (ULONG_PTR)hook->HookFunction;
#else
                    * slot = (DWORD)(ULONG_PTR)hook->HookFunction;
#endif
                    VirtualProtect(slot, sizeof(ULONG_PTR), old, &old);
                    hook->state.isIatHooked = TRUE;
                }

                iat++;
                if (intb) intb++;
            }
            dly++;
        }
    }
}

__declspec(noinline) BOOL XATHook_Enable(XATHook* hook) {
    if (hook->state.isEatHooked == TRUE || hook->state.isIatHooked == TRUE) {
        return FALSE;
    }

    hook->IatPatchCount = 0;
    hook->state.isIatHooked = FALSE;
    hook->state.isEatHooked = FALSE;

    HANDLE hProc = GetCurrentProcess();

    FARPROC realProc = GetProcAddress((HMODULE)hook->modImage.ImageBase, hook->ProcedureName);
    ULONG_PTR exportAddr = 0;
    if (hook->modImage.ImageBase && hook->OriginalRva) {
        exportAddr = (ULONG_PTR)hook->modImage.ImageBase + (ULONG_PTR)hook->OriginalRva;
    }

    HMODULE mods[1024];
    DWORD cbNeeded = 0;

    if (!EnumProcessModules(hProc, mods, sizeof(mods), &cbNeeded)) {
        return FALSE;
    }

    for (DWORD mi = 0; mi < cbNeeded / sizeof(HMODULE); mi++) {
        MODULEINFO info;
        if (!GetModuleInformation(hProc, mods[mi], &info, sizeof(info))) {
            continue;
        }

        DWORD_PTR base = (DWORD_PTR)info.lpBaseOfDll;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            continue;
        }

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            continue;
        }

        DWORD importVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (!importVA) {
            continue;
        }

        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + importVA);

        while (imp->Name) {
            LPCSTR dllName = (LPCSTR)(base + imp->Name);

            if (GetModuleHandleA(dllName) != (HMODULE)hook->modImage.ImageBase) {
                imp++;
                continue;
            }

#if defined(_WIN64)
            PIMAGE_THUNK_DATA64 iat = (PIMAGE_THUNK_DATA64)(base + imp->FirstThunk);
            PIMAGE_THUNK_DATA64 intb = imp->OriginalFirstThunk ? (PIMAGE_THUNK_DATA64)(base + imp->OriginalFirstThunk) : NULL;
#else
            PIMAGE_THUNK_DATA32 iat = (PIMAGE_THUNK_DATA32)(base + imp->FirstThunk);
            PIMAGE_THUNK_DATA32 intb = imp->OriginalFirstThunk ? (PIMAGE_THUNK_DATA32)(base + imp->OriginalFirstThunk) : NULL;
#endif

            while (iat && iat->u1.Function) {
                ULONG_PTR cur = (ULONG_PTR)iat->u1.Function;
                BOOL match = FALSE;

                if (intb && intb->u1.AddressOfData && !IMAGE_SNAP_BY_ORDINAL(intb->u1.Ordinal)) {
                    PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(base + intb->u1.AddressOfData);
                    match = (_stricmp((char*)ibn->Name, hook->ProcedureName) == 0);
                }
                else {
                    if (realProc && cur == (ULONG_PTR)realProc) {
                        match = TRUE;
                    }
                    else if (exportAddr && cur == exportAddr) {
                        match = TRUE;
                    }
                }

                if (match) {
                    if (!XATHook_ReservePatches(hook, hook->IatPatchCount + 1)) {
                        break;
                    }

                    ULONG_PTR* slot = (ULONG_PTR*)&iat->u1.Function;

                    DWORD old;
                    VirtualProtect(slot, sizeof(ULONG_PTR), PAGE_READWRITE, &old);
                    hook->IatPatches[hook->IatPatchCount].IatSlot = slot;
                    hook->IatPatches[hook->IatPatchCount].Original = *slot;
                    hook->IatPatchCount++;
#if defined(_WIN64)
                    *slot = (ULONG_PTR)hook->HookFunction;
#else
                    * slot = (DWORD)(ULONG_PTR)hook->HookFunction;
#endif
                    VirtualProtect(slot, sizeof(ULONG_PTR), old, &old);
                    hook->state.isIatHooked = TRUE;
                }

                iat++;
                if (intb) intb++;
            }
            imp++;
        }
    }

    XATHook_EnableDelayIAT(hook);

#if defined(_M_ARM64)
    // ARM64: ldr x16, #8 ; br x16 ; <uint64_t target>
    BYTE jmpBytes[16] = {
        0x50, 0x00, 0x00, 0x58,   // 58000050 : ldr x16, #8
        0x00, 0x02, 0x1F, 0xD6,   // D61F0200 : br  x16
        0xFF, 0xFF, 0xFF, 0xFF,   // target address placeholder (low 32)
        0xFF, 0xFF, 0xFF, 0xFF    // target address placeholder (high 32)
    };
#elif defined(_WIN64)
    BYTE jmpBytes[12] = { 0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0xFF, 0xE0 }; // x64: mov rax, imm64 ; jmp rax
#else
    BYTE jmpBytes[7] = { 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xE0 }; // x86: mov eax, imm32 ; jmp eax
#endif

    ParsedPEImage* pe = &hook->modImage;
    if (pe->ImageBase && pe->ExportDirectory) {
        DWORD_PTR base = (DWORD_PTR)pe->ImageBase;
        PIMAGE_EXPORT_DIRECTORY exp = pe->ExportDirectory;

        DWORD exportDirRva = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD exportDirSize = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (exp->AddressOfFunctions && exp->AddressOfNames && exp->AddressOfNameOrdinals) {
            PDWORD funcs = (PDWORD)(base + exp->AddressOfFunctions);
            PDWORD names = (PDWORD)(base + exp->AddressOfNames);
            PWORD  ords = (PWORD)(base + exp->AddressOfNameOrdinals);

            for (DWORD i = 0; i < exp->NumberOfNames; i++) {
                LPCSTR name = (LPCSTR)(base + names[i]);
                if (_stricmp(name, hook->ProcedureName) != 0) {
                    continue;
                }

                WORD ord = ords[i];
                DWORD rva = funcs[ord];

                if (exportDirRva && exportDirSize &&
                    rva >= exportDirRva && rva < exportDirRva + exportDirSize) {
                    break;
                }

                hook->OriginalRva = rva;

#if defined(_M_ARM64)
                memcpy(jmpBytes + 8, &hook->HookFunction, sizeof(UINT64));
#elif defined(_WIN64)
                memcpy(jmpBytes + 2, &hook->HookFunction, sizeof(UINT64));
#else
                DWORD tgt = (DWORD)(ULONG_PTR)hook->HookFunction;
                memcpy(jmpBytes + 1, &tgt, sizeof(DWORD));
#endif

                PVOID tramp = AllocateJmpNearModule(pe->ImageBase, sizeof(jmpBytes));
                if (!tramp) {
                    break;
                }

                memcpy(tramp, jmpBytes, sizeof(jmpBytes));
                FlushInstructionCache(hProc, tramp, sizeof(jmpBytes));

                hook->Trampoline = tramp;

                DWORD newRva = (DWORD)((DWORD_PTR)tramp - base);

                DWORD old;
                VirtualProtect(&funcs[ord], sizeof(DWORD), PAGE_READWRITE, &old);
                funcs[ord] = newRva;
                VirtualProtect(&funcs[ord], sizeof(DWORD), old, &old);

                hook->state.isEatHooked = TRUE;
                break;
            }
        }
    }

    return (hook->state.isIatHooked || hook->state.isEatHooked);
}

__forceinline void XATHook_RestoreRecordedIAT(XATHook* hook) {
    for (DWORD i = 0; i < hook->IatPatchCount; i++) {
        ULONG_PTR* slot = hook->IatPatches[i].IatSlot;
        if (!slot) {
            continue;
        }

        DWORD old;
        VirtualProtect(slot, sizeof(ULONG_PTR), PAGE_READWRITE, &old);
#if defined(_WIN64)
        *slot = hook->IatPatches[i].Original;
#else
        * slot = (DWORD)hook->IatPatches[i].Original;
#endif
        VirtualProtect(slot, sizeof(ULONG_PTR), old, &old);
    }

    XATHook_FreePatches(hook);
    hook->state.isIatHooked = FALSE;
}

__declspec(noinline) void XATHook_SweepRestoreAllDelayIAT(XATHook* hook) {
    HANDLE hProc = GetCurrentProcess();

    FARPROC realProc = GetProcAddress((HMODULE)hook->modImage.ImageBase, hook->ProcedureName);
    if (!realProc) {
        return;
    }

    HMODULE hMods[2048];
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        return;
    }

    for (DWORD mi = 0; mi < cbNeeded / sizeof(HMODULE); mi++) {
        MODULEINFO info;
        if (!GetModuleInformation(hProc, hMods[mi], &info, sizeof(info))) {
            continue;
        }

        DWORD_PTR base = (DWORD_PTR)info.lpBaseOfDll;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            continue;
        }

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            continue;
        }

        DWORD dlyVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
        if (!dlyVA) {
            continue;
        }

        PIMAGE_DELAYLOAD_DESCRIPTOR dly = (PIMAGE_DELAYLOAD_DESCRIPTOR)(base + dlyVA);

        while (dly->DllNameRVA) {
#if defined(_WIN64)
            PIMAGE_THUNK_DATA64 iat = (PIMAGE_THUNK_DATA64)(base + dly->ImportAddressTableRVA);
            PIMAGE_THUNK_DATA64 intb = dly->ImportNameTableRVA ? (PIMAGE_THUNK_DATA64)(base + dly->ImportNameTableRVA) : NULL;
#else
            PIMAGE_THUNK_DATA32 iat = (PIMAGE_THUNK_DATA32)(base + dly->ImportAddressTableRVA);
            PIMAGE_THUNK_DATA32 intb = dly->ImportNameTableRVA ? (PIMAGE_THUNK_DATA32)(base + dly->ImportNameTableRVA) : NULL;
#endif

            while (iat && iat->u1.Function) {
                ULONG_PTR cur = (ULONG_PTR)iat->u1.Function;

                if (cur == (ULONG_PTR)hook->HookFunction || (hook->Trampoline && cur == (ULONG_PTR)hook->Trampoline)) {
                    BOOL nameMatch = TRUE;

                    if (intb && intb->u1.AddressOfData && !IMAGE_SNAP_BY_ORDINAL(intb->u1.Ordinal)) {
                        PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(base + intb->u1.AddressOfData);
                        nameMatch = (_stricmp((char*)ibn->Name, hook->ProcedureName) == 0);
                    }

                    if (nameMatch) {
                        ULONG_PTR* slot = (ULONG_PTR*)&iat->u1.Function;

                        DWORD old;
                        VirtualProtect(slot, sizeof(ULONG_PTR), PAGE_READWRITE, &old);
#if defined(_WIN64)
                        *slot = (ULONG_PTR)realProc;
#else
                        * slot = (DWORD)(ULONG_PTR)realProc;
#endif
                        VirtualProtect(slot, sizeof(ULONG_PTR), old, &old);
                    }
                }

                iat++;
                if (intb) intb++;
            }
            dly++;
        }
    }
}

__declspec(noinline) void XATHook_SweepRestoreAllIAT(XATHook* hook) {
    HANDLE hProc = GetCurrentProcess();

    FARPROC realProc = GetProcAddress((HMODULE)hook->modImage.ImageBase, hook->ProcedureName);
    if (!realProc) {
        return;
    }

    HMODULE hMods[2048];
    DWORD cbNeeded = 0;

    if (!EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
        return;
    }

    for (DWORD mi = 0; mi < cbNeeded / sizeof(HMODULE); mi++) {
        MODULEINFO info;
        if (!GetModuleInformation(hProc, hMods[mi], &info, sizeof(info))) {
            continue;
        }

        DWORD_PTR base = (DWORD_PTR)info.lpBaseOfDll;

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            continue;
        }

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            continue;
        }

        DWORD impVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (!impVA) {
            continue;
        }

        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + impVA);

        while (imp->Name) {
            LPCSTR dllName = (LPCSTR)(base + imp->Name);
            if (GetModuleHandleA(dllName) != (HMODULE)hook->modImage.ImageBase) {
                imp++;
                continue;
            }

#if defined(_WIN64)
            PIMAGE_THUNK_DATA64 iat = (PIMAGE_THUNK_DATA64)(base + imp->FirstThunk);
            PIMAGE_THUNK_DATA64 intab = imp->OriginalFirstThunk ? (PIMAGE_THUNK_DATA64)(base + imp->OriginalFirstThunk) : NULL;
#else
            PIMAGE_THUNK_DATA32 iat = (PIMAGE_THUNK_DATA32)(base + imp->FirstThunk);
            PIMAGE_THUNK_DATA32 intab = imp->OriginalFirstThunk ? (PIMAGE_THUNK_DATA32)(base + imp->OriginalFirstThunk) : NULL;
#endif

            while (iat && iat->u1.Function) {
                ULONG_PTR cur = (ULONG_PTR)iat->u1.Function;

                if (cur == (ULONG_PTR)hook->HookFunction || (hook->Trampoline && cur == (ULONG_PTR)hook->Trampoline)) {

                    BOOL match = TRUE;

                    if (intab && intab->u1.AddressOfData && !IMAGE_SNAP_BY_ORDINAL(intab->u1.Ordinal)) {
                        PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(base + intab->u1.AddressOfData);
                        match = (_stricmp((char*)ibn->Name, hook->ProcedureName) == 0);
                    }

                    if (match) {
                        ULONG_PTR* slot = (ULONG_PTR*)&iat->u1.Function;

                        DWORD old;
                        VirtualProtect(slot, sizeof(ULONG_PTR), PAGE_READWRITE, &old);
#if defined(_WIN64)
                        *slot = (ULONG_PTR)realProc;
#else
                        * slot = (DWORD)(ULONG_PTR)realProc;
#endif
                        VirtualProtect(slot, sizeof(ULONG_PTR), old, &old);
                    }
                }

                iat++;
                if (intab) intab++;
            }
            imp++;
        }
    }
}

__declspec(noinline) void XATHook_RestoreEAT(XATHook* hook)
{
    if (hook->state.isEatHooked && hook->OriginalRva) {
        DWORD_PTR base = (DWORD_PTR)hook->modImage.ImageBase;
        PIMAGE_EXPORT_DIRECTORY exp = hook->modImage.ExportDirectory;

        if (!base || !exp || !exp->AddressOfFunctions || !exp->AddressOfNames || !exp->AddressOfNameOrdinals) {
            hook->state.isEatHooked = FALSE;
            return;
        }

        PDWORD funcs = (PDWORD)(base + exp->AddressOfFunctions);
        PDWORD names = (PDWORD)(base + exp->AddressOfNames);
        PWORD ords = (PWORD)(base + exp->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exp->NumberOfNames; i++) {
            LPCSTR name = (LPCSTR)(base + names[i]);
            if (_stricmp(name, hook->ProcedureName) == 0) {
                WORD ordIndex = ords[i];
                if (ordIndex >= exp->NumberOfFunctions) {
                    break;
                }

                DWORD oldProtect;
                VirtualProtect(&funcs[ordIndex], sizeof(DWORD), PAGE_READWRITE, &oldProtect);
                funcs[ordIndex] = hook->OriginalRva;
                VirtualProtect(&funcs[ordIndex], sizeof(DWORD), oldProtect, &oldProtect);
                break;
            }
        }

        hook->state.isEatHooked = FALSE;
    }
}

__declspec(noinline) BOOL XATHook_Disable(XATHook* hook) {
    if (hook->state.isEatHooked == FALSE && hook->state.isIatHooked == FALSE) {
        return FALSE;
    }

    XATHook_RestoreRecordedIAT(hook);
    XATHook_RestoreEAT(hook);
    XATHook_SweepRestoreAllIAT(hook);
    XATHook_SweepRestoreAllDelayIAT(hook);

    if (hook->Trampoline) {
        VirtualFree(hook->Trampoline, 0, MEM_RELEASE);
        hook->Trampoline = NULL;
    }

    return TRUE;
}