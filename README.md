# eXtended-Address-Table-Hooking

## Introduction

**XAT** is a lightweight, architecture-aware hooking library focused on **Address Table manipulation**, providing reliable interception of API calls via:

- **IAT (Import Address Table)** patching
- **Delay-IAT** patching (delay-load imports)
- **EAT (Export Address Table)** patching (when safe)

Unlike inline hooks or trampoline-based detours, XAT operates at the **linker/loader boundary**. It redirects calls by changing resolver outputs and table entries rather than patching function prologues, making it well-suited for early-stage instrumentation, loader-time hooks, and environments where code integrity, CFG, or instruction integrity checks make inline patching undesirable.

---

## Features

- **Address table hooking coverage**
  - Normal **IAT** patching (already-resolved imports)
  - **Delay-IAT** patching (delay-load imports)
  - **EAT** patching (export RVA redirection via trampoline)
- **Cross-architecture support**
  - x86 (32-bit)
  - x64 (AMD64)
  - ARM64 (AArch64, Windows)
- **No inline patching**
  - No overwritten prologues
  - No instruction decoding
  - No detour trampolines (in the inline-hook sense)
- **Loader-aware**
  - Works with delay-loaded imports
  - Compatible with manually mapped PE images (assuming imports/exports are present and mapped normally)
- **Low footprint**
  - Minimal executable stubs
  - No VEH or debug-register-based interception
  - Deterministic unhooking via recorded patch list + sweeps

---

## Design Philosophy

XAT is built on the premise that **address tables are one of the cleanest interception points when it comes to code integrity checks** in the Windows execution model. By modifying resolver outputs rather than execution flow, XAT avoids many of the detectability issues associated with traditional inline patching techniques.

The “eXtended” in **XAT** reflects:
- Support for **multiple table types** (IAT + Delay-IAT + EAT)
- **Multi-architecture jump stubs**
- A design intended to scale to additional resolver-level interception patterns

---

## Architecture Notes

XAT emits an absolute jump stub appropriate to the active architecture:

- **x86**  
  `mov eax, imm32 ; jmp eax`

- **x64**  
  `mov rax, imm64 ; jmp rax`

- **ARM64**  
  `ldr x16, #literal ; br x16`

Stubs are emitted into allocated executable memory and (on ARM64 especially) require instruction-cache coherence; XAT calls `FlushInstructionCache` after writing stubs.

---

## Typical Use Cases

- API interception without inline hooks
- Loader-time instrumentation
- Game, DRM, and anti-cheat research
- Malware analysis and sandboxing
- Red-team tooling and evasive monitoring

---

# How it works

This section explains the **XAT** implementation: how it performs **IAT**, **Delay-IAT**, and **EAT** hooking, how restoration works, and the important caveats, especially around **forwarded exports**.

At a high level, XAT:
1. Initializes a hook record and resolves baseline export metadata.
2. Scans all loaded modules and patches **IAT** entries targeting the chosen module+symbol.
3. Scans all loaded modules and patches **Delay-IAT** entries as well.
4. Patches the target module’s **EAT** entry by replacing the export RVA with an RVA to a nearby trampoline stub.
5. Disables cleanly by restoring recorded **IAT** writes, restoring **EAT**, then sweeping for any remaining pointers.

---

## Core concepts (PE refresher)

### Import Address Table (IAT)
Each importing module has an IAT containing **resolved function addresses**. Overwriting an IAT slot redirects calls for *that module*.

- ✅ Scope: per importing module
- ✅ Fast: one pointer write
- ✅ Stable: no code patching
- ❌ Doesn’t affect code that uses cached pointers or its own resolver logic

### Delay Import Address Table (Delay-IAT)
Delay-load imports are resolved lazily and stored in a delay IAT. Many hookers miss this path.

- ✅ Captures delay-load call sites after they’ve been resolved (and some cases even when name tables are missing)
- ✅ Complements standard IAT patching

### Export Address Table (EAT)
The exporting module’s EAT contains **RVAs** for exported functions. Patching the RVA affects *future* resolutions.

- ✅ Scope: future `GetProcAddress`, future binds, delay-load fixups
- ✅ No inline patching
- ❌ Doesn’t automatically update already-resolved IATs unless you patch those too (**XAT does**)

---

## Data structures

### `ParsedPEImage`
```c
typedef struct {
    PVOID ImageBase;
    PIMAGE_DOS_HEADER Dos;
    PIMAGE_NT_HEADERS NtHeaders;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
    IMAGE_FILE_HEADER FileHeader;
    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
} ParsedPEImage;
```

A convenience wrapper holding:
- module base address and validated headers
- pointers to import/export directories (if present)

### `IatPatch`
```c
typedef struct {
    ULONG_PTR* IatSlot;
    ULONG_PTR Original;
} IatPatch;
```

A recorded IAT write:
- `IatSlot` = the exact slot you overwrote
- `Original` = the old pointer value
---
### `XATHook`
```c
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
```

Tracks:
- dynamic list of IAT/Delay-IAT patches
- target module + procedure
- hook function pointer
- original export RVA (for EAT restore)
- trampoline pointer used for EAT redirection (if enabled)
- state flags for IAT/EAT status

---

## Memory allocation near the module

### `AllocateJmpNearModule`
Purpose: allocate executable memory “near” the exporting module so the trampoline RVA is well-behaved and suitable for EAT redirection.

Key properties of the final implementation:
- Uses system allocation granularity (validated as power-of-two, fallback to 0x10000).
- Computes a search window around the end of the module image.
- Bounded scan (`maxSteps` capped) to avoid infinite loops.
- Tries allocations both upward and downward.

Why “near” matters:
- EAT stores **RVAs**, so your trampoline must be representable as:
  `newRva = tramp - moduleBase`
- “Near” allocation reduces address-space weirdness and improves reliability across processes/layouts.

---

## Parsing PE images safely

### `ParsePeImage`
Final version is defensive:
- validates DOS and NT signatures
- only sets Import/Export pointers if the directory exists
- returns a zeroed `ParsedPEImage` on failure

This prevents “assume directory exists” crashes while scanning arbitrary modules.

---

## Patch bookkeeping

### `XATHook_ReservePatches`
Maintains a growable heap array of `IatPatch`:
- starts at 256
- doubles until enough capacity
- uses `HeapAlloc`/`HeapReAlloc`

### `XATHook_FreePatches`
Frees the list and resets counters.

Why this matters:
- disable is deterministic: “recorded restore” can revert exact writes quickly.
- sweeps remain as a safety net (see below).

---

## Initialization

### `XATHook_Init`
Responsibilities:
1. Ensures the target module is loaded.
2. Initializes the hook record and parses:
   - current process image (`ParsePeImage(NULL)`)
   - target module image (`ParsePeImage(ModuleName)`)
3. Optionally returns the **loader-resolved** export address via:
   - `GetProcAddress(hMod, ProcedureName)`
4. Locates and stores the named export RVA in `hook->OriginalRva` (if found in the name table).

Important behavioral detail:
- `GetProcAddress` may return an address that reflects loader behavior (including forwarded exports).
- `hook->OriginalRva` only describes what is present in the exporting module’s EAT entry for that name.

---

## Enabling hooks

### Overview: `XATHook_Enable`
XAT applies hooks in this order:
1. Patch **IAT** across all loaded modules
2. Patch **Delay-IAT** across all loaded modules
3. Patch **EAT** in the exporting module (only if safe and non-forwarded)

Returns `TRUE` if any of these succeed.

It refuses to run if already enabled (prevents double-patching and duplicate patch records).

---

## How IAT hooking works (normal imports)

### Step 1: Enumerate modules
XAT enumerates all process modules with `EnumProcessModules`, then for each:
- validates DOS/NT headers
- locates Import Directory
- iterates import descriptors

### Step 2: Filter to import descriptors targeting the chosen module
```c
if (GetModuleHandleA(dllName) != (HMODULE)hook->modImage.ImageBase) {
    imp++;
    continue;
}
```

### Step 3: Identify the correct import slot
XAT uses two strategies:

**A) Name-based (preferred)**
If INT/OriginalFirstThunk is present and not ordinal:
- compare `IMAGE_IMPORT_BY_NAME->Name` with `ProcedureName`

**B) Pointer-based fallback**
If name info isn’t available:
- compare the current slot value to either:
  - `realProc = GetProcAddress(targetModule, ProcedureName)`
  - `exportAddr = moduleBase + OriginalRva`

### Step 4: Record and patch
When matched:
- reserve patch capacity
- `VirtualProtect` the slot
- record `{ slot, original }`
- write hook pointer
- restore protection
- set `isIatHooked = TRUE`

---

## Delay-IAT hooking

### `XATHook_EnableDelayIAT`
Delay-load imports are located via `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`.

For each delay import descriptor:
- walk delay IAT and optionally the delay INT
- match by name when possible; else fall back to pointer matching (`realProc` / `exportAddr`)
- record and patch using the same `IatPatch` list

This closes a major coverage gap: many real targets are imported via delay load.

---

## EAT hooking (export redirection)

### Why a trampoline is required
EAT entries are **32-bit RVAs**, not pointers. Even on x64, the EAT stores RVAs.

Therefore XAT:
1. Builds a small, CPU-specific absolute-jump stub.
2. Allocates executable memory and writes the stub there.
3. Stores the trampoline’s RVA into `AddressOfFunctions[ordinal]`.

After writing the trampoline bytes, XAT calls:
```c
FlushInstructionCache(hProc, tramp, sizeof(jmpBytes));
```
This is crucial on ARM64.

### Forwarded export detection (critical)
Before patching EAT, XAT checks whether the function RVA points *inside the export directory range*:
```c
if (exportDirRva && exportDirSize &&
    rva >= exportDirRva && rva < exportDirRva + exportDirSize) {
    break;
}
```
If true, it’s treated as a **forwarded export** and EAT patching is skipped.

This is intentional.

---

## Disabling hooks / restoration

### Overview: `XATHook_Disable`
Disable is multi-phase:

1. **Restore recorded IAT patches**
   - `XATHook_RestoreRecordedIAT` reverts every recorded slot and frees the patch list.
2. **Restore EAT**
   - `XATHook_RestoreEAT` restores the original RVA if EAT was hooked.
3. **Sweep restore (normal + delay)**
   - `XATHook_SweepRestoreAllIAT` and `XATHook_SweepRestoreAllDelayIAT` scan the process and restore any remaining slots still pointing at your hook or trampoline back to `GetProcAddress` truth.
4. **Free trampoline memory**
   - `VirtualFree(hook->Trampoline, 0, MEM_RELEASE)`

Why sweep restore exists even with recorded patches:
- other code could have patched the same slots after you
- you might have missed some entries due to missing metadata, unusual layouts, or name-less matching
- sweep acts as “return process to loader truth” cleanup

---

## Caveats / deep details

### 1) Forwarded exports: why XAT skips them and why “safe hooking” them isn’t really solvable

A forwarded export isn’t code. The EAT entry points to a **forwarder string** inside the export directory, e.g.:
- `"KERNEL32.Sleep"`
- `"NTDLL.RtlSomething"`

The loader resolves it by:
1. reading the string
2. locating/loading the forwarded-to module
3. resolving the forwarded-to export
4. returning the final function address

#### Why you cannot “just hook the forwarded export RVA”
If you overwrite that forwarder RVA with a trampoline RVA:
- you destroy the forwarder semantics and the forwarder string reference
- anything relying on the export being forwarded (including introspection tooling) can break
- you convert a forwarded export into a non-forwarded export, which changes PE semantics and can be detectable

#### Why you can’t “safely hook the forwarder target” in a general way
Even if you parse the forwarder string and try to hook the destination export instead, there are unavoidable problems:

- **No single authoritative target**
  - API-set mapping, redirections, WOW64 behavior, and OS versioning can change what the forwarder resolves to at runtime.
- **Timing and loader dependency**
  - The destination module may not be loaded yet; you’ve turned this into a loader orchestration / race problem.
- **Semantic mismatch**
  - Forwarders exist specifically to preserve ABI while moving implementations. Hooking the destination may affect a broader set of callers than the forwarder contract implies.
- **No “safe EAT patch point”**
  - You can’t patch “the forwarder” as code because it isn’t code. Converting it to code is inherently a semantic mutation.

**Practical conclusion:**
Forwarded exports are best handled by:
- hooking the **resolved addresses** via **IAT/Delay-IAT** (what XAT already does), and/or
- hooking the destination module’s **real** export if and when it’s non-forwarded (as a separate hook instance).

XAT’s policy: skip EAT patching when the export is forwarded, is the correct default.

---

### 2) Pointer-based IAT matching can create false positives
When name tables aren’t available, XAT matches by:
- `cur == realProc` or `cur == exportAddr`

This can match more than intended if:
- multiple imports resolve to the same address
- another hooker already changed the slot to a value equal to your compare target
- the INT is missing and the import is by ordinal or otherwise ambiguous

Mitigations (optional future ideas):
- prefer name-based matching whenever possible
- validate import descriptor identity (module name normalization can help)
- reduce reliance on pointer matching unless necessary

---

### 3) EAT hooking does not update existing caches
EAT patching affects future resolutions, but:
- existing IAT slots won’t change unless you patch them (**XAT does**)
- copied function pointers stored by the program won’t be updated
- custom resolvers may bypass both EAT and IAT

---

### 4) Delay-load complexity
Delay-load machinery varies:
- name table may be missing
- resolution happens lazily
- runtime helpers can rewrite slots

XAT covers both:
- patching delay IAT entries when found
- sweeping restore during disable

---

### 5) Instruction cache coherence (especially ARM64)
After writing trampoline bytes into executable memory, instruction cache must be coherent.

XAT calls:
```c
FlushInstructionCache(hProc, tramp, sizeof(jmpBytes));
```
This is essential on ARM64 and safe elsewhere.

---

## Minimal usage example

```c
XATHook hk;

if (!XATHook_Init(&hk, "user32.dll", "MessageBoxA", MyMessageBoxA, (PVOID*)&OriginalMessageBoxA)) {
    return;
}

if (XATHook_Enable(&hk)) {
    // Hooked via IAT, Delay-IAT, and/or EAT depending on feasibility.
}

// later...
if (XATHook_Disable(&hk)) {
    // ...
}
```

---

## Glossary

- **IAT**: Import Address Table - resolved import pointer slots per module.
- **Delay-IAT**: delay-load import pointer slots (resolved lazily).
- **EAT**: Export Address Table - exporter’s list of RVAs for exported symbols.
- **RVA**: Relative Virtual Address - offset from module base.
- **Forwarded export**: EAT entry that points to a forwarder string inside the export directory.
- **Trampoline**: small executable stub used to reach an absolute hook address while the table stores only RVAs.
