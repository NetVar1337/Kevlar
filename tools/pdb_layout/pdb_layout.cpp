// pdb_layout: dump field offsets + sizes for named kernel structs from a PDB
// using the DIA SDK, emitting a C header of GEN_<STRUCT>_<FIELD> defines.
//
// This is the generator for the roadmap item "Generate Windows-build-specific
// kernel structure layouts from PDBs": the harness hardcodes Win10 21H2
// layouts in ntoskrnl_struct.h; this tool emits the layouts of the *actual*
// target ntoskrnl PDB so they can be diffed/replaced.
//
// Usage: pdb_layout <input.pdb> [struct1,struct2,...] [output.h]
//   Struct list default covers the harness's hardcoded kernel structures.
//   Build: tools\pdb_layout.ps1
//
// ponytail: layout-only (offsets + sizes), no vtable/anonymous-union naming
// heuristics beyond a placeholder. Upgrade: name anonymous unions when a
// driver reads into them.
#include <windows.h>
#include <dia2.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <string>
#include <vector>

namespace {

struct UdtSpec {
    std::wstring Name;
};

// Pick the largest UDT with this name (skips fwd-decl/partial records).
bool FindUdt(IDiaSession* Session, IDiaSymbol* Global, const std::wstring& Name, IDiaSymbol** Out) {
    *Out = nullptr;
    IDiaEnumSymbols* Enum = nullptr;
    if (Session->findChildren(Global, SymTagUDT, Name.c_str(), nsCaseSensitive | nsfUndecoratedName, &Enum) != S_OK)
        return false;

    IDiaSymbol* Best = nullptr;
    ULONGLONG BestLen = 0;
    IDiaSymbol* Sym = nullptr;
    ULONG C = 0;
    while (Enum->Next(1, &Sym, &C) == S_OK && C == 1) {
        ULONGLONG Len = 0;
        Sym->get_length(&Len);
        if (Len >= BestLen) {
            if (Best) Best->Release();
            Best = Sym;
            BestLen = Len;
        } else {
            Sym->Release();
        }
    }
    Enum->Release();
    *Out = Best;
    return Best != nullptr;
}

void FieldNameToNarrow(BSTR Wide, int Index, char* Out, size_t OutSize) {
    if (Wide && *Wide) {
        WideCharToMultiByte(CP_UTF8, 0, Wide, -1, Out, (int)OutSize, nullptr, nullptr);
    } else {
        snprintf(Out, OutSize, "anon%d", Index);
    }
    for (char* p = Out; *p; ++p) {  // header-safe names
        if (!(isalnum((unsigned char)*p) || *p == '_')) *p = '_';
    }
}

void DumpUdt(IDiaSymbol* Udt, const std::wstring& StructName, FILE* Out) {
    ULONGLONG Size = 0;
    Udt->get_length(&Size);
    fprintf(Out, "#define GEN_%ls_StructSize 0x%llx\n", StructName.c_str(), (unsigned long long)Size);

    IDiaEnumSymbols* Ch = nullptr;
    if (Udt->findChildren(SymTagNull, nullptr, 0 /*nsfNone*/, &Ch) != S_OK)
        return;

    IDiaSymbol* C = nullptr;
    ULONG N = 0;
    int Index = 0;
    while (Ch->Next(1, &C, &N) == S_OK && N == 1) {
        DWORD Tag = 0;
        C->get_symTag(&Tag);
        if (Tag == SymTagData) {
            DWORD Loc = 0;
            C->get_locationType(&Loc);
            if (Loc == LocIsThisRel) {
                LONG Off = 0;
                C->get_offset(&Off);
                BSTR Name = nullptr;
                C->get_name(&Name);
                char Narrow[256] = {};
                FieldNameToNarrow(Name, Index, Narrow, sizeof(Narrow));
                fprintf(Out, "#define GEN_%ls_%s 0x%x\n", StructName.c_str(), Narrow, Off);
                SysFreeString(Name);
                Index++;
            }
        }
        C->Release();
    }
    Ch->Release();
}

const wchar_t* kDefaultStructs[] = {
    L"_DRIVER_OBJECT", L"_DRIVER_EXTENSION", L"_DEVICE_OBJECT",
    L"_ETHREAD", L"_KTHREAD", L"_EPROCESS", L"_KPROCESS",
    L"_KPCR", L"_KPRCB", L"_KUSER_SHARED_DATA",
    L"_KLDR_DATA_TABLE_ENTRY", L"_UNICODE_STRING", L"_KEVENT", L"_KDPC", L"_KTIMER",
};

} // namespace

// msdia140.dll may not be COM-registered (requires admin regsvr32). Load it
// directly and drive it through DllGetClassObject so no registration is needed.
HRESULT CreateDiaSource(IDiaDataSource** Out) {
    *Out = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IDiaDataSource, (void**)Out);
    if (SUCCEEDED(hr) && *Out)
        return S_OK;

    HMODULE Dia = LoadLibraryW(L"msdia140.dll");
    if (!Dia) {
        if (const wchar_t* SdkBin = _wgetenv(L"DIA_SDK_BIN")) {
            std::wstring P(SdkBin);
            P += L"\\msdia140.dll";
            Dia = LoadLibraryW(P.c_str());
        }
    }
    if (!Dia) {
        static const wchar_t* kDefaultPaths[] = {
            L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\DIA SDK\\bin\\amd64\\msdia140.dll",
            L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\Community\\DIA SDK\\bin\\amd64\\msdia140.dll",
            L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\Professional\\DIA SDK\\bin\\amd64\\msdia140.dll",
            L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\DIA SDK\\bin\\amd64\\msdia140.dll",
        };
        for (auto* P : kDefaultPaths) {
            Dia = LoadLibraryW(P);
            if (Dia) break;
        }
    }
    if (!Dia) {
        fwprintf(stderr, L"msdia140.dll not found (set DIA_SDK_BIN or install the DIA SDK)\n");
        return E_FAIL;
    }

    typedef HRESULT(WINAPI* DllGetClassObjectFn)(REFCLSID, REFIID, void**);
    auto DllGetClassObjectFnPtr = (DllGetClassObjectFn)GetProcAddress(Dia, "DllGetClassObject");
    if (!DllGetClassObjectFnPtr) {
        fwprintf(stderr, L"DllGetClassObject not exported by msdia140.dll\n");
        return E_FAIL;
    }

    IClassFactory* Factory = nullptr;
    hr = DllGetClassObjectFnPtr(CLSID_DiaSource, IID_IClassFactory, (void**)&Factory);
    if (FAILED(hr) || !Factory) {
        fwprintf(stderr, L"DllGetClassObject(CLSID_DiaSource) failed: 0x%08x\n", hr);
        return E_FAIL;
    }
    hr = Factory->CreateInstance(nullptr, IID_IDiaDataSource, (void**)Out);
    Factory->Release();
    if (FAILED(hr)) {
        fwprintf(stderr, L"CreateInstance(IDiaDataSource) failed: 0x%08x\n", hr);
        return hr;
    }
    return S_OK;
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        fwprintf(stderr, L"usage: pdb_layout <input.pdb> [output.h] [struct,struct,...]\n");
        return 1;
    }
    const wchar_t* PdbPath = argv[1];

    std::wstring OutPath = (argc >= 3) ? argv[2] : L"generated\\kernel_layout.h";

    std::vector<std::wstring> Structs;
    if (argc >= 4) {
        std::wstring List(argv[3]);
        size_t Start = 0;
        while (true) {
            size_t Comma = List.find(L',', Start);
            Structs.push_back(List.substr(Start, Comma == std::wstring::npos ? std::wstring::npos : Comma - Start));
            if (Comma == std::wstring::npos) break;
            Start = Comma + 1;
        }
    } else {
        for (auto* S : kDefaultStructs) Structs.push_back(S);
    }

    if (FAILED(CoInitialize(nullptr))) {
        fwprintf(stderr, L"CoInitialize failed\n");
        return 1;
    }

    IDiaDataSource* Source = nullptr;
    HRESULT hr = CreateDiaSource(&Source);
    if (FAILED(hr) || !Source) {
        fwprintf(stderr, L"DIA source creation failed\n");
        return 1;
    }
    hr = Source->loadDataFromPdb(PdbPath);
    if (FAILED(hr)) {
        fwprintf(stderr, L"loadDataFromPdb failed for %s: 0x%08x\n", PdbPath, hr);
        Source->Release();
        return 1;
    }

    IDiaSession* Session = nullptr;
    if (FAILED(Source->openSession(&Session))) {
        fwprintf(stderr, L"openSession failed\n");
        Source->Release();
        return 1;
    }
    IDiaSymbol* Global = nullptr;
    Session->get_globalScope(&Global);

    FILE* Out = nullptr;
    if (_wfopen_s(&Out, OutPath.c_str(), L"wb") != 0 || !Out) {
        fwprintf(stderr, L"cannot write %s\n", OutPath.c_str());
        return 1;
    }
    fprintf(Out, "// Generated by tools\\pdb_layout from %ls\n", PdbPath);
    fprintf(Out, "// Field offsets/sizes for the named kernel structs. Regenerate with\n");
    fprintf(Out, "// tools\\pdb_layout.ps1 after refreshing the target ntoskrnl PDB.\n");
    fprintf(Out, "#pragma once\n\n");

    for (auto& S : Structs) {
        IDiaSymbol* Udt = nullptr;
        if (FindUdt(Session, Global, S, &Udt) && Udt) {
            DumpUdt(Udt, S, Out);
            fprintf(Out, "\n");
            fwprintf(stdout, L"ok   %ls\n", S.c_str());
            Udt->Release();
        } else {
            fprintf(Out, "// GEN_%ls not found in PDB\n\n", S.c_str());
            fwprintf(stdout, L"MISS %ls\n", S.c_str());
        }
    }

    fclose(Out);
    Global->Release();
    Session->Release();
    Source->Release();
    CoUninitialize();
    return 0;
}
