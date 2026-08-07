
#include "host/providers/static_export_provider.h"
#include "host/providers/ntoskrnl_provider.h"
#include "host/providers/provider.h"
#include "core/loader/environment.h"
#include "core/exec/unicorn_engine.h"
#include "core/memory/unicorn_memory.h"
#include <Logger/Logger.h>

namespace ntoskrnl_export {
    void Initialize() { InitializeExport(); }

    void InitializeObjectType() {
        uint64_t ProcessTypeUcAddr = UnicornMem::AllocateVariable(
            UnicornEmu::PrimaryEngine, sizeof(_OBJECT_TYPE) * 2, "NTOSKRNL.PsProcessType");
        auto ProcessTypeHost = (_OBJECT_TYPE*)UnicornMem::UcToHost(ProcessTypeUcAddr);
        ProcessTypeHost->TotalNumberOfObjects = 1;
        PsProcessType = (_OBJECT_TYPE*)ProcessTypeUcAddr;

        uint64_t ThreadTypeUcAddr = UnicornMem::AllocateVariable(
            UnicornEmu::PrimaryEngine, sizeof(_OBJECT_TYPE) * 2, "NTOSKRNL.PsThreadType");
        auto ThreadTypeHost = (_OBJECT_TYPE*)UnicornMem::UcToHost(ThreadTypeUcAddr);
        ThreadTypeHost->TotalNumberOfObjects = 1;
        PsThreadType = (_OBJECT_TYPE*)ThreadTypeUcAddr;

        uint64_t FileTypeUcAddr = UnicornMem::AllocateVariable(
            UnicornEmu::PrimaryEngine, sizeof(_OBJECT_TYPE) * 2, "NTOSKRNL.IoFileObjectType");
        auto FileTypeHost = (_OBJECT_TYPE*)UnicornMem::UcToHost(FileTypeUcAddr);
        FileTypeHost->TotalNumberOfObjects = 1;
        IoFileObjectType = FileTypeUcAddr;

        uint64_t DriverTypeUcAddr = UnicornMem::AllocateVariable(
            UnicornEmu::PrimaryEngine, sizeof(_OBJECT_TYPE) * 2, "NTOSKRNL.IoDriverObjectType");
        auto DriverTypeHost = (_OBJECT_TYPE*)UnicornMem::UcToHost(DriverTypeUcAddr);
        DriverTypeHost->TotalNumberOfObjects = 1;
        IoDriverObjectType = DriverTypeUcAddr;

        uint64_t DeviceTypeUcAddr = UnicornMem::AllocateVariable(
            UnicornEmu::PrimaryEngine, sizeof(_OBJECT_TYPE) * 2, "NTOSKRNL.IoDeviceObjectType");
        auto DeviceTypeHost = (_OBJECT_TYPE*)UnicornMem::UcToHost(DeviceTypeUcAddr);
        DeviceTypeHost->TotalNumberOfObjects = 1;
        IoDeviceObjectType = DeviceTypeUcAddr;
    }

    void InitializePsLoadedModuleList() {
        PsLoadedModuleList = Environment::PsLoadedModuleList;
    }

    void InitializeRuntimeValues() {
        auto Kusd = (uint8_t*)0x7FFE0000;

        uint32_t BuildNumber = *(uint32_t*)(Kusd + 0x260);
        NtBuildNumber = (uint32_t)(0xF0000000UL | BuildNumber);

        MmSystemRangeStart = 0xFFFF800000000000ULL;
        MmUserProbeAddress = 0x7FFFFFFEFFFFULL;
        MmHighestUserAddress = 0x7FFFFFFEFFFFULL;

        SYSTEM_INFO Si;
        GetNativeSystemInfo(&Si);
        KeNumberProcessors = (uint8_t)Si.dwNumberOfProcessors;
        if (KeNumberProcessors < 4) KeNumberProcessors = 4;

        NlsAnsiCodePage = (uint16_t)GetACP();
        NlsOemCodePage = (uint16_t)GetOEMCP();
        NlsMbCodePageTag = (NlsAnsiCodePage == 932 || NlsAnsiCodePage == 936 ||
                            NlsAnsiCodePage == 949 || NlsAnsiCodePage == 950 ||
                            NlsAnsiCodePage == 1361) ? 1 : 0;
        NlsMbOemCodePageTag = (NlsOemCodePage == 932 || NlsOemCodePage == 936 ||
                               NlsOemCodePage == 949 || NlsOemCodePage == 950 ||
                               NlsOemCodePage == 1361) ? 1 : 0;

        Mm64BitPhysicalAddress = 1;
        PsInitialSystemProcess = (uint64_t)EPROCESS_BASE_UC;

        Logger::Log("{CYN}RuntimeValues: NtBuildNumber=0x%x (%u) Processors=%u ACP=%u OEM=%u{RESET}\n",
            NtBuildNumber, BuildNumber, (uint32_t)KeNumberProcessors, (uint32_t)NlsAnsiCodePage, (uint32_t)NlsOemCodePage);
        Logger::Log("{CYN}RuntimeValues: MmSystemRangeStart=0x%llx MmUserProbeAddress=0x%llx MmHighestUserAddress=0x%llx{RESET}\n",
            MmSystemRangeStart, MmUserProbeAddress, MmHighestUserAddress);
    }

    void InitializeSystemTime() {

    }

    void InitializeExport() {
        InitializeRuntimeValues();
        ntoskrnl_export::InitializeObjectType();
        ntoskrnl_export::InitializePsLoadedModuleList();

        Provider::AddDataImpl("SeExports", (PVOID)SeExport, sizeof(SeExport));
        Provider::AddDataImpl("KdDebuggerNotPresent", &KdDebuggerNotPresent, sizeof(KdDebuggerNotPresent));
        Provider::AddDataImpl("KiBugCheckData", &KiBugCheckData, sizeof(KiBugCheckData));
        Provider::AddDataImpl("KdDebuggerEnabled", &KdDebuggerEnabled, sizeof(KdDebuggerEnabled));
        Provider::AddDataImpl("KdEnteredDebugger", &KdEnteredDebugger, sizeof(KdEnteredDebugger));
        Provider::AddDataImpl("PsInitialSystemProcess", &PsInitialSystemProcess, sizeof(PsInitialSystemProcess));
        Provider::AddDataImpl("PsLoadedModuleList", &PsLoadedModuleList, sizeof(PsLoadedModuleList));
        Provider::AddDataImpl("PsProcessType", &PsProcessType, sizeof(PsProcessType));
        Provider::AddDataImpl("PsThreadType", &PsThreadType, sizeof(PsThreadType));
        Provider::AddDataImpl("InitSafeBootMode", &InitSafeBootMode, sizeof(InitSafeBootMode));
        Provider::AddDataImpl("MmSystemRangeStart", &MmSystemRangeStart, sizeof(MmSystemRangeStart));
        Provider::AddDataImpl("MmUserProbeAddress", &MmUserProbeAddress, sizeof(MmUserProbeAddress));
        Provider::AddDataImpl("MmHighestUserAddress", &MmHighestUserAddress, sizeof(MmHighestUserAddress));
        Provider::AddDataImpl("NtBuildNumber", &NtBuildNumber, sizeof(NtBuildNumber));
        Provider::AddDataImpl("KeNumberProcessors", &KeNumberProcessors, sizeof(KeNumberProcessors));
        Provider::AddDataImpl("NtGlobalFlag", &NtGlobalFlag, sizeof(NtGlobalFlag));
        Provider::AddDataImpl("IoDriverObjectType", &IoDriverObjectType, sizeof(IoDriverObjectType));
        Provider::AddDataImpl("IoDeviceObjectType", &IoDeviceObjectType, sizeof(IoDeviceObjectType));
        Provider::AddDataImpl("IoFileObjectType", &IoFileObjectType, sizeof(IoFileObjectType));
        Provider::AddDataImpl("PsLoadedModuleResource", &PsLoadedModuleResource, sizeof(PsLoadedModuleResource));
        Provider::AddDataImpl("PsJobType", &PsJobType, sizeof(PsJobType));
        Provider::AddDataImpl("SeTokenObjectType", &SeTokenObjectType, sizeof(SeTokenObjectType));
        Provider::AddDataImpl("CmKeyObjectType", &CmKeyObjectType, sizeof(CmKeyObjectType));
        Provider::AddDataImpl("Mm64BitPhysicalAddress", &Mm64BitPhysicalAddress, sizeof(Mm64BitPhysicalAddress));
        Provider::AddDataImpl("NlsAnsiCodePage", &NlsAnsiCodePage, sizeof(NlsAnsiCodePage));
        Provider::AddDataImpl("NlsOemCodePage", &NlsOemCodePage, sizeof(NlsOemCodePage));
        Provider::AddDataImpl("NlsMbCodePageTag", &NlsMbCodePageTag, sizeof(NlsMbCodePageTag));
        Provider::AddDataImpl("NlsMbOemCodePageTag", &NlsMbOemCodePageTag, sizeof(NlsMbOemCodePageTag));
        Provider::AddDataImpl("__security_cookie", &__security_cookie_val, sizeof(__security_cookie_val));
    }
} // namespace ntoskrnl_export
