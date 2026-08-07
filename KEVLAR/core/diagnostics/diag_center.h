#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

enum DiagAccessType {
    ACCESS_READ = 0,
    ACCESS_WRITE = 1,
    ACCESS_EXECUTE = 2,
    ACCESS_API = 3,
    ACCESS_EXCEPTION = 4,
    ACCESS_UNKNOWN = 5
};

enum DiagRejectReason {
    REJECT_KUSER_SHARED_DATA = 0,
    REJECT_HYPERVISOR_SHARED_PAGE = 1,
    REJECT_POOL = 2,
    REJECT_STACK = 3,
    REJECT_SENTINEL = 4,
    REJECT_STRING_LIKE = 5,
    REJECT_UNMAPPED = 6,
    REJECT_NON_CANONICAL = 7,
    REJECT_NO_MODULE = 8,
    REJECT_NON_EXEC_SECTION = 9,
    REJECT_UNLIKELY_CODE = 10,
    REJECT_FAR_FROM_MODULES = 11,
    REJECT_SMALL_INT = 12,
    REJECT_OK = 13
};

enum DiagProbeType {
    PROBE_MZ = 0,
    PROBE_E_LFANEW = 1,
    PROBE_PE_SIGNATURE = 2,
    PROBE_SECTION_TABLE = 3,
    PROBE_EXPORT_DIR = 4,
    PROBE_IMPORT_DIR = 5,
    PROBE_RSRC_DIR = 6,
    PROBE_RELOC_DIR = 7,
    PROBE_TLS_DIR = 8,
    PROBE_SIZE_OF_IMAGE = 9,
    PROBE_ADDRESS_OF_ENTRY_POINT = 10,
    PROBE_DOS_HEADER_SCAN = 11,
    PROBE_UNKNOWN = 12
};

enum DiagSourceProv {
    SRC_UNKNOWN = 0,
    SRC_SYS_MODULE_INFO = 1,
    SRC_PS_LOADED_MODULE_LIST = 2,
    SRC_STACK = 3,
    SRC_DRIVER_OBJECT = 4,
    SRC_PHYSICAL_MAPPING = 5,
    SRC_SCAN_RANGE = 6,
    SRC_HARDCODE = 7,
    SRC_REGISTRY = 8,
    SRC_BCD = 9
};

enum DiagSeverity {
    SEV_INFO = 0,
    SEV_WARN = 1,
    SEV_ERROR = 2
};

struct DiagEventBase {
    uint64_t Sequence;
    uint64_t Rip;
    uint64_t ModuleBase;
    uint32_t ModuleRva;
    DiagAccessType AccessType;
    uint64_t TimestampQpc;
};

struct SehEvent {
    DiagEventBase Base;
    uint32_t ExceptionCode;
    uint64_t FaultAddress;
    uint32_t FirstChance;
    uint64_t HandlerRip;
    uint32_t HandlerRva;
    uint64_t ResumeRip;
    uint32_t Disposition;
    uint64_t StackSlot;
    uint8_t Hints;
    char ModuleName[32];
    char Reason[128];
    uint64_t GprAX, GprBX, GprCX, GprDX, GprSI, GprDI;
    uint64_t GprR8, GprR9, GprR10, GprR11, GprR12, GprR13, GprR14, GprR15;
    uint64_t GprSP, GprBP;
    uint32_t Eflags;
};

struct MemProbeEvent {
    DiagEventBase Base;
    uint64_t Address;
    uint32_t Size;
    DiagProbeType ProbeType;
    DiagSourceProv Provenance;
    uint64_t CandidateBase4k;
    uint64_t CandidateBase64k;
    uint32_t Offset4k;
    uint32_t Offset64k;
    uint64_t Value;
    uint8_t DecodedInsn[16];
    uint8_t InsnLen;
    char SourceReg[8];
    char ModuleName[32];
    char RegionName[64];
    char SectionName[16];
};

struct PeProbeEvent {
    DiagEventBase Base;
    uint64_t CandidateBase;
    uint64_t ReadAddress;
    uint32_t Offset;
    DiagProbeType ProbeType;
    DiagSourceProv Provenance;
    uint32_t IsMapped;
    uint64_t Value;
    char ModuleName[32];
};

struct StackRejectEvent {
    uint64_t Sequence;
    uint64_t Value;
    uint64_t StackSlot;
    DiagRejectReason Reason;
    uint64_t Rip;
    uint32_t ModuleRva;
    char ReasonStr[64];
    char ModuleName[32];
};

struct StackAcceptEvent {
    uint64_t Sequence;
    uint64_t Value;
    uint64_t StackSlot;
    uint64_t Rip;
    uint32_t ModuleRva;
    char Section[16];
    char ModuleName[32];
    uint32_t Confidence;
};

struct HvspReadEvent {
    DiagEventBase Base;
    uint64_t Address;
    uint32_t Offset;
    uint32_t Size;
    uint64_t Value;
    char FieldName[24];
    uint8_t DynamicUpdate;
    char ModuleName[32];
};

struct KusdReadEvent {
    DiagEventBase Base;
    uint64_t Address;
    uint32_t Offset;
    uint32_t Size;
    uint64_t Value;
    char FieldName[24];
};

struct BootEnvReadEvent {
    DiagEventBase Base;
    uint64_t BufferAddr;
    uint32_t BufferLen;
    uint32_t Status;
    uint8_t Guid[16];
    uint32_t FirmwareType;
    uint64_t BootFlags;
};

struct CiReadEvent {
    DiagEventBase Base;
    uint64_t BufferAddr;
    uint32_t BufferLen;
    uint32_t Status;
    uint32_t Options;
    uint32_t HVCIOptions;
    uint64_t Version;
    uint8_t PolicyGuid[16];
};

struct FirmwareQueryEvent {
    DiagEventBase Base;
    uint64_t BufferAddr;
    uint32_t InputLen;
    uint32_t OutputLen;
    uint32_t Status;
    uint32_t Provider;
    uint32_t Action;
    uint32_t TableId;
    uint64_t Instance;
    uint8_t First32Bytes[32];
    uint8_t IsFake;
    char ProviderName[16];
};

struct CpuidEvent {
    DiagEventBase Base;
    uint32_t Leaf;
    uint32_t SubLeaf;
    uint32_t PreEax, PreEbx, PreEcx, PreEdx;
    uint32_t PostEax, PostEbx, PostEcx, PostEdx;
    uint32_t ChangedBits[4];
    char VendorStr[13];
    char LeafName[48];
    uint8_t HypervisorPresent;
    uint8_t SelfModify;
    char ModuleName[32];
};

struct ModuleQueryEvent {
    DiagEventBase Base;
    uint64_t BufferAddr;
    uint32_t BufferLen;
    uint32_t RequiredLen;
    uint32_t InitiaStatus;
    uint32_t FinalStatus;
    uint32_t ModuleCountBefore;
    uint32_t ModuleCountAfter;
    uint32_t ModuleCountInjected;
    char InjectedModuleName[64];
    uint64_t InjectedModuleBase;
};

struct DrvSelfReadEvent {
    DiagEventBase Base;
    uint64_t TargetVa;
    uint32_t TargetRva;
    uint32_t Size;
    uint64_t Value;
    char Section[16];
    uint8_t IsHot;
    char IntegrityReason[32];
};

struct NtosReadEvent {
    DiagEventBase Base;
    uint64_t TargetVa;
    uint32_t TargetRva;
    uint32_t Size;
    uint64_t Value;
    char Section[16];
    char Symbol[64];
    uint8_t IsPatched;
    uint8_t Suspicious;
    char SuspiciousReason[64];
};

struct UnmappedReadEvent {
    DiagEventBase Base;
    uint64_t FaultAddress;
    uint32_t Size;
    uint64_t CandidateBase4k;
    uint64_t CandidateBase64k;
    uint32_t Offset4k;
    uint32_t Offset64k;
    DiagProbeType Hint;
    uint8_t LazyMapped;
    uint8_t HasHandler;
    char RegionName[64];
    char ModuleName[32];
    uint64_t RecentRipRing[8];
    uint32_t RecentEventRing[8];
};

struct ConsistencyEvent {
    uint64_t Sequence;
    DiagSeverity Severity;
    char CheckName[64];
    char Message[256];
    uint64_t Va1, Va2;
    uint32_t Rva1, Rva2;
};

class DiagCenter {
public:
    static DiagCenter& Instance();

    void Initialize();
    void Shutdown();

    uint64_t NextSeq();

    bool IsEnabled() const;

    void RecordSeh(const SehEvent& e);
    void RecordMemProbe(const MemProbeEvent& e);
    void RecordPeProbe(const PeProbeEvent& e);
    void RecordStackReject(const StackRejectEvent& e);
    void RecordStackAccept(const StackAcceptEvent& e);
    void RecordHvspRead(const HvspReadEvent& e);
    void RecordKusdRead(const KusdReadEvent& e);
    void RecordBootEnvRead(const BootEnvReadEvent& e);
    void RecordCiRead(const CiReadEvent& e);
    void RecordFirmwareQuery(const FirmwareQueryEvent& e);
    void RecordCpuid(const CpuidEvent& e);
    void RecordModuleQuery(const ModuleQueryEvent& e);
    void RecordDrvSelfRead(const DrvSelfReadEvent& e);
    void RecordNtosRead(const NtosReadEvent& e);
    void RecordUnmappedRead(const UnmappedReadEvent& e);
    void RecordConsistency(const ConsistencyEvent& e);

    void DumpSehEvents();
    void DumpStackRejectEvents();
    void DumpStackAcceptEvents();
    void DumpHvspReads();
    void DumpBootEnvReads();
    void DumpCiReads();
    void DumpFirmwareQueries();
    void DumpCpuidEvents();
    void DumpModuleQueryEvents();
    void DumpDrvSelfReads();
    void DumpNtosReads();
    void DumpUnmappedReads();
    void DumpConsistencyReport();
    void RunConsistencyChecks();

    void EmitPeProbeHint(uint64_t faultAddr, uint32_t offset64k, char* outBuf, size_t bufSize);
    void EmitRejectReason(DiagRejectReason r, char* outBuf, size_t bufSize);
    const char* FormatVa(uint64_t va);
    const char* FormatModuleRva(uint64_t va);

    bool IsPlausibleReturnAddress(uint64_t va);
    bool IsCanonicalKernelVa(uint64_t va);
    bool IsKuserSharedDataVa(uint64_t va);
    bool IsHypervisorSharedPageVa(uint64_t va);
    bool IsPoolVa(uint64_t va);
    bool IsStackVa(uint64_t va);
    bool IsEmulatorSentinelVa(uint64_t va);
    bool IsStringLikeData(uint64_t va);
    bool IsMappedExecutable(uint64_t va);

    bool ResolveVaToModule(uint64_t va, uint64_t& outBase, uint32_t& outRva, char* outModName, size_t nameSize);
    bool ResolveVaToRegionName(uint64_t va, char* outName, size_t nameSize);
    bool ResolveVaToPeSection(uint64_t va, char* outSection, size_t secSize);
    bool ResolveVaToSymbol(uint64_t va, char* outSym, size_t symSize);

    uint32_t ComputePeProbeHint(uint64_t faultAddr);

    void LogFormatted(const char* prefix, const char* msg);

    static const size_t SEH_RING_SIZE = 128;
    static const size_t STACK_REJECT_RING_SIZE = 256;
    static const size_t STACK_ACCEPT_RING_SIZE = 128;
    static const size_t HVSP_RING_SIZE = 256;
    static const size_t KUSD_RING_SIZE = 256;
    static const size_t BOOTENV_RING_SIZE = 128;
    static const size_t CI_RING_SIZE = 128;
    static const size_t FW_RING_SIZE = 128;
    static const size_t CPUID_RING_SIZE = 256;
    static const size_t MODULE_QUERY_RING_SIZE = 64;
    static const size_t DRV_SELF_RING_SIZE = 512;
    static const size_t NTOS_RING_SIZE = 512;
    static const size_t UNMAPPED_RING_SIZE = 256;
    static const size_t CONSISTENCY_RING_SIZE = 128;
    static const size_t PEPROBE_RING_SIZE = 256;
    static const size_t MEMPROBE_RING_SIZE = 256;

private:
    DiagCenter();
    ~DiagCenter();

    uint64_t mSeq;
    bool mEnabled;

    SehEvent mSehRing[SEH_RING_SIZE];
    uint32_t mSehRingIdx;
    uint32_t mSehCount;

    MemProbeEvent mMemProbeRing[MEMPROBE_RING_SIZE];
    uint32_t mMemProbeRingIdx;
    uint32_t mMemProbeCount;

    PeProbeEvent mPeProbeRing[PEPROBE_RING_SIZE];
    uint32_t mPeProbeRingIdx;
    uint32_t mPeProbeCount;

    StackRejectEvent mStackRejectRing[STACK_REJECT_RING_SIZE];
    uint32_t mStackRejectIdx;
    uint32_t mStackRejectCount;

    StackAcceptEvent mStackAcceptRing[STACK_ACCEPT_RING_SIZE];
    uint32_t mStackAcceptIdx;
    uint32_t mStackAcceptCount;

    HvspReadEvent mHvspRing[HVSP_RING_SIZE];
    uint32_t mHvspRingIdx;
    uint32_t mHvspCount;

    KusdReadEvent mKusdRing[KUSD_RING_SIZE];
    uint32_t mKusdRingIdx;
    uint32_t mKusdCount;

    BootEnvReadEvent mBootEnvRing[BOOTENV_RING_SIZE];
    uint32_t mBootEnvIdx;
    uint32_t mBootEnvCount;

    CiReadEvent mCiRing[CI_RING_SIZE];
    uint32_t mCiRingIdx;
    uint32_t mCiCount;

    FirmwareQueryEvent mFwRing[FW_RING_SIZE];
    uint32_t mFwRingIdx;
    uint32_t mFwCount;

    CpuidEvent mCpuidRing[CPUID_RING_SIZE];
    uint32_t mCpuidRingIdx;
    uint32_t mCpuidCount;

    ModuleQueryEvent mModQueryRing[MODULE_QUERY_RING_SIZE];
    uint32_t mModQueryIdx;
    uint32_t mModQueryCount;

    DrvSelfReadEvent mDrvSelfRing[DRV_SELF_RING_SIZE];
    uint32_t mDrvSelfIdx;
    uint32_t mDrvSelfCount;

    NtosReadEvent mNtosRing[NTOS_RING_SIZE];
    uint32_t mNtosRingIdx;
    uint32_t mNtosCount;

    UnmappedReadEvent mUnmappedRing[UNMAPPED_RING_SIZE];
    uint32_t mUnmappedIdx;
    uint32_t mUnmappedCount;

    ConsistencyEvent mConsistencyRing[CONSISTENCY_RING_SIZE];
    uint32_t mConsistencyIdx;
    uint32_t mConsistencyCount;

    char mFmtBuf[512];
};

#define DIAG_SEQ DiagCenter::Instance().NextSeq()

#define DIAG_SEH(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordSeh(ev); } while (0)

#define DIAG_MEMPROBE(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordMemProbe(ev); } while (0)

#define DIAG_PEPROBE(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordPeProbe(ev); } while (0)

#define DIAG_STACK_REJECT(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordStackReject(ev); } while (0)

#define DIAG_STACK_ACCEPT(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordStackAccept(ev); } while (0)

#define DIAG_HVSP_READ(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordHvspRead(ev); } while (0)

#define DIAG_KUSD_READ(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordKusdRead(ev); } while (0)

#define DIAG_BOOTENV_READ(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordBootEnvRead(ev); } while (0)

#define DIAG_CI_READ(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordCiRead(ev); } while (0)

#define DIAG_FW_QUERY(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordFirmwareQuery(ev); } while (0)

#define DIAG_CPUID(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordCpuid(ev); } while (0)

#define DIAG_MODULE_QUERY(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordModuleQuery(ev); } while (0)

#define DIAG_DRV_SELF_READ(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordDrvSelfRead(ev); } while (0)

#define DIAG_NTOS_READ(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordNtosRead(ev); } while (0)

#define DIAG_UNMAPPED_READ(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordUnmappedRead(ev); } while (0)

#define DIAG_CONSISTENCY(ev) \
    do { if (DiagCenter::Instance().IsEnabled()) DiagCenter::Instance().RecordConsistency(ev); } while (0)

#define DIAG_IS_ENABLED() DiagCenter::Instance().IsEnabled()
