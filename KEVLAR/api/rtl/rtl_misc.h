#pragma once
#include "include/common.h"

uint64_t h_RtlRandomEx(unsigned long* seed);
NTSTATUS h_RtlGetVersion(RTL_OSVERSIONINFOW* lpVersionInformation);
void h_RtlTimeToTimeFields(PLARGE_INTEGER Time, PTIME_FIELDS TimeFields);
PIMAGE_NT_HEADERS h_RtlImageNtHeader(PVOID ImageBase);
PRUNTIME_FUNCTION h_RtlLookupFunctionEntry(uint64_t ControlPc, uint64_t* ImageBase, PVOID HistoryTable);
PVOID h_RtlVirtualUnwind(DWORD HandlerType, uint64_t ImageBase, uint64_t ControlPc, PRUNTIME_FUNCTION FunctionEntry, PCONTEXT ContextRecord, PVOID* HandlerData, uint64_t* EstablisherFrame, PVOID ContextPointers);
void h_RtlCaptureContext(PCONTEXT ContextRecord);
BOOLEAN h_RtlTimeFieldsToTime(PTIME_FIELDS TimeFields, PLARGE_INTEGER Time);
NTSTATUS h_RtlGUIDFromString(PUNICODE_STRING GuidString, GUID* Guid);
NTSTATUS h_RtlStringFromGUID(GUID* Guid, PUNICODE_STRING GuidString);
