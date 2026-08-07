#pragma once
#include "include/common.h"
#include <vector>
#include <mutex>
#include <string>

namespace DeviceTracker {

struct DeviceInfo {
    uint64_t UcAddr;
    std::wstring DeviceName;
    std::wstring SymLinkName;
    ULONG DeviceType;
};

extern std::vector<DeviceInfo> Devices;
extern std::mutex DeviceLock;

uint64_t FindByName(const std::wstring& Name);
uint64_t GetFirst();
const DeviceInfo* GetByIndex(size_t Index);
size_t GetCount();

}

NTSTATUS h_IoCreateDevice(_DRIVER_OBJECT* DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DWORD DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, _DEVICE_OBJECT** DeviceObject);
NTSTATUS h_IoCreateFileEx(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, OBJECT_ATTRIBUTES* ObjectAttributes, void* IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG Disposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength, void* CreateFileType, PVOID InternalParameters, ULONG Options, void* DriverContext);
void h_IoDeleteController(PVOID ControllerObject);
NTSTATUS h_IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName);
NTSTATUS h_IoCreateSymbolicLink(PUNICODE_STRING SymbolicLinkName, PUNICODE_STRING DeviceName);
BOOL h_IoIsSystemThread(_ETHREAD* thread);
void h_IoDeleteDevice(_DEVICE_OBJECT* obj);
void* h_IoGetTopLevelIrp();
NTSTATUS h_IoQueryFileDosDeviceName(PVOID fileObject, PVOID* name_info);
NTSTATUS h_IoWMIOpenBlock(LPCGUID Guid, ULONG DesiredAccess, PVOID* DataBlockObject);
NTSTATUS h_IoWMIQueryAllData(PVOID DataBlockObject, PULONG InOutBufferSize, PVOID OutBuffer);
void h_IofCompleteRequest(void* pirp, CHAR boost);
NTSTATUS h_IoGetDeviceInterfaces(const GUID* InterfaceClassGuid, _DEVICE_OBJECT* PhysicalDeviceObject, ULONG Flags, wchar_t** SymbolicLinkList);
NTSTATUS h_IoCreateNotificationEvent(PUNICODE_STRING EventName, PHANDLE EventHandle);
PVOID h_IoGetAttachedDeviceReference(_DEVICE_OBJECT* DeviceObject);
NTSTATUS h_IoRegisterPlugPlayNotification(uint32_t EventCategory, ULONG EventCategoryFlags, PVOID EventCategoryData, PVOID DriverObject, PVOID CallbackRoutine, PVOID Context, PVOID* NotificationEntry);
NTSTATUS h_IoUnregisterPlugPlayNotificationEx(PVOID NotificationEntry);
void* h_IoThreadToProcess(void* Thread);
PVOID h_IoAllocateWorkItem(_DEVICE_OBJECT* DeviceObject);
void h_IoFreeWorkItem(PVOID IoWorkItem);
void h_IoQueueWorkItem(PVOID IoWorkItem, PVOID WorkerRoutine, uint32_t QueueType, PVOID Context);
void h_IoInitializeWorkItem(PVOID IoObject, PVOID IoWorkItem);
NTSTATUS h_IoRegisterShutdownNotification(_DEVICE_OBJECT* DeviceObject);
NTSTATUS h_IoCreateDeviceSecure(_DRIVER_OBJECT* DriverObject, ULONG DeviceExtensionSize, PUNICODE_STRING DeviceName, DWORD DeviceType, ULONG DeviceCharacteristics, BOOLEAN Exclusive, PUNICODE_STRING DefaultSDDLString, void* DeviceClassGuid, _DEVICE_OBJECT** DeviceObject);
NTSTATUS h_IoValidateDeviceIoControlAccess(void* Irp, ULONG RequiredAccess);
