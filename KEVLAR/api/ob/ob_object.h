#pragma once
#include "include/common.h"

uint64_t h_ObfDereferenceObject(PVOID obj);
LONG_PTR h_ObfReferenceObject(PVOID Object);
NTSTATUS h_ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes, PVOID PassedAccessState, ACCESS_MASK DesiredAccess, uint64_t ObjectType, uint64_t AccessMode, PHANDLE Handle);
NTSTATUS h_ObQueryNameString(PVOID Object, PVOID ObjectNameInfo, ULONG Length, PULONG ReturnLength);
NTSTATUS h_ObReferenceObjectByHandle(HANDLE handle, ACCESS_MASK DesiredAccess, _OBJECT_TYPE* ObjectType, uint64_t AccessMode, PVOID* Object, void* HandleInformation);
NTSTATUS h_ObRegisterCallbacks(PVOID CallbackRegistration, PVOID* RegistrationHandle);
void h_ObUnRegisterCallbacks(PVOID RegistrationHandle);
void* h_ObGetFilterVersion(void* arg);
NTSTATUS h_ObDereferenceObjectDeferDelete(PVOID Object);
void h_ObDereferenceObjectWithTag(PVOID Object, ULONG Tag);
NTSTATUS h_ObOpenObjectByName(OBJECT_ATTRIBUTES* ObjectAttributes, void* ObjectType, uint8_t AccessMode, void* AccessState, ACCESS_MASK DesiredAccess, void* ParseContext, PHANDLE Handle);
NTSTATUS h_ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, void* AccessState, ACCESS_MASK DesiredAccess, void* ObjectType, uint8_t AccessMode, void* ParseContext, PVOID* Object);
NTSTATUS h_ObOpenObjectByPointerWithTag(PVOID Object, ULONG HandleAttributes, PVOID PassedAccessState, ACCESS_MASK DesiredAccess, uint64_t ObjectType, uint8_t AccessMode, ULONG Tag, PHANDLE Handle);
