#include "include/common.h"
#include "cng.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

NTSTATUS h_BCryptOpenAlgorithmProvider(PVOID* phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags) {
    auto HostAlg = UcPtr(phAlgorithm);
    auto HostAlgId = UcPtr((wchar_t*)pszAlgId);
    auto HostImpl = pszImplementation ? UcPtr((wchar_t*)pszImplementation) : nullptr;
    return BCryptOpenAlgorithmProvider((BCRYPT_ALG_HANDLE*)HostAlg, HostAlgId, HostImpl, dwFlags);
}

NTSTATUS h_BCryptCloseAlgorithmProvider(PVOID hAlgorithm, ULONG dwFlags) {
    return BCryptCloseAlgorithmProvider((BCRYPT_ALG_HANDLE)hAlgorithm, dwFlags);
}

NTSTATUS h_BCryptCreateHash(PVOID hAlgorithm, PVOID* phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags) {
    return BCryptCreateHash(
        (BCRYPT_ALG_HANDLE)hAlgorithm,
        (BCRYPT_HASH_HANDLE*)UcPtr(phHash),
        UcPtr(pbHashObject),
        cbHashObject,
        UcPtr(pbSecret),
        cbSecret,
        dwFlags);
}

NTSTATUS h_BCryptHashData(PVOID hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    return BCryptHashData((BCRYPT_HASH_HANDLE)hHash, UcPtr(pbInput), cbInput, dwFlags);
}

NTSTATUS h_BCryptFinishHash(PVOID hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags) {
    return BCryptFinishHash((BCRYPT_HASH_HANDLE)hHash, UcPtr(pbOutput), cbOutput, dwFlags);
}

NTSTATUS h_BCryptDestroyHash(PVOID hHash) {
    return BCryptDestroyHash((BCRYPT_HASH_HANDLE)hHash);
}

NTSTATUS h_BCryptGetProperty(PVOID hObject, LPCWSTR pszProperty, PUCHAR pbOutput, ULONG cbOutput, PULONG pcbResult, ULONG dwFlags) {
    return BCryptGetProperty(
        (BCRYPT_HANDLE)hObject,
        UcPtr((wchar_t*)pszProperty),
        UcPtr(pbOutput),
        cbOutput,
        UcPtr(pcbResult),
        dwFlags);
}

NTSTATUS h_BCryptSetProperty(PVOID hObject, LPCWSTR pszProperty, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    return BCryptSetProperty(
        (BCRYPT_HANDLE)hObject,
        UcPtr((wchar_t*)pszProperty),
        UcPtr(pbInput),
        cbInput,
        dwFlags);
}

NTSTATUS h_BCryptGenRandom(PVOID hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags) {
    return BCryptGenRandom((BCRYPT_ALG_HANDLE)hAlgorithm, UcPtr(pbBuffer), cbBuffer, dwFlags);
}

NTSTATUS h_BCryptGenerateSymmetricKey(PVOID hAlgorithm, PVOID* phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags) {
    return BCryptGenerateSymmetricKey(
        (BCRYPT_ALG_HANDLE)hAlgorithm,
        (BCRYPT_KEY_HANDLE*)UcPtr(phKey),
        UcPtr(pbKeyObject),
        cbKeyObject,
        UcPtr(pbSecret),
        cbSecret,
        dwFlags);
}

NTSTATUS h_BCryptEncrypt(PVOID hKey, PUCHAR pbInput, ULONG cbInput, PVOID pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, PULONG pcbResult, ULONG dwFlags) {
    return BCryptEncrypt(
        (BCRYPT_KEY_HANDLE)hKey,
        UcPtr(pbInput),
        cbInput,
        UcPtr((uint8_t*)pPaddingInfo),
        UcPtr(pbIV),
        cbIV,
        UcPtr(pbOutput),
        cbOutput,
        UcPtr(pcbResult),
        dwFlags);
}

NTSTATUS h_BCryptDecrypt(PVOID hKey, PUCHAR pbInput, ULONG cbInput, PVOID pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, PULONG pcbResult, ULONG dwFlags) {
    return BCryptDecrypt(
        (BCRYPT_KEY_HANDLE)hKey,
        UcPtr(pbInput),
        cbInput,
        UcPtr((uint8_t*)pPaddingInfo),
        UcPtr(pbIV),
        cbIV,
        UcPtr(pbOutput),
        cbOutput,
        UcPtr(pcbResult),
        dwFlags);
}

NTSTATUS h_BCryptImportKeyPair(PVOID hAlgorithm, PVOID hImportKey, LPCWSTR pszBlobType, PVOID* phKey, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags) {
    return BCryptImportKeyPair(
        (BCRYPT_ALG_HANDLE)hAlgorithm,
        (BCRYPT_KEY_HANDLE)hImportKey,
        UcPtr((wchar_t*)pszBlobType),
        (BCRYPT_KEY_HANDLE*)UcPtr(phKey),
        UcPtr(pbInput),
        cbInput,
        dwFlags);
}

NTSTATUS h_BCryptExportKey(PVOID hKey, PVOID hExportKey, LPCWSTR pszBlobType, PUCHAR pbOutput, ULONG cbOutput, PULONG pcbResult, ULONG dwFlags) {
    return BCryptExportKey(
        (BCRYPT_KEY_HANDLE)hKey,
        (BCRYPT_KEY_HANDLE)hExportKey,
        UcPtr((wchar_t*)pszBlobType),
        UcPtr(pbOutput),
        cbOutput,
        UcPtr(pcbResult),
        dwFlags);
}

NTSTATUS h_BCryptVerifySignature(PVOID hKey, PVOID pPaddingInfo, PUCHAR pbHash, ULONG cbHash, PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags) {
    return BCryptVerifySignature(
        (BCRYPT_KEY_HANDLE)hKey,
        UcPtr((uint8_t*)pPaddingInfo),
        UcPtr(pbHash),
        cbHash,
        UcPtr(pbSignature),
        cbSignature,
        dwFlags);
}

NTSTATUS h_BCryptSignHash(PVOID hKey, PVOID pPaddingInfo, PUCHAR pbInput, ULONG cbInput, PUCHAR pbOutput, ULONG cbOutput, PULONG pcbResult, ULONG dwFlags) {
    return BCryptSignHash(
        (BCRYPT_KEY_HANDLE)hKey,
        UcPtr((uint8_t*)pPaddingInfo),
        UcPtr(pbInput),
        cbInput,
        UcPtr(pbOutput),
        cbOutput,
        UcPtr(pcbResult),
        dwFlags);
}

NTSTATUS h_BCryptDeriveKeyPBKDF2(PVOID hPrf, PUCHAR pbPassword, ULONG cbPassword, PUCHAR pbSalt, ULONG cbSalt, ULONGLONG cIterations, PUCHAR pbDerivedKey, ULONG cbDerivedKey, ULONG dwFlags) {
    return BCryptDeriveKeyPBKDF2(
        (BCRYPT_ALG_HANDLE)hPrf,
        UcPtr(pbPassword),
        cbPassword,
        UcPtr(pbSalt),
        cbSalt,
        cIterations,
        UcPtr(pbDerivedKey),
        cbDerivedKey,
        dwFlags);
}

NTSTATUS h_BCryptDestroyKey(PVOID hKey) {
    return BCryptDestroyKey((BCRYPT_KEY_HANDLE)hKey);
}

NTSTATUS h_BCryptDuplicateHash(PVOID hHash, PVOID* phNewHash, PUCHAR pbHashObject, ULONG cbHashObject, ULONG dwFlags) {
    return BCryptDuplicateHash(
        (BCRYPT_HASH_HANDLE)hHash,
        (BCRYPT_HASH_HANDLE*)UcPtr(phNewHash),
        UcPtr(pbHashObject),
        cbHashObject,
        dwFlags);
}

NTSTATUS h_BCryptHash(PVOID hAlgorithm, PUCHAR pbSecret, ULONG cbSecret, PUCHAR pbInput, ULONG cbInput, PUCHAR pbOutput, ULONG cbOutput) {
    return BCryptHash(
        (BCRYPT_ALG_HANDLE)hAlgorithm,
        UcPtr(pbSecret),
        cbSecret,
        UcPtr(pbInput),
        cbInput,
        UcPtr(pbOutput),
        cbOutput);
}
