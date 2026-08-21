#pragma once
#include "include/common.h"

NTSTATUS h_BCryptOpenAlgorithmProvider(PVOID* phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
NTSTATUS h_BCryptCloseAlgorithmProvider(PVOID hAlgorithm, ULONG dwFlags);
NTSTATUS h_BCryptCreateHash(PVOID hAlgorithm, PVOID* phHash, PUCHAR pbHashObject, ULONG cbHashObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
NTSTATUS h_BCryptHashData(PVOID hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
NTSTATUS h_BCryptFinishHash(PVOID hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags);
NTSTATUS h_BCryptDestroyHash(PVOID hHash);
NTSTATUS h_BCryptGetProperty(PVOID hObject, LPCWSTR pszProperty, PUCHAR pbOutput, ULONG cbOutput, PULONG pcbResult, ULONG dwFlags);
NTSTATUS h_BCryptSetProperty(PVOID hObject, LPCWSTR pszProperty, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
NTSTATUS h_BCryptGenRandom(PVOID hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);
NTSTATUS h_BCryptGenerateSymmetricKey(PVOID hAlgorithm, PVOID* phKey, PUCHAR pbKeyObject, ULONG cbKeyObject, PUCHAR pbSecret, ULONG cbSecret, ULONG dwFlags);
NTSTATUS h_BCryptEncrypt(PVOID hKey, PUCHAR pbInput, ULONG cbInput, PVOID pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, PULONG pcbResult, ULONG dwFlags);
NTSTATUS h_BCryptDecrypt(PVOID hKey, PUCHAR pbInput, ULONG cbInput, PVOID pPaddingInfo, PUCHAR pbIV, ULONG cbIV, PUCHAR pbOutput, ULONG cbOutput, PULONG pcbResult, ULONG dwFlags);
NTSTATUS h_BCryptImportKeyPair(PVOID hAlgorithm, PVOID hImportKey, LPCWSTR pszBlobType, PVOID* phKey, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags);
NTSTATUS h_BCryptExportKey(PVOID hKey, PVOID hExportKey, LPCWSTR pszBlobType, PUCHAR pbOutput, ULONG cbOutput, PULONG pcbResult, ULONG dwFlags);
NTSTATUS h_BCryptVerifySignature(PVOID hKey, PVOID pPaddingInfo, PUCHAR pbHash, ULONG cbHash, PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags);
NTSTATUS h_BCryptSignHash(PVOID hKey, PVOID pPaddingInfo, PUCHAR pbInput, ULONG cbInput, PUCHAR pbOutput, ULONG cbOutput, PULONG pcbResult, ULONG dwFlags);
NTSTATUS h_BCryptDeriveKeyPBKDF2(PVOID hPrf, PUCHAR pbPassword, ULONG cbPassword, PUCHAR pbSalt, ULONG cbSalt, ULONGLONG cIterations, PUCHAR pbDerivedKey, ULONG cbDerivedKey, ULONG dwFlags);
NTSTATUS h_BCryptDestroyKey(PVOID hKey);
NTSTATUS h_BCryptDuplicateHash(PVOID hHash, PVOID* phNewHash, PUCHAR pbHashObject, ULONG cbHashObject, ULONG dwFlags);
NTSTATUS h_BCryptHash(PVOID hAlgorithm, PUCHAR pbSecret, ULONG cbSecret, PUCHAR pbInput, ULONG cbInput, PUCHAR pbOutput, ULONG cbOutput);
