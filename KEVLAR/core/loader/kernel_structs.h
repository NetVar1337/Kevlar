#pragma once

#include <cstdint>
#include <string>

class PEFile;

extern const wchar_t* DriverName;
extern const wchar_t* RegistryBuffer;
extern std::wstring DriverBaseName;
extern std::wstring DriverFullPath;

void PopulateKernelStructs();
void SetupDriverLdrEntry(PEFile* MainModule);
