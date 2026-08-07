#!/usr/bin/env python3
"""Generate a minimal x64 native PE (.sys) for KEVLAR smoke tests.

The driver has no imports, reads KPCR.Self through the GS segment (exercising
the synthetic KPCR + GS-base mapping), and returns STATUS_SUCCESS from
DriverEntry. This exercises PE parsing/mapping, relocation, kernel-struct
setup and emulator initialization end-to-end.

No .reloc section is needed: the code is fully position-independent.

Usage: make_test_driver.py [output.sys]   (default: test_driver.sys)
With --verify, the image is mapped with LoadLibraryExA(DONT_RESOLVE_DLL_REFERENCES)
(the same way KEVLAR's PEFile::Open loads it) to confirm it is a valid image.
"""
import ctypes
import ctypes.wintypes
import struct
import sys

MZ, PE = 0x5A4D, 0x00004550
AMD64, MAGIC64 = 0x8664, 0x20B
EXEC, LARGE = 0x0002, 0x0020
NATIVE = 1
HIGH_ENTROPY_VA = 0x0020
SCN_CODE = 0x20
SCN_MEM_EXECUTE, SCN_MEM_READ = 0x20000000, 0x40000000

IMAGE_BASE = 0x140000000
SECTION_RVA = 0x1000       # .text VMA
SECTION_RAW = 0x400        # .text raw offset (== SizeOfHeaders)
FILE_ALIGN = 0x200


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def build_driver():
    # --- code at RVA 0x1000: KPCR.Self via GS, conditional branch, STATUS_SUCCESS ---
    #   0x1000: sub rsp, 0x28
    #   0x1004: mov rax, qword ptr gs:[0x20]     ; KPCR.Self
    #   0x100d: test rax, rax
    #   0x1010: jz 0x1020 (fail)                 ; taken only if KPCR.Self == 0
    #   0x1012: xor eax, eax                     ; STATUS_SUCCESS
    #   0x1014: add rsp, 0x28
    #   0x1018: ret
    #   0x1020: mov eax, 0xC0000001              ; STATUS_UNSUCCESSFUL
    #   0x1025: add rsp, 0x28
    #   0x1029: ret
    code = bytearray()
    code += bytes([0x48, 0x83, 0xEC, 0x28])                                       # sub rsp,0x28
    code += bytes([0x65, 0x48, 0x8B, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00])         # mov rax, gs:[0x20]
    code += bytes([0x48, 0x85, 0xC0])                                             # test rax,rax
    code += bytes([0x74, 0x0E])                                                   # jz fail
    code += bytes([0x31, 0xC0])                                                   # xor eax,eax
    code += bytes([0x48, 0x83, 0xC4, 0x28])                                       # add rsp,0x28
    code += bytes([0xC3])                                                         # ret
    code += b"\x00" * (0x20 - len(code))
    code += bytes([0xB8, 0x01, 0x00, 0x00, 0xC0])                                 # mov eax,0xC0000001
    code += bytes([0x48, 0x83, 0xC4, 0x28])                                       # add rsp,0x28
    code += bytes([0xC3])                                                         # ret

    data = bytearray(code)
    raw_size = align(len(data), FILE_ALIGN)
    data += b"\x00" * (raw_size - len(data))
    size_of_image = align(SECTION_RVA + raw_size, 0x1000)

    # --- headers (explicit field-by-field packing) ---
    dos = bytearray(0x80)
    struct.pack_into("<H", dos, 0, MZ)
    struct.pack_into("<I", dos, 0x3C, 0x80)          # e_lfanew -> NT headers at 0x80

    hdr = bytearray()
    hdr += struct.pack("<I", PE)                     # Signature
    hdr += struct.pack("<HHIIIHH", AMD64, 1, 0, 0, 0, 0xF0, EXEC | LARGE)  # FileHeader

    o = bytearray()
    o += struct.pack("<HBB", MAGIC64, 14, 0)         # Magic + linker ver
    o += struct.pack("<I", raw_size)                 # SizeOfCode
    o += struct.pack("<I", 0)                        # SizeOfInitializedData
    o += struct.pack("<I", 0)                        # SizeOfUninitializedData
    o += struct.pack("<I", SECTION_RVA)              # AddressOfEntryPoint
    o += struct.pack("<I", SECTION_RVA)              # BaseOfCode
    o += struct.pack("<Q", IMAGE_BASE)               # ImageBase
    o += struct.pack("<I", 0x1000)                   # SectionAlignment
    o += struct.pack("<I", FILE_ALIGN)               # FileAlignment
    o += struct.pack("<HHHHHH", 6, 0, 0, 0, 6, 0)    # OS/Image/Subsystem versions
    o += struct.pack("<I", 0)                        # Win32VersionValue
    o += struct.pack("<I", size_of_image)            # SizeOfImage
    o += struct.pack("<I", SECTION_RAW)              # SizeOfHeaders
    o += struct.pack("<I", 0)                        # CheckSum
    o += struct.pack("<H", NATIVE)                   # Subsystem
    o += struct.pack("<H", HIGH_ENTROPY_VA)          # DllCharacteristics
    o += struct.pack("<Q", 0x40000)                  # SizeOfStackReserve
    o += struct.pack("<Q", 0x1000)                   # SizeOfStackCommit
    o += struct.pack("<Q", 0x100000)                 # SizeOfHeapReserve
    o += struct.pack("<Q", 0x1000)                   # SizeOfHeapCommit
    o += struct.pack("<I", 0)                        # LoaderFlags
    o += struct.pack("<I", 16)                       # NumberOfRvaAndSizes
    assert len(o) == 0x70, f"optional header prefix {len(o)} != 112"
    for _ in range(16):
        o += struct.pack("<II", 0, 0)
    assert len(o) == 0xF0, f"optional header {len(o)} != 240"

    hdr += o
    sec = struct.pack("<8sIIIIIIHHI", b".text\x00\x00\x00", raw_size, SECTION_RVA,
                      raw_size, SECTION_RAW, 0, 0, 0, 0,
                      SCN_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ)
    hdr += sec
    hdr += b"\x00" * (SECTION_RAW - 0x80 - len(hdr))
    assert 0x80 + len(hdr) == SECTION_RAW

    return bytes(dos) + bytes(hdr) + bytes(data)


def verify_load(path):
    """Map the image the way KEVLAR's PEFile::Open does."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    DONT_RESOLVE = 0x00000001
    h = kernel32.LoadLibraryExW(ctypes.wintypes.LPCWSTR(path), None, DONT_RESOLVE)
    if not h:
        raise SystemExit(f"LoadLibraryEx failed: {ctypes.get_last_error()}")
    kernel32.FreeLibrary(h)
    print("LoadLibraryEx OK (valid image)")


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "test_driver.sys"
    image = build_driver()
    with open(out, "wb") as f:
        f.write(image)
    print(f"wrote {out} ({len(image)} bytes)")
    if "--verify" in sys.argv:
        verify_load(out)


if __name__ == "__main__":
    main()
