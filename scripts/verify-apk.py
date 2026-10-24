#!/usr/bin/env python3
"""Check packaged ABIs, executable ELF files, and loader segment alignment."""
import pathlib
import struct
import sys
import zipfile

apk = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "app/build/outputs/apk/debug/app-debug.apk")
with zipfile.ZipFile(apk) as archive:
    for abi, machine in [("arm64-v8a", 183), ("x86_64", 62)]:
        for library in ["libboxkernel.so", "libboxloader.so", "libtermux.so"]:
            name = f"lib/{abi}/{library}"
            data = archive.read(name)
            assert data[:6] == b"\x7fELF\x02\x01", name
            assert struct.unpack_from("<H", data, 18)[0] == machine, name
            offset = struct.unpack_from("<Q", data, 32)[0]
            size, count = struct.unpack_from("<HH", data, 54)
            segments = [struct.unpack_from("<IIQQQQQQ", data, offset + i * size) for i in range(count)]
            loads = [segment for segment in segments if segment[0] == 1]
            assert loads, name
            assert all(segment[7] >= 16384 for segment in loads), f"{name} needs 16 KiB alignment"
            if library == "libboxloader.so":
                assert struct.unpack_from("<H", data, 16)[0] == 2, "Loader must be a fixed-address executable"
            print(f"OK {name}: {len(data):,} bytes; ELF architecture and 16 KiB alignment")
    assert not any(path.startswith(("lib/armeabi-v7a/", "lib/x86/")) for path in archive.namelist())
print(f"Verified {apk}")
