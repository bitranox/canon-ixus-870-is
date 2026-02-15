# CHDK Webcam Bridge

## Prerequisites

- Visual Studio 17 2022 Build Tools (or Community) with C++ workload
- vcpkg (`C:\vcpkg`)
- `vcpkg install libusb:x64-windows libjpeg-turbo:x64-windows`

## Source Directory

The CMakeLists.txt references source files under `src/`, but the actual source directory is `bridge_src/`. Before building, rename it:

```
ren bridge_src src
```

Or update the paths in CMakeLists.txt (`src/` -> `bridge_src/`).

## Build

cmake is not on PATH; use the full path:
```
set CMAKE="C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
```

### Configure (only needed once or after CMakeLists.txt changes)
```
%CMAKE% -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
```

### Build
```
%CMAKE% --build build --config Release
```

Output binary: `build\Release\chdk-webcam.exe`

### Runtime Dependencies

The following DLLs must be alongside `chdk-webcam.exe` (vcpkg copies them automatically):
- `libusb-1.0.dll`
- `turbojpeg.dll`
