# CHDK Webcam Bridge

## Build

Uses Visual Studio 17 2022 Build Tools with vcpkg (C:\vcpkg) for dependencies.

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
