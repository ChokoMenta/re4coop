cmake_minimum_required(VERSION 3.15)

# Runtime estatico: asi no hace falta instalar nada extra de Visual C++ para usar el mod.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")

project(re4coop CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# El RE4 UHD de Steam (bio4.exe) es de 32 bits: hay que compilar con "-A Win32".
add_library(dinput8 SHARED
    src/dllmain.cpp
    src/mod.cpp
    src/dinput8.def
)

set_target_properties(dinput8 PROPERTIES PREFIX "" OUTPUT_NAME "dinput8")
target_compile_definitions(dinput8 PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
