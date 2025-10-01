cmake_minimum_required(VERSION 3.15)
project(ThreadJect LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Disable specific warnings
if(MSVC)
    add_compile_options(/wd4996 /wd4091 /wd6387 /wd4477)
endif()

# Include directories
include_directories(Include)

# Add executable
add_executable(ThreadJect
    "src/Main.cpp"
    "Include/ManualInject.h"
    "src/ManualInject.cpp"
)

# Set properties
set_target_properties(ThreadJect PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

# Platform-specific settings
if(WIN32)
    # Common Windows libraries
    target_link_libraries(ThreadJect ntdll.lib psapi.lib)
    
    # Set output names based on architecture
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        # 64-bit build
        set_target_properties(ThreadJect PROPERTIES
            OUTPUT_NAME "ThreadJect64"
            SUFFIX ".exe"
        )
        target_compile_definitions(ThreadJect PRIVATE _WIN64)
        message(STATUS "Building 64-bit version")
    else()
        # 32-bit build
        set_target_properties(ThreadJect PROPERTIES
            OUTPUT_NAME "ThreadJect32" 
            SUFFIX ".exe"
        )
        message(STATUS "Building 32-bit version")
    endif()
    
    # Windows-specific compiler options
    target_compile_options(ThreadJect PRIVATE /W4)
    target_compile_definitions(ThreadJect PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()