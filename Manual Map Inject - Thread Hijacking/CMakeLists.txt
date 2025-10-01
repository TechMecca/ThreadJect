cmake_minimum_required(VERSION 3.12)
project(ThreadJect)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

# Link libraries (Windows specific)
if(WIN32)
    target_link_libraries(ThreadJect ntdll.lib)
endif()