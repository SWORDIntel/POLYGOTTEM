cmake_minimum_required(VERSION 3.15)
project(POLYGOTTEM_C_Methods VERSION 2.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

# Platform detection
if(WIN32)
    set(PLATFORM_NAME "windows")
    set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")
elseif(APPLE)
    set(PLATFORM_NAME "macos")
    set(CMAKE_SHARED_LIBRARY_SUFFIX ".dylib")
else()
    set(PLATFORM_NAME "linux")
    set(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
endif()

# Build directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Compiler flags for different platforms
if(MSVC)
    # Windows MSVC compiler flags
    add_compile_options(/W4 /O2)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    # GCC/Clang compiler flags
    add_compile_options(-Wall -Wextra -pedantic -O2)

    # Add -fPIC for shared libraries on Linux/macOS
    if(UNIX AND NOT APPLE)
        add_compile_options(-fPIC)
    endif()
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Category 1: Exploitation Methods
add_library(privilege_escalation exploitation/privilege_escalation.c)
add_library(memory_exploitation exploitation/memory_exploitation.c)
add_library(kernel_exploitation exploitation/kernel_exploitation.c)
add_library(windows_exploitation exploitation/windows_exploitation.c)

# Category 2: Advanced Utilities
add_library(process_injection utilities/process_injection.c)
add_library(system_manipulation utilities/system_manipulation.c)
add_library(anti_analysis utilities/anti_analysis.c)
add_library(obfuscation utilities/obfuscation.c)

# Category 3: Native Components
add_library(cryptography native/cryptography.c)
add_library(memory_ops native/memory_operations.c)
add_library(network_ops native/network_operations.c)
add_library(compression native/compression.c)

# Category 4: Cross-Platform Payloads
add_library(windows_payloads payloads/windows_payloads.c)
add_library(linux_payloads payloads/linux_payloads.c)
add_library(macos_payloads payloads/macos_payloads.c)

# Platform-specific linking
if(WIN32)
    # Windows libraries
    target_link_libraries(windows_exploitation kernel32 advapi32 ntdll)
    target_link_libraries(process_injection kernel32 advapi32)
    target_link_libraries(windows_payloads kernel32 advapi32 shell32 ole32)
    target_link_libraries(network_ops ws2_32 iphlpapi)
elseif(APPLE)
    # macOS libraries
    target_link_libraries(kernel_exploitation System)
    target_link_libraries(linux_payloads System)
    target_link_libraries(macos_payloads System)
    target_link_libraries(process_injection System)
else()
    # Linux libraries
    target_link_libraries(kernel_exploitation pthread)
    target_link_libraries(linux_payloads pthread)
    target_link_libraries(memory_ops m)
    target_link_libraries(network_ops m)
endif()

# Create combined library
add_library(polygottem_c_methods SHARED
    exploitation/privilege_escalation.c
    exploitation/memory_exploitation.c
    exploitation/kernel_exploitation.c
    exploitation/windows_exploitation.c
    utilities/process_injection.c
    utilities/system_manipulation.c
    utilities/anti_analysis.c
    utilities/obfuscation.c
    native/cryptography.c
    native/memory_operations.c
    native/network_operations.c
    native/compression.c
    payloads/windows_payloads.c
    payloads/linux_payloads.c
    payloads/macos_payloads.c
)

# Platform-specific linking for combined library
if(WIN32)
    target_link_libraries(polygottem_c_methods kernel32 advapi32 ntdll ws2_32 iphlpapi)
elseif(APPLE)
    target_link_libraries(polygottem_c_methods System pthread m)
else()
    target_link_libraries(polygottem_c_methods pthread m)
endif()

# Export configuration
set_target_properties(polygottem_c_methods PROPERTIES
    PUBLIC_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/polygottem_c.h"
    VERSION ${PROJECT_VERSION}
    SOVERSION 2
)

# Installation targets
install(TARGETS polygottem_c_methods
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)

install(DIRECTORY include/ DESTINATION include)

# Print configuration summary
message(STATUS "=== POLYGOTTEM C Methods Build Configuration ===")
message(STATUS "Platform: ${PLATFORM_NAME}")
message(STATUS "CMake Version: ${CMAKE_VERSION}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Output Directory: ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}")
message(STATUS "================================================")
