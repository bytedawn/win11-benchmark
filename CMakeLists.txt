cmake_minimum_required(VERSION 3.10)
project(win11-benchmark)

# Specify C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add source files
set(SOURCES
    src/main.cpp
    src/command_parser.cpp
    src/benchmark_engine.cpp
    src/sections/section1/account_policies.cpp
    src/sections/section2/security_options.cpp
    src/sections/section4/restricted_groups.cpp
    src/sections/section5/system_services.cpp
    src/sections/section9/windows_firewall_section.cpp
    src/sections/section17/advanced_audit_policy_section.cpp
    src/sections/section18/
    src/sections/section19/
)

# Add include directories
include_directories(
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
)

# Create executable
add_executable(benchmark ${SOURCES})

# Link Windows libraries
target_link_libraries(benchmark
    netapi32    # For NetUserModalsGet
    advapi32    # For Registry functions
    secur32     # For security functions
)