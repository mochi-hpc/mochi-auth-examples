cmake_minimum_required (VERSION 3.14)

# Project name and supported languages
project (MochiAuthExample LANGUAGES C CXX)

# Set C and C++ standard
set (CMAKE_C_STANDARD 11)
set (CMAKE_CXX_STANDARD 17)
set (CMAKE_C_STANDARD_REQUIRED ON)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Add warnings
add_compile_options (-Wall -Wextra -Werror)

# Find required packages
find_package (OpenSSL REQUIRED)
find_package (PkgConfig REQUIRED)
find_package (thallium REQUIRED)

# Find pkg-config packages
pkg_check_modules (margo REQUIRED IMPORTED_TARGET margo)
pkg_check_modules (munge REQUIRED IMPORTED_TARGET munge)

# Find the sources
file (GLOB filenames ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
message (STATUS "AAA ${filenames}")

foreach (filename ${filenames})
    get_filename_component (name ${filename} NAME_WE)
    message (STATUS "Found executable to build: ${name}")
    add_executable (${name} ${filename})
    target_link_libraries (${name} PRIVATE thallium PkgConfig::munge OpenSSL::Crypto)
endforeach ()
