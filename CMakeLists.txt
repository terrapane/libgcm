cmake_minimum_required(VERSION 3.21)

# Define the GCM Library project
project(libgcm
        VERSION 1.0.1.0
        DESCRIPTION "GCM Library"
        LANGUAGES CXX)

# Tests are built by default when this is a top-level project
if(PROJECT_IS_TOP_LEVEL)
    # Option to control whether tests are built
    option(libgcm_BUILD_TESTS "Build Tests for the GCM Library" ON)
else()
    # Option to control whether tests are built
    option(libgcm_BUILD_TESTS "Build Tests for the GCM Library" OFF)
endif()

# Option to control ability to install the library
option(libgcm_INSTALL "Install the GCM Library" ON)

# Determine whether clang-tidy will be performed
option(libgcm_CLANG_TIDY "Use clang-tidy to perform linting during build" OFF)

add_subdirectory(dependencies)
add_subdirectory(src)

include(CTest)

if(BUILD_TESTING AND libgcm_BUILD_TESTS)
    add_subdirectory(test)
endif()
