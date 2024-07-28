# Create the library
add_library(gcm STATIC gcm.cpp ghash.cpp)
add_library(Terra::libgcm ALIAS gcm)

# Make project include directory available to external projects
target_include_directories(gcm
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

# Specify the C++ standard to observe
set_target_properties(gcm
    PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF)

# Use the following compile options
target_compile_options(gcm
    PRIVATE
        $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>: -Wpedantic -Wextra -Wall>
        $<$<CXX_COMPILER_ID:MSVC>: >)

# Link against library dependencies
target_link_libraries(gcm PUBLIC Terra::secutil Terra::libaes)

# Install target and associated include files
if(libgcm_INSTALL)
    include(GNUInstallDirs)
    install(TARGETS gcm EXPORT gcmTargets ARCHIVE)
    install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/ TYPE INCLUDE)
    install(EXPORT gcmTargets
            FILE gcmConfig.cmake
            NAMESPACE Terra::
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/gcm)
endif()
