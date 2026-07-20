# Create the test executable
add_executable(test_aes_gcm test_aes_gcm.cpp)

# Link to the required libraries
target_link_libraries(test_aes_gcm Terra::libgcm Terra::stf)

# Specify the C++ standard to observe
set_target_properties(test_aes_gcm
    PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_EXTENSIONS OFF)

# Specify the compiler options
target_compile_options(test_aes_gcm
    PRIVATE
        $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>>:-Wpedantic -Wextra -Wall -Werror -Wconversion -Wshadow>
        $<$<CXX_COMPILER_ID:GNU>:-Wpedantic -Wextra -Wall -Werror -Wconversion -Wshadow=local>
        $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>)

# Ensure CTest can find the test
add_test(NAME test_aes_gcm
         COMMAND test_aes_gcm)

# If speed tests are enabled, pass that to the compiler
if(libgcm_SPEED_TESTS)
    target_compile_definitions(test_aes_gcm PRIVATE TERRA_ENABLE_GCM_SPEED_TESTS)
endif()
