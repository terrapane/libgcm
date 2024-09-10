# Enable fetching content
include(FetchContent)

# Set the root of the Terrapane source repositories
if(DEFINED ENV{TERRAPANE_SOURCE_URI})
    set(TERRAPANE_SOURCE_URI "$ENV{TERRAPANE_SOURCE_URI}")
else()
    set(TERRAPANE_SOURCE_URI "https://github.com/terrapane")
endif()

if(libgcm_BUILD_TESTS)
    # Fetch the Simple Test Framework library
    FetchContent_Declare(stf
        GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/stf.git
        GIT_TAG        v1.0.0
        GIT_SHALLOW    true)

    # It is not necessary to install the STF library
    set(stf_INSTALL OFF)

    # Make dependencies available
    FetchContent_MakeAvailable(stf)
endif()

# Fetch and make available security-related utility functions
FetchContent_Declare(secutil
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/secutil.git
    GIT_TAG        v1.0.1
    GIT_SHALLOW    true)

# Fetch and make available bit-oriented utility functions
FetchContent_Declare(bitutil
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/bitutil.git
    GIT_TAG        v1.0.0
    GIT_SHALLOW    true)

# Fetch and make available the AES library
FetchContent_Declare(libaes
    GIT_REPOSITORY ${TERRAPANE_SOURCE_URI}/libaes.git
    GIT_TAG        v1.0.1
    GIT_SHALLOW    true)

# Make dependencies available
FetchContent_MakeAvailable(secutil bitutil libaes)
