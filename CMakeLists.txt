# CMakeLists.txt
# BAYAPS-FF — Build config for native components
# ALPHA XK / ALPHA يعمل

cmake_minimum_required(VERSION 3.20)
project(bayaps_ff LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Native library ─────────────────────────────────
add_library(ff_bypass SHARED
    userspace/libff_bypass.cpp
)

target_include_directories(ff_bypass PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/userspace
)

# ── Android logging ────────────────────────────────
find_library(log-lib log)
target_link_libraries(ff_bypass PRIVATE ${log-lib})

# ── Compile flags ──────────────────────────────────
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(ff_bypass PRIVATE
        -O2
        -fPIC
        -fvisibility=hidden
        -Wall
        -Wextra
        -Wno-unused-parameter
    )
    target_compile_definitions(ff_bypass PRIVATE
        LOG_TAG="ALPHA_XK"
    )
endif()

# ── Strip symbols in release ───────────────────────
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(ff_bypass PRIVATE -s)
endif()

# ── Install path ───────────────────────────────────
install(TARGETS ff_bypass
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)