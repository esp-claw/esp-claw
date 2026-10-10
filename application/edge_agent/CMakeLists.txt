cmake_minimum_required(VERSION 3.16)

include("${CMAKE_SOURCE_DIR}/tools/cmake/esp_idf_patch.cmake")
include("${CMAKE_SOURCE_DIR}/tools/cmake/flash_partition_defaults.cmake")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Local builds: derive the app version from the git tag so the firmware update check
# (which compares esp_app_desc_t.version) does not see 0.1.0. Release CI writes
# version.txt, which must win, so PROJECT_VER is only set when that file is absent.
# v0.2.6-3-gabc1234-dirty -> 0.2.6+3.gabc1234.dirty (semver build metadata, equal to 0.2.6).
if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/version.txt" AND NOT DEFINED PROJECT_VER)
    execute_process(
        COMMAND git -C "${CMAKE_CURRENT_LIST_DIR}/../.." describe --tags --dirty
        OUTPUT_VARIABLE EDGE_AGENT_GIT_DESCRIBE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    # Strip -dirty first so it cannot be mistaken for a pre-release identifier.
    string(REGEX REPLACE "-dirty$" "" EDGE_AGENT_GIT_CLEAN "${EDGE_AGENT_GIT_DESCRIBE}")
    if(EDGE_AGENT_GIT_CLEAN MATCHES "^v?([0-9]+\\.[0-9]+\\.[0-9]+(-[0-9A-Za-z.]+)?)(-([0-9]+)-(g[0-9a-f]+))?$")
        set(EDGE_AGENT_GIT_VERSION "${CMAKE_MATCH_1}")
        set(EDGE_AGENT_GIT_BUILD "")
        if(CMAKE_MATCH_3)
            set(EDGE_AGENT_GIT_BUILD "${CMAKE_MATCH_4}.${CMAKE_MATCH_5}")
        endif()
        if(NOT EDGE_AGENT_GIT_CLEAN STREQUAL EDGE_AGENT_GIT_DESCRIBE)
            string(JOIN "." EDGE_AGENT_GIT_BUILD ${EDGE_AGENT_GIT_BUILD} "dirty")
        endif()
        if(EDGE_AGENT_GIT_BUILD)
            string(APPEND EDGE_AGENT_GIT_VERSION "+${EDGE_AGENT_GIT_BUILD}")
        endif()
        string(LENGTH "${EDGE_AGENT_GIT_VERSION}" EDGE_AGENT_GIT_VERSION_LEN)
        if(EDGE_AGENT_GIT_VERSION_LEN LESS_EQUAL 31)
            set(PROJECT_VER "${EDGE_AGENT_GIT_VERSION}")
        endif()
    endif()
endif()

project(edge_agent VERSION 0.1.0)

set(EDGE_AGENT_FATFS_IMAGE_ROOT "${CMAKE_SOURCE_DIR}/fatfs_image")
set(EDGE_AGENT_FATFS_SOURCE_ROOT "${EDGE_AGENT_FATFS_IMAGE_ROOT}/storage")
set(EDGE_AGENT_FATFS_BUILD_ROOT "${CMAKE_BINARY_DIR}/fatfs_image")
set(EDGE_AGENT_FATFS_SYSTEM_SOURCE_ROOT "${EDGE_AGENT_FATFS_IMAGE_ROOT}/system")
set(EDGE_AGENT_FATFS_SYSTEM_BUILD_ROOT "${CMAKE_BINARY_DIR}/system_fs_image")
set(EDGE_AGENT_BOARD_GENERATED_CMAKELISTS "${CMAKE_SOURCE_DIR}/components/gen_bmgr_codes/CMakeLists.txt")
set(EDGE_AGENT_FATFS_STORAGE_COPY_COMMANDS "")

set(EDGE_AGENT_BOARD_FATFS_SYSTEM_COPY_COMMANDS "")

if(EXISTS "${EDGE_AGENT_BOARD_GENERATED_CMAKELISTS}")
    file(STRINGS "${EDGE_AGENT_BOARD_GENERATED_CMAKELISTS}" EDGE_AGENT_BOARD_PATH_LINE
        REGEX "^message\\(STATUS \"Board Path: .+\"\\)$"
    )

    if(EDGE_AGENT_BOARD_PATH_LINE)
        list(GET EDGE_AGENT_BOARD_PATH_LINE 0 EDGE_AGENT_BOARD_PATH_LINE)
        string(REGEX REPLACE
            "^message\\(STATUS \"Board Path: (.*)\"\\)$"
            "\\1"
            EDGE_AGENT_BOARD_PATH
            "${EDGE_AGENT_BOARD_PATH_LINE}"
        )

        set(EDGE_AGENT_BOARD_FATFS_SOURCE_ROOT "${EDGE_AGENT_BOARD_PATH}/fatfs_image")

        if(EXISTS "${EDGE_AGENT_BOARD_FATFS_SOURCE_ROOT}")
            list(APPEND EDGE_AGENT_BOARD_FATFS_SYSTEM_COPY_COMMANDS
                COMMAND ${CMAKE_COMMAND} -E copy_directory
                        "${EDGE_AGENT_BOARD_FATFS_SOURCE_ROOT}"
                        "${EDGE_AGENT_FATFS_SYSTEM_BUILD_ROOT}"
            )
        endif()
    endif()
endif()

add_custom_target(edge_agent_prepare_fatfs_image ALL
    COMMAND ${CMAKE_COMMAND} -E rm -rf "${EDGE_AGENT_FATFS_BUILD_ROOT}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${EDGE_AGENT_FATFS_BUILD_ROOT}"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${EDGE_AGENT_FATFS_SOURCE_ROOT}"
            "${EDGE_AGENT_FATFS_BUILD_ROOT}"
    ${EDGE_AGENT_FATFS_STORAGE_COPY_COMMANDS}
    VERBATIM
)

# Prepare the read-only system partition build tree: mirror the source
# system_fs_image/ into a build-side staging dir that skill/lua syncs
# can also write into before fatfsgen packs it.
add_custom_target(edge_agent_prepare_system_fs_image ALL
    COMMAND ${CMAKE_COMMAND} -E rm -rf "${EDGE_AGENT_FATFS_SYSTEM_BUILD_ROOT}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${EDGE_AGENT_FATFS_SYSTEM_BUILD_ROOT}"
    COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${EDGE_AGENT_FATFS_SYSTEM_SOURCE_ROOT}"
            "${EDGE_AGENT_FATFS_SYSTEM_BUILD_ROOT}"
    ${EDGE_AGENT_BOARD_FATFS_SYSTEM_COPY_COMMANDS}
    VERBATIM
)

if(CONFIG_EDGE_AGENT_SYSTEM_FS_EMBEDDED)
    # No system partition: pack the staging tree (minus the display fonts) into an image that
    # main embeds in the app and serves at /system (main/app_romfs.c).
    set(EDGE_AGENT_SYSTEM_FS_TARGET edge_agent_system_fs_blob)
    idf_build_get_property(python PYTHON)
    add_custom_target(edge_agent_system_fs_blob ALL
        COMMAND ${python} "${CMAKE_SOURCE_DIR}/tools/pack_system_fs.py"
                "${EDGE_AGENT_FATFS_SYSTEM_BUILD_ROOT}" "${CMAKE_BINARY_DIR}/system_fs.bin" --exclude fonts
        BYPRODUCTS "${CMAKE_BINARY_DIR}/system_fs.bin"
        VERBATIM
    )
else()
    set(EDGE_AGENT_SYSTEM_FS_TARGET fatfs_system_bin)
    fatfs_create_rawflash_image(system "${EDGE_AGENT_FATFS_SYSTEM_BUILD_ROOT}" FLASH_IN_PROJECT)
endif()
fatfs_create_spiflash_image(storage "${EDGE_AGENT_FATFS_BUILD_ROOT}" FLASH_IN_PROJECT)

# Skill / Lua resources are now baked into the read-only system partition (or the embedded
# system image) so storage can be reformatted at runtime without losing them.
skill_builder_configure_skill_sync(
    TARGET ${EDGE_AGENT_SYSTEM_FS_TARGET}
    SKILL_OUTPUT_DIR "${EDGE_AGENT_FATFS_SYSTEM_BUILD_ROOT}/skills"
)

lua_module_builder_configure_builtin_lua_sync(
    TARGET ${EDGE_AGENT_SYSTEM_FS_TARGET}
    BUILTIN_OUTPUT_DIR "${EDGE_AGENT_FATFS_SYSTEM_BUILD_ROOT}/scripts/builtin"
    DOCS_OUTPUT_DIR "${EDGE_AGENT_FATFS_SYSTEM_BUILD_ROOT}/scripts/docs"
)

add_dependencies(skill_builder_sync_skills edge_agent_prepare_system_fs_image)
add_dependencies(lua_module_builder_sync_builtin_scripts edge_agent_prepare_system_fs_image)
add_dependencies(lua_module_builder_sync_docs edge_agent_prepare_system_fs_image)
add_dependencies(${EDGE_AGENT_SYSTEM_FS_TARGET} edge_agent_prepare_system_fs_image)
add_dependencies(fatfs_storage_bin edge_agent_prepare_fatfs_image)
