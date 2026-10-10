idf_component_register(
    SRC_DIRS "."
    INCLUDE_DIRS "."
)

if(CONFIG_EDGE_AGENT_SYSTEM_FS_EMBEDDED)
    # Built by the edge_agent_system_fs_blob target in the project CMakeLists.txt.
    set(system_fs_bin "${CMAKE_BINARY_DIR}/system_fs.bin")
    set_source_files_properties("${system_fs_bin}" PROPERTIES GENERATED TRUE)
    target_add_binary_data(${COMPONENT_LIB} "${system_fs_bin}" BINARY DEPENDS edge_agent_system_fs_blob)
endif()
