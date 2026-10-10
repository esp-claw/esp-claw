idf_component_register(
    SRCS
        "src/cap_ssh.c"
        "src/cap_ssh_files.c"
        "src/cap_ssh_netdb.c"
        "src/cap_ssh_rules.c"
    INCLUDE_DIRS
        "include"
    REQUIRES
        claw_cap
    PRIV_REQUIRES
        cap_im_platform
        freertos
        mbedtls
        nvs_flash
)

# libssh needs a getnameinfo() that accepts lwIP's NI_* flags, see cap_ssh_netdb.c.
target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=getnameinfo" "-u __wrap_getnameinfo")

# The libssh component leaves out the SFTP client; build it here for the remote_* file tools.
idf_component_get_property(libssh_dir david-cermak__libssh COMPONENT_DIR)
set(libssh_sftp_srcs "${libssh_dir}/libssh-mirror/src/sftp.c" "${libssh_dir}/libssh-mirror/src/sftp_common.c")
target_sources(${COMPONENT_LIB} PRIVATE ${libssh_sftp_srcs})
set_source_files_properties(${libssh_sftp_srcs} PROPERTIES
    COMPILE_DEFINITIONS "WITH_SFTP;LIBSSH_STATIC"
    COMPILE_OPTIONS "-Wno-format;-Wno-int-conversion;-Wno-char-subscripts")
