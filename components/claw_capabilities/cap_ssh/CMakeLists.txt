idf_component_register(
    SRCS
        "src/cap_ssh.c"
        "src/cap_ssh_netdb.c"
    INCLUDE_DIRS
        "include"
    REQUIRES
        claw_cap
    PRIV_REQUIRES
        cap_im_platform
        freertos
        mbedtls
        nvs_flash
        espressif__sock_utils
)

# libssh needs a getnameinfo() that also handles AF_INET6, see cap_ssh_netdb.c.
target_link_libraries(${COMPONENT_LIB} INTERFACE "-Wl,--wrap=getnameinfo")
