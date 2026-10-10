idf_component_register(
    SRCS
        "src/cap_system.c"
    INCLUDE_DIRS
        "include"
    REQUIRES
        claw_cap
        claw_core
        esp_netif
        esp_wifi
    PRIV_REQUIRES
        app_update
        bootloader_support
        esp_app_format
        esp_driver_tsens
        esp_event
        esp_timer
        espcoredump
        fatfs
        lwip
        nvs_flash
)

idf_component_optional_requires(PRIVATE claw_manager claw_skill cap_lua)
