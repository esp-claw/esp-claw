# wasm_runtime_terminate() can only stop running app code (call budgets) when WAMR is built with
# its thread manager. WAMR's ESP-IDF Kconfig has no switch for it except lib-pthread, which would
# also expose pthread_create to apps, so enable just the thread manager here; project_include.cmake
# runs in the project scope before the WAMR component's CMakeLists.txt reads it.
if(CONFIG_APP_CLAW_CAP_WASM_APPS)
    set(WAMR_BUILD_THREAD_MGR 1)
endif()
