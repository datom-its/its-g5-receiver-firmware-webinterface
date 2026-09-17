idf_component_register(
    SRCS
        "main.c"
        "ble_cache.c"
        "bt_stream.c"
        "cmd_sniffer.c"
        "cmd_pcap.c"
        "config.c"
        "ethernet.c"
        "events.c"
        "events_log.c"
       "tracklog.c"
        "inventory.c"
        "ptlog.c"
        "its_decode.c"
        "led.c"
        "mqtt.cpp"
        "ota.c"
        "sdcard.c"
        "sdlog.c"
        "sdpcap.c"
        "stats.c"
        "spatem.c"
        "spi.c"
        "spi_eppp.c"
        "sysmon.c"
        "sysstat.c"
        "temperature.c"
        "web_strings.c"
        "web_tar.c"
        "web_files.c"
        "web_settings.c"
        "web_system.c"
        "web_traffic.c"
        "webserver.c"
    PRIV_REQUIRES
        app_trace
        bt
        app_update
        console
        esp_coex
        esp_eth
        esp_http_server
        esp_https_ota
        esp_netif
        esp_wifi
        esp_system
        espcoredump
        fatfs
        mdns
        nvs_flash
        spi_flash
    INCLUDE_DIRS
        "."
    EMBED_FILES
        "assets/favicon.png"
        "assets/apple-touch-icon.png"
        "assets/icon-192.png"
        "assets/icon-512.png"
        "assets/logo-52.png"
)

# The three big web assets ship pre-compressed. Generating the .gz here keeps
# the embedded copy in step with its source, and only the .gz reaches flash.
idf_build_get_property(python PYTHON)
foreach(asset "leaflet.js" "leaflet.css" "s.css")
    string(MAKE_C_IDENTIFIER "${asset}_gz" asset_sym)
    add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${asset}.gz"
        COMMAND "${python}" "${CMAKE_CURRENT_LIST_DIR}/gzip_asset.py"
                "${CMAKE_CURRENT_LIST_DIR}/assets/${asset}"
                "${CMAKE_CURRENT_BINARY_DIR}/${asset}.gz"
        MAIN_DEPENDENCY "${CMAKE_CURRENT_LIST_DIR}/assets/${asset}"
        DEPENDS "${CMAKE_CURRENT_LIST_DIR}/gzip_asset.py"
        COMMENT "Compressing ${asset}")
    target_add_binary_data(${COMPONENT_LIB} "${CMAKE_CURRENT_BINARY_DIR}/${asset}.gz" BINARY
        RENAME_TO ${asset_sym}
        DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/${asset}.gz")
endforeach()
