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
        "priolog.c"
        "sd_csv.c"
        "sd_rcache.c"
        "spatlog.c"
        "infolog.c"
        "its_decode.c"
        "its_srem.c"
        "its_poim.c"
        "its_cpm.c"
        "cpm_geo.c"
        "cpm_store.c"
        "web_cpm.c"
        "its_security.c"
        "its_sechdr.c"
        "its_gn.c"
        "its_certcache.c"
        "its_verify.c"
        "its_msgsig.c"
        "its_trustlist.c"
        "its_castore.c"
        "its_crl.c"
        "msg_extra.c"
        "led.c"
        "mqtt.cpp"
        "mqtt_uri.c"
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
        "settings_apply.c"
        "settings_backup.c"
        "settings_json.cpp"
        "web_backup.c"
        "web_dlname.c"
        "web_system.c"
        "web_msgsig.c"
        "web_traffic.c"
        "web_infolog.c"
        "web_msgdetail.c"
        "web_sechdr.c"
        "web_gn.c"
        "web_trust.c"
        "web_faults.c"
        "web_mqtt.c"
        "web_auth.c"
        "web_csrf.c"
        "web_nav.c"
        "web_rsu.c"
        "web_glance.c"
        "web_fmt.c"
        "web_start.c"
        "web_messages.c"
        "web_map.c"
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
