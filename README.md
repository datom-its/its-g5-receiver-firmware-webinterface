# ITS-G5 Receiver Firmware (Web-UI Fork)

Modified firmware for the **opentrafficmap ITS-G5 receiver** (official board,
HW variant `i5r-r1`) — a passive 802.11p / ITS-G5 (V2X) sniffer on ESP32-C5 that
forwards raw frames over MQTT. This fork adds a built-in web interface and a few
bug fixes on top of the upstream firmware.

Upstream base: https://codeberg.org/opentrafficmap/its-g5-receiver-firmware

## Version history

Newest first. The app version comes from `version.txt` (scheme `<base>-webui`);
each build is archived (bins + source) under `~/esp/releases/<version>/`.

| Version       | Changes |
|---------------|---------|
| **0.7.1-webui** | Security hardening for the SD card manager: `/sdcard` (browsing) and `/sdcard/download` now require the web password like the other write actions do; fixed a reflected-XSS in the path breadcrumb (`?p=` was rendered unescaped); rejected control characters (CR/LF) in paths/filenames to prevent HTTP response header injection via `Content-Disposition`. |
| **0.7.0-webui** | SD card manager in the web interface: new `/sdcard` page to browse folders/files, see storage usage, upload files, delete files, and format the card. The card is auto-mounted at boot. Write actions honour the web password. |
| **0.6.5-webui** | Status page now reports internal SRAM and PSRAM free heap separately. Previously "free heap" summed all regions, so the 8 MB PSRAM hid the scarce internal RAM (it always read ~8 MiB). |
| **0.6.4-webui** | Fix garbled German umlauts in JS dialogs / plain-text responses: the "uploading", "reboot the device?" and "confirmed" messages showed `&auml;` literally because they are set via `innerText`/`confirm()`/`alert()`, which don't decode HTML entities. |
| **0.6.3-webui** | Web password field on `/settings`: set or remove the `webpasswd` protection directly from the browser (previously console only). |
| **0.6.2-webui** | NTP time sync. `/messages` now shows the real local wall-clock time (`HH:MM:SS`, Europe/Berlin) once synced, instead of a device-relative `seconds.ms` value. |
| **0.6.1-webui** | "Confirm update" button on the status page, so a web/OTA update can be confirmed (rollback cancelled) from the browser. |
| **0.6.0-webui** | First web-UI firmware: status dashboard, `/messages`, `/settings`, browser `/update` (OTA), optional password protection. Round-1 bug fixes: sniffer format-string bugs, OTA reentrancy guard, swapped config case labels. |

> Keep this table up to date: every new build must add a row here.

## Web interface

Once the device has an IP address, a built-in web interface is available on
port 80. German by default; append `?lang=en` (or use the language link) for
English.

- `/` — status dashboard: node ID, MAC, firmware version, sniffer state, active
  channel, MQTT status, uptime, packets received, packet rate (last 60 s), free
  heap, temperature. Auto-refreshes every 5 s; Start/Stop sniffer and Reboot
  buttons. If the running firmware was installed via update and not yet
  confirmed, a banner with a **Confirm update** button appears here.
- `/messages` — the last 20 received frames (time, RSSI, length, hex preview),
  newest first, auto-refreshing. Times are real local `HH:MM:SS` once NTP has
  synced (see 0.6.2).
- `/settings` — view and change node ID, MQTT URI, autostart channel, LED
  brightness (applied live) and the web password, all from the browser. Saved to
  NVS.
- `/update` — upload a `.bin` from the browser to flash the inactive OTA
  partition; the device reboots into it.

### Update confirmation (rollback)

After a web/OTA update the new firmware must be confirmed within **30 minutes**,
otherwise the device automatically rolls back to the previous version. Confirm
via the status-page button, or `ota --confirm` on the console.

### Password protection

By default `/update` and the `/settings` write action are open to anyone on the
network. To require a password (HTTP Basic Auth, username `admin`), either:

- set it on the **`/settings`** page (Web password field), or
- run on the serial console:
  ```
  config_set webpasswd <your-password>
  ```

Leave the field empty to keep the current password; tick "remove password
protection" (or `config_clear webpasswd`) to disable it again. The status and
message pages remain unauthenticated.

> Note: the web interface is plain HTTP on port 80 and Basic Auth is only
> base64-encoded, so the password travels in clear text on the LAN.

## Hardware

- Chip: **ESP32-C5** (RISC-V)
- Ethernet: **KSZ8851SNL** (SPI) — not W5500/ENC28J60; the upstream
  `sdkconfig.proto-*` files do **not** match this board.
- Flash: **8 MB**, partition table `partitions_8M.csv` (A/B OTA slots).
- The correct board config lives in the project's `sdkconfig`
  (`HW_VARIANT=i5r-r1`, 8 MB, `partitions_8M.csv`). Do **not** let
  `idf.py set-target` overwrite it.

## Flashing a pre-compiled firmware

The easiest way is the web interface (`/update`). To flash over serial instead,
use the four `.bin` files from a release folder:
```
esptool --chip esp32c5 -p /dev/ttyACM0 -b 921600 --before=default-reset --after=hard-reset \
  write-flash --flash-mode dio --flash-freq 80m --flash-size 8MB \
  0x2000  bootloader.bin \
  0x8000  partition-table.bin \
  0x1e000 ota_data_initial.bin \
  0x20000 its-g5-receiver-firmware.bin
```
Replace the serial port with the one where the ESP is connected. This requires
the ESP-IDF environment for the `esptool` command.

## Building

This project needs ESP-IDF at the exact upstream commit `12f36a021f`
(a v6.1-dev snapshot) and Python 3.10+. Stable releases (v5.5.x) do **not** work
unmodified, because the project uses v6.1-only APIs.

```
. ~/esp/esp-idf/export.sh      # once per shell
cd ~/esp/its-g5-receiver-firmware
idf.py build                   # do NOT run set-target (it overwrites sdkconfig)
```

If you get an "app partition too small" error, the sdkconfig was reset to the
1 MB default — restore the correct `sdkconfig` (8 MB + `partitions_8M.csv` +
`i5r-r1`), `rm -rf build`, and rebuild.
