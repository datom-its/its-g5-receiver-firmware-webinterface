# ITS-G5 Receiver Firmware (Web-UI Fork)

Modified firmware for the **opentrafficmap ITS-G5 receiver** (official board)
— a passive 802.11p / ITS-G5 (V2X) sniffer on ESP32-C5 that forwards raw frames
over MQTT. This fork adds a built-in web interface, a live map, on-device PCAP
recording with playback, and optional Bluetooth streaming to a phone.

Upstream base: https://codeberg.org/opentrafficmap/its-g5-receiver-firmware

![Status page](docs/screenshot-status.png)

*Status page. The node ID and MAC address are masked in this screenshot.*

![File management](docs/screenshot-files.png)

*File management: flash partitions and the SD card.*

## Download

Pre-compiled binaries are available under
[**Releases**](https://codeberg.org/datom/its-g5-receiver-firmware-webinterface/releases)
— the newest release is at the top of that page. Download
`its-g5-receiver-firmware.bin` and flash it via the web interface (`/update`),
or grab all four `.bin` files for an initial flash over USB (see below).
No build environment needed.

> ⚠️ **Coming from the original opentrafficmap firmware, or from 0.16.0 or
> earlier, flash all four `.bin` files once over USB** (see
> [Flashing a pre-compiled firmware](#flashing-a-pre-compiled-firmware)). This
> fork's partition table adds a `coredump` partition, and a web `/update` OTA
> writes only the app slot. After one USB flash, updates go over the web
> interface as usual.

## Version history

Newest first.

| Version       | Changes |
|---------------|---------|
| **0.29.0-webui** | New look for the whole web interface: no framed cards, values under small labels with a status dot, the stylesheet in a cached file. Red-amber has its own column on `/traffic`, warnings record their sender, and the SD card bulk delete works again. General bug fixes. |
| **0.28.0-webui** | The Bluetooth branch is merged in. BLE live streaming of received frames is part of this build, off by default and switched on under `/settings`. With it off the radio stays on 802.11p alone and 8 KB more internal memory is free than before. With it on, BLE and reception share the one radio, so frames are missed. |
| **0.27.7-webui** | The "confirm update" banner now appears on every page, not just the status page. Confirming is behind the web password, where one is set. Tables inside the new boxes are shaded, and the SD line reads "12.3 GB of 59.5 GB used" instead of two bare numbers. |
| **0.27.6-webui** | `/traffic` is split into boxes: traffic lights, hourly statistics and warnings. Each intersection gets its own box with its phases and measured switching times. The status page shows SD card usage instead of the hardware variant. |
| **0.27.5-webui** | Reboot and power-off now sit behind the web password, where one is set, like the firmware update. Settings that were rejected are reported separately from those that were saved. On `/transit`, the zero-deviation column is called "no value", with a footnote on what it counts. |
| **0.27.4-webui** | The floating unsaved-changes bar gets a "Save & reboot" button, for settings that only take effect after a restart. |
| **0.27.3-webui** | Reboot button on `/settings`. The page shown during a restart polls the device and reloads itself once it answers. |
| **0.27.2-bt** | *On the `experimental` branch, not on `main`.* Adds a Bluetooth Low Energy live stream of received frames, so a phone app can show them without a network in between. Bluetooth is off by default, and with the switch off this firmware behaves exactly like the release above. Only while it is switched on does the receiver have to share its single radio, which costs capture rate — `BLUETOOTH.md` on that branch has the numbers. The BLE code is adapted from [V2Xtend](https://github.com/githubapache2/V2Xtend) and, through it, [V2X2MAP](https://github.com/pit711/V2X2MAP), both MIT — see `NOTICE`. |
| **0.27.2-webui** | Frees 36 KB of internal memory by switching off JTAG application tracing. The `pcap` console command writes to the SD card instead. The freed memory goes to the network stack, the web server and the SD writer. |

Older entries, back to the first web-UI firmware, are in [CHANGELOG.md](CHANGELOG.md).

## Web interface

Once the device has an IP address, a built-in web interface is available on
port 80. It is in German. The flags in the top right corner switch to English.

- `/` — status dashboard: frames received, rate over the last minute, uptime,
  active channel, sniffer state, MQTT, SD card usage, temperature, node ID, MAC
  and firmware version. A sparkline draws the last minute of traffic, and every
  other receiver on the network gets a row with its rate and uptime.
  Start/Stop sniffer, reboot and power-off buttons. If the running firmware was
  installed via update and not yet confirmed, a banner with a **Confirm update**
  button appears here.
- `/messages` — the last 20 received frames (time, RSSI, length, type, hex
  preview), newest first, live over WebSocket. Times are real local `HH:MM:SS`
  once NTP has synced (see 0.6.2).
- `/map` — live map of decoded positions: vehicles (from CAM) and stationary
  senders such as traffic lights / RSUs (from the GeoNetworking layer), one
  emoji marker per station type, clickable for details (and km/h for
  vehicles). A **from/to time range + Load** control below the map replays
  positions recorded in the PCAP files (see `/settings`) with a slider and a
  play button; a **Live** button returns to the real-time feed. Map tiles
  need the browser to have internet access (OpenStreetMap) — the device
  itself does not.
- `/traffic` — how many vehicles of each category were seen per hour, rolled up
  per day beyond 48 hours. Green, red-amber, amber and red phase durations are
  measured from the traffic lights themselves, and a chip says how long the
  current phase has been running. Stored warnings are listed with the station
  that sent them and, over a window longer than a day, as a profile by hour of
  day and by weekday.
- `/senders` — every stationary sender heard (traffic light or roadside unit),
  with the message types it transmits, signal level, position, radio address
  and how long it has been known. Vehicles use locally administered addresses
  and roadside units carry a vendor prefix, so the two are easy to tell apart.
  Survives restarts on the SD card and can be reset.
- `/transit` — the public-transport telegrams (VDV R09) decoded into passages
  per line, schedule deviation, headway, operating hours, the two most common
  destinations, and a log of individual passages.
- `/settings` — view and change node ID, MQTT URI, autostart channel, LED
  brightness (applied live), the web password, network (DHCP / static IP /
  DNS), NTP server, SD logging, and **rolling PCAP capture** (off by default:
  raw frames to `/sdcard/pcap/`, with retention hours + a storage ceiling),
  and **Bluetooth** (off by default; see below). Saved to NVS.
- `/update` — upload a `.bin` from the browser to flash the inactive OTA
  partition; the device reboots into it.
- `/system` — chip/CPU info, ESP-IDF version, last reset reason, uptime,
  internal + PSRAM memory, and a per-task CPU-load table. Shows a banner with
  a download/delete link if a crash dump is available.
- `/sdcard` — browse the SD card, sort by name or size, walk back up through
  the path line, see usage, upload/delete files (single or multi-select),
  download files/folders as a `.tar`, format the card
  (requires the web password). Recorded PCAP files live under `/sdcard/pcap/`
  and can be downloaded here and opened in Wireshark/tshark.
- `/logs` — view the SD log files (`system.log`, `frames.csv`) inline in the
  browser, filter them down to warnings and errors, search them, or reach the
  previous log file. Logging is toggled on `/settings`.

`/messages` and `/map` update over a WebSocket. The other pages fetch
themselves again on a timer, with a pause button in the corner. Setting the
interval to `0` on `/settings` switches that off.

### Bluetooth (off by default)

The receiver can stream decoded frames to a phone over Bluetooth Low Energy.
Off by default. Switch it on under `/settings` and restart.

The board has one radio, so BLE and 5.9 GHz reception take turns. With
Bluetooth on, about a quarter of frames are missed, and about half while a
phone is connected. SD recording and MQTT keep running, with gaps in them.
`/system` shows how long reception has been paused.

### Update confirmation (rollback)

After a web/OTA update the new firmware must be confirmed within **30 minutes**,
otherwise the device automatically rolls back to the previous version. Confirm
via the status-page button, or `ota --confirm` on the console.

### Password protection

By default `/update`, reboot, power-off and the `/settings` write action are
open to anyone on the network. To require a password (HTTP Basic Auth, username `admin`), either:

- set it on the **`/settings`** page (Web password field), or
- run on the USB console:
  ```
  config_set webpasswd <your-password>
  ```

Leave the field empty to keep the current password; tick "remove password
protection" (or `config_clear webpasswd`) to disable it again. The status, map
and message pages remain unauthenticated. Forgetting the password: run
`config_clear webpasswd` on the USB console, then set a new one.

> Note: the web interface is plain HTTP on port 80 and Basic Auth is only
> base64-encoded, so the password travels in clear text on the LAN. The
> password itself is stored as a salted hash, not plaintext.

## PCAP recording & playback

When **rolling PCAP capture** is enabled on `/settings`, received 802.11p
frames are written to the SD card under `/sdcard/pcap/`, one file per hour
(`pcap-YYYYMMDD-HHMMSS.pcap`), and old files are pruned by age (retention
hours) and by a total-size ceiling. The files are standard
`LINKTYPE_IEEE802_11` pcap — open them directly in **Wireshark** or **tshark**
to inspect any frame down to the GeoNetworking / C-ITS layer.

The **map playback** control on `/map` reads those same files back on the
device: pick a from/to time range, click **Load**, and scrub or auto-play the
recorded positions over the map. Capture is off by default because
continuous SD writes have a real flash-wear/capacity cost on an unattended
field device.

## Hardware

- Chip: **ESP32-C5** (RISC-V)
- Ethernet: **KSZ8851SNL** over SPI on this board. The `sdkconfig.proto-*`
  files build for the W5500 and ENC28J60 prototypes instead. The network-LED
  switch is KSZ8851SNL-only and is hidden in those builds.
- The SD card shares the SPI bus with the Ethernet controller. That bus is
  timing-sensitive under concurrent traffic. The SD clock runs at the 20 MHz
  default.
- Flash: **8 MB**, partition table `partitions_8M.csv` (A/B OTA slots plus a
  small coredump partition).
- The correct board config lives in the project's `sdkconfig`
  (`HW_VARIANT=i5r-r1`, 8 MB, `partitions_8M.csv`). Do **not** let
  `idf.py set-target` overwrite it.

## Flashing a pre-compiled firmware

The easiest way is the web interface (`/update`). To flash over USB instead,
use the four `.bin` files from a release folder:
```
esptool --chip esp32c5 -p /dev/ttyACM0 -b 921600 --before=default-reset --after=hard-reset \
  write-flash --flash-mode dio --flash-freq 80m --flash-size 8MB \
  0x2000  bootloader.bin \
  0x8000  partition-table.bin \
  0x1e000 ota_data_initial.bin \
  0x20000 its-g5-receiver-firmware.bin
```
Replace the port with the one the board shows up as. This requires
the ESP-IDF environment for the `esptool` command.

> A firmware that changes the partition table (like 0.20.0, which adds the
> coredump partition) must be flashed once over USB with all four `.bin`
> files; the web `/update` only ever writes the app slot. Routine updates
> afterwards can go back to the web interface.

## Building

This project needs ESP-IDF at the exact commit `0d928780081`, a snapshot of the
`release/v6.1` line, and Python 3.10+. Stable releases (v5.5.x) do **not** work
unmodified, because the project uses v6.1-only APIs, and the 802.11p
promiscuous-mode hack is sensitive to Wi-Fi-stack changes, so the pin is
deliberate.

```
. ~/esp/esp-idf/export.sh      # once per shell
cd ~/esp/its-g5-receiver-firmware
idf.py build                   # do NOT run set-target (it overwrites sdkconfig)
```

If you get an "app partition too small" error, the sdkconfig was reset to the
1 MB default — restore the correct `sdkconfig` (8 MB + `partitions_8M.csv` +
`i5r-r1`), `rm -rf build`, and rebuild.
