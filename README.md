# ITS-G5 Receiver Firmware (Web-UI Fork)

Modified firmware for the **opentrafficmap ITS-G5 receiver**. The device is a
passive 802.11p / ITS-G5 (V2X) sniffer on an ESP32-C5. It listens to what
vehicles and roadside units broadcast around it and forwards the raw frames
over MQTT.

This fork adds a web interface, a live map, PCAP recording on the device with
playback, and Bluetooth streaming to a phone.

Upstream base: https://codeberg.org/opentrafficmap/its-g5-receiver-firmware

![Status page](docs/screenshot-status.png)

*The **Status** page. The node ID and MAC address are masked in this
screenshot.*

![File management](docs/screenshot-files.png)

*The **Files** page: flash partitions and the SD card.*

## Download

Pre-compiled binaries are under [**Releases**](https://codeberg.org/datom/its-g5-receiver-firmware-webinterface/releases).
A device that already runs this fork takes `its-g5-receiver-firmware.bin`
alone. Download it and flash it in the web interface under
**Firmware Update**. A first flash needs all four `.bin` files over USB (see
below). Neither way needs a build environment.

> ⚠️ **The first flash from the original opentrafficmap firmware has to go
> over USB with all four `.bin` files** (see
> [Flashing a pre-compiled firmware](#flashing-a-pre-compiled-firmware)). This
> fork's partition table adds a `coredump` partition, and a web update
> writes only the app slot. Every update after that goes over the web
> interface.

## Version history

Newest first.

| Version       | Changes |
|---------------|---------|
| **0.30.5-webui** | Built on ESP-IDF v6.1. The log page now also includes the device's console: the last 64 messages, kept in RAM and readable with no card in the slot. The file page names the reason a card is not in use. Formatting a card no longer stops the log and the recording. |
| **0.30.0-webui** | The status page draws the last hour of traffic and temperature. Destructive buttons are red outlines now, long explanations fold away, and the long pages carry a jump bar. The dark map draws the OpenStreetMap tiles inverted in the browser, instead of the CARTO ones it used before. General bug fixes. |
| **0.29.0-webui** | New look for the whole web interface: no framed cards, values under small labels with a status dot, the stylesheet in a cached file. Red-amber has its own column on `/traffic`, warnings record their sender, and the SD card bulk delete works again. General bug fixes. |
| **0.28.0-webui** | The Bluetooth branch is merged in. BLE live streaming of received frames is part of this build, off by default and switched on under `/settings`. With it off the radio stays on 802.11p alone and 8 KB more internal memory is free than before. With it on, BLE and reception share the one radio, so frames are missed. |
| **0.27.7-webui** | The "confirm update" banner now appears on every page, not just the status page. Confirming is behind the web password, where one is set. Tables inside the new boxes are shaded, and the SD line reads "12.3 GB of 59.5 GB used" instead of two bare numbers. |
| **0.27.6-webui** | `/traffic` is split into boxes: traffic lights, hourly statistics and warnings. Each intersection gets its own box with its phases and measured switching times. The status page shows SD card usage instead of the hardware variant. |
| **0.27.5-webui** | Reboot and power-off now sit behind the web password, where one is set, like the firmware update. Settings that were rejected are reported separately from those that were saved. On `/transit`, the zero-deviation column is called "no value", with a footnote on what it counts. |
| **0.27.4-webui** | The floating unsaved-changes bar gets a "Save & reboot" button, for settings that only take effect after a restart. |
| **0.27.3-webui** | Reboot button on `/settings`. The page shown during a restart polls the device and reloads itself once it answers. |

Older entries, back to the first web-UI firmware, are in
[CHANGELOG.md](CHANGELOG.md).

## Web interface

The device serves a web interface on port 80 as soon as it has an IP address.
It is in German. The flags in the top right corner switch to English.

- **Status** — frames received, the rate over the last minute, uptime, active
  channel, sniffer state, MQTT, SD card usage, temperature, node ID, MAC and
  firmware version. A sparkline draws the last minute of traffic. Two charts
  below it draw the last hour, one for frames, one for temperature. A block
  "Message types since power-on" keeps a counter per message type. Receivers
  entered under **Settings** get a row each with node, rate, uptime and MQTT
  state. The browser asks them directly, not through this device. Buttons
  start and stop the sniffer, reboot and power off. Firmware installed by
  update shows a banner with a **Confirm update** button until it is
  confirmed.
- **Messages** — the last 20 frames received, newest first: time, RSSI,
  length, type, sender MAC and a decoded summary in one line. They arrive over
  a WebSocket. Times are real local `HH:MM:SS` once NTP has synced. A text
  field above the table filters the rows while you type. Two more boxes read
  the PCAP recording and need it switched on. One searches it over a time
  range, filtered by message type, sender address or station ID, and the hits
  download as a `.pcap`. Search and export both cover at most 24 hours. The
  search lists 200 rows at most, and the export stops at 4 MB and puts
  `GEKUERZT` in the file name when it does. The other box sends recorded
  traffic lights and roadside units to opentrafficmap over MQTT, thinned to
  one frame per station and message type, one an hour, or one every ten
  minutes.
- **Map** — where the senders are. Vehicles come from CAM messages. Traffic
  lights and roadside units come from the position in the GeoNetworking layer.
  Each station type has its own symbol. A click opens the details: type, time,
  RSSI, km/h for vehicles, and for buses and trams the line, the destination
  and the delay they report. The popup also shows signal-phase chips and the
  active hazard warnings. A marker disappears once nothing new has arrived
  from it for the hold time set under **Settings**. The map loads the lane
  geometry of the intersections and recolours it every three seconds to the
  running signal phase. The layer control offers four base maps: dark, map,
  light and satellite. Two overlays add the recorded vehicle tracks and the
  tracks of the other receivers. A from/to range and **Load** under the map
  replay positions out of the PCAP recording, with a slider, a step control
  and a play button. **Live** returns to the current feed. The tiles come from
  OpenStreetMap and from Esri/ArcGIS Online. The browser fetches them, the
  device does not.
- **Traffic** — what was received per hour, split by road user: car, bus,
  truck, two-wheeler, pedestrian, traffic light/RSU, other. The vehicle
  columns count distinct radio identifiers rather than messages, which at a
  pass-through point is roughly the number of vehicles. The ETSI standard lets
  a vehicle change its identifier mid-journey. The number stays a lower bound.
  `≥` marks something else: the hour's counting table was at least three
  quarters full (it holds 2048 identifiers), or a restart split the hour. The
  figures roll up per day beyond 48 hours, and each class then contributes its
  busiest hour instead of the day's sum. The table also gives average and top
  speed. Every intersection then lists its signal groups with the number of
  green phases and the measured durations of green, red-amber, amber and red,
  taken from the traffic lights themselves. A chip says how long the current
  phase has been running. The DENM warnings come last with the station that
  sent them, at most the newest 256. Over a window longer than a day they also
  appear as a profile by hour of day and by weekday. The window is 24 hours, 7
  days or 30 days.
- **Senders** — every traffic light and roadside unit the device has heard,
  one row each: name, ID and MAC, the message types it sends, frame count,
  signal level as lowest…highest with an average, position, first seen and
  last seen. Vehicles are not listed. They swap their identifier as they
  drive, so each row would be a pseudonym rather than a car. Their frames are
  only counted, and that count restarts with the device. With a card the list
  is written to `/sdcard/logs/senders.csv` every five minutes and survives a
  restart. Without one it starts empty at every boot. It holds 128 senders and
  says so when it is full. A button resets it.
- **Transit** — the VDV R09 telegrams from passing buses and trams. Per line:
  sightings, average deviation from the timetable, worst delay, worst early
  arrival, a "no value" count for messages without a deviation figure, and
  when it was last seen. The radio format encodes at most ±7 minutes. Values
  at that limit are marked. A passage counts as open until 90 seconds after
  its last message. The passage table follows with time, line, course,
  destination, deviation and how long the vehicle stayed in range. Headway,
  operating hours and the two most common destinations are worked out from the
  stored passages.
- **Settings** — everything the device lets you change. Node ID and MQTT URI.
  Network: DHCP or a static address with netmask, gateway and up to three DNS
  servers, plus the NTP server. Radio: the channel to start on, and whether to
  keep broadcast frames only. LED brightness and a fixed colour, both applied
  straight away, and the Ethernet port's own link LEDs. The web password. The
  auto-refresh interval of the pages. SD logging with a size budget. Rolling
  PCAP capture, off by default, with retention hours, a size ceiling, the
  buffer it fills in PSRAM before writing, how often it writes at the latest,
  and a filter that thins traffic-light messages out or keeps vehicles and
  warnings only. How long traffic statistics and warnings are kept. How long a
  map marker stays without an update. The other receivers whose vehicles
  belong on the map. Vehicle track recording and its retention in days. And
  Bluetooth, off by default. Settings are kept in flash and survive a restart.
  The page also offers **Save & reboot** and a reboot button of its own.
- **Firmware Update** — upload a `.bin` from the browser into the inactive OTA
  slot. The device reboots into it.
- **System** — chip, cores, CPU clock, flash size, ESP-IDF version, IP address
  and the last reset reason. A stability box counts reboots, crashes, the last
  crash and the longest uptime, and a button resets those counters. A second
  table lists what the device had to drop since it started: full receive
  buffers, a full MQTT queue, track points, lost recording, frames thinned on
  purpose, the BLE queue and its notifications, passage rows, displaced
  warnings, and the longest SD failure run and hold time. Internal RAM and
  PSRAM get a row each, as free, minimum and total. A table of tasks lists
  state, priority, CPU load and remaining stack. A banner with a download and
  a delete link appears when a crash dump is stored.
- **Files** — the internal flash and the SD card. Sort by name or size, move
  back up through the path line, see how full it is, upload and delete files
  singly or several at once, download files and folders as a `.tar`, and
  format the card. The flash partition table is above the card. A partition
  label opens the internal filesystem, and each partition downloads as an
  `.img`. The whole page needs the web password, where one is set. Recorded
  PCAP files are under `/sdcard/pcap/` and open in Wireshark or tshark.
- **Logs** — the log files from the card, `system.log` and the previous
  `system.1.log`, shown in the browser. A filter narrows them down to warnings
  and errors, a search box finds text, and a link opens the previous file.
  Logging is switched on under **Settings**. The device's own console follows
  underneath: the last 64 messages, held in RAM. They are there even with no
  card in the slot.

**Messages** and **Map** update over a WebSocket. **Status**, **System** and
**Traffic** reload themselves on a timer, with a pause button in the corner.
No other page refreshes on its own. Setting the interval to `0` under
**Settings** switches the timer off.

### Bluetooth (off by default)

The device can stream the raw frames to a phone over Bluetooth Low Energy,
each behind a 14-byte header. It decodes a single byte, to give hazard
warnings priority in the queue. Bluetooth is off by default. Switch it on
under **Settings** and restart.

The board has one radio. BLE and 5.9 GHz reception take turns on it. About
25 % of frames are lost with Bluetooth on. About 48 % are lost while a phone
is connected. SD recording and MQTT keep running, just with gaps. **System**
counts how long reception was paused.

### Update confirmation (rollback)

Firmware installed over the web or by OTA has to be confirmed within **30
minutes**. Otherwise the device rolls back to the version it came from.
Confirm with the button on the **Status** page, or with `ota -C` on the
console.

### Password protection

Without a password, anyone on the network can use the whole device. That
covers the settings, the firmware update, reboot and power-off, starting and
stopping the sniffer, confirming an update, the clear buttons on **Senders**
and **Transit**, mounting the card, and the re-send to opentrafficmap. The
files are open too: the SD card, the internal flash, **Logs** and the PCAP
export. To require a password (HTTP Basic Auth, user name `admin`), either:

- set it on the **Settings** page, in the Web password field, or
- run on the USB console:
  ```
  config_set webpasswd <your-password>
  ```

An empty field keeps the current password. To switch the protection off, tick
"remove password protection", or run `config_clear webpasswd`. These pages
stay open either way: **Status**, **Messages**, **Map**, **Traffic**,
**Senders**, **Transit**, **System**, and the JSON data. If the password is
lost, run `config_clear webpasswd` on the USB console and set a new one.

Two writing actions stay open on purpose: resetting the stability counters and
deleting the crash dump. The archive search on **Messages** also reads without
a password, while the export next to it needs one.

> Note: the web interface is plain HTTP on port 80 and Basic Auth is only
> base64-encoded, so the password travels in clear text on the LAN. The
> password itself is stored as a salted hash, not plaintext.

## PCAP recording & playback

Switch on **rolling PCAP capture** under **Settings** and the device writes
the 802.11p frames it receives to the SD card under `/sdcard/pcap/`, one file
per hour named `pcap-YYYYMMDD-HHMMSS.pcap`. Old files go by age and by a total
size ceiling, both set on the same page. The files are ordinary
`LINKTYPE_IEEE802_11` pcap. Wireshark and tshark open them and show every
frame down to the GeoNetworking and C-ITS layer.

The playback control on **Map** reads those same files back on the device:
pick a from/to range, press **Load**, then scrub or play the recorded
positions.

Capture is off by default. Round-the-clock writing wears the card out and
fills it up. Nobody notices either one on a device out in the field.

## Machine-readable data

The device serves its own figures as JSON, without a password. I use this
myself for a separate dashboard.

- `/status.json` — the status dashboard: frames, rate, uptime, channel,
  sniffer and MQTT state, temperature, and the card — how full it is, or why
  there is none.
- `/spatem.json` — one entry per traffic light heard, with its name, revision
  and the current phase of each signal group.
- `/markers.json` — the last 20 frames out of the ring, one entry per frame,
  with or without a position. The browser groups them per station.
- `/lanes.json` — the lane geometry of the intersections, in 1e-7 degrees.
- `/tracks.json` — recorded vehicle tracks. Reads from the SD card.
- `/system.json` — uptime, CPU load and memory. Half of it is HTML meant for
  the page.

`/status.json` is built from values already in memory, except the card
figures, which it asks the filesystem for. The **Status** page itself
fetches it every five seconds. `/tracks.json` reads from the SD card on every
request. Leave a few minutes between them. `/tracks.json?days=5` asks for the
last five days, up to seven. Without the parameter you get two.

If I ever change one of these, I will note it here.

## Hardware

- Chip: **ESP32-C5** (RISC-V)
- Ethernet: **KSZ8851SNL** over SPI on this board. The `sdkconfig.proto-*`
  files build for three prototypes instead: W5500, ENC28J60 and SPI-EPPP,
  which takes its IP link from another ESP32 over SPI. The network-LED
  switch is KSZ8851SNL-only and is hidden in those builds.
- The SD card shares the SPI bus with the Ethernet controller. That bus is
  timing-sensitive under concurrent traffic. The SD clock runs at the 20 MHz
  default.
- Flash: **8 MB**, partition table `partitions_8M.csv` (A/B OTA slots plus a
  small coredump partition).
- The correct board config is in the project's `sdkconfig`
  (`HW_VARIANT=i5r-r1`, 8 MB, `partitions_8M.csv`). Do **not** let
  `idf.py set-target` overwrite it.

## Flashing a pre-compiled firmware

The easiest way is the web interface, under **Firmware Update**.
To flash over USB instead, use the four `.bin` files from a release folder:
```
esptool --chip esp32c5 -p /dev/ttyACM0 -b 921600 --before=default-reset --after=hard-reset \
  write-flash --flash-mode dio --flash-freq 80m --flash-size 8MB \
  0x2000  bootloader.bin \
  0x8000  partition-table.bin \
  0x1e000 ota_data_initial.bin \
  0x20000 its-g5-receiver-firmware.bin
```
Replace `/dev/ttyACM0` with the port your board uses. The `esptool` command
comes with the ESP-IDF environment.

> A web update only ever writes the app slot. A firmware that changes the
> partition table needs one USB flash with all four files.

## Building

This project needs ESP-IDF **v6.1** and Python 3.10+. Stable releases before
it (v5.5.x) do **not** work unmodified. The project uses v6.1-only APIs, and
the 802.11p promiscuous-mode hack reacts to changes in the Wi-Fi stack.

```
cd ~/esp/esp-idf
git checkout v6.1
git submodule update --init --recursive
./install.sh esp32c5           # once, after switching version
. ~/esp/esp-idf/export.sh      # once per shell
cd ~/esp/its-g5-receiver-firmware
idf.py build                   # do NOT run set-target (it overwrites sdkconfig)
```

An "app partition too small" error means the sdkconfig was reset to the 1 MB
default. Restore the correct `sdkconfig` (8 MB + `partitions_8M.csv` +
`i5r-r1`), run `rm -rf build`, and rebuild.
