# ITS-G5 Receiver Firmware (Web-UI Fork)

Modified firmware for the **opentrafficmap ITS-G5 receiver**. The device is a
passive 802.11p / ITS-G5 (V2X) sniffer on an ESP32-C5. It listens to what
vehicles and roadside units broadcast around it and forwards the raw frames
over MQTT.

Upstream base: https://codeberg.org/opentrafficmap/its-g5-receiver-firmware

![Status page](docs/screenshot-status.png)

*The **Status** page. The node ID and the names of the traffic light and
the bus line are changed in this screenshot.*

![File management](docs/screenshot-files.png)

*The **Files** page: the SD card and the flash memory of the device.*

## Features

**Receiving and decoding**
- Decodes the C-ITS messages it receives: CAM, DENM, SPATEM, MAPEM, SREM,
  SSEM, CPM, POIM, EVCSN and RTCMEM. IVIM and SAEM are recognised by type.
- Reads the GeoNetworking header: target area, hops, lifetime and traffic class.
- Reads the VDV R09 telegrams of buses and trams.
- Measures the noise floor and counts broken frames.

**Security**
- Checks each sender's certificate chain with ECDSA, up to the European trust
  lists built into the firmware, including validity and revocation.
- Checks whether the certificate allows the service and the content of a
  message.
- Checks the signature of a sample of the messages.

**Web interface** (German and English, for phone and PC)
- Live map with vehicles, traffic lights, warning areas and sensor objects,
  the recorded vehicle tracks and the vehicles of other receivers in the same
  network.
- Traffic lights with their phases and a phase history, and the priority
  requests of buses and trams with the answer of the light.
- Warnings with their state, also as a profile by hour of day and weekday.
- Traffic counts per hour by road user, over 24 hours, 7 or 30 days.
- Bus and tram lines with delay, headway and passages.
- Lists of messages, roadside units and certificates.
- The status of other receivers in the same network on the start page. The
  browser fetches it from each receiver directly.
- A bar on every page that says what is wrong and links to the page that
  helps.
- **System** page with memory, tasks, radio, network, temperature and SD card
  figures.
- Log viewer and file manager for the SD card and the internal flash.

**Recording**
- Rolling PCAP capture on the SD card, readable by Wireshark. Search, export
  and playback on the map.
- Logs of warnings, phases, priority requests, transit passages, vehicle
  tracks and traffic counts on the SD card.

**Operation**
- Forwards the raw frames over MQTT, as the original firmware does.
- On request, sends the traffic lights and roadside units of a recording to
  opentrafficmap.
- Firmware update in the browser, with automatic rollback if the new version
  does not confirm.
- Optional web password, protection against requests from other web sites,
  settings export and import, and JSON endpoints for other programs.
- Network by DHCP or a fixed address, reachable as `its-<node>.local` (mDNS).
- Restart and power-off from the browser. Time from NTP with a time zone.
- Status LED with brightness and an optional fixed color. The LEDs of the
  network socket can be switched off.
- Crash dumps, a console that keeps the lines from before a restart, and
  network counters for diagnosis.
- Keeps running without Ethernet or DHCP and recovers on its own.
- Bluetooth streaming to a phone (off by default).

## Download

Pre-compiled binaries are under [**Releases**](https://codeberg.org/datom/its-g5-receiver-firmware-webinterface/releases).
A device that already runs this fork needs `its-g5-receiver-firmware.bin`
and nothing else. Download it and flash it in the web interface under
**Firmware**. A first flash needs all four `.bin` files over USB (see below).
Neither way needs a build environment.

> ⚠️ **The first flash from the original opentrafficmap firmware has to go
> over USB with all four `.bin` files** (see
> [Flashing a pre-compiled firmware](#flashing-a-pre-compiled-firmware)). This
> fork's partition table adds a `coredump` partition, and a web update
> writes only the app slot. Every update after that goes over the web
> interface.

## Version history

Newest first.

### 0.40.0-webui

1. The device keeps running when the Ethernet chip does not answer at boot. It
   tries again after 5 s, then up to once a minute.
2. The firmware has its own copy of Espressif's KSZ8851SNL Ethernet driver in
   `components/`. Section 6 of NOTICE lists every change against the original.
3. The driver uses interrupts on the SPI bus that the Ethernet chip shares
   with the SD card. A failed SPI access no longer stops sending or
   receiving. A disturbed frame length no longer writes past the receive
   buffer.
4. The driver follows Microchip's errata sheet for the chip.
5. **System** has a new row **Network counters**. It counts pause frames sent,
   buffer overflows, CRC and symbol errors, long frames, SPI bus errors and
   wrong frame lengths since the start. `/system.json` has the same counters
   in seven new `eth_*` fields.
6. The console on **Logs** holds 256 lines from the start. It also shows the
   lines from before the last restart in their own group.
7. **System** shows "time unknown" for a crash without a recorded time, not
   "none yet".
8. A download of a file that cannot be read answers "read error", not "not
   found". The log gets a line about it.
9. The system log does not rotate while a download reads it.
10. The Ethernet chip's SPI clock is 20 MHz instead of 16.
11. The built-in revocation lists and authority certificates are from
    11 October 2026.

### 0.39.5-webui

1. New decoders for priority requests and their answers (SREM, SSEM), sensor
   objects (CPM), parking (POIM), charging stations (EVCSN) and GNSS
   corrections (RTCMEM). CAM, DENM, SPATEM and MAPEM are read further. IVIM
   and SAEM are recognised by type only.
2. The three European Certificate Trust Lists (33 root certificates), 48
   authority certificates and 24 revocation lists are built into the firmware.
3. Each sender's certificate chain is checked with ECDSA up to its root,
   including validity, revocation and whether every issuer may grant what the
   certificate below it claims. A second check asks whether the certificate
   allows the service and the content of the message.
4. A sample of the messages also gets its signature checked, using at most 5 %
   of the CPU. P-256 takes 19 ms in hardware, Brainpool 3.6 s in software.
5. Warnings show their state and twelve more fields, which also go into
   `logs/events.csv`. Relayed warnings are marked. The map draws their target
   areas and the objects reported by CPM.
6. **Traffic** shows a phase history and the priority requests of buses and
   trams with the answer of the traffic light. Both are kept on the SD card.
   **Transit** shows the signal request a bus or tram sends with its telegram.
7. New look for the web interface: four menu groups, cards instead of long
   tables on a phone, small three-lamp traffic lights, a fault bar under each
   heading and one button for all explanations. The texts are improved and
   corrected. New page **Certificates**, and **Senders** is now
   **Roadside units**.
8. Export and import of the settings as a JSON file. Without a DHCP server the
   device takes an address in 169.254.0.0/16.
9. A POST from another web site gets 403, with or without a web password.
   Scripts and `curl` work as before. No other site can show the pages in a
   frame or open the live WebSocket.
10. Trails on the map no longer jump back to the vehicle at their end. Lane
    position 14 shows as hard shoulder, and a failed SD write keeps the old
    file.

### 0.32.1-webui

1. Nothing changes on screen.
2. Every input, checkbox and drop-down on the Files, Messages, Update and Logs
   pages now carries a name, so a screen reader announces what it is.
3. Visible captions became real labels.
4. The date fields and row checkboxes carry an invisible name, so the page
   shows no wording that was not there before.
5. Both action columns had an empty header, which left their cells without
   one.
6. The partition table's Type column stayed German on the English page.
7. Every page also carries a short description.
8. On Settings all 31 fields and both drop-downs relied on the heading of
   their table row, which does not name a field either; each heading is now a
   real label.

Earlier versions:

| Version       | Changes |
|---------------|---------|
| **0.32.0-webui** | Four fixes, and three changes to the web interface. **Files** could show a wrong folder, or fail to load, when a card mounted while the page was being built. The hourly cleanup of the track log treated a read error like the end of the file. It then replaced the log with the shortened copy and lost the newest points. A traffic-light countdown above 10 minutes counted as unknown and stayed empty. The bound is now one hour, the maximum the message format can express. At a traffic-actuated junction a green phase can run for hours, and the old limit dropped those values. The GeoNetworking decoder read a GeoUnicast extended header as 44 bytes instead of 48. It also took the sender position of a multi-hop broadcast from the wrong offset, which dropped the station type. The map page also transfers about 128 KiB less: `leaflet.js`, `leaflet.css` and `s.css` are compressed when the firmware is built, and the device serves them with `Content-Encoding: gzip`. The compression frees the same amount in flash. A client that does not accept gzip gets 406, since the device cannot unpack them. The navigation bar loads its own 52-pixel logo in place of the 192-pixel app icon: 3.5 KiB per page instead of 21 KiB. And the page body sits in a `<main>` landmark, so a screen reader can skip the navigation. |
| **0.31.1-webui** | The device unmounts a card that stops taking writes and fails a test write. **System** and `/status.json` count lost PCAP frames, failed writes and these unmounts across restarts. The console on **Logs** no longer fills with temperature readings. Power-off says how much of the recording it could not write. Power-off now answers with a status code: 200 when the device is prepared, 503 while a download still streams from the card, 500 when it could not be prepared. A failed update confirmation answers with 500. An unmount waits at most 10 seconds for the card instead of forever, and a blocked card gets its own message. |
| **0.31.0-webui** | The web server is split into modules. `webserver.c` went from 10435 lines to 5536, and the texts, the tar writer, **Traffic**, **Files**, **Settings** and **System** each have their own file now. Nothing changes on the device. |
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

The device serves a web interface in German and English on port 80 as soon
as it has an IP address. Pages open in the language of the browser until you
pick the other one with the flags in the top right corner, and the browser
remembers that choice.

The menu has four groups: **Status**, Nearby (**Map**, **Traffic**,
**Transit**, **Roadside units**), Radio (**Messages**, **Certificates**) and
Device (**System**, **Logs**, **Files**, **Settings**, **Firmware**). On a
phone the long tables turn into cards. Explanations start hidden, and a button
next to the flags shows and hides them. When something is wrong, a bar under
the heading of every page says what it is and links to the page that helps:
the SD card is full, refuses data or has no usable file system, nothing has
arrived for two minutes, the clock is not set, the device has crashed, or
MQTT is disconnected.

- **Status** — frames received and the rate over the last minute, uptime,
  channel, reception, MQTT, SD card, temperature, node ID, MAC and firmware
  version. The rate turns red when nothing arrives. Charts show the last
  minute of traffic and the last hour of frames and temperature, and each
  message type has a counter of its own. A row below shows what is nearby:
  the traffic lights, the last bus or tram, the active warnings and the other
  receivers. Each receiver entered under **Settings** gets a row of its own,
  which the browser fetches from that receiver directly. Buttons start and
  stop reception, reboot the device and power it off.
- **Map** — where the senders are, each station type with its own symbol.
  Vehicles come from CAM messages, traffic lights and roadside units from
  their position in the GeoNetworking layer. A click on a marker shows type,
  time, RSSI and speed. Buses and trams add their line, destination and
  reported delay, and traffic lights their signal phases. Active hazard
  warnings show there too. A marker goes away when nothing new has come from
  it for the hold time set under **Settings**. The intersections are drawn
  lane by lane in the colour of the running signal phase. Besides four base
  maps there are up to five overlays: the recorded vehicle tracks, the tracks
  of the other receivers, the target areas of warnings, and the objects other
  stations see with their sensors (CPM) together with the area those sensors
  cover. Under the map, **Load** replays positions from the PCAP recording for
  a from/to range, and **Live** returns to the current feed. The browser loads
  the tiles from OpenStreetMap and Esri/ArcGIS Online.
- **Traffic** — the traffic lights first: each intersection with its signal
  groups, the number of green phases and the measured lengths of green,
  red-amber, amber and red. Below them come the DENM warnings, at most the
  newest 256, each with the station that raised it, its state (active,
  cancelled, withdrawn, expired or unknown) and up to twelve more fields such
  as range, direction and speed. Relayed warnings are marked. With a window
  longer than a day the warnings also appear as a profile by hour of day and
  by weekday. The priority requests of buses and trams with the answer of the
  traffic light follow, then the phase history. Both are recorded on the SD
  card, and each has its own delete button. Another section shows the newest
  message of each sender about sensor objects (CPM), charging stations
  (EVCSN), parking (POIM) and GNSS corrections (RTCMEM). The hourly table
  comes last: what was received per hour, by road user (car, bus, truck,
  two-wheeler, pedestrian, traffic light/RSU, other), with average and top
  speed. The vehicle columns count distinct station IDs. At a through road
  that comes close to the number of vehicles, though the ETSI standard lets a
  vehicle change its ID. `≥` marks a lower bound: the hour's counting table,
  which holds 2048 IDs, was at least three quarters full, or a restart split
  the hour. Beyond 48 hours there is one row per day, and each class shows its
  busiest hour. The window is 24 hours, 7 days or 30 days.
- **Transit** — the VDV R09 telegrams from passing buses and trams. Per line:
  sightings, average deviation from the timetable, worst delay, worst early
  arrival, a "no value" count for messages without a deviation figure, and
  when the line was last seen. The radio format encodes at most ±7 minutes.
  Values at that limit are marked. A passage counts as open until 90 seconds
  after its last message. The passage table follows with time, line, course,
  destination, deviation and how long the vehicle stayed in range. Headway,
  operating hours and the two most common destinations are worked out from the
  stored passages.
- **Roadside units** — every traffic light and roadside unit the device has
  heard, one row each: name, ID and MAC, the message types it sends, frame
  count, signal level, the transmit power and channel load it reports,
  position, and when it was first and last seen. A signature column shows the
  result of the certificate check, and a line under the frame count tells how
  many numbered packets went missing. Vehicles get no row, only a count of
  their frames, which restarts with the device. With a card the list is saved
  to `/sdcard/logs/senders.csv` every five minutes and survives a restart. It
  holds 128 senders, says when it is full and has a reset button. A box on the
  same page sends recorded traffic lights and roadside units to opentrafficmap
  over MQTT, thinned to one frame per station and message type, one an hour,
  or one every ten minutes.
- **Messages** — the last 20 frames, newest first, live over a WebSocket. Each
  row shows the time (local once NTP has synced), RSSI, type, sender and a
  decoded summary. A grey line underneath shows who signed the frame, the
  result of the chain check, whether the certificate allows the service and
  content, and for a sample of messages whether the signature itself is
  valid. It also gives the security header and whether the frame came
  directly or was relayed. A field above the table filters the rows as you
  type. With PCAP recording on, a search box looks through the recording by
  time range, message type, sender address or station ID, and the hits
  download as a `.pcap`. Search and export cover at most 24 hours. The search
  lists 200 rows at most, and the export stops at 4 MB and then puts
  `cut` in the file name.
- **Certificates** — the certificates the device holds, up to 512, each with
  the result of its chain check and the reason, issuer, root, validity, key,
  and how many message signatures from it were valid. Below them are the
  newest 32 checks of a message signature with sender, message, curve, result
  and the time taken. The European trust lists, 48 authority certificates and
  24 revocation lists built into the firmware come last, with their dates.
  The device does not fetch any of it from the network. Without a set clock
  it cannot judge validity, and the page says so.
- **System** — chip, cores, CPU clock, flash size, ESP-IDF version, IP
  address, the last reset reason and the state of the clock. The network
  counters of the Ethernet chip follow the IP address. A stability box
  counts reboots and crashes and shows the last crash and the longest uptime,
  and a button resets those counters and the SD losses. A table lists what the
  device had to drop since it started, such as full receive buffers, a full
  MQTT queue or failed recording writes, with the three figures that survive a
  restart in the last row. Frames thinned on purpose are counted on their own.
  The radio figures give the noise floor and the number of broken frames. The
  certificate figures count the chain checks with the start-up self test, the
  permission checks, and the message signatures with average and longest time
  per curve. RAM, PSRAM and a task list with CPU load and free stack follow. A
  banner with a download and a delete link appears when a crash dump is
  stored.
- **Logs** — the log files from the card, `system.log` and the previous
  `system.1.log`, shown in the browser with the newest lines in view. Warnings
  are coloured, and temperature messages hide behind a link. A filter narrows
  the file down to warnings and errors, a search box finds text, and a link
  opens the previous file. After a read error a note says that newer lines are
  missing. Logging is switched on under **Settings**. The device's own console
  follows underneath: up to 256 lines since the start, held in RAM. They are
  there even with no card in the slot. The lines from before the last restart
  show in their own group.
- **Files** — the SD card and the internal flash. Sort by name or size, move
  back up through the path line, see how full it is, upload and delete files
  one at a time or several at once, download files and folders as a `.tar`,
  format the card and mount it again. The flash partition table sits below the
  card. A partition label opens the internal filesystem, and each partition
  downloads as an `.img`. The whole page needs the web password, where one is
  set. Recorded PCAP files are under `/sdcard/pcap/` and open in Wireshark or
  tshark.
- **Settings** — everything the device lets you change, in groups for device,
  reception, network, links, SD card, web and security. Among them are MQTT,
  DHCP or a static address, the NTP server and the time zone, the web
  password, the refresh interval of the pages, rolling PCAP capture, vehicle
  track recording, how long statistics, warnings and tracks are kept, the
  hold time of map markers, and the other receivers whose vehicles belong on
  the map. Settings are kept in flash and survive a restart, and they export
  and import as a JSON file. The page asks before unsaved changes are lost
  and offers **Save & reboot** and a reboot button of its own.
- **Firmware** — the running version, and an upload of a `.bin` from the
  browser into the inactive OTA slot. The device reboots into it. If an update
  did not start and the device went back to the old version, the page says so.

**Messages** and **Map** update over a WebSocket. **Status**, **System** and
**Traffic** reload on a timer, which a switch in the page head pauses and an
interval of `0` under **Settings** switches off. **Traffic** keeps its open
sections and the scroll position through a reload. No other page refreshes on
its own. When the device stops answering, the live pages grey their values and
show a bar with the time of the last answer.

### Bluetooth (off by default)

The device can stream the raw frames to a phone over Bluetooth Low Energy,
each behind a 14-byte header. The device decodes a single byte to give hazard
warnings priority in the queue. Bluetooth is off by default. Switch it on
under **Settings** and restart.

The board has one radio. BLE and 5.9 GHz reception take turns on it. About 25
% of frames are lost with Bluetooth on, about 48 % while a phone is connected.
SD recording and MQTT keep running, just with gaps. **System**
counts how long reception was paused.

### Update confirmation (rollback)

Firmware installed over the web or by OTA has to be confirmed within **30
minutes** of its first start, or the device rolls back to the version it came
from. Until then a banner on every page asks for it. Press its button, or run
`ota -C` on the console.

### Password protection

Without a password, anyone on the network can use the whole device. A password
covers the settings with their export and import, the firmware update,
confirming an update, reboot and power-off, starting and stopping reception,
the clear buttons on **Roadside units** and **Transit**, the two delete
buttons on **Traffic**, mounting the card, and the re-send to opentrafficmap.
It also covers all file access: the SD card, the internal flash, **Logs** and
the PCAP export. To require a password (HTTP Basic Auth, user name `admin`),
either:

- set it on the **Settings** page, in the Web password field, or
- run this on the USB console:
  ```
  config_set webpasswd <your-password>
  ```

An empty field keeps the current password. To switch the protection off, tick
"remove password protection", or run `config_clear webpasswd`. These pages
stay open either way: **Status**, **Map**, **Traffic**, **Transit**,
**Roadside units**, **Messages**, **Certificates**, **System**, and the JSON
data. If the password is lost, run `config_clear webpasswd` on the USB console
and set a new one.

Two write actions stay open on purpose: resetting the counters on **System**
and deleting the crash dump. The archive search on **Messages** also reads
without a password, while the export next to it needs one.

> Note: the web interface is plain HTTP on port 80 and Basic Auth is only
> base64-encoded, so the password travels in clear text on the LAN. The
> password itself is stored as a salted hash, not plaintext.

### Requests from other web sites

The device accepts a change only from its own pages. A browser names the page
a POST comes from in the `Origin` header, or in `Referer` when `Origin` is
missing, and that name has to match the `Host` header of the request. A POST
from a page of another site gets `403 Forbidden` and changes nothing, with or
without a web password. That includes the two write actions on **System**
that need no password. A request with neither header passes, the way `curl`
and scripts send it. A reverse proxy in front of the device has to pass the
`Host` header on unchanged. For nginx that is this line:

```
proxy_set_header Host $http_host;
```

No other site can show a page of the device inside its own page: every page
sends `X-Frame-Options: DENY` and the policy `frame-ancestors 'none'`. The
live WebSocket opens only for the device's own pages and for clients that send
no `Origin`, such as scripts.

DNS rebinding gets past the check: a site points a name of its own at the
address of the device, and then `Origin` and `Host` name the same site. A web
password still stops it, except for those two actions on **System** and the
live WebSocket. The browser then asks for a login for the foreign name. Do not
enter the password there. The rebind protection of many routers stops it as
well.

## PCAP recording & playback

Switch on **rolling PCAP capture** under **Settings** and the device writes
the 802.11p frames it receives to the SD card under `/sdcard/pcap/`, one file
per hour named `pcap-YYYYMMDD-HHMMSS.pcap`. Old files are deleted by age and
by a total size ceiling, both set on the same page. The files are ordinary
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
  sniffer and MQTT state, and temperature. The card is in there too: how full
  it is, or why there is none, and what it has lost. It also carries the noise
  floor of the last minute, the number of frames with a broken checksum, the
  number of warnings in force, and whether the device is on its fallback
  address.
- `/spatem.json` — one entry per traffic light heard, with its name, revision
  and the current phase of each signal group.
- `/markers.json` — the last 20 frames out of the ring buffer, one entry per
  frame, with or without a position. The browser groups them per station.
- `/lanes.json` — the lane geometry of the intersections, in 1e-7 degrees.
- `/tracks.json` — recorded vehicle tracks. Reads from the SD card.
- `/warning_areas.json` — the area each warning in force is addressed to, with
  its shape, centre, size and state. The map draws these.
- `/cpm.json` — what the collective perception messages of the last three
  seconds report: each sender with its objects and the areas its sensors
  cover, placed on the map. The maps of the other receivers read it too.
- `/system.json` — uptime, CPU load and memory, the radio figures, and the
  figures of the certificate check: the certificates seen, the chain checks,
  the start-up self test, the message signatures and the permission answers
  for service and content. Since 0.40.0 it also has the network counters
  `eth_pause`, `eth_overrun`, `eth_crc`, `eth_symbol`, `eth_long`,
  `eth_spi_err` and `eth_bad_len`. Half of it is HTML meant for the page.

`/status.json` is built from values already in memory, except the card
figures, which it asks the filesystem for. The **Status** page itself
fetches it every five seconds. `/tracks.json` reads from the SD card on every
request. Leave a few minutes between them. `/tracks.json?days=5` asks for the
last five days. Seven is the most it accepts. Without the parameter you get
two.

With a card the device also writes CSV files to `/sdcard/logs/`, and **Files**
offers them for download. `events.csv` holds one row per warning, `phases.csv`
the traffic-light phases, `priority.csv` the priority requests and their
answers, and `traffic.csv` the hourly figures. `passages.csv` and
`transit.csv` hold the buses and trams, `senders.csv` the roadside units and
`tracks.csv` the vehicle tracks. `cpm.csv` and `rtcmem.csv` get one row per
sender and minute. `evcsn.csv` and `poim.csv` get a row when the content
changes, and once an hour.

There is one more endpoint worth knowing if you automate the device. A POST to
`/poweroff` writes out everything still buffered and unmounts the card. The
power can then be cut without losing the last minutes. The POST answers 200
when the card is unmounted, 503 while a download is still streaming from it,
and 500 when the card could not be prepared. A card that stays blocked for 10
seconds counts as not prepared. The answer stays 200 when only the buffered
recording could not be written. The text then says how much is lost, and the
header `X-Unsaved-Bytes` gives the number of bytes. The device does not switch
itself off. It only gets ready. Afterwards `/status.json` reports the card as
`unmounted`, which is the state you asked for, not a fault.

If no write reaches the card for a minute and a small test write fails as
well, the device unmounts the card and tries to mount it again every 30
seconds. `/status.json` then gives the reason `write_failed`, and `retry` says
whether it still tries. It stops trying when the card fails again with no
write in between, or when it fails for the third time within 30 minutes. A
manual mount or a
restart starts over. The check only runs while the system log or the recording
writes to the card.

If I ever change one of these, I will note it here.

## Hardware

- Chip: **ESP32-C5** (RISC-V)
- Ethernet: **KSZ8851SNL** over SPI on this board. The `sdkconfig.proto-*`
  files build for three prototypes instead: W5500, ENC28J60 and SPI-EPPP.
  The last of those takes its IP link from another ESP32 over SPI. The
  network-LED switch is KSZ8851SNL-only, and the prototype builds hide it.
- The SD card shares the SPI bus with the Ethernet controller. That bus is
  timing-sensitive under concurrent traffic. The SD clock runs at the 20 MHz
  default.
- Flash: at least **8 MB**. The board carries an ESP32-C5-WROOM-1 module with
  8 MB (N8R8) or 16 MB (N16R8). The partition table `partitions_8M.csv` uses
  the first 8 MB and holds two OTA slots, a small FAT area and a coredump
  partition. Modules with 4 MB are not supported.
- The correct board config is in the project's `sdkconfig`
  (`HW_VARIANT=i5r-r1`, 8 MB, `partitions_8M.csv`). Do **not** let
  `idf.py set-target` overwrite it.

## Flashing a pre-compiled firmware

The easiest way is the web interface, under **Firmware**.
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
v6.1 (v5.5.x) do **not** work unmodified. The project uses v6.1-only APIs,
and the 802.11p promiscuous-mode hack reacts to changes in the Wi-Fi stack.

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
