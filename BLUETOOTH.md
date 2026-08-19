# Bluetooth streaming (experimental)

This branch is `main` plus a Bluetooth Low Energy live stream of received
frames, so a phone app can show them without a network in between. It is young:
it has been running for hours, not weeks, and the Bluetooth path has seen far
less traffic than the rest of the firmware.

## What it costs — only while Bluetooth is on

With the switch off, nothing here costs anything: the stack is never started,
no task is created, and reception is exactly what the release on `main` gives
you. The trade-off below applies only once you switch Bluetooth on, because the
ESP32-C5 has one radio and cannot serve 5.9 GHz and 2.4 GHz at the same time —
the sniffer is then paused in turns while Bluetooth has the antenna:

| | frames captured |
|---|---|
| Bluetooth off | 100 % |
| on, nobody connected | about 75 % |
| on, phone connected | about half |

Recording to SD and MQTT keeps running throughout, just with gaps. The
settings page states the same numbers next to the switch.

## Using it

Bluetooth is **off by default**. With the switch off this firmware behaves
exactly like `main` — the stack is not started, no task is created, and the
sniffer gets the radio to itself. The switch takes effect after a restart.

Once on, the receiver advertises as `ITS-G5-RX` and exposes one service with
three characteristics: a notify channel carrying the frames, a config
characteristic for the capture/Bluetooth duty cycle, and a read-only one with
the factory Bluetooth address. A connected client may change the duty cycle
within bounds; the value is not persisted, so a restart returns to the
built-in one.

## Where the code comes from

`main/bt_stream.c` and `main/ble_cache.c` are adapted from
[V2Xtend](https://github.com/githubapache2/V2Xtend) by githubapache2, which is
itself a fork of [V2X2MAP](https://github.com/pit711/V2X2MAP) by Peter
Holzhauser — that is where the BLE streaming originally comes from. Both are
MIT-licensed; `NOTICE` carries the full notice and lists what was changed here.

For a receiver that should simply record, use `main`.
