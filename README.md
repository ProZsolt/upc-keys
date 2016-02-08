# upc-keys
WPA2 passphrase recovery tool for UPC%07d devices with automatic WIFI scanning and passphrase validation.

## What is this?
[Novella/Meijer/Verdult](https://www.usenix.org/system/files/conference/woot15/woot15-paper-lorente.pdf) figured out that untouched WIFI access points by UPC are vulnerable to passphrase cracking attack based on their SSID. A [proof of concept](https://haxx.in/upc_keys.c) was quickly coded by [bl4sty](https://twitter.com/bl4sty). This is a weaponized Ruby port of that script, with added support for routers with serials starting with SAAP, SBAP and SAPP.

## Requirements
**OS X**

**Linux** with network-manager

We've tested it on: OS X 10.10

## How to use

```
~$ sudo ./crack_upc.rb -i en0
```
or for a targeted run
```
~$ sudo ./crack_upc.rb -i en0 -s UPC6661337
```
