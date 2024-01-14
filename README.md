# Go BOF Runner

A standalone/cmdline BOF runner implemented in pure Go and CGO.

![](/screenshots/runbof.png?raw=true "")


## Background
This is a stitched together project of the GoCoffLoader by latortuga71, the BOF compatibility layer from trustedsec's COFFLoader and the BOF packer of sliver. The code is not using any Windows APIs but indirect syscalls via Acheron.

In the code I how you can link back the callbacks from the BOF to your Go implant but I only implemented this for BeaconOutput and BeaconPrintf as this is only a small PoC. There are probably smarter ways how to integrate the Beacon functions during relocation but this was the quickest way I could imagine. 

This code is not field-tested and probably buggy, so be aware :)

## Usage

```
.\bof_loader.exe CS-Situational-Awareness-BOF\SA\probe\probe.x64.o string:192.168.56.1 int:8000
```

## Compile

```
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build
```

## Credits
[GOCoffLoader](https://github.com/latortuga71/GOCoffLoader) by latortuga71  
[COFFLoader](https://github.com/trustedsec/COFFLoader) by trustedsec  
[sliver](https://github.com/BishopFox/sliver/blob/master/client/core/bof.go) by BishopFox  
[Acheron](https://github.com/f1zm0/acheron/) by f1zm0

## Other Projects
[Go Sleep / Heap Encryption](https://github.com/parzel/GoSleepyCrypt)