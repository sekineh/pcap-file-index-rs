# pcap-file-ra

This crate provides random access to packets in a pcap file.
You can `get()` n'th packet of pcap in a constant time.

The crate is consider to be a companion crate of the  `pcap-file`.

## Usage

Add to Cargo.toml:
```
[dependency]
pcap-file = "0.10.0"
pcap-file-ra = "0.1.1" 
```

Tested with pcap-file 0.10.0 on windows 64-bit platform.

## Features

- PcapReader wrapper that extracts offsets from pcap file
- Save offset file to speed-up future access.

## Features not planned

- implement `Index` trait for PcapReader
  - `Index` trait can't be implemented because it assumes the returned value is already on some memory location.

## Comparison matrix of existing crates
We depend on `pcap-file`.
The crate was chosen based on the following criteria.

- pcap 0.7.0 - wrapper of pcap/WinPcap
  - support other than little endian: yes
  - support nanosecond pcap: unknown

- **pcap-file** 0.7.0 - manually written pcap parser
  - support other than little endian: yes
  - support nanosecond pcap: yes
  - support write: yes
  - can access to underlying reader: yes

- pcap-rs 1.0.1 - nom-based pcap parser
  - support other than little endian: yes
  - support nanosecond pcap: yes
  - support write: no

- rpcap 0.3.0 - bytepack-based pcap parser
  - support other than little endian: yes
  - support nanosecond pcap: yes
  - support write: yes
  - can access to underlying reader: no

- pcapng 1.0.0 - nom-based pcapng-only parser
  - support other than little endian: no
    - https://github.com/richo/pcapng-rs/issues/1
  - support nanosecond pcap: no
  - support pcap file: no
