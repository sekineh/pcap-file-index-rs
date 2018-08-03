# pcap-file-index

This crate provides O(1) index access for packets in a pcap file.
You can access to the nth packet in the pcap file in constant time.

## Usage

Add to Cargo.toml:
```
[dependency]
pcap-file = "0.10.0"
pcap-file-index = "0.1.0" 
```
I tested with pcap-file 0.10.0 on windows 64-bit platform.

## Features
- PcapReader Wrapper that extracts offsets from pcap file
- create index file that help random access of pcap

## Features not planned
- implement `Index` trait for PcapReader
  - `Index` trait can't be implemented because it assumes the returned value is already on some memory location.

## Comparison matrix 
The dependency on pcap-file was determined based on the following criteria.

- pcap 0.7.0 - wrapper of pcap/WinPcap
  - support other than little endian: yes
  - support nanosecond pcap: unknown

- pcap-file 0.7.0 - manually written pcap parser
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
