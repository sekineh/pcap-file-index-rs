# pcap-random-access

This crate provides random access for pcap files.

## comparison matrix

- pcap 0.7.0 - wrapper of pcap/WinPcap
  - support other than little endian: yes
  - support nanosecond pcap: unknown

- pcap-file 0.7.0 - manually written pcap parser
  - support other than little endian: yes
  - support nanosecond pcap: yes
  - support write: yes

- pcap-rs 1.0.1 - nom-based pcap parser
  - support other than little endian: yes
  - support nanosecond pcap: yes
  - support write: no

- rpcap 0.3.0 - bytepack-based pcap parser
  - support other than little endian: yes
  - support nanosecond pcap: yes
  - support write: yes

- pcapng 1.0.0 - nom-based pcapng-only parser
  - support other than little endian: no
    - https://github.com/richo/pcapng-rs/issues/1
  - support nanosecond pcap: no
