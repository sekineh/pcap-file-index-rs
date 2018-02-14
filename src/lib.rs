extern crate pcap_file;

use pcap_file::errors::ResultChain;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;
use pcap_file::*;

use std::fs::File;
use std::io::BufReader;

/// PcapReader that support Index trait
struct PcapReaderIndex {
    pub inner: PcapReader<BufReader<File>>,
    index: FileOffsetIndex,
}

impl PcapReaderIndex {
    pub fn new(path: &str) -> errors::ResultChain<PcapReaderIndex> {
        let index = FileOffsetIndex::from_pcap_path(path)?;
        let file = File::open(path)?;
        let buf = std::io::BufReader::new(file);
        Ok(PcapReaderIndex {
            inner: PcapReader::new(buf)?,
            index: index,
        })
    }

    fn index_file_name(path: &str) -> String {
        format!("{}.index", path)
    }

    pub fn get(&mut self, index: usize) -> Option<ResultChain<Packet<'static>>> {
        let offset = self.index.inner[index];
        self.inner.get_mut().seek(SeekFrom::Start(offset)).ok()?;
        self.inner.next()
    }
}

/// Store packet offsets included within the pcap file
#[derive(Debug)]
struct FileOffsetIndex {
    inner: Vec<u64>,
}

impl FileOffsetIndex {
    pub fn from_pcap_path(pcap_path: &str) -> errors::ResultChain<Self> {
        let mut reader = PcapReader::new(std::fs::File::open(pcap_path)?)?;
        let mut inner: Vec<u64> = Vec::new();

        loop {
            inner.push(reader.get_ref().seek(SeekFrom::Current(0))?);
            match reader.next() {
                Some(_) => continue,
                None => break,
            }
        }

        Ok(FileOffsetIndex { inner: inner })
    }
}

// #[cfg(test)]
mod tests {
    use std::fs::File;
    use super::*;

    #[test]
    fn sanity() {
        let file = File::open("tests/test_in.pcap").expect("Error opening file");
        let mut pcap_reader = PcapReader::new(file).unwrap();

        let mut calc_offset = 24;

        loop {
            let offset = pcap_reader.get_ref().seek(SeekFrom::Current(0)).unwrap();
            assert_eq!(offset, calc_offset);
            // println!("offset: {:?}", offset);
            if let Some(Ok(pkt)) = pcap_reader.next() {
                // println!("pkt: {:?}", pkt);
                calc_offset = offset + 16 + pkt.header.incl_len as u64;
            // println!("tell + 16 + pkt.incl_len: {}", calc_offset);
            } else {
                break;
            }
        }
    }

    #[test]
    fn pcap_access() {
        let mut reader =
            PcapReaderIndex::new("tests/test_in.pcap").expect("Error opening pcap file");
        println!("1: {:?}", reader.get(1));
        println!("0: {:?}", reader.get(0));
        println!("5: {:?}", reader.get(5));
    }
}
