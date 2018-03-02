extern crate pcap_file;

use std::path::Path;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::Result as IoResult;
use std::fs::File;
use std::io::BufReader;
use pcap_file::*;
use pcap_file::errors::ResultChain;

/// extension methods for PcapReader
pub trait PcapReaderSeek {
    fn tell(&mut self) -> IoResult<u64>;
    fn seek(&mut self, offset: u64) -> IoResult<u64>;
}

/// extension methods for PcapReader when the underlying Reader provides `Seek` trait.
impl<T> PcapReaderSeek for PcapReader<T>
where
    T: Read + Seek,
{
    /// returns the current offset
    fn tell(&mut self) -> IoResult<u64> {
        self.get_mut().seek(SeekFrom::Current(0))
    }
    /// seeks to the specified offset
    fn seek(&mut self, offset: u64) -> IoResult<u64> {
        self.get_mut().seek(SeekFrom::Start(offset))
    }
}

/// Stores packet offsets included within the pcap file
#[derive(Debug)]
struct FileOffsets {
    inner: Vec<u64>,
}

impl FileOffsets {
    /// Creates
    pub fn from_pcap<P: AsRef<Path>>(pcap: P) -> errors::ResultChain<Self> {
        let mut reader = PcapReader::new(BufReader::new(File::open(pcap)?))?;
        let mut inner: Vec<u64> = Vec::new();

        loop {
            inner.push(reader.tell()?);
            match reader.next() {
                Some(_) => continue,
                None => break,
            }
        }
        Ok(FileOffsets { inner: inner })
    }
}

/// PcapReader that support random access
struct PcapReaderIndex {
    pub pcap_reader: PcapReader<BufReader<File>>,
    offsets: FileOffsets,
}

impl PcapReaderIndex {
    /// Creates new `PcapReaderIndex` struct
    pub fn new<P: AsRef<Path>>(pcap: P) -> errors::ResultChain<PcapReaderIndex> {
        Ok(PcapReaderIndex {
            pcap_reader: PcapReader::new(BufReader::new(File::open(&pcap)?))?,
            offsets: FileOffsets::from_pcap(&pcap)?,
        })
    }

    fn index_file_name(path: &str) -> String {
        format!("{}.index", path)
    }

    pub fn get(&mut self, index: usize) -> Option<ResultChain<Packet<'static>>> {
        if index >= self.offsets.inner.len() {
            return None;
        }
        let offset = self.offsets.inner[index];
        self.pcap_reader.seek(offset);
        self.pcap_reader.next()
    }

    pub fn next(&mut self) -> Option<ResultChain<Packet<'static>>> {
        self.pcap_reader.next()
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
