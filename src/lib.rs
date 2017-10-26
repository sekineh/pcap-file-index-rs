extern crate pcap_file;

use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;
use pcap_file::*;
// use pcap_file::errors::ResultChain;

pub struct PcapReaderSeek<R>
    where R: Read + Seek
{
    pub inner: PcapReader<R>,
}

impl<R> PcapReaderSeek<R>
    where R: Read + Seek
{
    pub fn new(reader: R) -> errors::ResultChain<PcapReaderSeek<R>> {
        Ok(PcapReaderSeek { inner: PcapReader::new(reader)? })
    }

    pub fn tell(&mut self) -> io::Result<u64> {
        self.seek(SeekFrom::Current(0))
    }
}

impl<R> Seek for PcapReaderSeek<R>
    where R: Read + Seek
{
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let file = self.inner.get_mut();
        file.seek(pos)
    }
}

impl<R: Read + Seek> Iterator for PcapReaderSeek<R>
{
    type Item = Packet<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterator::next(&mut self.inner)
        self.inner.next()
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use super::*;
    #[test]
    fn sanity() {
        let file = File::open("tests/test_in.pcap").expect("Error opening file");
        let mut pcap_reader = PcapReaderSeek::new(file).unwrap();

        let mut calc_offset = 24;

        loop {
            let offset = pcap_reader.tell().unwrap();
            assert_eq!(offset, calc_offset);
            // println!("offset: {:?}", offset);
            if let Some(pkt) = pcap_reader.next() {
                // println!("pkt: {:?}", pkt);
                calc_offset = offset + 16 + pkt.header.incl_len as u64;
                // println!("tell + 16 + pkt.incl_len: {}", calc_offset);
            } else {
                break;
            }
        }
    }
}
