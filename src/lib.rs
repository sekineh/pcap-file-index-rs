extern crate pcap_file;

use std::io;
use std::io::prelude::*;
use pcap_file::*;
use pcap_file::errors::*;

pub struct PcapReaderSeek<R>
    where R: io::Read + io::Seek
{
    pub inner: PcapReader<R>,
}

impl<R> PcapReaderSeek<R>
    where R: io::Read + io::Seek
{
    pub fn new(reader: R) -> errors::ResultChain<PcapReaderSeek<R>> {
        Ok(PcapReaderSeek { inner: PcapReader::new(reader)? })
    }

    pub fn tell(&mut self) -> io::Result<u64> {
        self.seek(io::SeekFrom::Current(0))
    }
}

impl<R> io::Seek for PcapReaderSeek<R>
    where R: io::Read + io::Seek
{
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let file = self.inner.get_mut();
        file.seek(pos)
    }
}

// impl<R> Iterator for PcapReaderSeek<R>
//     where R: io::Read + io::Seek
// {
//     type Item = ResultChain<Packet<'static>>;

//     fn next(&mut self) -> Option<Self::Item> {
//         self.inner.next()
//     }
// }

#[cfg(test)]
mod tests {
    use std::fs::File;
    use super::*;
    #[test]
    fn it_works() {
        let file = File::open("tests/test_in.pcap").expect("Error opening file");
        let mut pcap_reader = PcapReaderSeek::new(file).unwrap();

        let mut calc_offset = 24;

        loop {
            let offset = pcap_reader.tell().unwrap();
            assert_eq!(offset, calc_offset);
            // println!("offset: {:?}", offset);
            if let Some(pkt) = pcap_reader.inner.next() {
                // println!("pkt: {:?}", pkt);
                calc_offset = offset + 16 + pkt.header.incl_len as u64;
                // println!("tell + 16 + pkt.incl_len: {}", calc_offset);
            } else {
                break;
            }
        }
    }
}
