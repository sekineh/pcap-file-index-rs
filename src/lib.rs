extern crate pcap_file;

use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;
use pcap_file::*;

use std::fs::File;
use std::io::BufReader;

/// PcapReader that support Index trait
struct PcapReaderIndex {
    pub inner: PcapReaderSeek<BufReader<File>>,
    index: FileOffsetIndex,
}

impl PcapReaderIndex {
    pub fn new(path: &str) -> errors::ResultChain<PcapReaderIndex> {
        let index = FileOffsetIndex::from_pcap_path(path)?;
        let file = File::open(path)?;
        let buf = std::io::BufReader::new(file);
        Ok(PcapReaderIndex {
            inner: PcapReaderSeek::new(buf)?,
            index: index,
        })
    }

    fn index_file_name(path: &str) -> String {
        format!("{}.index", path)
    }

    pub fn access(&mut self, index: usize) -> Packet<'static> {
        let offset = self.index.inner[index];
        self.inner.seek(SeekFrom::Start(offset));
        self.inner.next().unwrap()
    }
}

// impl std::ops::Index<usize> for PcapReaderIndex {
//     type Output = Packet<'static>;
//     fn index(&self, index: usize) -> Self::Output {
//         let offset = self.index.inner[index];
//         unsafe {
//             let reader: &mut PcapReaderSeek<BufReader<File>> = std::mem::transmute(&self.inner);
//             reader.seek(SeekFrom::Start(offset));
//             reader.next().unwrap()
//         }
//     }
// }

/// Store packet offsets included within the pcap file
#[derive(Debug)]
struct FileOffsetIndex {
    inner: Vec<u64>,
}

impl FileOffsetIndex {
    pub fn from_pcap_path(pcap: &str) -> errors::ResultChain<Self> {
        let mut reader = PcapReaderSeek::new(std::fs::File::open(pcap)?).unwrap();
        let mut inner: Vec<u64> = Vec::new();

        loop {
            inner.push(reader.tell()?);
            match reader.next() {
                Some(_) => continue,
                None => break,
            }
        }

        Ok(FileOffsetIndex { inner: inner })
    }
}

/// Thin wrapper to the PcapReader that support Seek and Iterator traits.
///
/// The functionality is minimum, use inner field to access more features.
pub struct PcapReaderSeek<R>
    where R: Read + Seek
{
    pub inner: PcapReader<R>,
}

impl<R> PcapReaderSeek<R>
    where R: Read + Seek
{
    /// Create the object from R: Read + Seek
    pub fn new(reader: R) -> errors::ResultChain<PcapReaderSeek<R>> {
        Ok(PcapReaderSeek { inner: PcapReader::new(reader)? })
    }

    /// Returns the current offset within the file.
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

impl<R: Read + Seek> Iterator for PcapReaderSeek<R> {
    type Item = Packet<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterator::next(&mut self.inner)
        self.inner.next()
    }
}

// #[cfg(test)]
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

    #[test]
    fn pcap_access() {
        let mut reader = PcapReaderIndex::new("tests/test_in.pcap").expect("Error opening pcap file");
        println!("1: {:?}", reader.access(1));
        println!("0: {:?}", reader.access(0));
        println!("5: {:?}", reader.access(5));
    }
}
