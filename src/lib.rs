extern crate bincode;
// #[macro_use]
extern crate failure;
// #[macro_use] extern crate failure_derive;
extern crate log;
extern crate pcap_file;
extern crate serde;
#[macro_use]
extern crate serde_derive;

// use failure::ResultExt;
use failure::Error as FailureError;
use std::error::Error;

// #[derive(Debug)]
// struct Error {
//     inner: Context<ErrorKind>,
// }

// #[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
// enum ErrorKind {
//     #[fail(display = "A contextual error message.")]
//     PcapFileError(PcapError),
// }
// use pcap_file::errors::Error as PcapError;
// use std::path::Path;
use pcap_file::errors::ResultChain;
use pcap_file::*;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Result as IoResult;
use std::io::SeekFrom;

// impl Fail for Error {
//     fn cause(&self) -> Option<&Fail> {
//         self.inner.cause()
//     }

//     fn backtrace(&self) -> Option<&Backtrace> {
//         self.inner.backtrace()
//     }
// }

// impl Display for Error {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         Display::fmt(&self.inner, f)
//     }
// }

// ==========

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

// ==========

/// Stores packet offsets included within the pcap file
#[derive(Debug, Serialize, Deserialize)]
struct FileOffsets {
    inner: Vec<u64>,
}

impl FileOffsets {
    /// Creates offsets
    pub fn from_pcap(pcap: &str) -> ResultChain<Self> {
        // pub fn from_pcap(pcap: &str) -> errors::ResultChain<Self> {
        let file = File::open(pcap)?;
        let mut pcap_reader = PcapReader::new(BufReader::new(file))?;
        let mut inner: Vec<u64> = Vec::new();

        loop {
            let tell = pcap_reader.tell()?;
            match pcap_reader.next() {
                Some(_) => {
                    inner.push(tell);
                    continue;
                }
                None => break,
            }
        }
        Ok(FileOffsets { inner: inner })
    }

    /// save offsets into file
    pub fn save_to(&self, offset_path: &str) -> bincode::Result<()> {
        let file = File::create(offset_path)?;
        let buf = BufWriter::new(file);
        bincode::serialize_into(buf, self)
    }

    /// load offsets from file
    pub fn load_from(offset_path: &str) -> bincode::Result<FileOffsets> {
        let file = File::open(offset_path)?;
        let buf = BufReader::new(file);
        bincode::deserialize_from(buf)
    }
}

/// PcapReader that support random access
#[derive(Debug)]
pub struct PcapReaderIndex {
    pub pcap_path: String,
    pub offset_path: String,
    pub pcap_reader: PcapReader<BufReader<File>>,
    offsets: FileOffsets,
}

impl PcapReaderIndex {
    /// Creates new `PcapReaderIndex` struct
    pub fn new(
        pcap_path: &str,
        offset_path: &str,
        force_save: bool, // if set, recreate offset file
    ) -> Result<PcapReaderIndex, Box<Error>> {
        let offsets: FileOffsets = if force_save {
            let offsets = FileOffsets::from_pcap(pcap_path)?;
            offsets.save_to(offset_path)?;
            offsets
        } else {
            FileOffsets::load_from(offset_path)?
        };

        Ok(PcapReaderIndex {
            pcap_path: pcap_path.to_owned(),
            offset_path: offset_path.to_owned(),
            pcap_reader: PcapReader::new(BufReader::new(File::open(&pcap_path)?))?,
            offsets: offsets,
        })
    }

    pub fn from_pcap(pcap_path: &str) -> Result<PcapReaderIndex, Box<Error>> {
        let res = Self::new(pcap_path, &Self::offset_path(pcap_path), false);
        if res.is_err() {
            Self::new(pcap_path, &Self::offset_path(pcap_path), true)
        } else {
            res
        }
    }

    fn offset_path(path: &str) -> String {
        format!("{}.offset", path)
    }

    pub fn save_index(&self) -> Result<(), FailureError> {
        let f = File::open("index_path")?;
        let w = BufWriter::new(f);
        bincode::serialize_into(w, &self.offsets)?;
        Ok(())
    }

    /// returns the Packet at the specified `index`
    pub fn get(&mut self, index: usize) -> Option<ResultChain<Packet<'static>>> {
        if index >= self.offsets.inner.len() {
            return None; // out of range
        }
        let offset = self.offsets.inner[index];
        let seek_result = self.pcap_reader.seek(offset);
        if let Err(_) = seek_result {
            return None;
        }
        self.pcap_reader.next()
    }

    /// returns the next Packet
    pub fn next(&mut self) -> Option<ResultChain<Packet<'static>>> {
        self.pcap_reader.next()
    }
}

// #[cfg(test)]
mod tests {
    // use std::fs::File;
    use ::*;

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

    mod file_offsets {
        use ::*;

        #[test]
        fn methods() {
            let offsets =
                FileOffsets::from_pcap("tests/test_in.pcap").expect("Error opening pcap file");
            assert_eq!(
                offsets.inner,
                vec![24, 157, 442, 528, 614, 708, 941, 1027, 1221, 1319]
            );
            offsets
                .save_to("tests/test_in.pcap.offsets")
                .expect("Error writing offset file");
            let load = FileOffsets::load_from("tests/test_in.pcap.offsets")
                .expect("Error reading offset file");
            assert_eq!(offsets.inner, load.inner);
        }

    }
}
