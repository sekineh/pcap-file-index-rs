//! # pcap-file-index
//! 
//! The crate provides random access to the underlying `PcapReader`.
//!
//! ## Examples
//!
//! ```
//! use pcap_file_index::PcapReaderIndex;
//!
//! let mut pcap = PcapReaderIndex::from_pcap("tests/test_in.pcap").unwrap();
//!
//! // offset file is created:
//! assert_eq!(std::path::Path::new("tests/test_in.pcap.offset.bincode").exists(), true);
//!
//! assert_eq!(pcap.len(), 10);
//! assert_eq!(pcap.get(0).unwrap().unwrap().header.incl_len, 117);
//! assert_eq!(pcap.get(9).unwrap().unwrap().header.incl_len, 120);
//! assert_eq!(pcap.get(3).unwrap().unwrap().header.incl_len, 70);
//! assert!(pcap.get(10).is_none());
//! ```

extern crate bincode;
extern crate pcap_file;
extern crate serde;
#[macro_use]
extern crate serde_derive;

use pcap_file::errors::ResultChain;
use pcap_file::*;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Result as IoResult;
use std::io::SeekFrom;

/// Extension methods for `PcapReader`.
/// 
/// It is used by `PacketOffsets`.
trait PcapReaderSeek {
    /// Returns the current offset
    fn tell(&mut self) -> IoResult<u64>;

    /// Seeks to the specified offset
    fn seek(&mut self, offset: u64) -> IoResult<u64>;
}

/// Extension methods for `PcapReader` when the underlying `Reader` also provides `Seek` trait.
impl<T> PcapReaderSeek for PcapReader<T>
where
    T: Read + Seek,
{
    fn tell(&mut self) -> IoResult<u64> {
        self.get_mut().seek(SeekFrom::Current(0))
    }

    fn seek(&mut self, offset: u64) -> IoResult<u64> {
        self.get_mut().seek(SeekFrom::Start(offset))
    }
}

/// Stores packet offsets included within the pcap file
#[derive(Debug, Serialize, Deserialize)]
struct PacketOffsets {
    inner: Vec<u64>,
}

impl PacketOffsets {
    /// Creates offsets for nth packets of pcap file.
    pub fn from_pcap(pcap: &str) -> ResultChain<Self> {
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
        Ok(PacketOffsets { inner })
    }

    /// Save offsets into file
    pub fn save_to(&self, offset_path: &str) -> bincode::Result<()> {
        let file = File::create(offset_path)?;
        let buf = BufWriter::new(file);

        bincode::serialize_into(buf, self)
    }

    /// Load offsets from file
    pub fn load_from(offset_path: &str) -> bincode::Result<PacketOffsets> {
        let file = File::open(offset_path)?;
        let buf = BufReader::new(file);

        bincode::deserialize_from(buf)
    }
}

/// `PcapReader` that support random access
///
/// It wraps `PcapReader`, and creates 'offset' file if necccesary.
///
/// For the time being, the path of the offset file is determined automatically.
#[derive(Debug)]
pub struct PcapReaderIndex {
    /// Underlying reader
    inner: PcapReader<BufReader<File>>,
    /// Stores offsets for each packet
    offsets: PacketOffsets,
    /// path for the pcap file
    pcap_path: String,
    /// path for the offset file
    offset_path: String,
}

impl PcapReaderIndex {
    /// Creates the struct with full control.
    pub fn new_full_control(
        pcap_path: &str,
        offset_path: &str,
        recalc_offset: bool,
        save_offset_file: bool,
    ) -> Result<PcapReaderIndex, Box<Error>> {
        // TODO: add timestamp check for offset file?

        let offsets = if recalc_offset {
            PacketOffsets::from_pcap(pcap_path)?
        } else {
            PacketOffsets::load_from(offset_path)?
        };

        if save_offset_file {
            offsets.save_to(offset_path)?;
        }

        Ok(PcapReaderIndex {
            pcap_path: pcap_path.to_owned(),
            offset_path: offset_path.to_owned(),
            inner: PcapReader::new(BufReader::new(File::open(&pcap_path)?))?,
            offsets: offsets,
        })
    }

    /// Creates the struct with the default offset file name.
    /// If offset file is already created, reuse it.
    ///
    /// ## Example
    ///
    /// ```
    /// let pcap = pcap_file_index::PcapReaderIndex::from_pcap("tests/test_in.pcap").unwrap();
    ///
    /// assert_eq!(std::path::Path::new("tests/test_in.pcap.offset.bincode").exists(), true);
    /// ```
    pub fn from_pcap(pcap_path: &str) -> Result<PcapReaderIndex, Box<Error>> {
        let offset_path = Self::default_offset_path(pcap_path);
        let res = Self::new_full_control(pcap_path, &offset_path, false, false);

        if res.is_err() {
            Self::new_full_control(pcap_path, &offset_path, true, true)
        } else {
            res
        }
    }

    /// Returns the default offset path for the given `pcap_path`.
    /// By default, offset file name is created by just adding ".offset.bincode" suffix.
    pub fn default_offset_path(pcap_path: &str) -> String {
        format!("{}.offset.bincode", pcap_path)
    }

    /// Returns the Packet at the specified `index`.
    ///
    /// ## Example
    ///
    /// ```
    /// let mut pcap = pcap_file_index::PcapReaderIndex::from_pcap("tests/test_in.pcap").unwrap();
    ///
    /// assert_eq!(pcap.get(0).unwrap().unwrap().header.incl_len, 117);
    /// assert_eq!(pcap.get(9).unwrap().unwrap().header.incl_len, 120);
    /// assert_eq!(pcap.get(3).unwrap().unwrap().header.incl_len, 70);
    /// assert!(pcap.get(10).is_none());
    /// ```
    pub fn get(&mut self, index: usize) -> Option<ResultChain<Packet<'static>>> {
        if index >= self.offsets.inner.len() {
            return None; // out of range
        }
        let offset = self.offsets.inner[index];
        let seek_result = self.inner.seek(offset);
        if let Err(_) = seek_result {
            return None;
        }
        self.inner.next()
    }

    /// Returns the number of packets.
    ///
    /// ## Example
    ///
    /// ```
    /// let mut pcap = pcap_file_index::PcapReaderIndex::from_pcap("tests/test_in.pcap").unwrap();
    ///
    /// assert_eq!(pcap.len(), 10);
    /// ```
    pub fn len(&self) -> usize {
        self.offsets.inner.len()
    }
}

/// Wraps the underlying `PcapReader`'s `Iterator`
impl Iterator for PcapReaderIndex {
    type Item = ResultChain<Packet<'static>>;

    fn next(&mut self) -> Option<ResultChain<Packet<'static>>> {
        self.inner.next()
    }
}

#[cfg(test)]
mod tests {
    use *;
    const PCAP_PATH: &str = "tests/test_in.pcap";

    mod pcap_reader_seek {
        use self::tests::*;
        use PcapReaderSeek; // provides .tell()
        use *;

        #[test]
        fn compare_with_calculated_offsets() {
            let file = File::open(PCAP_PATH).unwrap();
            let mut pcap_reader = PcapReader::new(file).unwrap();

            let mut calculated_offset = 24; // initial value == size of pcap file header
            loop {
                let offset = pcap_reader.tell().unwrap();
                assert_eq!(offset, calculated_offset);
                if let Some(Ok(pkt)) = pcap_reader.next() {
                    calculated_offset += 16 + pkt.header.incl_len as u64;
                } else {
                    break;
                }
            }
        }
    }

    mod packet_offsets {
        use self::tests::*;
        use *;

        #[test]
        fn methods() {
            const OFFSET_PATH: &str = "tests/OFFSET_for_methods"; // must use dedicated file

            // Setup
            let _ = std::fs::remove_file(OFFSET_PATH); // remove if it already exists
            assert_eq!(std::path::Path::new(OFFSET_PATH).exists(), false);

            // Create
            let offsets = PacketOffsets::from_pcap(PCAP_PATH).expect("Error opening pcap file");
            assert_eq!(
                offsets.inner,
                vec![24, 157, 442, 528, 614, 708, 941, 1027, 1221, 1319]
            );

            // Save
            offsets.save_to(OFFSET_PATH).unwrap();
            assert_eq!(std::path::Path::new(OFFSET_PATH).exists(), true);

            // Load
            let load = PacketOffsets::load_from(OFFSET_PATH).unwrap();
            assert_eq!(offsets.inner, load.inner);

            // Teardown
            std::fs::remove_file(OFFSET_PATH).unwrap(); // clean up
            assert_eq!(std::path::Path::new(OFFSET_PATH).exists(), false);
        }

    }

    mod pcap_reader_index {
        use self::tests::*;
        use *;

        /// asserts for test file
        fn asserts_for_pcap(pcap: &mut PcapReaderIndex) {
            assert_eq!(pcap.len(), 10);
            assert_eq!(pcap.get(0).unwrap().unwrap().header.incl_len, 117);
            assert_eq!(pcap.get(9).unwrap().unwrap().header.incl_len, 120);
            assert_eq!(pcap.get(3).unwrap().unwrap().header.incl_len, 70);
            assert!(pcap.get(10).is_none());
        }

        #[test]
        fn new() {
            // Setup
            // We need to specify a didicated offset file here because tests are run concurrently.
            const OFFSET_PATH: &str = "tests/OFFSET_for_new";

            let _ = std::fs::remove_file(OFFSET_PATH);
            assert_eq!(std::path::Path::new(OFFSET_PATH).exists(), false);

            // 1st: Reuse offset file => fail
            let pcap = PcapReaderIndex::new_full_control(PCAP_PATH, OFFSET_PATH, false, false);
            assert_eq!(pcap.is_err(), true); // should fail because offset_path does not exist.
            assert_eq!(std::path::Path::new(OFFSET_PATH).exists(), false);

            // 2nd: Create new offset file => success
            let mut pcap = PcapReaderIndex::new_full_control(PCAP_PATH, OFFSET_PATH, true, true).unwrap();
            assert_eq!(std::path::Path::new(OFFSET_PATH).exists(), true);
            asserts_for_pcap(&mut pcap);

            // 3rd: Reuse offset file => success
            let mut pcap = PcapReaderIndex::new_full_control(PCAP_PATH, OFFSET_PATH, false, false).unwrap();
            assert_eq!(std::path::Path::new(OFFSET_PATH).exists(), true);
            asserts_for_pcap(&mut pcap);

            // Teardown
            std::fs::remove_file(OFFSET_PATH).unwrap(); // clean up
            assert_eq!(std::path::Path::new(OFFSET_PATH).exists(), false);
        }

        #[test]
        fn from_pcap() {
            // setup
            let offset_path = PcapReaderIndex::default_offset_path(PCAP_PATH);
            let _ = std::fs::remove_file(&offset_path);
            assert_eq!(std::path::Path::new(&offset_path).exists(), false);

            // 1st run
            let mut pcap = PcapReaderIndex::from_pcap(PCAP_PATH).unwrap();
            assert_eq!(std::path::Path::new(&offset_path).exists(), true);
            asserts_for_pcap(&mut pcap);

            // 2nd run
            let mut pcap = PcapReaderIndex::from_pcap(PCAP_PATH).unwrap();
            assert_eq!(std::path::Path::new(&offset_path).exists(), true);
            asserts_for_pcap(&mut pcap);

            // teardown
            let _ = std::fs::remove_file(&offset_path);
            assert_eq!(std::path::Path::new(&offset_path).exists(), false);
        }

        #[test]
        fn iterator() {
            const OFFSET_PATH: &str = "tests/OFFSET_for_iterator";

            let pcap = PcapReaderIndex::new_full_control(PCAP_PATH, OFFSET_PATH, true, true).unwrap();
            let incl_lens: Vec<_> = pcap.map(|p| p.unwrap().header.incl_len).collect();
            assert_eq!(incl_lens, vec![117, 269, 70, 70, 78, 217, 70, 178, 82, 120]);

            // teardown
            std::fs::remove_file(OFFSET_PATH).unwrap();
        }
    }
}
