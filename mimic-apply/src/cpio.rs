use anyhow::Result;
use std::io::{Read, Write};
use std::str;

pub struct CpioWriter<W: Write> {
    writer: W,
    inode: u32,
}

impl<W: Write> CpioWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer, inode: 1 }
    }

    pub fn write_entry(&mut self, name: &str, content: &[u8], mode: u32) -> Result<()> {
        let header = self.build_header(name, content.len() as u32, mode);
        self.writer.write_all(header.as_bytes())?;
        self.writer.write_all(name.as_bytes())?;
        self.writer.write_all(&[0])?; // Null terminator for name
        self.pad_to_4bytes(110 + name.len() + 1)?;

        self.writer.write_all(content)?;
        self.pad_to_4bytes(content.len())?;

        self.inode += 1;
        Ok(())
    }

    pub fn finish(mut self) -> Result<W> {
        self.write_entry("TRAILER!!!", &[], 0)?;
        Ok(self.writer)
    }

    fn build_header(&self, name: &str, size: u32, mode: u32) -> String {
        format!(
            "{:06}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            "070701",       // Magic
            self.inode,     // Inode
            mode,           // Mode
            0,              // Uid
            0,              // Gid
            1,              // Nlink
            0,              // Mtime
            size,           // Filesize
            0,              // Major
            0,              // Minor
            0,              // Rmajor
            0,              // Rminor
            name.len() + 1, // Namesize (incl null)
            0               // Checksum
        )
    }

    fn pad_to_4bytes(&mut self, length: usize) -> Result<()> {
        let pad = (4 - (length % 4)) % 4;
        for _ in 0..pad {
            self.writer.write_all(&[0])?;
        }
        Ok(())
    }
}

pub struct CpioReader<R: Read> {
    reader: R,
}

pub struct CpioEntry {
    pub name: String,
    pub mode: u32,
    pub content: Vec<u8>,
}

impl<R: Read> CpioReader<R> {
    pub fn new(reader: R) -> Self {
        Self { reader }
    }

    pub fn next_entry(&mut self) -> Result<Option<CpioEntry>> {
        // Peek or Read magic
        // We strictly expect "070701"
        let mut magic_buf = [0u8; 6];
        match self.reader.read_exact(&mut magic_buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let magic = str::from_utf8(&magic_buf).unwrap_or("");
        if magic != "070701" {
            // If it doesn't match magic, we assume end of CPIO stream or invalid
            // In the original code we just broke the loop.
            return Ok(None);
        }

        // Read rest of header (104 bytes)
        let mut rest_header = [0u8; 104];
        self.reader.read_exact(&mut rest_header)?;

        let header_str = str::from_utf8(&rest_header).unwrap_or("");

        let mode_hex = &header_str[8..16];
        let filesize_hex = &header_str[48..56];
        let namesize_hex = &header_str[88..96];

        let mode = u32::from_str_radix(mode_hex, 16).unwrap_or(0);
        let filesize = usize::from_str_radix(filesize_hex, 16).unwrap_or(0);
        let namesize = usize::from_str_radix(namesize_hex, 16).unwrap_or(0);

        // Read filename
        let mut name_buf = vec![0u8; namesize];
        self.reader.read_exact(&mut name_buf)?;

        // Strip null terminator
        let name = str::from_utf8(&name_buf[..namesize - 1])
            .unwrap_or("")
            .to_string();

        // Consume padding for name
        let header_plus_name = 110 + namesize;
        let pad = (4 - (header_plus_name % 4)) % 4;
        if pad > 0 {
            let mut skip = [0u8; 4];
            self.reader.read_exact(&mut skip[..pad])?;
        }

        // Read Content
        let mut content = vec![0u8; filesize];
        self.reader.read_exact(&mut content)?;

        // Consume padding for content
        let pad_content = (4 - (filesize % 4)) % 4;
        if pad_content > 0 {
            let mut skip = [0u8; 4];
            self.reader.read_exact(&mut skip[..pad_content])?;
        }

        if name == "TRAILER!!!" {
            return Ok(None);
        }

        Ok(Some(CpioEntry {
            name,
            mode,
            content,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_cpio_write_read() {
        let mut buffer = Vec::new();
        // Scope to valid variable borrow
        {
            let mut writer = CpioWriter::new(&mut buffer);
            writer
                .write_entry("test.txt", b"Hello World", 0o100644)
                .unwrap();
            writer
                .write_entry("dir/file2", b"Content 2", 0o100644)
                .unwrap();
            writer.finish().unwrap();
        }

        let mut reader = CpioReader::new(Cursor::new(buffer));

        let entry = reader.next_entry().unwrap().expect("Should have entry 1");
        assert_eq!(entry.name, "test.txt");
        assert_eq!(entry.content, b"Hello World");
        assert_eq!(entry.mode, 0o100644);

        let entry = reader.next_entry().unwrap().expect("Should have entry 2");
        assert_eq!(entry.name, "dir/file2");
        assert_eq!(entry.content, b"Content 2");

        let entry = reader.next_entry().unwrap();
        assert!(entry.is_none());
    }

    #[test]
    fn test_padding_logic() {
        let mut buffer = Vec::new();
        let mut writer = CpioWriter::new(&mut buffer);

        // "a" is length 1. 110+2 = 112. 112%4 = 0. Pad 0.
        // content "b" is length 1. 1%4=1. Pad 3.
        writer.write_entry("a", b"b", 0).unwrap();
        let _ = writer.finish().unwrap();

        // Check buffer size or content manually if needed, but roundtrip test is better.
        let mut reader = CpioReader::new(Cursor::new(buffer));
        let entry = reader.next_entry().unwrap().unwrap();
        assert_eq!(entry.name, "a");
        assert_eq!(entry.content, b"b");
    }
}
