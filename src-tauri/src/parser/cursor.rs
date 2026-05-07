pub struct ByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn read_u8(&mut self) -> Result<u8, String> {
        if self.offset >= self.bytes.len() {
            return Err("unexpected end of buffer".to_string());
        }

        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    pub fn read_be_u16(&mut self) -> Result<u16, String> {
        let first = self.read_u8()? as u16;
        let second = self.read_u8()? as u16;
        Ok((first << 8) | second)
    }

    pub fn read_be_u32(&mut self) -> Result<u32, String> {
        let first = self.read_be_u16()? as u32;
        let second = self.read_be_u16()? as u32;
        Ok((first << 16) | second)
    }

    pub fn read_array_6(&mut self) -> Result<[u8; 6], String> {
        let slice = self.read_slice(6)?;
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(slice);
        Ok(bytes)
    }

    pub fn read_slice(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self.offset + len;
        if end > self.bytes.len() {
            return Err("unexpected end of buffer".to_string());
        }

        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    pub fn offset(&self) -> usize {
        self.offset
    }
}
