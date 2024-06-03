use super::TonCellError;

#[derive(Clone)]
pub struct BitArrayReader {
    pub array: Vec<u8>,
    pub cursor: usize,
}

impl BitArrayReader {
    /**
     * Gets n-th bit
     *
     * @param {number} n
     * @return {boolean} Bit value at position `n`
     */
    pub fn get(&self, n: usize) -> bool {
        return (self.array[(n / 8) | 0] & (1 << (7 - (n % 8)))) > 0;
    }

    /**
     * Gets `n` length bit range from `start` position
     *
     * @param {number} start Start position
     * @param {number} n
     * @return {Uint8Array} [start:start+n] bits
     */
    pub fn get_range(&self, start: usize, n: usize) -> Vec<u8> {
        let mut array: Vec<u8> = vec![];
        let mut cursor = 0;
        for x in start..start + n {
            let b = self.get(x);

            if b {
                array[(cursor / 8) as usize] |= 1 << (7 - (cursor % 8));
            } else {
                array[(cursor / 8) as usize] &= !(1 << (7 - (cursor % 8)));
            }

            cursor += 1;
        }
        return array;
    }

    pub fn read_uint8(&self, start: usize) -> u8 {
        return self.read_uint(start, 8) as u8;
    }

    pub fn read_uint16(&self, start: usize) -> u16 {
        return self.read_uint(start, 16) as u16;
    }

    pub fn read_uint(&self, start: usize, bit_length: usize) -> u128 {
        if bit_length < 1 {
            panic!("Incorrect bitLength");
        }

        let mut result: u128 = 0;

        for i in start..start + bit_length {
            let b = self.get(i);
            if b {
                result |= 1 << (start + bit_length - i - 1);
            }
        }

        result
    }

    /**
     * Gets Top Upped Array (see TON docs)
     *
     * @return {Uint8Array}
     */
    pub fn get_top_upped_array(&self) -> Result<Vec<u8>, TonCellError> {
        let mut ret = self.clone();

        let mut tu = ((ret.cursor + 7) / 8 * 8) - ret.cursor;
        if tu > 0 {
            tu = tu - 1;
            ret.write_bit(true as usize)?;
            while tu > 0 {
                tu = tu - 1;
                ret.write_bit(false as usize)?;
            }
        }
        ret.array.truncate((ret.cursor + 7) / 8);
        return Ok(ret.array);
    }

    fn write_bit(&mut self, b: usize) -> Result<(), TonCellError> {
        if b > 0 {
            self.on(self.cursor)?;
        } else {
            self.off(self.cursor)?;
        }

        self.cursor += 1;
        Ok(())
    }

    /// Sets bit value to 1 at position `n`
    fn on(&mut self, n: usize) -> Result<(), TonCellError> {
        self.check_range(n)?;
        self.array[n / 8 | 0] |= 1 << (7 - (n % 8));
        Ok(())
    }

    /// Sets bit value to 0 at position `n`
    fn off(&mut self, n: usize) -> Result<(), TonCellError> {
        self.check_range(n)?;
        self.array[n / 8 | 0] &= !(1 << (7 - (n % 8)));
        Ok(())
    }

    fn check_range(&self, n: usize) -> Result<(), TonCellError> {
        if n > self.array.len() * 8 {
            return Err(TonCellError::cell_parser_error("Bit data overflow"));
        }
        Ok(())
    }
}
