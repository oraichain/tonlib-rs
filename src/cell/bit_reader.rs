#[derive(Clone)]
pub struct BitArrayReader {
    pub array: Vec<u8>,
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
}
