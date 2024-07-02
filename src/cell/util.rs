use std::io;

use bitstream_io::{BitRead, BitReader, Endianness};

use crate::cell::{MapTonCellError, TonCellError};

use super::CellType;

pub trait BitReadExt {
    fn read_bits(&mut self, num_bits: usize, slice: &mut [u8]) -> Result<(), TonCellError>;
}

impl<R: io::Read, E: Endianness> BitReadExt for BitReader<R, E> {
    fn read_bits(&mut self, num_bits: usize, slice: &mut [u8]) -> Result<(), TonCellError> {
        let total_bytes = (num_bits + 7) / 8;
        if total_bytes > slice.len() {
            let msg = format!(
                "Attempt to read {} bits into buffer {} bytes",
                num_bits,
                slice.len()
            );
            return Err(TonCellError::CellParserError(msg));
        }
        let full_bytes = (num_bits) / 8;
        self.read_bytes(&mut slice[0..full_bytes])
            .map_cell_parser_error()?;
        let last_byte_len = num_bits % 8;
        if last_byte_len != 0 {
            let last_byte = self
                .read::<u8>(last_byte_len as u32)
                .map_cell_parser_error()?;
            slice[full_bytes] = last_byte << (8 - last_byte_len);
        }
        Ok(())
    }
}

pub fn concat_bytes(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    let mut c = Vec::with_capacity(a.len() + b.len());
    c.extend_from_slice(a);
    c.extend_from_slice(b);
    c
}

pub fn resolve_cell_type(is_exotic: &mut bool, data: &[u8]) -> u8 {
    if data.len() == 0 {
        *is_exotic = false;
        return CellType::OrdinaryCell as u8;
    }
    let exotic_type = data[0];
    if *is_exotic
        && (exotic_type == CellType::PrunnedBranchCell as u8
            || exotic_type == CellType::LibraryCell as u8
            || exotic_type == CellType::MerkleProofCell as u8
            || exotic_type == CellType::MerkleUpdateCell as u8)
    {
        return exotic_type;
    }
    *is_exotic = false;
    return CellType::OrdinaryCell as u8;
}

mod tests {
    use crate::cell::resolve_cell_type;

    #[test]
    fn test_resolve_cell_type() {
        let mut is_exotic = false;
        assert_eq!(resolve_cell_type(&mut is_exotic, &vec![1]), 255);
        assert_eq!(is_exotic, false);
        is_exotic = true;
        assert_eq!(resolve_cell_type(&mut is_exotic, &vec![]), 255);
        assert_eq!(is_exotic, false);
        is_exotic = true;
        assert_eq!(resolve_cell_type(&mut is_exotic, &vec![2]), 2);
        assert_eq!(is_exotic, true);
        assert_eq!(resolve_cell_type(&mut is_exotic, &vec![3]), 3);
        assert_eq!(is_exotic, true);
        assert_eq!(resolve_cell_type(&mut is_exotic, &vec![4]), 4);
        assert_eq!(is_exotic, true);
        assert_eq!(resolve_cell_type(&mut is_exotic, &vec![5]), 255);
        assert_eq!(is_exotic, false);
    }
}
