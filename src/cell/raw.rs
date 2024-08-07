use std::io::Cursor;

use bitstream_io::{BigEndian, BitWrite, BitWriter, ByteRead, ByteReader};
use crc::Crc;
use lazy_static::lazy_static;
use log::debug;

use crate::cell::{MapTonCellError, TonCellError};

use super::resolve_cell_type;

lazy_static! {
    pub static ref CRC_32_ISCSI: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISCSI);
}

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub enum CellType {
    OrdinaryCell = 255,
    PrunnedBranchCell = 1,
    LibraryCell = 2,
    MerkleProofCell = 3,
    MerkleUpdateCell = 4,
}

// Function to convert u8 to CellType
impl CellType {
    pub fn from_u8(value: u8) -> Option<CellType> {
        match value {
            255 => Some(CellType::OrdinaryCell),
            1 => Some(CellType::PrunnedBranchCell),
            2 => Some(CellType::LibraryCell),
            3 => Some(CellType::MerkleProofCell),
            4 => Some(CellType::MerkleUpdateCell),
            _ => None, // Return None if the value doesn't match any variant
        }
    }
}

/// Raw representation of Cell.
///
/// References are stored as indices in BagOfCells.
#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub(crate) struct RawCell {
    pub(crate) data: Vec<u8>,
    pub(crate) bit_len: usize,
    pub(crate) references: Vec<usize>,
    pub(crate) max_level: u8, // same as level_mask
    pub(crate) cell_type: u8,
    pub(crate) is_exotic: bool,
    pub(crate) has_hashes: bool,
}

/// Raw representation of BagOfCells.
///
/// `cells` must be topologically sorted.
#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub(crate) struct RawBagOfCells {
    pub(crate) cells: Vec<RawCell>,
    pub(crate) roots: Vec<usize>,
}

const GENERIC_BOC_MAGIC: u32 = 0xb5ee9c72;
const PROOF_BOC_MAGIC: u32 = 0x62356565;
const _INDEXED_BOC_MAGIC: u32 = 0x68ff65f3;
const _INDEXED_CRC32_MAGIC: u32 = 0xacc3a728;

impl RawBagOfCells {
    pub(crate) fn parse(serial: &[u8]) -> Result<RawBagOfCells, TonCellError> {
        let cursor = Cursor::new(serial);

        // parse header
        let mut reader: ByteReader<Cursor<&[u8]>, BigEndian> =
            ByteReader::endian(cursor, BigEndian);
        // serialized_boc#b5ee9c72
        let magic = reader.read::<u32>().map_boc_deserialization_error()?;

        let (has_idx, has_crc32c, _has_cache_bits, size_bytes) = match magic {
            GENERIC_BOC_MAGIC => {
                // has_idx:(## 1) has_crc32c:(## 1) has_cache_bits:(## 1) flags:(## 2) { flags = 0 }
                let header = reader.read::<u8>().map_boc_deserialization_error()?;
                let has_idx = (header >> 7) & 1 == 1;
                let has_crc32c = (header >> 6) & 1 == 1;
                let has_cache_bits = (header >> 5) & 1 == 1;
                // size:(## 3) { size <= 4 }
                let size = header & 0b0000_0111;

                (has_idx, has_crc32c, has_cache_bits, size)
            }
            magic => {
                return Err(TonCellError::boc_deserialization_error(format!(
                    "Unsupported cell magic number: {:#}",
                    magic
                )));
            }
        };
        //   off_bytes:(## 8) { off_bytes <= 8 }
        let off_bytes = reader.read::<u8>().map_boc_deserialization_error()?;
        //cells:(##(size * 8))
        let cells = read_var_size(&mut reader, size_bytes)?;
        //   roots:(##(size * 8)) { roots >= 1 }
        let roots = read_var_size(&mut reader, size_bytes)?;
        //   absent:(##(size * 8)) { roots + absent <= cells }
        let _absent = read_var_size(&mut reader, size_bytes)?;
        //   tot_cells_size:(##(off_bytes * 8))
        let _tot_cells_size = read_var_size(&mut reader, off_bytes)?;
        //   root_list:(roots * ##(size * 8))
        let mut root_list = vec![];
        for _ in 0..roots {
            root_list.push(read_var_size(&mut reader, size_bytes)?)
        }
        //   index:has_idx?(cells * ##(off_bytes * 8))
        let mut index = vec![];
        if has_idx {
            for _ in 0..cells {
                index.push(read_var_size(&mut reader, off_bytes)?)
            }
        }

        // finish parse header

        //   cell_data:(tot_cells_size * [ uint8 ])
        // read_var_size(&mut reader, _tot_cells_size as u8)?;
        let mut cell_vec = Vec::with_capacity(cells);
        let cur_cursor = reader
            .bitreader()
            .position_in_bits()
            .map_err(|err| TonCellError::boc_deserialization_error(err.to_string()))?;
        let serial_size = serial.len();

        let total_bytes_unread = serial.len() - (cur_cursor / 8) as usize;
        debug!("total bytes unread: {:?}", total_bytes_unread);
        if total_bytes_unread < _tot_cells_size {
            return Err(TonCellError::boc_deserialization_error(
                "Not enough bytes for cells data",
            ));
        }

        for i in 0..cells {
            let cell = read_cell(&mut reader, size_bytes)?;
            cell_vec.push(cell);
        }

        //   crc32c:has_crc32c?uint32
        let _crc32c = if has_crc32c {
            reader.read::<u32>().map_boc_deserialization_error()?
        } else {
            0
        };

        let position = reader
            .bitreader()
            .position_in_bits()
            .map_err(|err| TonCellError::boc_deserialization_error(err.to_string()))?;
        // TODO: Check crc32

        Ok(RawBagOfCells {
            cells: cell_vec,
            roots: root_list,
        })
    }

    pub(crate) fn serialize(&self, has_crc32: bool) -> Result<Vec<u8>, TonCellError> {
        //Based on https://github.com/toncenter/tonweb/blob/c2d5d0fc23d2aec55a0412940ce6e580344a288c/src/boc/Cell.js#L198

        let root_count = self.roots.len();
        if root_count > 1 {
            return Err(TonCellError::boc_serialization_error(format!(
                "Single root expected, got {}",
                root_count
            )));
        }

        let num_ref_bits = 32 - (self.cells.len() as u32).leading_zeros();
        let num_ref_bytes = (num_ref_bits + 7) / 8;

        let mut full_size = 0u32;
        let mut index = Vec::<u32>::with_capacity(self.cells.len());
        for cell in &self.cells {
            index.push(full_size);
            full_size += raw_cell_size(cell, num_ref_bytes);
        }

        let num_offset_bits = 32 - full_size.leading_zeros();
        let num_offset_bytes = (num_offset_bits + 7) / 8;

        let mut writer = BitWriter::endian(Vec::new(), BigEndian);

        writer
            .write(32, GENERIC_BOC_MAGIC)
            .map_boc_serialization_error()?;

        //write flags byte
        let has_idx = false;
        let has_cache_bits = false;
        let flags: u8 = 0;
        writer.write_bit(has_idx).map_boc_serialization_error()?;
        writer.write_bit(has_crc32).map_boc_serialization_error()?;
        writer
            .write_bit(has_cache_bits)
            .map_boc_serialization_error()?;
        writer.write(2, flags).map_boc_serialization_error()?;
        writer
            .write(3, num_ref_bytes)
            .map_boc_serialization_error()?;
        writer
            .write(8, num_offset_bytes)
            .map_boc_serialization_error()?;
        writer
            .write(8 * num_ref_bytes, self.cells.len() as u32)
            .map_boc_serialization_error()?;
        writer
            .write(8 * num_ref_bytes, 1)
            .map_boc_serialization_error()?; // One root for now
        writer
            .write(8 * num_ref_bytes, 0)
            .map_boc_serialization_error()?; // Complete BOCs only
        writer
            .write(8 * num_offset_bytes, full_size)
            .map_boc_serialization_error()?;
        writer
            .write(8 * num_ref_bytes, 0)
            .map_boc_serialization_error()?; // Root should have index 0

        for cell in &self.cells {
            write_raw_cell(&mut writer, cell, num_ref_bytes)?;
        }

        if has_crc32 {
            let bytes = writer.writer().ok_or_else(|| {
                TonCellError::boc_serialization_error("Stream is not byte-aligned")
            })?;
            let cs = CRC_32_ISCSI.checksum(bytes.as_slice());
            writer
                .write_bytes(cs.to_le_bytes().as_slice())
                .map_boc_serialization_error()?;
        }
        writer.byte_align().map_boc_serialization_error()?;
        let res = writer
            .writer()
            .ok_or_else(|| TonCellError::boc_serialization_error("Stream is not byte-aligned"))?;
        Ok(res.clone())
    }
}

fn read_cell(
    reader: &mut ByteReader<Cursor<&[u8]>, BigEndian>,
    size: u8,
) -> Result<RawCell, TonCellError> {
    let d1 = reader.read::<u8>().map_boc_deserialization_error()?;
    let d2 = reader.read::<u8>().map_boc_deserialization_error()?;

    let max_level = d1 >> 5;
    let mut is_exotic = (d1 & 8) != 0;
    let ref_num = d1 & 0x07;
    let data_size = ((d2 >> 1) + (d2 & 1)).into();
    let full_bytes = (d2 & 0x01) == 0;
    let has_hashes = (d1 & 16) != 0;
    let hashes_size = if has_hashes {
        get_hash_count(max_level) * 32
    } else {
        0
    };
    let depth_size = if has_hashes {
        get_hash_count(max_level) * 2
    } else {
        0
    };

    read_var_size(reader, hashes_size)?;
    read_var_size(reader, depth_size)?;

    let mut data = reader
        .read_to_vec(data_size)
        .map_boc_deserialization_error()?;

    let data_len = data.len();
    let padding_len = if data_len > 0 && !full_bytes {
        // Fix last byte,
        // see https://github.com/toncenter/tonweb/blob/c2d5d0fc23d2aec55a0412940ce6e580344a288c/src/boc/BitString.js#L302
        let num_zeros = data[data_len - 1].trailing_zeros();
        if num_zeros >= 8 {
            return Err(TonCellError::boc_deserialization_error(
                "Last byte of binary must not be zero if full_byte flag is not set",
            ));
        }
        data[data_len - 1] &= !(1 << num_zeros);
        num_zeros + 1
    } else {
        0
    };
    let bit_len = data.len() * 8 - padding_len as usize;

    let mut references: Vec<usize> = Vec::new();
    for _ in 0..ref_num {
        references.push(read_var_size(reader, size)?);
    }

    // the first byte is the cell type
    let cell_type = resolve_cell_type(&mut is_exotic, &data);
    let cell = RawCell {
        data,
        bit_len,
        references,
        max_level,
        cell_type,
        is_exotic,
        has_hashes,
    };
    Ok(cell)
}

fn get_hash_count(level_mask: u8) -> u8 {
    get_level_from_mask(level_mask & 7)
}

fn get_level_from_mask(mask: u8) -> u8 {
    let mut mask = mask;
    let mut n = 0;
    for i in 0..3 {
        n += mask & 1;
        mask = mask >> 1u8;
    }
    return n + 1;
}

fn raw_cell_size(cell: &RawCell, ref_size_bytes: u32) -> u32 {
    let data_len = (cell.bit_len + 7) / 8;
    2 + data_len as u32 + cell.references.len() as u32 * ref_size_bytes
}

fn write_raw_cell(
    writer: &mut BitWriter<Vec<u8>, BigEndian>,
    cell: &RawCell,
    ref_size_bytes: u32,
) -> Result<(), TonCellError> {
    let level = 0u32; // TODO: Support
    let is_exotic = 0u32; // TODO: Support
    let num_refs = cell.references.len() as u32;
    let d1 = num_refs + is_exotic * 8 + level * 32;

    let padding_bits = cell.bit_len % 8;
    let full_bytes = padding_bits == 0;
    let data = cell.data.as_slice();
    let data_len_bytes = (cell.bit_len + 7) / 8;
    // data_len_bytes <= 128 by spec, but d2 must be u8 by spec as well
    let d2 = (data_len_bytes * 2 - if full_bytes { 0 } else { 1 }) as u8; //subtract 1 if the last byte is not full

    writer.write(8, d1).map_boc_serialization_error()?;
    writer.write(8, d2).map_boc_serialization_error()?;
    if !full_bytes {
        writer
            .write_bytes(&data[..data_len_bytes - 1])
            .map_boc_serialization_error()?;
        let last_byte = data[data_len_bytes - 1];
        let l = last_byte | 1 << (8 - padding_bits - 1);
        writer.write(8, l).map_boc_serialization_error()?;
    } else {
        writer.write_bytes(data).map_boc_serialization_error()?;
    }

    for r in cell.references.as_slice() {
        writer
            .write(8 * ref_size_bytes, *r as u32)
            .map_boc_serialization_error()?;
        // One root for now
    }

    Ok(())
}

fn read_var_size(
    reader: &mut ByteReader<Cursor<&[u8]>, BigEndian>,
    n: u8,
) -> Result<usize, TonCellError> {
    let bytes = reader
        .read_to_vec(n.into())
        .map_boc_deserialization_error()?;

    let mut result = 0;
    for &byte in &bytes {
        result <<= 8;
        result |= usize::from(byte);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use tokio_test::assert_ok;

    use super::*;

    #[test]
    fn test_raw_cell_serialize() {
        let raw_cell = RawCell {
            data: vec![1; 128],
            bit_len: 1023,
            references: vec![],
            max_level: 255,
            cell_type: CellType::OrdinaryCell as u8,
            is_exotic: false,
            has_hashes: false,
        };
        let raw_bag = RawBagOfCells {
            cells: vec![raw_cell],
            roots: vec![0],
        };
        let _res = assert_ok!(raw_bag.serialize(false));
    }
}
