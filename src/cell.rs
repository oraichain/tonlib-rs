use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;
use std::io::Cursor;
use std::ops::Deref;
use std::process::exit;
use std::sync::Arc;

pub use bag_of_cells::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bit_reader::BitArrayReader;
use bit_string::*;
use bitstream_io::{BigEndian, BitReader, BitWrite, BitWriter, ByteRead, ByteReader};
pub use builder::*;
pub use dict_loader::*;
pub use error::*;
use log::debug;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, ToPrimitive, Zero};
pub use parser::*;
pub use raw::*;
use sha2::{Digest, Sha256};
pub use slice::*;
pub use state_init::*;
pub use util::*;

use crate::hashmap::{Hashmap, HashmapAugEResult, HashmapAugResult};
use crate::responses::{
    AccountBlock, BinTreeFork, BinTreeLeafRes, BinTreeRes, BlkPrevRef, BlockData, BlockExtra,
    BlockInfo, ConfigParam, ConfigParams, ConfigParamsValidatorSet, ExtBlkRef, McBlockExtra,
    ShardDescr, Transaction, ValidatorDescr, Validators,
};

mod bag_of_cells;
mod bit_reader;
mod bit_string;
mod builder;
mod dict_loader;
mod error;
mod parser;
mod raw;
mod slice;
mod state_init;
mod util;

pub type ArcCell = Arc<Cell>;

pub type SnakeFormattedDict = HashMap<[u8; 32], Vec<u8>>;

pub const HASH_BYTES: usize = 32;
pub const DEPTH_BYTES: usize = 2;

#[derive(PartialEq, Eq, Clone, Hash)]
pub struct Cell {
    pub data: Vec<u8>,
    pub bit_len: usize,
    pub references: Vec<ArcCell>,
    pub cell_type: u8,
    pub level_mask: u8,
    pub is_exotic: bool,
    pub has_hashes: bool,
    pub proof: bool,
    pub hashes: Vec<Vec<u8>>,
    pub depth: Vec<u16>,
}

impl Cell {
    pub fn parser(&self) -> CellParser {
        let bit_len = self.bit_len;
        let cursor = Cursor::new(&self.data);
        let bit_reader: BitReader<Cursor<&Vec<u8>>, BigEndian> =
            BitReader::endian(cursor, BigEndian);

        CellParser {
            bit_len,
            bit_reader,
        }
    }

    #[allow(clippy::let_and_return)]
    pub fn parse<F, T>(&self, parse: F) -> Result<T, TonCellError>
    where
        F: FnOnce(&mut CellParser) -> Result<T, TonCellError>,
    {
        let mut parser = self.parser();
        let res = parse(&mut parser);
        res
    }

    pub fn parse_fully<F, T>(&self, parse: F) -> Result<T, TonCellError>
    where
        F: FnOnce(&mut CellParser) -> Result<T, TonCellError>,
    {
        let mut reader = self.parser();
        let res = parse(&mut reader);
        reader.ensure_empty()?;
        res
    }

    pub fn reference(&self, idx: usize) -> Result<&ArcCell, TonCellError> {
        self.references.get(idx).ok_or(TonCellError::InvalidIndex {
            idx,
            ref_count: self.references.len(),
        })
    }

    fn get_level_from_mask(mut mask: u8) -> u8 {
        for i in 0..3 {
            if mask == 0 {
                return i;
            }
            mask = mask >> 1;
        }
        3
    }

    fn get_hashes_count_from_mask(mut mask: u8) -> u8 {
        let mut n = 0;
        for i in 0..3 {
            n += mask & 1;
            mask = mask >> 1;
        }
        return n + 1; // 1 repr + up to 3 higher hashes
    }

    fn get_level(&self) -> u8 {
        Cell::get_level_from_mask(self.level_mask & 7)
    }

    fn get_hashes_count(&self) -> u8 {
        return Cell::get_hashes_count_from_mask(self.level_mask & 7);
    }

    fn is_level_significant(&self, level: u8) -> bool {
        level == 0 || (self.level_mask >> (level - 1)) % 2 != 0
    }

    fn apply_level_mask(&self, level: u8) -> u8 {
        self.level_mask & ((1 << level) - 1)
    }

    fn get_level_mask(&self) -> Result<u8, TonCellError> {
        if self.is_exotic && self.cell_type != CellType::LibraryCell as u8 {
            // console.log(this.type);
            if self.cell_type == CellType::PrunnedBranchCell as u8 {
                return Ok(self.level_mask);
            }
            if self.cell_type == CellType::MerkleProofCell as u8 {
                return Ok(self.reference(0)?.get_level_mask()? >> 1);
            }
            if self.cell_type == CellType::MerkleUpdateCell as u8 {
                return Ok(self.reference(0)?.get_level_mask()?
                    | self.reference(1)?.get_level_mask()? >> 1);
            }
            return Err(TonCellError::cell_parser_error("Unknown special cell type"));
        } else {
            let mut level_mask = 0;
            for i in 0..self.references.len() {
                let reference = self.reference(i)?;
                level_mask |= reference.get_level_mask()?;
            }
            return Ok(level_mask);
        }
    }

    pub fn get_hash(&self, level: u8) -> Vec<u8> {
        let mut hash_i = Cell::get_hashes_count_from_mask(self.apply_level_mask(level)) - 1;
        if self.cell_type == CellType::PrunnedBranchCell as u8 {
            let this_hash_i = self.get_hashes_count() - 1;
            if hash_i != this_hash_i {
                let bit_reader = BitArrayReader {
                    array: self.data.clone(),
                    cursor: 0,
                };
                return bit_reader.get_range(16 + (hash_i as usize) * HASH_BYTES * 8, 256);
            }
            hash_i = 0;
        }
        return self.hashes[hash_i as usize].clone();
    }

    fn get_depth(&self, level: Option<u8>) -> u64 {
        let mut hash_i = Cell::get_hashes_count_from_mask(Cell::apply_level_mask(
            &self,
            level.unwrap_or_default(),
        )) - 1;

        if self.cell_type == CellType::PrunnedBranchCell as u8 {
            let this_hash_i = self.get_hashes_count() - 1;
            if hash_i != this_hash_i {
                let bit_reader = BitArrayReader {
                    array: self.data.clone(),
                    cursor: self.bit_len,
                };
                return bit_reader.read_uint16(
                    16 + this_hash_i as usize * HASH_BYTES * 8 + hash_i as usize * DEPTH_BYTES * 8,
                ) as u64;
            }
            hash_i = 0;
        }

        return self.depth[hash_i as usize] as u64;
    }

    fn get_max_depth(&self) -> usize {
        let mut max_depth = 0;
        if !self.references.is_empty() {
            for k in &self.references {
                let depth = k.get_max_depth();
                if depth > max_depth {
                    max_depth = depth;
                }
            }
            max_depth += 1;
        }
        max_depth
    }

    fn get_refs_descriptor(&self, _level_mask: Option<u8>) -> Result<[u8; 1], TonCellError> {
        let mut level_mask = 0u8;
        if !self.proof {
            level_mask = if let Some(level_mask) = _level_mask {
                level_mask
            } else {
                self.get_level_mask()?
            };
        }
        let mut d1: [u8; 1] = [0];
        //d1[0] = this.refs.length + this.isExotic * 8 + this.hasHashes * 16 + levelMask * 32;
        // ton node variant used
        let is_exotic_val = if self.is_exotic { 1 } else { 0 };
        d1[0] = (self.references.len() + is_exotic_val * 8 + (level_mask as usize) * 32) as u8;
        Ok(d1)
    }

    fn get_bits_descriptor(&self) -> u8 {
        let rest_bits = self.bit_len % 8;
        let full_bytes = rest_bits == 0;
        self.data.len() as u8 * 2 - if full_bytes { 0 } else { 1 } //subtract 1 if the last byte is not full
    }

    fn depth_to_array(&self, depth: usize) -> [u8; 2] {
        let mut d = [0; 2];
        d[1] = (depth % 256) as u8;
        d[0] = (depth / 256) as u8;
        d
    }

    pub fn get_repr(&self) -> Result<Vec<u8>, TonCellError> {
        let data_len = self.data.len();
        let rest_bits = self.bit_len % 8;
        let full_bytes = rest_bits == 0;
        let mut writer = BitWriter::endian(Vec::new(), BigEndian);
        let val = self.get_refs_descriptor(None)?;
        writer
            .write(8, val[0] as u32)
            .map_boc_serialization_error()?;
        writer
            .write(8, self.get_bits_descriptor())
            .map_boc_serialization_error()?;
        if !full_bytes {
            writer
                .write_bytes(&self.data[..data_len - 1])
                .map_boc_serialization_error()?;
            let last_byte = self.data[data_len - 1];
            let l = last_byte | 1 << (8 - rest_bits - 1);
            writer.write(8, l).map_boc_serialization_error()?;
        } else {
            writer
                .write_bytes(&self.data)
                .map_boc_serialization_error()?;
        }

        for r in &self.references {
            writer
                .write(8, (r.get_max_depth() / 256) as u8)
                .map_boc_serialization_error()?;
            writer
                .write(8, (r.get_max_depth() % 256) as u8)
                .map_boc_serialization_error()?;
        }
        for r in &self.references {
            writer
                .write_bytes(&r.cell_hash()?)
                .map_boc_serialization_error()?;
        }
        let result = writer
            .writer()
            .ok_or_else(|| TonCellError::cell_builder_error("Stream is not byte-aligned"))
            .map(|b| b.to_vec());
        result
    }

    pub fn finalize(&mut self) -> Result<(), TonCellError> {
        let bit_reader = BitArrayReader {
            array: self.data.clone(),
            cursor: self.bit_len,
        };

        let mut _type = CellType::OrdinaryCell as u8;
        if self.is_exotic {
            if self.bit_len < 8 {
                return Err(TonCellError::boc_deserialization_error(
                    "Not enough data for a special cell",
                ));
            }

            _type = bit_reader.read_uint8(0);
            if _type == CellType::OrdinaryCell as u8 {
                return Err(TonCellError::boc_deserialization_error(
                    "Special cell has Ordinary type",
                ));
            }
        }
        self.cell_type = _type;
        // println!("Cell Type {:?}", _type);

        match CellType::from_u8(_type).unwrap() {
            CellType::OrdinaryCell => {
                if self.proof != true {
                    for k in &self.references {
                        self.level_mask |= k.level_mask;
                    }
                }
            }
            CellType::PrunnedBranchCell => {
                if self.references.len() != 0 {
                    return Err(TonCellError::boc_deserialization_error(
                        "PrunnedBranch special cell has a cell reference",
                    ));
                }
                if self.data.len() < 16 {
                    return Err(TonCellError::boc_deserialization_error(
                        "Not enough data for a PrunnedBranch special cell",
                    ));
                }
                self.level_mask = bit_reader.read_uint8(8);
                let level = self.get_level();
                if level > 3 || level == 0 {
                    return Err(TonCellError::boc_deserialization_error(
                        "Prunned Branch has an invalid level",
                    ));
                }
                let new_level_mask = self.apply_level_mask(level - 1);
                let hashes = Cell::get_hashes_count_from_mask(new_level_mask);

                if self.data.len() * 8 < (2 + hashes as usize * (HASH_BYTES + DEPTH_BYTES)) * 8 {
                    return Err(TonCellError::boc_deserialization_error(
                        "Not enouch data for a PrunnedBranch special cell",
                    ));
                }
            }
            CellType::LibraryCell => {
                if self.data.len() * 8 < 8 + HASH_BYTES * 8 {
                    return Err(TonCellError::boc_deserialization_error(
                        "Not enouch data for a Library special cell",
                    ));
                }
            }
            CellType::MerkleProofCell => {
                if self.data.len() * 8 != 8 + (HASH_BYTES + DEPTH_BYTES) * 8 {
                    return Err(TonCellError::boc_deserialization_error(
                        "Not enouch data for a MerkleProof special cell",
                    ));
                }
                if self.references.len() != 1 {
                    return Err(TonCellError::boc_deserialization_error(
                        "Wrong references count for a MerkleProof special cell",
                    ));
                }
                let merkle_hash = bit_reader.get_range(8, HASH_BYTES * 8);
                let child_hash = self.references[0].get_hash(0);

                if !merkle_hash.eq(&child_hash) {
                    return Err(TonCellError::boc_deserialization_error(
                        "Hash mismatch in a MerkleProof special cell",
                    ));
                }
                if bit_reader.read_uint16(8 + HASH_BYTES * 8)
                    != self.references[0].get_depth(Some(0)) as u16
                {
                    return Err(TonCellError::boc_deserialization_error(
                        "Depth mismatch in a MerkleProof special cell",
                    ));
                }
                self.level_mask = self.references[0].level_mask >> 1;
            }
            CellType::MerkleUpdateCell => {
                if self.data.len() * 8 != 8 + (HASH_BYTES + DEPTH_BYTES) * 8 * 2 {
                    return Err(TonCellError::boc_deserialization_error(
                        "Not enouch data for a MerkleUpdate special cell",
                    ));
                }
                if self.references.len() != 2 {
                    return Err(TonCellError::boc_deserialization_error(
                        "Wrong references count for a MerkleUpdate special cell",
                    ));
                }
                let merkle_hash_0 = bit_reader.get_range(8, HASH_BYTES * 8);
                let child_hash_0 = self.references[0].get_hash(0);
                if !merkle_hash_0.eq(&child_hash_0) {
                    return Err(TonCellError::boc_deserialization_error(
                        "First hash mismatch in a MerkleUpdate special cell",
                    ));
                }

                if bit_reader.read_uint16(8 + 16 * HASH_BYTES)
                    != self.references[0].get_depth(Some(0)) as u16
                {
                    return Err(TonCellError::boc_deserialization_error(
                        "First depth mismatch in a MerkleUpdate special cell",
                    ));
                }
                if bit_reader.read_uint16(8 + 16 * HASH_BYTES + DEPTH_BYTES * 8)
                    != self.references[1].get_depth(Some(0)) as u16
                {
                    return Err(TonCellError::boc_deserialization_error(
                        "Second depth mismatch in a MerkleUpdate special cell",
                    ));
                }
                self.level_mask =
                    (self.references[0].level_mask | self.references[1].level_mask) >> 1;
            }

            _ => {
                return Err(TonCellError::boc_deserialization_error(
                    "Unknown special cell type",
                ));
            }
        }

        let total_hash_count = self.get_hashes_count();
        let hash_count = if _type == CellType::PrunnedBranchCell as u8 {
            1
        } else {
            total_hash_count
        };
        let hash_i_offset = total_hash_count - hash_count;

        self.hashes = vec![vec![]; hash_count as usize];
        self.depth = vec![0; hash_count as usize];

        let mut hash_i = 0;
        let level = self.get_level();

        for level_i in 0..=level {
            if !self.is_level_significant(level_i) {
                continue;
            }

            if hash_i < hash_i_offset {
                hash_i += 1;
                continue;
            }

            let mut repr: Vec<u8> = vec![];

            let new_level_mask = self.apply_level_mask(level_i);

            let d1 = self.get_refs_descriptor(Some(new_level_mask))?;
            let d2 = self.get_bits_descriptor();

            repr = concat_bytes(&repr, &d1.to_vec());
            repr = concat_bytes(&repr, &vec![d2]);

            if hash_i == hash_i_offset {
                if level_i != 0 && self.cell_type != CellType::PrunnedBranchCell as u8 {
                    return Err(TonCellError::boc_deserialization_error(
                        "Cannot deserialize cell",
                    ));
                }

                repr = concat_bytes(&repr, &bit_reader.get_top_upped_array()?);
            } else {
                //debug_log("add to hash own " + (hash_i - hash_i_offset - 1) + " hash", bytesToHex(this.hashes[hash_i - hash_i_offset - 1]));

                if level_i == 0 || self.cell_type == CellType::PrunnedBranchCell as u8 {
                    return Err(TonCellError::boc_deserialization_error(
                        "Cannot deserialize cell",
                    ));
                }

                repr = concat_bytes(&repr, &self.hashes[(hash_i - hash_i_offset - 1) as usize]);
            }

            let dest_i = hash_i - hash_i_offset;

            let mut depth = 0;
            for i in &self.references {
                let mut child_depth = 0;
                if self.cell_type == CellType::MerkleProofCell as u8
                    || self.cell_type == CellType::MerkleUpdateCell as u8
                {
                    child_depth = i.get_depth(Some(level_i + 1));
                } else {
                    child_depth = i.get_depth(Some(level_i));
                }
                repr = concat_bytes(&repr, &i.depth_to_array(child_depth as usize).to_vec());
                depth = std::cmp::max(depth, child_depth);
            }

            if self.references.len() != 0 {
                if depth >= 1024 {
                    return Err(TonCellError::boc_deserialization_error("Depth is too big"));
                }

                depth += 1;
            }
            self.depth[dest_i as usize] = depth as u16;

            // children hash
            for i in 0..self.references.len() {
                if self.cell_type == CellType::MerkleProofCell as u8
                    || self.cell_type == CellType::MerkleUpdateCell as u8
                {
                    repr = concat_bytes(&repr, &self.references[i].get_hash(level_i + 1));
                } else {
                    repr = concat_bytes(&repr, &self.references[i].get_hash(level_i));
                }
            }

            let mut hasher: Sha256 = Sha256::new();
            hasher.update(repr);

            self.hashes[dest_i as usize] = hasher.finalize()[..].to_vec();

            hash_i += 1;
        }
        // println!("hashes {:?}", self.hashes);
        // println!("depth {:?}", self.depth);
        Ok(())
    }

    pub fn cell_hash(&self) -> Result<Vec<u8>, TonCellError> {
        let mut hasher: Sha256 = Sha256::new();
        hasher.update(self.get_repr()?.as_slice());
        Ok(hasher.finalize()[..].to_vec())
    }

    pub fn cell_hash_base64(&self) -> Result<String, TonCellError> {
        Ok(URL_SAFE_NO_PAD.encode(self.cell_hash()?))
    }

    pub fn cell_hash_hex(&self) -> Result<String, TonCellError> {
        Ok(hex::encode(self.cell_hash()?))
    }

    ///Snake format when we store part of the data in a cell and the rest of the data in the first child cell (and so recursively).
    ///
    ///Must be prefixed with 0x00 byte.
    ///### TL-B scheme:
    ///
    /// ``` tail#_ {bn:#} b:(bits bn) = SnakeData ~0; ```
    ///
    /// ``` cons#_ {bn:#} {n:#} b:(bits bn) next:^(SnakeData ~n) = SnakeData ~(n + 1); ```
    pub fn load_snake_formatted_dict(&self) -> Result<SnakeFormattedDict, TonCellError> {
        let dict_loader = GenericDictLoader::new(
            key_extractor_256bit,
            value_extractor_snake_formatted_string,
            256,
        );
        self.load_generic_dict(&dict_loader)
    }

    pub fn load_snake_formatted_string(&self) -> Result<String, TonCellError> {
        let mut cell: &Cell = self;
        let mut first_cell = true;
        let mut uri = String::new();
        loop {
            let parsed_cell = if first_cell {
                String::from_utf8_lossy(&cell.data[1..]).to_string()
            } else {
                String::from_utf8_lossy(&cell.data).to_string()
            };
            uri.push_str(&parsed_cell);
            match cell.references.len() {
                0 => return Ok(uri),
                1 => {
                    cell = cell.references[0].deref();
                    first_cell = false;
                }
                n => {
                    return Err(TonCellError::boc_deserialization_error(format!(
                        "Invalid snake format string: found cell with {} references",
                        n
                    )))
                }
            }
        }
    }

    fn parse_snake_data(&self, buffer: &mut Vec<u8>) -> Result<(), TonCellError> {
        let mut cell: &Cell = self;
        let mut first_cell = true;
        loop {
            let mut parser = cell.parser();
            if first_cell {
                let first_byte = parser.load_u8(8)?;

                if first_byte != 0 {
                    return Err(TonCellError::boc_deserialization_error(
                        "Invalid snake format",
                    ));
                }
            }
            let remaining_bytes = parser.remaining_bytes();
            let mut data = parser.load_bytes(remaining_bytes)?;
            buffer.append(&mut data);
            match cell.references.len() {
                0 => return Ok(()),
                1 => {
                    cell = cell.references[0].deref();
                    first_cell = false;
                }
                n => {
                    return Err(TonCellError::boc_deserialization_error(format!(
                        "Invalid snake format string: found cell with {} references",
                        n
                    )))
                }
            }
        }
    }

    pub fn load_generic_dict<K, V, L>(&self, dict_loader: &L) -> Result<HashMap<K, V>, TonCellError>
    where
        K: Hash + Eq + Clone,
        L: DictLoader<K, V>,
    {
        let mut map: HashMap<K, V> = HashMap::new();
        self.dict_to_hashmap::<K, V, L>(BitString::new(), &mut map, dict_loader)?;
        Ok(map)
    }

    ///Port of https://github.com/ton-community/ton/blob/17b7e9e6154131399d57507b0c4a178752342fd8/src/boc/dict/parseDict.ts#L55
    fn dict_to_hashmap<K, V, L>(
        &self,
        prefix: BitString,
        map: &mut HashMap<K, V>,
        dict_loader: &L,
    ) -> Result<(), TonCellError>
    where
        K: Hash + Eq,
        L: DictLoader<K, V>,
    {
        let mut parser = self.parser();

        let lb0 = parser.load_bit()?;
        let mut pp = prefix;
        let prefix_length;
        if !lb0 {
            // Short label detected
            prefix_length = parser.load_unary_length()?;
            // Read prefix
            if prefix_length != 0 {
                let val = parser.load_uint(prefix_length)?;
                pp.shl_assign_and_add(prefix_length, val);
            }
        } else {
            let lb1 = parser.load_bit()?;
            if !lb1 {
                // Long label detected
                prefix_length = parser
                    .load_uint(
                        ((dict_loader.key_bit_len() - pp.bit_len() + 1) as f32)
                            .log2()
                            .ceil() as usize,
                    )?
                    .to_usize()
                    .unwrap();
                if prefix_length != 0 {
                    let val = parser.load_uint(prefix_length)?;
                    pp.shl_assign_and_add(prefix_length, val);
                }
            } else {
                // Same label detected
                let bit = parser.load_bit()?;
                prefix_length = parser
                    .load_uint(
                        ((dict_loader.key_bit_len() - pp.bit_len() + 1) as f32)
                            .log2()
                            .ceil() as usize,
                    )?
                    .to_usize()
                    .unwrap();
                if bit {
                    pp.shl_assign_and_fill(prefix_length);
                } else {
                    pp.shl_assign(prefix_length)
                }
            }
        }

        if dict_loader.key_bit_len() - pp.bit_len() == 0 {
            let bytes = pp.get_value_as_bytes();
            let key = dict_loader.extract_key(bytes.as_slice())?;
            let offset = self.bit_len - parser.remaining_bits();
            let cell_slice = CellSlice::new_with_offset(self, offset)?;
            let value = dict_loader.extract_value(&cell_slice)?;
            map.insert(key, value);
        } else {
            // NOTE: Left and right branches are implicitly contain prefixes '0' and '1'
            let left = self.reference(0)?;
            let right = self.reference(1)?;
            pp.shl_assign(1);
            left.dict_to_hashmap(pp.clone(), map, dict_loader)?;
            pp = pp + BigUint::one();
            right.dict_to_hashmap(pp, map, dict_loader)?;
        }
        Ok(())
    }

    pub fn to_arc(self) -> ArcCell {
        Arc::new(self)
    }

    pub fn load_ref_if_exist<F, T>(
        &self,
        ref_index: &mut usize,
        parse_option: Option<F>,
    ) -> Result<(Option<T>, Option<&Cell>), TonCellError>
    where
        F: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<T, TonCellError>,
    {
        let reference = self.reference(ref_index.to_owned())?;
        *ref_index += 1;
        let mut parser = reference.parser();
        if reference.cell_type != CellType::PrunnedBranchCell as u8 && parse_option.is_some() {
            let parse = parse_option.unwrap();
            let res = parse(&reference, &mut 0usize, &mut parser)?;
            return Ok((Some(res), None));
        } else if reference.cell_type == CellType::PrunnedBranchCell as u8 {
            return Ok((None, Some(reference)));
        }
        Err(TonCellError::cell_parser_error("Load ref not supported"))
    }

    pub fn load_maybe_ref<F, F2, T>(
        &self,
        ref_index: &mut usize,
        parser: &mut CellParser,
        parse_option: Option<F>,
        parse_prunned_branch_cell_option: Option<F2>,
    ) -> Result<(Option<T>, Option<&Cell>), TonCellError>
    where
        F: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<T, TonCellError>,
        F2: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<T, TonCellError>,
    {
        let exist = parser.load_bit()?;
        if !exist || parse_option.is_none() {
            return Ok((None, None));
        };
        let reference = self.reference(ref_index.to_owned())?;
        *ref_index += 1;
        let mut new_parser = reference.parser();
        debug!(
            "reference cell type, ref index and ref data: {:?}, {:?}, {:?}",
            reference.cell_type, ref_index, reference.data
        );
        if reference.cell_type != CellType::PrunnedBranchCell as u8 {
            let f = parse_option.unwrap();
            let res = f(&reference, &mut 0usize, &mut new_parser)?;
            return Ok((Some(res), None));
        } else if let Some(f2) = parse_prunned_branch_cell_option {
            let res = f2(&reference, &mut 0usize, &mut new_parser)?;
            return Ok((Some(res), None));
        }
        Ok((None, Some(reference)))
    }

    pub fn load_ref_if_exist_without_self<F, T>(
        &self,
        ref_index: &mut usize,
        parse_option: Option<F>,
    ) -> Result<(Option<T>, Option<&Cell>), TonCellError>
    where
        F: FnOnce(&mut CellParser) -> Result<T, TonCellError>,
    {
        let reference = self.reference(ref_index.to_owned())?;
        *ref_index += 1;
        if reference.cell_type != CellType::PrunnedBranchCell as u8 && parse_option.is_some() {
            let parse = parse_option.unwrap();
            let res = reference.parse(parse)?;
            return Ok((Some(res), None));
        } else if reference.cell_type == CellType::PrunnedBranchCell as u8 {
            return Ok((None, Some(reference)));
        }
        Err(TonCellError::cell_parser_error("Load ref not supported"))
    }

    pub fn load_block_info(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<BlockInfo, TonCellError> {
        let mut block_info = BlockInfo::default();
        if parser.load_u32(32)? != 0x9bc7a987 {
            return Err(TonCellError::cell_parser_error("Not a BlockInfo"));
        }
        let version = parser.load_u32(32)?;
        let not_master = parser.load_bit()?;
        let after_merge = parser.load_bit()?;
        let before_split = parser.load_bit()?;
        let after_split = parser.load_bit()?;
        let want_split = parser.load_bit()?;
        let want_merge = parser.load_bit()?;
        let key_block = parser.load_bit()?;
        let vert_seqno_incr = parser.load_bit()?;
        let flags = parser.load_u8(8)?;
        if flags > 1 {
            return Err(TonCellError::cell_parser_error("data.flags > 1"));
        }
        let seq_no = parser.load_u32(32)?;
        let vert_seq_no = parser.load_u32(32)?;
        if vert_seqno_incr && vert_seq_no < 1 {
            return Err(TonCellError::cell_parser_error(
                "data.vert_seqno_incr > data.vert_seq_no",
            ));
        }
        let prev_seq_no = seq_no - 1;
        parser.load_shard_ident()?;
        let gen_utime = parser.load_u32(32)?;
        let start_lt = parser.load_u64(64)?;
        let end_lt = parser.load_u64(64)?;
        let gen_validator_list_hash_short = parser.load_u32(32)?;
        let gen_catchain_seqno = parser.load_u32(32)?;
        let min_ref_mc_seqno = parser.load_u32(32)?;
        let prev_key_block_seqno = parser.load_u32(32)?;
        debug!("prev key block seq no: {:?}", prev_key_block_seqno);
        debug!("flag & 1: {:?}", flags & 1);
        debug!("not master: {:?}", not_master);

        if flags & 1 > 0 {
            parser.load_global_version()?;
        }
        if not_master {
            cell.load_ref_if_exist_without_self(ref_index, Some(Cell::load_blk_master_info))?;
        }

        let result = cell.load_ref_if_exist(
            ref_index,
            Some(
                |c: &Cell, inner_ref_index: &mut usize, p: &mut CellParser| {
                    Cell::load_blk_prev_info(c, inner_ref_index, p, after_merge)
                },
            ),
        )?;
        block_info.prev_ref = result.0.unwrap_or_default();

        if vert_seqno_incr {
            cell.load_ref_if_exist(
                ref_index,
                Some(
                    |c: &Cell, inner_ref_index: &mut usize, p: &mut CellParser| {
                        Cell::load_blk_prev_info(c, inner_ref_index, p, false)
                    },
                ),
            )?;
        }
        Ok(block_info)
    }

    pub fn load_blk_master_info(parser: &mut CellParser) -> Result<ExtBlkRef, TonCellError> {
        Cell::load_ext_blk_ref(parser)
    }

    pub fn load_ext_blk_ref(parser: &mut CellParser) -> Result<ExtBlkRef, TonCellError> {
        let end_lt = parser.load_u64(64)?;
        let seqno = parser.load_u32(32)?;
        let root_hash = parser.load_bytes(32)?;
        let file_hash = parser.load_bytes(32)?;
        debug!("end_lt and seq_no: {:?}, {:?}", end_lt, seqno);
        debug!("root hash: {:?}", hex::encode(root_hash.clone()));
        debug!("file hash: {:?}", file_hash);
        Ok(ExtBlkRef {
            end_lt,
            seqno,
            root_hash,
            file_hash,
        })
    }

    pub fn load_blk_prev_info(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: bool,
    ) -> Result<BlkPrevRef, TonCellError> {
        if !n {
            return Ok(BlkPrevRef {
                first_prev: Some(Cell::load_ext_blk_ref(parser)?),
                second_prev: None,
            });
        }
        let first_prev_result =
            cell.load_ref_if_exist_without_self(ref_index, Some(Cell::load_ext_blk_ref))?;
        let second_prev_result =
            cell.load_ref_if_exist_without_self(ref_index, Some(Cell::load_ext_blk_ref))?;
        Ok(BlkPrevRef {
            first_prev: first_prev_result.0,
            second_prev: second_prev_result.0,
        })
    }

    pub fn load_value_flow(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        let magic = parser.load_u32(32)?;
        if magic != 0xb8e48dfb {
            // return Err(TonCellError::cell_parser_error("not a ValueFlow"));
            return Ok(());
        }
        Ok(())
    }

    pub fn load_merkle_update(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        if parser.load_u8(8)? != 0x04 {
            return Err(TonCellError::cell_parser_error("not a Merkle Update"));
        }
        debug!("current ref index: {:?}", ref_index);
        let old_hash = parser.load_bytes(32)?;
        let new_hash = parser.load_bytes(32)?;
        debug!("old hash: {:?}", old_hash);
        debug!("new hash: {:?}", new_hash);
        let old = cell.reference(*ref_index)?;
        *ref_index += 1;
        let new = cell.reference(*ref_index)?;
        *ref_index += 1;
        Ok(())
    }

    pub fn load_block_extra(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<BlockExtra, TonCellError> {
        if parser.load_u32(32)? != 0x4a33f6fd {
            return Err(TonCellError::cell_parser_error("not a BlockExtra"));
        }

        // debug!("Cell hash: {:?}", cell.());

        let mut block_extra = BlockExtra::default();

        cell.load_ref_if_exist_without_self(ref_index, Some(Cell::load_in_msg_descr))?;
        cell.load_ref_if_exist_without_self(ref_index, Some(Cell::load_out_msg_descr))?;
        block_extra.account_blocks = cell
            .load_ref_if_exist(ref_index, Some(Cell::load_shard_account_blocks))?
            .0;
        let rand_seed = parser.load_bytes(32)?;
        let created_by = parser.load_bytes(32)?;

        let res = cell.load_maybe_ref(
            ref_index,
            parser,
            Some(Cell::load_mc_block_extra),
            None::<fn(&Cell, &mut usize, &mut CellParser) -> Result<McBlockExtra, TonCellError>>,
        )?;

        if let Some(custom) = res.0 {
            block_extra.custom = custom;
        }
        Ok(block_extra)
    }

    pub fn load_in_msg_descr(parser: &mut CellParser) -> Result<(), TonCellError> {
        Ok(())
    }

    pub fn load_out_msg_descr(parser: &mut CellParser) -> Result<(), TonCellError> {
        Ok(())
    }

    pub fn load_shard_account_blocks(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<HashMap<String, AccountBlock>, TonCellError> {
        let result = Cell::load_hash_map_aug_e(
            cell,
            ref_index,
            parser,
            256,
            Cell::load_account_block,
            Cell::load_currency_collection,
        )?;
        Ok(result.into_iter().map(|(k, v)| (k, v.value)).collect())
    }

    pub fn load_hash_map<T>(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: usize,
        f: fn(&Cell, &mut usize, &mut CellParser, &BigUint) -> Result<Option<T>, TonCellError>,
    ) -> Result<HashMap<String, T>, TonCellError>
    where
        T: Debug,
    {
        let mut hashmap = Hashmap::new(n, f);
        hashmap.deserialize(cell, ref_index, parser)?;
        Ok(hashmap.map)
    }

    pub fn load_hash_map_e<T>(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: usize,
        f: fn(&Cell, &mut usize, &mut CellParser, &BigUint) -> Result<Option<T>, TonCellError>,
    ) -> Result<HashMap<String, T>, TonCellError>
    where
        T: Debug,
    {
        let mut hashmap = Hashmap::new(n, f);
        hashmap.deserialize_e(cell, ref_index, parser)?;
        Ok(hashmap.map)
    }

    pub fn load_hash_map_aug_e<F1, F2, T1, T2>(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: usize,
        f1: F1,
        f2: F2,
    ) -> Result<HashMap<String, HashmapAugEResult<T1, T2>>, TonCellError>
    where
        F1: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<T1, TonCellError> + Copy,
        F2: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<T2, TonCellError> + Copy,
        T1: Clone + Debug + Default,
        T2: Clone + Debug + Default,
    {
        let hash_map_fn = |cell: &Cell,
                           ref_index: &mut usize,
                           parser: &mut CellParser,
                           _key: &BigUint|
         -> Result<Option<HashmapAugEResult<T1, T2>>, TonCellError> {
            let extra = f2(cell, ref_index, parser)?;
            let value = f1(cell, ref_index, parser)?;
            Ok(Some(HashmapAugEResult { value, extra }))
        };
        let mut hashmap = Hashmap::new(n, hash_map_fn);
        hashmap.deserialize_e(cell, ref_index, parser)?;
        debug!("data map: {:?}", hashmap.map);
        Ok(hashmap.map)
    }

    pub fn load_hash_map_aug<F1, F2, T1, T2>(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: usize,
        f1: F1,
        f2: F2,
    ) -> Result<HashMap<String, HashmapAugResult<T1, T2>>, TonCellError>
    where
        F1: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<T1, TonCellError> + Copy,
        F2: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<T2, TonCellError> + Copy,
        T1: Clone + Debug + Default,
        T2: Clone + Debug + Default,
    {
        let hash_map_fn = |cell: &Cell,
                           ref_index: &mut usize,
                           parser: &mut CellParser,
                           _key: &BigUint|
         -> Result<Option<HashmapAugResult<T1, T2>>, TonCellError> {
            let extra = f2(cell, ref_index, parser)?;
            let value = f1(cell, ref_index, parser)?;
            Ok(Some(HashmapAugResult { extra, value }))
        };
        let mut hashmap = Hashmap::new(n, hash_map_fn);
        hashmap.deserialize(cell, ref_index, parser)?;

        Ok(hashmap.map)
    }

    pub fn load_shard_account(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        Cell::load_account(cell, ref_index, parser)?;
        let last_trans_hash = parser.load_bytes(32)?;
        let last_trans_lt = parser.load_u64(64)?;
        debug!("last trans hash: {:?}", last_trans_hash);
        debug!("last trans lt: {:?}", last_trans_lt);
        Ok(())
    }

    pub fn load_account_block(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<AccountBlock, TonCellError> {
        let magic = parser.load_uint(4)?;
        if magic != BigUint::from_u8(0x5).unwrap() {
            return Err(TonCellError::cell_parser_error("not an AccountBlock"));
        }
        let account_addr = parser.load_bytes(32)?;
        debug!("account addr load account block: {:?}", account_addr);
        let transactions = Cell::load_hash_map_aug(
            cell,
            ref_index,
            parser,
            64,
            |ref_cell: &Cell, inner_ref_index: &mut usize, _parser: &mut CellParser| {
                let result =
                    ref_cell.load_ref_if_exist(inner_ref_index, Some(Cell::load_transaction))?;
                Ok((result.0, result.1.map(|v| v.clone())))
            },
            Cell::load_currency_collection,
        )?;
        cell.load_ref_if_exist(ref_index, Some(Cell::load_hash_update))?;

        let mut account_block = AccountBlock::default();
        account_block.account_addr = account_addr;
        account_block.transactions = transactions
            .into_iter()
            .map(|(k, v)| (k, v.value))
            .collect();
        Ok(account_block)
    }

    pub fn load_depth_balance_info(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        let split_depth = parser.load_uint_le(30)?;
        debug!("split depth: {:?}", split_depth);
        Cell::load_currency_collection(cell, ref_index, parser)?;
        Ok(())
    }

    pub fn load_account(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        if parser.load_u32(32)? != 0x4a33f6fd {
            return Err(TonCellError::cell_parser_error("not a BlockExtra"));
        }
        cell.load_ref_if_exist_without_self(ref_index, Some(Cell::load_in_msg_descr))?;
        cell.load_ref_if_exist_without_self(ref_index, Some(Cell::load_out_msg_descr))?;
        cell.load_ref_if_exist(ref_index, Some(Cell::load_shard_account_blocks))?;
        Ok(())
    }

    pub fn load_currency_collection(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        Cell::load_grams(parser)?;
        Cell::load_extra_currency_collection(cell, ref_index, parser)?;
        Ok(())
    }

    pub fn load_grams(parser: &mut CellParser) -> Result<(), TonCellError> {
        parser.load_var_uinteger(16)?;
        Ok(())
    }

    pub fn load_extra_currency_collection(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        let result = Cell::load_hash_map_e(
            cell,
            ref_index,
            parser,
            32,
            |cell: &Cell, ref_index: &mut usize, parser: &mut CellParser, _key: &BigUint| {
                let result = parser.load_var_uinteger(32)?;
                debug!("load extra currency collection: {:?}", result);
                Ok(Some(result))
            },
        )?;
        Ok(())
    }

    pub fn load_transaction(
        cell: &Cell,
        _ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<Transaction, TonCellError> {
        let mut transaction = Transaction::default();
        transaction.hash = cell.get_hash(0);
        transaction.account_addr = parser.load_bytes(32)?;
        transaction.lt = parser.load_u64(64)?;
        transaction.prev_trans_hash = parser.load_bytes(32)?;
        transaction.prev_trans_lt = parser.load_u64(64)?;
        transaction.now = parser.load_u32(32)?;
        Ok(transaction)
    }

    pub fn load_hash_update(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        let magic = parser.load_u8(8)?;
        if magic != 0x72 {
            return Err(TonCellError::cell_parser_error("not a hash update"));
        }
        let old_hash = parser.load_bytes(32)?;
        let new_hash = parser.load_bytes(32)?;
        debug!("old hash load hash update: {:?}", old_hash);
        debug!("new hash load hash update: {:?}", new_hash);
        Ok(())
    }

    pub fn load_mc_block_extra(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<McBlockExtra, TonCellError> {
        let mut mc_block_extra = McBlockExtra::default();

        let magic = parser.load_u16(16)?;
        if magic != 0xcca5 {
            return Err(TonCellError::cell_parser_error("not a McBlockExtra"));
        }
        let key_block = parser.load_bit()?;
        mc_block_extra.shards = Cell::load_shard_hashes(cell, ref_index, parser)?;
        Cell::load_shard_fees(cell, ref_index, parser)?;

        let cell_r1 = cell.reference(ref_index.to_owned())?;
        *ref_index += 1;
        let new_ref_index = &mut 0usize;
        // use a new parser to reset cell cursor, since we are handling a new cell.
        let cell_r1_parser = &mut cell_r1.parser();
        debug!("current cell data: {:?}", cell.data);
        debug!("ref index after all: {:?}", ref_index);
        debug!("cell r1 type: {:?}", cell_r1.cell_type);
        debug!("cell r1: {:?}", cell_r1.data);
        if cell_r1.cell_type == CellType::OrdinaryCell as u8 {
            // prev_blk_signatures
            Cell::load_hash_map_e(
                &cell_r1,
                new_ref_index,
                cell_r1_parser,
                16,
                Cell::load_crypto_signature_pair,
            )?;
            // recover_create_msg
            Cell::load_maybe_ref(
                &cell_r1,
                new_ref_index,
                cell_r1_parser,
                Some(Cell::load_in_msg),
                None::<fn(&Cell, &mut usize, &mut CellParser) -> Result<(), TonCellError>>,
            )?;

            // mint_msg
            Cell::load_maybe_ref(
                &cell_r1,
                new_ref_index,
                cell_r1_parser,
                Some(Cell::load_in_msg),
                None::<fn(&Cell, &mut usize, &mut CellParser) -> Result<(), TonCellError>>,
            )?;
        }
        if key_block {
            mc_block_extra.config = Cell::load_config_params(cell, ref_index, parser)?;
        }
        Ok(mc_block_extra)
    }

    pub fn load_shard_hashes(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<HashMap<String, Vec<ShardDescr>>, TonCellError> {
        let hashmap = Cell::load_hash_map_e(
            cell,
            ref_index,
            parser,
            32,
            |ref_cell: &Cell,
             inner_ref_index: &mut usize,
             _parser: &mut CellParser,
             _key: &BigUint| {
                let result = ref_cell.load_ref_if_exist(
                    inner_ref_index,
                    Some(
                        |ref_ref_cell: &Cell,
                         inner_inner_ref_index: &mut usize,
                         parser: &mut CellParser| {
                            Cell::load_bin_tree(
                                ref_ref_cell,
                                inner_inner_ref_index,
                                parser,
                                Some(Cell::load_shard_descr),
                            )
                        },
                    ),
                )?;
                Ok(result.0)
            },
        )?;

        let mut result_map = HashMap::new();
        for (key, value) in hashmap {
            if let Some(tree_res) = value {
                let shard_descrs = tree_res.get_all_shard_descrs_as_vec();
                result_map.insert(key, shard_descrs);
            } else {
                result_map.insert(key, Vec::new());
            }
        }

        Ok(result_map)
    }

    pub fn load_bin_tree<F>(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        parse_option: Option<F>,
    ) -> Result<Option<BinTreeRes>, TonCellError>
    where
        F: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<BinTreeLeafRes, TonCellError>
            + Copy,
    {
        Cell::load_bin_tree_r(cell, ref_index, parser, parse_option)
    }

    pub fn load_bin_tree_r<F>(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        parse_option: Option<F>,
    ) -> Result<Option<BinTreeRes>, TonCellError>
    where
        F: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<BinTreeLeafRes, TonCellError>
            + Copy,
    {
        if !parser.load_bit()? {
            if parse_option.is_none() {
                return Ok(None);
            }

            let parse = parse_option.unwrap();
            let res: BinTreeLeafRes = parse(cell, ref_index, parser)?;
            return Ok(Some(BinTreeRes::Leaf(res)));
        } else {
            let left = cell
                .load_ref_if_exist(
                    ref_index,
                    Some(
                        |ref_ref_cell: &Cell,
                         inner_inner_ref_index: &mut usize,
                         parser: &mut CellParser| {
                            Cell::load_bin_tree_r(
                                ref_ref_cell,
                                inner_inner_ref_index,
                                parser,
                                parse_option,
                            )
                        },
                    ),
                )?
                .0;

            let right = cell
                .load_ref_if_exist(
                    ref_index,
                    Some(
                        |ref_ref_cell: &Cell,
                         inner_inner_ref_index: &mut usize,
                         parser: &mut CellParser| {
                            Cell::load_bin_tree_r(
                                ref_ref_cell,
                                inner_inner_ref_index,
                                parser,
                                parse_option,
                            )
                        },
                    ),
                )?
                .0;

            return Ok(Some(BinTreeRes::Fork(Box::new(BinTreeFork {
                left: left.unwrap_or(None),
                right: right.unwrap_or(None),
            }))));
        }
    }

    pub fn load_shard_descr(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<BinTreeLeafRes, TonCellError> {
        let _type = parser.load_uint(4)?;
        if _type != BigUint::from_u8(0xa).unwrap() && _type != BigUint::from_u8(0xb).unwrap() {
            return Err(TonCellError::cell_parser_error("not a ShardDescr"));
        }

        let mut shard_descr = ShardDescr::default();
        shard_descr.seqno = parser.load_u32(32)?;
        // println!("Shard {}", shard_descr.seqno);
        shard_descr.reg_mc_seqno = parser.load_u32(32)?;
        shard_descr.start_lt = parser.load_u64(64)?;
        shard_descr.end_lt = parser.load_u64(64)?;
        shard_descr.root_hash = parser.load_bytes(32)?;
        shard_descr.file_hash = parser.load_bytes(32)?;
        parser.load_bit()?; // before_split
        parser.load_bit()?; // before merge
        parser.load_bit()?; // want split
        parser.load_bit()?; // want merge
        parser.load_bit()?; // nx_cc_updated
        let flag = parser.load_uint(3)?; //flags
        if flag != BigUint::zero() {
            return Err(TonCellError::cell_parser_error(
                "ShardDescr data.flags !== 0",
            ));
        }
        parser.load_uint(32)?; //next_catchain_seqno
        shard_descr.next_validator_shard = parser.load_u64(64)?;
        parser.load_uint(32)?; //min_ref_mc_seqno
        shard_descr.gen_utime = parser.load_u64(32)?;
        // TODO: load split_merge_at, fees_collected, funds_created

        Ok(BinTreeLeafRes::ShardDescr(shard_descr))
    }

    pub fn load_shard_fees(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        let hashmap = Cell::load_hash_map_aug_e(
            cell,
            ref_index,
            parser,
            96,
            Cell::load_shard_fee_created,
            Cell::load_shard_fee_created,
        )?;
        Ok(())
    }

    pub fn load_shard_fee_created(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        Cell::load_currency_collection(cell, ref_index, parser)?;
        Cell::load_currency_collection(cell, ref_index, parser)?;
        Ok(())
    }

    pub fn load_crypto_signature_pair(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        _key: &BigUint,
    ) -> Result<Option<()>, TonCellError> {
        let node_id_short = parser.load_bytes(32)?;
        debug!("node id short: {:?}", node_id_short);
        Cell::load_crypto_signature(cell, ref_index, parser)?;
        // We can safely ignore this since it is called in load_ref_if_exist
        Ok(Some(()))
    }

    pub fn load_crypto_signature(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        let magic = parser.load_uint(4)?;
        if magic != BigUint::from_u8(0x5).unwrap() {
            return Err(TonCellError::cell_parser_error(
                "not a CryptoSignatureSimple",
            ));
        }
        let r = parser.load_bytes(32)?;
        let s = parser.load_bytes(32)?;
        Ok(())
    }

    pub fn load_in_msg(
        _cell: &Cell,
        _ref_index: &mut usize,
        _parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        Ok(())
    }

    pub fn load_config_params(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<ConfigParams, TonCellError> {
        let mut config_params = ConfigParams::default();

        let config_addr = parser.load_bytes(32)?;
        debug!("config addr: {:?}", config_addr);
        let res = cell.load_ref_if_exist(
            ref_index,
            Some(
                |inner_cell: &Cell, inner_ref_index: &mut usize, inner_parser: &mut CellParser| {
                    let res = Cell::load_hash_map(
                        inner_cell,
                        inner_ref_index,
                        inner_parser,
                        32,
                        |hashmap_cell: &Cell,
                         hashmap_ref_index: &mut usize,
                         _hashmap_parser: &mut CellParser,
                         n: &BigUint| {
                            let res = hashmap_cell.load_ref_if_exist(
                                hashmap_ref_index,
                                Some(|inner_inner_cell: &Cell,
                                 inner_inner_ref_index: &mut usize,
                                 inner_inner_parser: &mut CellParser| {
                                    Cell::load_config_param(inner_inner_cell, inner_inner_ref_index, inner_inner_parser, n)
                                }),
                            )?;
                            Ok(res.0)
                        },
                    )?;
                    Ok(res)
                },
            ),
        )?;

        if let Some(config) = res.0 {
            config_params.config = config;
        } else {
            return Err(TonCellError::cell_parser_error("No config params to load"));
        }
        Ok(config_params)
    }

    pub fn load_config_param(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: &BigUint,
    ) -> Result<Option<ConfigParam>, TonCellError> {
        if parser.remaining_bits() < parser.bit_len || *ref_index != 0 {
            return Err(TonCellError::cell_parser_error("Invalid config cell"));
        }
        debug!("config param number: {:?}", n.to_string());
        // we dont need to implement all config params because each param is a cell ref -> they are independent.
        let n_str = n.to_string();

        // validator set
        if n_str == "32" {
            return Ok(Some(ConfigParam::ConfigParams32(
                Cell::load_config_param_32(cell, ref_index, parser, n)?,
            )));
        }
        if n_str == "34" {
            return Ok(Some(ConfigParam::ConfigParams34(
                Cell::load_config_param_34(cell, ref_index, parser, n)?,
            )));
        }
        if n_str == "36" {
            return Ok(Some(ConfigParam::ConfigParams36(
                Cell::load_config_param_36(cell, ref_index, parser, n)?,
            )));
        }
        Ok(None)
    }

    pub fn load_config_param_32(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: &BigUint,
    ) -> Result<ConfigParamsValidatorSet, TonCellError> {
        let mut config_param = ConfigParamsValidatorSet::default();
        config_param.number = 32;

        let validators = Cell::load_validator_set(cell, ref_index, parser, n)?;
        config_param.validators = validators;
        Ok(config_param)
    }

    pub fn load_config_param_34(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: &BigUint,
    ) -> Result<ConfigParamsValidatorSet, TonCellError> {
        let mut config_params_34 = ConfigParamsValidatorSet::default();
        config_params_34.number = 34;

        let validators = Cell::load_validator_set(cell, ref_index, parser, n)?;
        config_params_34.validators = validators;
        Ok(config_params_34)
    }

    pub fn load_config_param_36(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: &BigUint,
    ) -> Result<ConfigParamsValidatorSet, TonCellError> {
        let mut config_param = ConfigParamsValidatorSet::default();
        config_param.number = 36;

        let validators = Cell::load_validator_set(cell, ref_index, parser, n)?;
        config_param.validators = validators;
        Ok(config_param)
    }

    pub fn load_validator_set(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: &BigUint,
    ) -> Result<Validators, TonCellError> {
        let mut curr_vals = Validators::default();

        let _type = parser.load_u8(8)?;
        if _type == 0x11 {
            curr_vals._type = "".to_string();
            curr_vals.utime_since = parser.load_u32(32)?;
            curr_vals.utime_until = parser.load_u32(32)?;
            curr_vals.total = parser.load_uint(16)?;
            curr_vals.main = parser.load_uint(16)?;
            if curr_vals.total < curr_vals.main {
                return Err(TonCellError::cell_parser_error("data.total < data.main"));
            }
            if curr_vals.main < BigUint::from_u8(1).unwrap() {
                return Err(TonCellError::cell_parser_error("data.main < 1"));
            }
            curr_vals.list =
                Cell::load_hash_map(cell, ref_index, parser, 16, Cell::load_validator_descr)?;
        } else if _type == 0x12 {
            curr_vals._type = "ext".to_string();
            curr_vals.utime_since = parser.load_u32(32)?;
            curr_vals.utime_until = parser.load_u32(32)?;
            curr_vals.total = parser.load_uint(16)?;
            curr_vals.main = parser.load_uint(16)?;
            if curr_vals.total < curr_vals.main {
                return Err(TonCellError::cell_parser_error("data.total < data.main"));
            }
            if curr_vals.main < BigUint::from_u8(1).unwrap() {
                return Err(TonCellError::cell_parser_error("data.main < 1"));
            }
            curr_vals.total_weight = parser.load_u64(64)?;
            curr_vals.list =
                Cell::load_hash_map_e(cell, ref_index, parser, 16, Cell::load_validator_descr)?;
        }
        Ok(curr_vals)
    }

    pub fn load_validator_descr(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: &BigUint,
    ) -> Result<Option<ValidatorDescr>, TonCellError> {
        let mut validator = ValidatorDescr::default();

        let _type = parser.load_u8(8)?;
        validator._type = _type;
        validator.public_key = parser.load_sig_pub_key()?;
        validator.weight = parser.load_u64(64)?;
        if _type != 0x53 {
            validator.adnl_addr = parser.load_bytes(32)?;
        }
        Ok(Some(validator))
    }

    pub fn load_block(&self) -> Result<BlockData, TonCellError> {
        let ref_index = &mut 0;
        let block_info = self
            .load_ref_if_exist(ref_index, Some(Cell::load_block_info))
            .unwrap();
        self.load_ref_if_exist(ref_index, Some(Cell::load_value_flow))
            .unwrap();

        self.load_ref_if_exist(ref_index, Some(Cell::load_merkle_update))
            .unwrap();

        let block_extra = self
            .load_ref_if_exist(ref_index, Some(Cell::load_block_extra))
            .unwrap();

        Ok(BlockData {
            info: block_info.0,
            extra: block_extra.0,
        })
    }
}

impl Debug for Cell {
    // pub proof: bool,
    // pub hashes: Vec<Vec<u8>>,
    // pub depth: Vec<u16>,
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Cell{{ data: [{}], cell_type: {}, level_mask: {}, is_exotic: {}, has_hashes: {}, ,proof: {}, bit_len: {}, references: [\n",
            self.data
                .iter()
                .map(|&byte| format!("{:02X}", byte))
                .collect::<Vec<_>>()
                .join(""),
            self.cell_type,
            self.level_mask,
            self.is_exotic,
            self.has_hashes,
            self.proof,
            self.bit_len,
        )?;

        for reference in &self.references {
            writeln!(
                f,
                "    {}\n",
                format!("{:?}", reference).replace('\n', "\n    ")
            )?;
        }
        write!(f, "], hashes:[ ")?;
        for hash_vec in &self.hashes {
            writeln!(f, "[{:?}]", hash_vec)?;
        }
        write!(f, "], depth:[ ")?;
        for depth in &self.depth {
            writeln!(f, "[{:?}]", depth)?;
        }

        write!(f, "] }}")
    }
}
