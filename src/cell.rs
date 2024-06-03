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
use bit_string::*;
use bitstream_io::{BigEndian, BitReader, BitWrite, BitWriter};
pub use builder::*;
pub use dict_loader::*;
pub use error::*;
use log::debug;
use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, ToPrimitive};
pub use parser::*;
pub use raw::*;
use sha2::{Digest, Sha256};
pub use slice::*;
pub use state_init::*;
pub use util::*;

use crate::hashmap::Hashmap;
use crate::responses::{
    BlockExtra, ConfigParams, ConfigParams34, CurrentValidators, McBlockExtra, ValidatorDescr,
};

mod bag_of_cells;
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

#[derive(PartialEq, Eq, Clone, Hash)]
pub struct Cell {
    pub data: Vec<u8>,
    pub bit_len: usize,
    pub references: Vec<ArcCell>,
    pub cell_type: u8,
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

    pub fn get_max_level(&self) -> u8 {
        //TODO level calculation differ for exotic cells
        let mut max_level = 0;
        for k in &self.references {
            let level = k.get_max_level();
            if level > max_level {
                max_level = level;
            }
        }
        max_level
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

    fn get_refs_descriptor(&self) -> u8 {
        self.references.len() as u8 + self.get_max_level() * 32
    }

    fn get_bits_descriptor(&self) -> u8 {
        let rest_bits = self.bit_len % 8;
        let full_bytes = rest_bits == 0;
        self.data.len() as u8 * 2 - if full_bytes { 0 } else { 1 } //subtract 1 if the last byte is not full
    }

    pub fn get_repr(&self) -> Result<Vec<u8>, TonCellError> {
        let data_len = self.data.len();
        let rest_bits = self.bit_len % 8;
        let full_bytes = rest_bits == 0;
        let mut writer = BitWriter::endian(Vec::new(), BigEndian);
        let val = self.get_refs_descriptor();
        writer.write(8, val).map_boc_serialization_error()?;
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
    ) -> Result<(), TonCellError> {
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

        cell.load_ref_if_exist(
            ref_index,
            Some(
                |c: &Cell, inner_ref_index: &mut usize, p: &mut CellParser| {
                    Cell::load_blk_prev_info(c, inner_ref_index, p, after_merge)
                },
            ),
        )?;

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
        Ok(())
    }

    pub fn load_blk_master_info(parser: &mut CellParser) -> Result<(), TonCellError> {
        Cell::load_ext_blk_ref(parser)
    }

    pub fn load_ext_blk_ref(parser: &mut CellParser) -> Result<(), TonCellError> {
        let end_lt = parser.load_u64(64)?;
        let seq_no = parser.load_u32(32)?;
        let root_hash = parser.load_bits(256)?;
        let file_hash = parser.load_bits(256)?;
        debug!("end_lt and seq_no: {:?}, {:?}", end_lt, seq_no);
        debug!("root hash: {:?}", root_hash);
        debug!("file hash: {:?}", file_hash);
        // FIXME: return ext blk ref
        Ok(())
    }

    pub fn load_blk_prev_info(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        after_merge: bool,
    ) -> Result<(), TonCellError> {
        if !after_merge {
            Cell::load_ext_blk_ref(parser)?;
        } else {
            cell.load_ref_if_exist_without_self(ref_index, Some(Cell::load_ext_blk_ref))?;
            cell.load_ref_if_exist_without_self(ref_index, Some(Cell::load_ext_blk_ref))?;
        }
        Ok(())
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
        let old_hash = parser.load_bits(256)?;
        let new_hash = parser.load_bits(256)?;
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
        cell.load_ref_if_exist(ref_index, Some(Cell::load_shard_account_blocks))?;
        let rand_seed = parser.load_bits(256)?;
        let created_by = parser.load_bits(256)?;
        debug!("rand seed: {:?}", rand_seed);
        debug!("created by: {:?}", created_by);

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
    ) -> Result<(), TonCellError> {
        let result = Cell::load_hash_map_aug_e(
            cell,
            ref_index,
            parser,
            256,
            Cell::load_account_block,
            Cell::load_currency_collection,
        )?;
        Ok(())
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

    pub fn load_hash_map_aug_e<F1, F2, T>(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: usize,
        f1: F1,
        f2: F2,
    ) -> Result<HashMap<String, T>, TonCellError>
    where
        F1: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<T, TonCellError> + Copy,
        F2: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<T, TonCellError> + Copy,
        T: Debug,
    {
        let hash_map_fn = |cell: &Cell,
                           ref_index: &mut usize,
                           parser: &mut CellParser,
                           key: &BigUint|
         -> Result<Option<T>, TonCellError> {
            let extra = f2(cell, ref_index, parser)?;
            let value = f1(cell, ref_index, parser)?;
            Ok(Some(value))
        };
        let mut hashmap = Hashmap::new(n, hash_map_fn);
        hashmap.deserialize_e(cell, ref_index, parser)?;
        debug!("data map: {:?}", hashmap.map);
        Ok(hashmap.map)
    }

    pub fn load_hash_map_aug<F1, F2, T>(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: usize,
        f1: F1,
        f2: F2,
    ) -> Result<HashMap<String, T>, TonCellError>
    where
        F1: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<T, TonCellError> + Copy,
        F2: FnOnce(&Cell, &mut usize, &mut CellParser) -> Result<T, TonCellError> + Copy,
        T: Debug,
    {
        let hash_map_fn = |cell: &Cell,
                           ref_index: &mut usize,
                           parser: &mut CellParser,
                           key: &BigUint|
         -> Result<Option<T>, TonCellError> {
            let extra = f2(cell, ref_index, parser)?;
            let value = f1(cell, ref_index, parser)?;
            Ok(Some(value))
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
        let last_trans_hash = parser.load_bits(256)?;
        let last_trans_lt = parser.load_u64(64)?;
        debug!("last trans hash: {:?}", last_trans_hash);
        debug!("last trans lt: {:?}", last_trans_lt);
        Ok(())
    }

    pub fn load_account_block(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        let magic = parser.load_uint(4)?;
        if magic != BigUint::from_u8(0x5).unwrap() {
            return Err(TonCellError::cell_parser_error("not an AccountBlock"));
        }
        let account_addr = parser.load_bits(256)?;
        debug!("account addr load account block: {:?}", account_addr);
        Cell::load_hash_map_aug(
            cell,
            ref_index,
            parser,
            64,
            |ref_cell: &Cell, inner_ref_index: &mut usize, _parser: &mut CellParser| {
                let _result =
                    ref_cell.load_ref_if_exist(inner_ref_index, Some(Cell::load_transaction))?;
                Ok(())
            },
            Cell::load_currency_collection,
        )?;
        cell.load_ref_if_exist(ref_index, Some(Cell::load_hash_update))?;
        Ok(())
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
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        // TODO: impl load transaction.
        // we can safely skip this because transaction is a different cell ref
        Ok(())
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
        let old_hash = parser.load_bits(256)?;
        let new_hash = parser.load_bits(256)?;
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
        Cell::load_shard_hashes(cell, ref_index, parser)?;
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
    ) -> Result<(), TonCellError> {
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
                            Cell::load_bin_tree(ref_ref_cell, inner_inner_ref_index, parser)
                        },
                    ),
                )?;
                Ok(result.0)
            },
        )?;
        Ok(())
    }

    pub fn load_bin_tree(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        // TODO: impl
        // We can safely ignore this since it is called in load_ref_if_exist
        Ok(())
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
        let node_id_short = parser.load_bits(256)?;
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
        let r = parser.load_bits(256)?;
        let s = parser.load_bits(256)?;
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

        let config_addr = parser.load_bits(256)?;
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
    ) -> Result<Option<ConfigParams34>, TonCellError> {
        if parser.remaining_bits() < parser.bit_len || *ref_index != 0 {
            return Err(TonCellError::cell_parser_error("Invalid config cell"));
        }
        debug!("config param number: {:?}", n.to_string());
        // we dont need to implement all config params because each param is a cell ref -> they are independent.
        let n_str = n.to_string();

        // validator set
        if n_str == "34" {
            return Ok(Some(Cell::load_config_param_34(
                cell, ref_index, parser, n,
            )?));
        }
        Ok(None)
    }

    pub fn load_config_param_34(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: &BigUint,
    ) -> Result<ConfigParams34, TonCellError> {
        let mut config_params_34 = ConfigParams34::default();
        config_params_34.number = 34;

        let validators = Cell::load_validator_set(cell, ref_index, parser, n)?;
        config_params_34.cur_validators = validators;
        Ok(config_params_34)
    }

    pub fn load_validator_set(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: &BigUint,
    ) -> Result<CurrentValidators, TonCellError> {
        let mut curr_vals = CurrentValidators::default();

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
        if _type == 0x53 {
            validator._type = "".to_string();
            validator.public_key = parser.load_sig_pub_key()?;
            validator.weight = parser.load_u64(64)?;
        } else {
            validator._type = "addr".to_string();
            validator.public_key = parser.load_sig_pub_key()?;
            validator.weight = parser.load_u64(64)?;
            validator.adnl_addr = parser.load_bits(256)?;
        }
        Ok(Some(validator))
    }
}

impl Debug for Cell {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Cell{{ data: [{}], bit_len: {}, references: [\n",
            self.data
                .iter()
                .map(|&byte| format!("{:02X}", byte))
                .collect::<Vec<_>>()
                .join(""),
            self.bit_len,
        )?;

        for reference in &self.references {
            writeln!(
                f,
                "    {}\n",
                format!("{:?}", reference).replace('\n', "\n    ")
            )?;
        }

        write!(f, "] }}")
    }
}
