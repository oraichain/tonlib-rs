use std::collections::HashMap;
use std::fmt;
use std::fmt::{Debug, Formatter};
use std::hash::Hash;
use std::io::Cursor;
use std::ops::Deref;
use std::sync::Arc;

pub use bag_of_cells::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bit_string::*;
use bitstream_io::{BigEndian, BitReader, BitWrite, BitWriter};
pub use builder::*;
pub use dict_loader::*;
pub use error::*;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};
pub use parser::*;
pub use raw::*;
use sha2::{Digest, Sha256};
pub use slice::*;
pub use state_init::*;
pub use util::*;

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
        println!("ref index: {:?}", ref_index);
        println!("reference cell type: {:?}", reference.cell_type);
        if reference.cell_type != CellType::PrunnedBranchCell as u8 && parse_option.is_some() {
            let parse = parse_option.unwrap();
            let res = parse(&reference, &mut 0usize, &mut parser)?;
            return Ok((Some(res), None));
        } else if reference.cell_type == CellType::PrunnedBranchCell as u8 {
            return Ok((None, Some(reference)));
        }
        Err(TonCellError::cell_parser_error("Load ref not supported"))
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
        println!("data: {:?}", prev_key_block_seqno);
        println!("flag & 1: {:?}", flags & 1);
        println!("not master: {:?}", not_master);

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
        println!("end_lt and seq_no: {:?}, {:?}", end_lt, seq_no);
        println!("root hash: {:?}", root_hash);
        println!("file hash: {:?}", file_hash);
        // FIXME: return ext blk ref
        Ok(())
    }

    pub fn load_blk_prev_info(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        after_merge: bool,
    ) -> Result<(), TonCellError> {
        println!("in load blk prev info");
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
        if parser.load_u32(32)? != 0xb8e48dfb {
            return Err(TonCellError::cell_parser_error("not a ValueFlow"));
        }
        Ok(())
    }

    pub fn load_merkle_update(
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        if parser.load_u8(32)? != 0x04 {
            return Err(TonCellError::cell_parser_error("not a Merkle Update"));
        }
        let old_hash = parser.load_bits(256)?;
        let new_hash = parser.load_bits(256)?;
        println!("old hash: {:?}", old_hash);
        println!("new hash: {:?}", new_hash);
        let old = cell.reference(*ref_index)?;
        *ref_index += 1;
        let new = cell.reference(*ref_index)?;
        *ref_index += 1;
        Ok(())
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
