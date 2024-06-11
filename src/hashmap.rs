use std::{collections::HashMap, fmt::Debug};

use log::debug;
use num_bigint::BigUint;
use num_traits::FromPrimitive;

use crate::cell::{Cell, CellParser, CellType, TonCellError};

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum HashMapType {
    HashMap,
    HashMapE,
    HashMapAug,
    HashMapAugE,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Hashmap<F, V>
where
    F: FnOnce(&Cell, &mut usize, &mut CellParser, &BigUint) -> Result<Option<V>, TonCellError>
        + Copy,
{
    pub map: HashMap<String, V>,
    pub pruned: Vec<String>,
    pub n: usize,
    f: F, // Function for leaf load, change the type signature if needed
    pub hash_map_type: HashMapType,
}

impl<F, V> Hashmap<F, V>
where
    F: FnOnce(&Cell, &mut usize, &mut CellParser, &BigUint) -> Result<Option<V>, TonCellError>
        + Copy,
{
    /// Creates an empty hashmap with `n` bitwidth
    ///
    /// # Arguments
    ///
    /// * `n` - Hash bitwidth
    /// * `f` - Function for leaf load
    pub fn new(n: usize, f: F) -> Self {
        Hashmap {
            map: HashMap::new(),
            pruned: Vec::new(),
            n,
            f,
            hash_map_type: HashMapType::HashMap,
        }
    }

    pub fn deserialize(
        &mut self,
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        self.load_hashmap(
            cell,
            ref_index,
            parser,
            self.n,
            BigUint::from_u8(0).unwrap(),
            false,
        )
    }

    // for HashMapE
    pub fn deserialize_e(
        &mut self,
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
    ) -> Result<(), TonCellError> {
        cell.load_maybe_ref(
            ref_index,
            parser,
            Some(
                |inner_cell: &Cell, inner_ref_index: &mut usize, inner_parser: &mut CellParser| {
                    self.load_hashmap(
                        inner_cell,
                        inner_ref_index,
                        inner_parser,
                        self.n,
                        BigUint::from_u8(0).unwrap(),
                        false,
                    )
                },
            ),
            Some(
                |_inner_cell: &Cell, _inner_ref_index: &mut usize, _parser: &mut CellParser| Ok(()),
            ),
        )?;
        Ok(())
    }

    pub fn load_hashmap(
        &mut self,
        cell: &Cell,
        ref_index: &mut usize,
        parser: &mut CellParser,
        n: usize,
        key: BigUint,
        fork: bool,
    ) -> Result<(), TonCellError> {
        if cell.cell_type != CellType::OrdinaryCell as u8 {
            if cell.cell_type == CellType::PrunnedBranchCell as u8 {
                self.pruned.push(key.to_str_radix(2));
            }
            return Ok(());
        }
        debug!("cell type in load hashmap: {:?}", cell.cell_type);
        debug!("cell bits: {:?}", cell.data);
        debug!("current n & fork: {:?}, {:?}", n, fork);
        if n == 0 && fork {
            let data = (self.f)(cell, ref_index, parser, &key)?;
            if let Some(data) = data {
                self.map.insert(key.to_str_radix(16), data);
            }
            return Ok(());
        }

        if fork {
            // left
            let left: BigUint = key << 1; // pow 2
            debug!("left key: {:?}", left);
            let left_ref_cell = cell.reference(ref_index.to_owned())?;
            let left_parser = &mut left_ref_cell.parser();
            self.load_hashmap(
                left_ref_cell,
                &mut 0usize,
                left_parser,
                n - 1,
                left.clone(),
                !fork,
            )?;
            *ref_index += 1;
            debug!("left ref cell data: {:?}", left_ref_cell.data);

            // right
            let right = left + BigUint::from_u8(1).unwrap();
            debug!("right key: {:?}", right);
            let right_ref_cell = cell.reference(ref_index.to_owned())?;
            let right_parser = &mut right_ref_cell.parser();
            self.load_hashmap(
                right_ref_cell,
                &mut 0usize,
                right_parser,
                n - 1,
                right,
                !fork,
            )?;
            *ref_index += 1;
            debug!("right ref cell data: {:?}", right_ref_cell.data);

            debug!("ref index after recursion: {:?}", ref_index);
            return Ok(());
        } else {
            let label = parser.load_label(n)?;
            debug!("label: {:?}", label);
            if label.1 > 0 {
                let next_key = key << label.1 | label.0;
                let m = n - usize::try_from(label.1).map_err(TonCellError::cell_parser_error)?;
                debug!("next key: {:?}", next_key);
                debug!("m: {:?}", m);
                self.load_hashmap(cell, ref_index, parser, m, next_key, !fork)?;
            } else {
                self.load_hashmap(cell, ref_index, parser, n, key, !fork)?;
            }
        }
        Ok(())
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct HashmapAugResult<T1, T2>
where
    T1: Clone + Debug + Default,
    T2: Clone + Debug + Default,
{
    pub value: T1,
    pub extra: T2,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct HashmapAugEResult<T1, T2>
where
    T1: Clone + Debug + Default,
    T2: Clone + Debug + Default,
{
    pub value: T1,
    pub extra: T2,
}
