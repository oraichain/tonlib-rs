use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;

use crate::cell::*;

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub struct BagOfCells {
    pub roots: Vec<ArcCell>,
}

impl BagOfCells {
    pub fn new(roots: &[ArcCell]) -> BagOfCells {
        BagOfCells {
            roots: roots.to_vec(),
        }
    }

    pub fn from_root(root: Cell) -> BagOfCells {
        let arc = Arc::new(root);
        BagOfCells { roots: vec![arc] }
    }

    pub fn add_root(&mut self, root: Cell) {
        let arc = Arc::new(root);
        self.roots.push(arc)
    }

    pub fn num_roots(&self) -> usize {
        self.roots.len()
    }

    pub fn root(&self, idx: usize) -> Result<&ArcCell, TonCellError> {
        self.roots.get(idx).ok_or_else(|| {
            TonCellError::boc_deserialization_error(format!(
                "Invalid root index: {}, BoC contains {} roots",
                idx,
                self.roots.len()
            ))
        })
    }

    pub fn single_root(&self) -> Result<&ArcCell, TonCellError> {
        let root_count = self.roots.len();
        if root_count == 1 {
            Ok(&self.roots[0])
        } else {
            Err(TonCellError::CellParserError(format!(
                "Single root expected, got {}",
                root_count
            )))
        }
    }

    pub fn parse(serial: &[u8]) -> Result<BagOfCells, TonCellError> {
        let raw = RawBagOfCells::parse(serial)?;
        let num_cells = raw.cells.len();
        let mut cells: Vec<ArcCell> = Vec::new();
        for i in (0..num_cells).rev() {
            let raw_cell = &raw.cells[i];
            let mut cell = Cell {
                data: raw_cell.data.clone(),
                bit_len: raw_cell.bit_len,
                references: Vec::new(),
                cell_type: raw_cell.cell_type,
            };
            for r in &raw_cell.references {
                if *r <= i {
                    return Err(TonCellError::boc_deserialization_error(
                        "References to previous cells are not supported",
                    ));
                }
                cell.references.push(cells[num_cells - 1 - r].clone());
            }
            cells.push(Arc::new(cell));
        }
        let roots: Vec<ArcCell> = raw
            .roots
            .iter()
            .map(|r| cells[num_cells - 1 - r].clone())
            .collect();
        Ok(BagOfCells { roots })
    }

    pub fn parse_hex(hex: &str) -> Result<BagOfCells, TonCellError> {
        let str: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        let bin = hex::decode(str.as_str()).map_boc_deserialization_error()?;
        Self::parse(&bin)
    }

    pub fn parse_base64(base64: &str) -> Result<BagOfCells, TonCellError> {
        let bin = STANDARD.decode(base64).map_boc_deserialization_error()?;
        Self::parse(&bin)
    }

    pub fn serialize(&self, has_crc32: bool) -> Result<Vec<u8>, TonCellError> {
        let raw = self.to_raw()?;
        raw.serialize(has_crc32)
    }

    /// Traverses all cells, fills all_cells set and inbound references map.
    fn traverse_cell_tree(
        cell: &ArcCell,
        all_cells: &mut HashSet<ArcCell>,
        in_refs: &mut HashMap<ArcCell, HashSet<ArcCell>>,
    ) -> Result<(), TonCellError> {
        if !all_cells.contains(cell) {
            all_cells.insert(cell.clone());
            for r in &cell.references {
                if r == cell {
                    return Err(TonCellError::BagOfCellsDeserializationError(
                        "Cell must not reference itself".to_string(),
                    ));
                }
                let maybe_refs = in_refs.get_mut(&r.clone());
                match maybe_refs {
                    Some(refs) => {
                        refs.insert(cell.clone());
                    }
                    None => {
                        let mut refs: HashSet<ArcCell> = HashSet::new();
                        refs.insert(cell.clone());
                        in_refs.insert(r.clone(), refs);
                    }
                }
                Self::traverse_cell_tree(r, all_cells, in_refs)?;
            }
        }
        Ok(())
    }

    /// Constructs raw representation of BagOfCells
    pub(crate) fn to_raw(&self) -> Result<RawBagOfCells, TonCellError> {
        let mut all_cells: HashSet<ArcCell> = HashSet::new();
        let mut in_refs: HashMap<ArcCell, HashSet<ArcCell>> = HashMap::new();
        for r in &self.roots {
            Self::traverse_cell_tree(r, &mut all_cells, &mut in_refs)?;
        }
        let mut no_in_refs: HashSet<ArcCell> = HashSet::new();
        for c in &all_cells {
            if !in_refs.contains_key(c) {
                no_in_refs.insert(c.clone());
            }
        }
        let mut ordered_cells: Vec<ArcCell> = Vec::new();
        let mut indices: HashMap<ArcCell, usize> = HashMap::new();
        while !no_in_refs.is_empty() {
            let cell = no_in_refs.iter().next().unwrap().clone();
            ordered_cells.push(cell.clone());
            indices.insert(cell.clone(), indices.len());
            for child in &cell.references {
                if let Some(refs) = in_refs.get_mut(child) {
                    refs.remove(&cell);
                    if refs.is_empty() {
                        no_in_refs.insert(child.clone());
                        in_refs.remove(child);
                    }
                }
            }
            no_in_refs.remove(&cell);
        }
        if !in_refs.is_empty() {
            return Err(TonCellError::CellBuilderError(
                "Can't construct topological ordering: cycle detected".to_string(),
            ));
        }
        let mut cells: Vec<RawCell> = Vec::new();
        for cell in &ordered_cells {
            let refs: Vec<usize> = cell
                .references
                .iter()
                .map(|c| *indices.get(c).unwrap())
                .collect();
            let raw = RawCell {
                data: cell.data.clone(),
                bit_len: cell.bit_len,
                references: refs,
                max_level: cell.get_max_level(),
                cell_type: cell.cell_type,
            };
            cells.push(raw);
        }
        let roots: Vec<usize> = self
            .roots
            .iter()
            .map(|c| *indices.get(c).unwrap())
            .collect();
        Ok(RawBagOfCells { cells, roots })
    }
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::sync::Arc;
    use std::time::Instant;

    use crate::cell::{BagOfCells, Cell, CellBuilder, TonCellError};
    use crate::message::ZERO_COINS;

    #[test]
    fn cell_repr_works() -> anyhow::Result<()> {
        let hole_address = "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c".parse()?;
        let contract = "EQDwHr48oKCFD5od9u_TnsCOhe7tGZIei-5ESWfzhlWLRYvW".parse()?;
        let token0 = "EQDk2VTvn04SUKJrW7rXahzdF8_Qi6utb0wj43InCu9vdjrR".parse()?;
        let token1 = "EQAIcb1WqNr0E7rOXgO0cbAZQnVbS06mgH2vgBvtBE6p0T2a".parse()?;
        let raw =
            "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\
        1MALHGAGMjLBVADzxZw+gISy2rMyYMG+wBA0lqA";

        let boc = BagOfCells::parse_base64(raw)?;
        let cell = boc.single_root()?;

        let jetton_wallet_code_lp = cell.reference(0)?;
        let pool_code = cell.reference(1)?;
        let account_lp_code = cell.reference(2)?;

        let protocol_fee = CellBuilder::new()
            .store_coins(&ZERO_COINS)?
            .store_coins(&ZERO_COINS)?
            .store_raw_address(&hole_address)?
            .store_coins(&ZERO_COINS)?
            .store_coins(&ZERO_COINS)?
            .build()?;

        let data = CellBuilder::new()
            .store_address(&contract)?
            .store_u8(4, 2)?
            .store_u8(4, 0)?
            .store_u8(4, 1)?
            .store_address(&token0)?
            .store_address(&token1)?
            .store_coins(&ZERO_COINS)?
            .store_reference(&Arc::new(protocol_fee))?
            .store_reference(jetton_wallet_code_lp)?
            .store_reference(account_lp_code)?
            .build()?;

        let state = CellBuilder::new()
            .store_bit(false)? //Split depth
            .store_bit(false)? //Ticktock
            .store_bit(true)? //Code
            .store_bit(true)? //Data
            .store_bit(false)? //Library
            .store_reference(pool_code)?
            .store_reference(&Arc::new(data))?
            .build()?;

        assert_eq!(
            hex::encode(state.get_repr()?),
            "0201340009000838eee530fd07306581470adf04f707ca92198672c6e4186c331954d4a82151\
                   d553f1bdeac386cb209570c7d74fac7b2b938896147530e3fb4459f46f7b0a18a0"
        );

        Ok(())
    }

    #[ignore]
    #[test]
    fn check_code_hash() -> Result<(), TonCellError> {
        let raw = include_str!("../../resources/wallet/wallet_v3r1.code");
        let boc = BagOfCells::parse_base64(raw)?;
        println!(
            "wallet_v3_code code_hash{:?}",
            boc.single_root()?.cell_hash_base64()?
        );

        let raw = include_str!("../../resources/wallet/wallet_v3r2.code");
        let boc = BagOfCells::parse_base64(raw)?;
        println!(
            "wallet_v3r2_code code_hash{:?}",
            boc.single_root()?.cell_hash_base64()?
        );

        let raw = include_str!("../../resources/wallet/wallet_v4r2.code");
        let boc = BagOfCells::parse_base64(raw)?;
        println!(
            "wallet_v4r2_code code_hash{:?}",
            boc.single_root()?.cell_hash_base64()?
        );
        Ok(())
    }

    #[ignore]
    #[test]
    fn benchmark_cell_repr() -> anyhow::Result<()> {
        let now = Instant::now();
        for _ in 1..10000 {
            let result = cell_repr_works();
            match result {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        let elapsed = now.elapsed();
        println!("Elapsed: {:.2?}", elapsed);
        Ok(())
        // initially it works for 10.39seceonds
    }

    #[test]
    fn it_constructs_raw() -> anyhow::Result<()> {
        let leaf = CellBuilder::new().store_byte(10)?.build()?;
        let inter = CellBuilder::new()
            .store_byte(20)?
            .store_child(leaf)?
            .build()?;
        let root = CellBuilder::new()
            .store_byte(30)?
            .store_child(inter)?
            .build()?;
        let boc = BagOfCells::from_root(root);
        let _raw = boc.to_raw()?;
        Ok(())
    }

    #[test]
    fn test_load_block() -> anyhow::Result<()> {
        let boc = "b5ee9c72410234010007c900041011ef55aafffffffd0103040501a09bc7a987000000000601004262100000000000ffffffff000000000000000063566c62000004d23f800dc0000004d23f800dc708fd4f290000df980042620d00425a75c400000003000000000000002e0208480101622689df2205931afa1d7c115f79f8fac4ea73f4edb05fabdca81c020f22a6130000084801012dfc806d1c50694678c34d5816e9316a00b94b05e085b5f97db07e9d8883040a0003084801011a6a28d6cea96f567bc6cd7da3ef88328865235ddd97386477d1436ce553595a001a04894a33f6fd5efff688d3a3cb98a24a4a498c8a67fd66e28a75139bf8363cd39ba56ebafdbedc9fcfce7dd2bf882a6833fb941d6e10bdc82bd9b2a4d123d114b81dde215c54c00607080908480101d72c3cbab4c1aded3d3342b743ec8f1f87d3d2656c439d39eccd5bab779c48e2000c08480101145ebae9f5d86e55979e5b6fcc1be5e39d70001e487d40a0bc4773b802c0fe4b000c08480101aef4bc8f76ad0dfb68e5a5c151d0fb544f45483ed32cacafde88ddb50a1121da000e0457cca5e87735940043b9aca002aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac0a0b0c0d08480101501d1b77377edb7e682530a6ea1678615080b4bd76d9b1591b6c921688b02a12000208480101e18e1a1a40f3e0ccfcc3fc904f6ae42006e9e1c78ce6ef4bbffbf7d6e3770895000008480101f510fd883f3bd56c0f3e7cb3ab4684b225b34998cbea82a9a3e446d2dde602a300040201200e330202d80f320201201011084801018a67f6328db6b01c422c97114927cd9f39ca6e9578d437debecdf1091a4e98d7000d020162123102012013140848010162c1ea84ef6c2221181abacda0baff83ac88e6d3dd77f16ce981319739dcdf70000601014815012b12635650f663566d16000e000e0ffffffffffffff8c0160202cc1726020120181f020120191c0201201a1b009b1ce3a049e2a2518bdda34c61d6688c3dcbbe4af6f340a8271e475039a80694fd090278922840492492492492493b0391252e60a1cf81bbacde546f1e2805087fc291d5da465d963bc14e53df9060009b1ce3a049e2aaeb6babda7e323ceb3052c9361f70c7c7e12ed7e64f1935df83ca21d0c30ca4c0492492492492491d24bbd188fe0ffa6fe5affaed46c3913b84d00011c04c9bf6e3a576387144c2e00201201d1e009b1ce3a049e2a7fa088020c2a7fdfa4a91c0aac7a69c3826ff06394142059cf5893fa442bbd800492492492492492d2eaf1e23aac0ed093523bcd157e2fc7bc76ec0f3777a0772a25a9d493f9338a0009b1ce3a049e28e87ef1aac2280bf5fbf1869d0bb94ac94c9a7f2922b757b41968231a7d0bff70049249249249249154e4c591dc8671e0169285fbf6dbf498a767668892de738e800cdc902660378e002012020230201202122009b1ce3a049e2b714cbc17f2056cc2123f17ad04ce3a8e19da0627da7f27ac6246038fe66ee3e404924924924924903e69b47ddd935888b818916e6ef5be4323655182b6c93dd8ab5f902b2f12584e0009b1ce3a049e29d989ee1e95c5fa72aacea0112a3dd7f636a62d44b015f95b7bfaa454a7e6d5cc04924924924924919f259fff0b013a108033f9f5e92a0f76940f8841876ff02b0f7142c2c79bdbc200201202425009b1ce3a049e2b727f3f39f74afe20a9a0cfee5075b842f720af66ca93448f4452e0777885715004924924924924917b92409e2a3f8307539cefb50b14617198615bbe5de202fefe644c72588260460009b1ce3a049e29d21582596bfcc6d1de358003ef042e5207f4c804d7a1c7eb4df45e61dcb12bac0492492492492492632154ae74d72cbf208021b88ec8d3d89a3fcc246e6532354b918b784c81030a0020120272e020120282b020120292a009b1ce3a049e2bb5203d6b26731acaa20369ddcf706ef8a861473e9c00fe2051695440e366cb9804924924924924924d365a568e1356f3d7e3b9949501619745721ca7cf0feb0fad4d2f8847c283020009b1ce3a049e2b5e9e4f9e2be0699846cd5462dd33c0db38ed1e20a8e2b5a11ea6d6fd71eb35b80492492492492493d7579a885d03932c5eba75600dceb15b9b2ae4968d27b4b80c640d6bfe60615a00201202c2d009b1ce3a049e2a25935e71c9cf1b50eadc3bb29e330df9cea0d3b68cd6aff8eedc2659ccab428404924924924924902cdb4413b9ee19a9b2db5e70ac0e41126747c2fee2edd6f2a224f09cf8d6be1e0009b1ce3a049e2b0b092e100a69d80c496cbb06414bc2512888a9c398315ad596b57764098164cc0492492492492491a0b69ee5777de48e854d7d2af8d143b0e0ab1930204b4f9e3a0ec57c2722f57e00201482f30009b1ce3a049e280d5bc09be3be73173d7e7cf402cc5706e9b4f1e5328331252638d4b6e187161004924924924924910d373d1795c02c745f16012330554d25d29f2cde88cab85f7b59f5572c59b52a0009b1ce3a049e28c93015aa3bf9e078b7a9bdd8e8f679834d75ecc1a0b51ade9a2395ec4a783e1c0492492492492491314ebb23c23bcf1ac5161fdf8ec6a3d3dad7d11b69a06af999f93bb9004e1a7200848010163511fa3d0e8eecd5420bafaaec83756e73f6acbc3914c5e73b2b2a22d122ef600060848010158c3ae4bc6066210f95a43067af52664c1f4d45f3618f3a8febe64da69e91598000208480101a6bce8d8b17cdf7388cb73c7978ae03862d2fdc3cc227d34475f0a8d3cee738e00059da9d19b";

        let mut ref_index = &mut 0;
        let cells = BagOfCells::parse_hex(boc).unwrap();
        let first_root = cells.single_root().unwrap();
        let mut parser = first_root.parser();
        let magic = parser.load_u32(32).unwrap();
        println!("magic: {:?}", magic);
        let global_id = parser.load_i32(32).unwrap();
        println!("global id: {:?}", global_id);
        println!(
            "current index: {:?}",
            parser.bit_reader.position_in_bits().unwrap()
        );
        let cell_type = first_root.get_bits_descriptor();
        println!("cell type: {:?}", first_root.cell_type);
        first_root
            .load_ref_if_exist(ref_index, Some(Cell::load_block_info))
            .unwrap();
        first_root
            .load_ref_if_exist(ref_index, Some(Cell::load_value_flow))
            .unwrap();

        first_root
            .load_ref_if_exist(ref_index, Some(Cell::load_merkle_update))
            .unwrap();
        Ok(())
    }
}
