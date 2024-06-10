use std::collections::HashMap;

use num_bigint::BigUint;

#[derive(Clone, Debug, Default)]
pub struct BlockInfo {
    pub prev_ref: BlkPrevRef,
}

#[derive(Clone, Debug, Default)]
pub struct BlockExtra {
    // pub in_msg_descr: Cell,
    // pub out_msg_descr: Cell,
    // pub account_blocks: Cell,
    // pub rand_seed: Vec<u8>,
    // pub created_by: Vec<u8>,
    pub custom: McBlockExtra,
}

#[derive(Clone, Debug, Default)]
pub struct McBlockExtra {
    // key_block: u8,
    // shard_hashes: Hashmap,
    // shard_fees: Hashmap,
    // replacement of shard_hashes, since it is unlikely that we will need the entire hashmap data of shard hashes, only shard data
    pub shards: HashMap<String, Vec<ShardDescr>>,
    pub config: ConfigParams,
}

#[derive(Clone, Debug, Default)]
pub struct ShardDescr {
    pub seqno: u64,
    pub reg_mc_seqno: u32,
    pub start_lt: BigUint,
    pub end_lt: BigUint,
    pub root_hash: Vec<u8>,
    pub file_hash: Vec<u8>,
    pub gen_utime: u64,
    pub next_validator_shard: BigUint,
}

#[derive(Clone, Debug, Default)]
pub struct BlkPrevRef {
    pub first_prev: Option<ExtBlkRef>,
    pub second_prev: Option<ExtBlkRef>,
}

#[derive(Clone, Debug, Default)]
pub struct ExtBlkRef {
    pub end_lt: u64,
    pub seqno: u32,
    pub root_hash: Vec<u8>,
    pub file_hash: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigParams {
    // pub config_addr: Vec<u8>,
    pub config: HashMap<String, Option<ConfigParam>>,
}

#[derive(Clone, Debug)]
pub enum ConfigParam {
    ConfigParams32(ConfigParamsValidatorSet),
    ConfigParams34(ConfigParamsValidatorSet),
    ConfigParams36(ConfigParamsValidatorSet),
}

#[derive(Clone, Debug, Default)]
pub struct ConfigParamsValidatorSet {
    pub number: u8,
    pub validators: Validators,
}

#[derive(Clone, Debug, Default)]
pub struct Validators {
    pub _type: String,
    pub utime_since: u32,
    pub utime_until: u32,
    pub total: BigUint,
    pub main: BigUint,
    pub total_weight: u64,
    pub list: HashMap<String, ValidatorDescr>,
}

#[derive(Clone, Debug, Default)]
pub struct ValidatorDescr {
    pub _type: u8,
    pub public_key: Vec<u8>,
    pub weight: u64,
    pub adnl_addr: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum BinTreeRes {
    Fork(Box<BinTreeFork>),
    Leaf(BinTreeLeafRes),
}

#[derive(Clone, Debug)]
pub struct BinTreeFork {
    pub left: Option<BinTreeRes>,
    pub right: Option<BinTreeRes>,
}

#[derive(Clone, Debug)]
pub enum BinTreeLeafRes {
    ShardDescr(ShardDescr),
}

impl BinTreeRes {
    pub fn get_all_shard_descrs_as_vec(&self) -> Vec<ShardDescr> {
        let mut result = Vec::new();
        self.collect_shard_descrs_into_vec(&mut result);
        result
    }

    fn collect_shard_descrs_into_vec(&self, vec: &mut Vec<ShardDescr>) {
        match self {
            BinTreeRes::Fork(fork) => {
                if let Some(left) = &fork.left {
                    left.collect_shard_descrs_into_vec(vec);
                }
                if let Some(right) = &fork.right {
                    right.collect_shard_descrs_into_vec(vec);
                }
            }
            BinTreeRes::Leaf(leaf_res) => match leaf_res {
                BinTreeLeafRes::ShardDescr(descr) => {
                    vec.push(descr.clone());
                }
                _ => (),
            },
        }
    }
}
