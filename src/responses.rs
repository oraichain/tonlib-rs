use std::collections::HashMap;

use num_bigint::BigUint;

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
    pub config: ConfigParams,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigParams {
    // pub config_addr: Vec<u8>,
    pub config: HashMap<String, Option<ConfigParam>>,
}

#[derive(Clone, Debug)]
pub enum ConfigParam {
    ConfigParams32(ConfigParams32),
    ConfigParams34(ConfigParams34),
    ConfigParams36(ConfigParams36),
}

#[derive(Clone, Debug, Default)]
pub struct ConfigParams36 {
    pub number: u8,
    pub next_validators: Validators,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigParams34 {
    pub number: u8,
    pub cur_validators: Validators,
}

#[derive(Clone, Debug, Default)]
pub struct ConfigParams32 {
    pub number: u8,
    pub prev_validators: Validators,
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
