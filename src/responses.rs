use std::{collections::HashMap, fmt::Debug};

use num_bigint::BigUint;

use crate::{address::TonAddress, cell::Cell};

#[derive(Clone, Debug, Default)]
pub struct VarUInteger {
    pub len: BigUint,
    pub value: BigUint,
}

#[derive(Clone, Debug, Default)]
pub struct BlockData {
    pub info: Option<BlockInfo>,
    pub extra: Option<BlockExtra>,
}

#[derive(Clone, Debug, Default)]
pub struct MaybeRefData<T>
where
    T: Clone + Debug + Default,
{
    pub data: Option<T>,
    pub cell: Option<Cell>,
}

#[derive(Clone, Debug, Default)]
pub struct BlockInfo {
    pub gen_utime: u32,
    pub prev_ref: BlkPrevRef,
}

#[derive(Clone, Debug, Default)]
pub struct BlockExtra {
    // pub in_msg_descr: Cell,
    // pub out_msg_descr: Cell,
    pub account_blocks: Option<HashMap<String, AccountBlock>>,
    // pub rand_seed: Vec<u8>,
    // pub created_by: Vec<u8>,
    pub custom: McBlockExtra,
}

#[derive(Clone, Debug, Default)]
pub struct AccountBlock {
    pub account_addr: Vec<u8>,
    pub transactions: HashMap<String, MaybeRefData<Transaction>>,
}

#[derive(Clone, Debug, Default)]
pub struct Transaction {
    pub hash: Vec<u8>,
    pub account_addr: Vec<u8>,
    pub lt: u64,
    pub prev_trans_hash: Vec<u8>,
    pub prev_trans_lt: u64,
    pub now: u32,
    pub outmsg_cnt: usize,
    pub orig_status: String,
    pub end_status: String,
    pub in_msg: MaybeRefData<TransactionMessage>,
    pub out_msgs: HashMap<String, MaybeRefData<TransactionMessage>>,
}

#[derive(Clone, Debug, Default)]
pub struct TransactionMessage {
    pub hash: Vec<u8>,
    pub info: CommonTransactionMessageInfo,
    pub body: TransactionBody,
}

#[derive(Clone, Debug, Default)]
pub struct TransactionBody {
    pub any: Option<AnyCell>,
    pub cell_ref: Option<(Option<AnyCell>, Option<Cell>)>,
}

#[derive(Clone, Debug, Default)]
pub struct CommonTransactionMessageInfo {
    pub msg_type: u8,
    pub ihr_disabled: bool,
    pub bounce: bool,
    pub bounced: bool,
    pub src: TonAddress,
    pub dest: TonAddress,
    pub value: CurrencyCollection,
    pub ihr_fee: VarUInteger,
    pub fwd_fee: VarUInteger,
    pub created_lt: u64,
    pub created_at: u32,
    pub import_fee: VarUInteger,
}

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub enum MessageType {
    Internal = 0,
    ExternalIn = 1,
    ExternalOut = 2,
}

#[derive(Clone, Debug, Default)]
pub struct McBlockExtra {
    // key_block: u8,
    // shard_hashes: Hashmap,
    // shard_fees: Hashmap,
    pub shards: HashMap<String, Vec<ShardDescr>>,
    pub config: ConfigParams,
}

#[derive(Clone, Debug, Default)]
pub struct ShardDescr {
    pub seqno: u32,
    pub reg_mc_seqno: u32,
    pub start_lt: u64,
    pub end_lt: u64,
    pub root_hash: Vec<u8>,
    pub file_hash: Vec<u8>,
    pub gen_utime: u64,
    pub next_validator_shard: u64,
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

#[derive(Clone, Debug, Default)]
pub struct CurrencyCollection {
    pub grams: VarUInteger,
    pub other: HashMap<String, VarUInteger>,
}

#[derive(Clone, Debug, Default)]
pub struct AnyCell {
    pub cell: Cell,
    pub ref_index: usize,
    pub parser_positions_in_bits: u64,
}
